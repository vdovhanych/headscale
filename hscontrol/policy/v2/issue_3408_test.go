package v2

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/juanfont/headscale/hscontrol/policy/matcher"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
)

// TestIssue3408ViaExitNodeVisibleToMembers reproduces
// https://github.com/juanfont/headscale/issues/3408: a grant of the form
//
//	{"src": ["autogroup:member"], "dst": ["autogroup:internet"],
//	 "via": ["tag:exit"], "ip": ["*"]}
//
// must offer the tag:exit exit node to viewers whose only matching grant
// is the via grant. Admins reaching the same node through a separate
// non-via rule already work; members matching only the via grant saw
// "No Exit Nodes Available".
func TestIssue3408ViaExitNodeVisibleToMembers(t *testing.T) {
	t.Parallel()

	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "admin", Email: "admin@example.com"},
		{Model: gorm.Model{ID: 2}, Name: "bob", Email: "bob@example.com"},
	}

	adminLaptop := node("admin-laptop", "100.64.0.1", "fd7a:115c:a1e0::1", users[0])
	adminLaptop.ID = 1

	bobLaptop := node("bob-laptop", "100.64.0.2", "fd7a:115c:a1e0::2", users[1])
	bobLaptop.ID = 2

	exitNode := node("exit-node", "100.64.0.3", "fd7a:115c:a1e0::3", users[0])
	exitNode.ID = 3
	exitNode.Tags = []string{"tag:exit"}
	exitNode.Hostinfo = &tailcfg.Hostinfo{
		RoutableIPs: tsaddr.ExitRoutes(),
	}
	exitNode.ApprovedRoutes = tsaddr.ExitRoutes()

	nodes := types.Nodes{adminLaptop, bobLaptop, exitNode}

	policy := `{
		"tagOwners": {
			"tag:exit": ["admin@example.com"]
		},
		"autoApprovers": {
			"exitNode": ["tag:exit"]
		},
		"groups": {
			"group:admins": ["admin@example.com"]
		},
		"grants": [
			{
				"src": ["group:admins"],
				"dst": ["*"],
				"ip": ["*"]
			},
			{
				"src": ["autogroup:member"],
				"dst": ["autogroup:internet"],
				"via": ["tag:exit"],
				"ip": ["*"]
			}
		]
	}`

	pm, err := NewPolicyManager([]byte(policy), users, nodes.ViewSlice())
	require.NoError(t, err)

	t.Run("ViaRoutesForPeer_includes_exit_routes_for_member", func(t *testing.T) {
		t.Parallel()

		result := pm.ViaRoutesForPeer(bobLaptop.View(), exitNode.View())
		for _, route := range tsaddr.ExitRoutes() {
			require.Containsf(t, result.Include, route,
				"bob viewing tag:exit exit node must Include %s so it lands in AllowedIPs", route)
		}

		require.Empty(t, result.Exclude,
			"bob viewing tag:exit exit node must not Exclude exit routes")
		require.Empty(t, result.UsePrimary,
			"no regular grant covers the internet for bob; via steering must apply")
	})

	t.Run("exit_node_filter_accepts_member_to_internet", func(t *testing.T) {
		t.Parallel()

		rules, err := pm.FilterForNode(exitNode.View())
		require.NoError(t, err)

		matches := matcher.MatchesFromFilterRules(rules)
		found := slices.ContainsFunc(matches, func(m matcher.Match) bool {
			return m.SrcsContainsIPs(netip.MustParseAddr("100.64.0.2")) &&
				m.DestsIsTheInternet()
		})
		require.Truef(t, found,
			"exit node filter must accept member bob's traffic to the internet; got rules=%+v", rules)
	})

	t.Run("member_reaches_exit_node_through_exit_nodes_matchers", func(t *testing.T) {
		t.Parallel()

		// Via rules are emitted only on the via-tagged node, so the rule
		// authorising bob -> exit node lives in the exit node's matchers,
		// not bob's. Peer-visibility filtering (mapper.reducePeers,
		// BuildPeerMap) must consult the peer's matchers for this pair.
		exitMatchers, err := pm.MatchersForNode(exitNode.View())
		require.NoError(t, err)
		require.True(t,
			bobLaptop.View().CanAccess(exitMatchers, exitNode.View()),
			"bob must reach the exit node under the exit node's matchers")
	})

	t.Run("BuildPeerMap_pairs_member_with_exit_node", func(t *testing.T) {
		t.Parallel()

		peerMap := pm.BuildPeerMap(nodes.ViewSlice())
		bobPeers := peerMap[bobLaptop.ID]
		require.Truef(t,
			slices.ContainsFunc(bobPeers, func(n types.NodeView) bool {
				return n.ID() == exitNode.ID
			}),
			"bob must see the exit node as a peer; got %d peers", len(bobPeers))
	})

	t.Run("admin_still_reaches_exit_node_via_regular_grant", func(t *testing.T) {
		t.Parallel()

		result := pm.ViaRoutesForPeer(adminLaptop.View(), exitNode.View())
		require.NotContains(t, result.Exclude, netip.MustParsePrefix("0.0.0.0/0"),
			"admin matches the non-via grant; exit routes must not be excluded")
	})
}
