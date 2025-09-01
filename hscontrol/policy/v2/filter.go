package v2

import (
	"errors"
	"fmt"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/rs/zerolog/log"
	"go4.org/netipx"
	"tailscale.com/tailcfg"
	"tailscale.com/types/views"
)

var ErrInvalidAction = errors.New("invalid action")

// compileFilterRules takes a set of nodes and an ACLPolicy and generates a
// set of Tailscale compatible FilterRules used to allow traffic on clients.
func (pol *Policy) compileFilterRules(
	users types.Users,
	nodes views.Slice[types.NodeView],
) ([]tailcfg.FilterRule, error) {
	if pol == nil {
		return tailcfg.FilterAllowAll, nil
	}

	var rules []tailcfg.FilterRule

	for _, acl := range pol.ACLs {
		if acl.Action != "accept" {
			return nil, ErrInvalidAction
		}

		srcIPs, err := acl.Sources.Resolve(pol, users, nodes)
		if err != nil {
			log.Trace().Err(err).Msgf("resolving source ips")
		}

		if srcIPs == nil || len(srcIPs.Prefixes()) == 0 {
			continue
		}

		// TODO(kradalby): integrate type into schema
		// TODO(kradalby): figure out the _ is wildcard stuff
		protocols, _, err := parseProtocol(acl.Protocol)
		if err != nil {
			return nil, fmt.Errorf("parsing policy, protocol err: %w ", err)
		}

		var destPorts []tailcfg.NetPortRange
		for _, dest := range acl.Destinations {
			ips, err := dest.Resolve(pol, users, nodes)
			if err != nil {
				log.Trace().Err(err).Msgf("resolving destination ips")
			}

			if ips == nil {
				log.Debug().Msgf("destination resolved to nil ips: %v", dest)
				continue
			}

			prefixes := ips.Prefixes()

			for _, pref := range prefixes {
				for _, port := range dest.Ports {
					pr := tailcfg.NetPortRange{
						IP:    pref.String(),
						Ports: port,
					}
					destPorts = append(destPorts, pr)
				}
			}
		}

		if len(destPorts) == 0 {
			continue
		}

		rules = append(rules, tailcfg.FilterRule{
			SrcIPs:   ipSetToPrefixStringList(srcIPs),
			DstPorts: destPorts,
			IPProto:  protocols,
		})
	}

	return rules, nil
}

// compileFilterRulesForNode compiles filter rules for a specific node.
// This follows the same pattern as compileSSHPolicy which always compiles per-node.
func (pol *Policy) compileFilterRulesForNode(
	users types.Users,
	node types.NodeView,
	nodes views.Slice[types.NodeView],
) ([]tailcfg.FilterRule, error) {
	if pol == nil {
		return tailcfg.FilterAllowAll, nil
	}

	var rules []tailcfg.FilterRule

	for _, acl := range pol.ACLs {
		if acl.Action != "accept" {
			return nil, ErrInvalidAction
		}

		// Always compile per-node to handle autogroup:self securely
		rule, err := pol.compileACLWithAutogroupSelf(acl, users, node, nodes)
		if err != nil {
			log.Trace().Err(err).Msgf("compiling ACL")
			continue
		}

		if rule != nil {
			rules = append(rules, *rule)
		}
	}

	return rules, nil
}

// compileACLWithAutogroupSelf compiles a single ACL rule, handling
// autogroup:self per-node while supporting all other alias types normally.
func (pol *Policy) compileACLWithAutogroupSelf(
	acl ACL,
	users types.Users,
	node types.NodeView,
	nodes views.Slice[types.NodeView],
) (*tailcfg.FilterRule, error) {
	// Check if this ACL has autogroup:self in destinations
	hasAutogroupSelf := false
	for _, dest := range acl.Destinations {
		if ag, ok := dest.Alias.(*AutoGroup); ok && ag.Is(AutoGroupSelf) {
			hasAutogroupSelf = true
			break
		}
	}

	// If this ACL doesn't use autogroup:self, fall back to standard compilation
	if !hasAutogroupSelf {
		// Use standard resolution for all aliases
		srcIPs, err := resolveACLSources(pol, acl.Sources, users, nodes)
		if err != nil {
			return nil, err
		}

		if srcIPs == nil || len(srcIPs.Prefixes()) == 0 {
			return nil, nil
		}

		protocols, _, err := parseProtocol(acl.Protocol)
		if err != nil {
			return nil, fmt.Errorf("parsing policy, protocol err: %w ", err)
		}

		var destPorts []tailcfg.NetPortRange
		for _, dest := range acl.Destinations {
			ips, err := dest.Resolve(pol, users, nodes)
			if err != nil {
				log.Trace().Err(err).Msgf("resolving destination ips")
				continue
			}

			if ips == nil {
				log.Debug().Msgf("destination resolved to nil ips: %v", dest)
				continue
			}

			prefixes := ips.Prefixes()
			for _, pref := range prefixes {
				for _, port := range dest.Ports {
					pr := tailcfg.NetPortRange{
						IP:    pref.String(),
						Ports: port,
					}
					destPorts = append(destPorts, pr)
				}
			}
		}

		if len(destPorts) == 0 {
			return &tailcfg.FilterRule{}, nil
		}

		return &tailcfg.FilterRule{
			SrcIPs:   ipSetToPrefixStringList(srcIPs),
			DstPorts: destPorts,
			IPProto:  protocols,
		}, nil
	}

	// Handle ACLs with autogroup:self in destinations
	var srcIPs netipx.IPSetBuilder

	// For ACLs with autogroup:self destinations, sources must be filtered 
	// to only include devices from the same user as the target node
	for _, src := range acl.Sources {
		// Sources are never autogroup:self (validation prevents this)
		// Instead, we resolve the source normally, then filter to same user
		ips, err := src.Resolve(pol, users, nodes)
		if err != nil {
			log.Trace().Err(err).Msgf("resolving source ips")
			continue
		}

		if ips != nil {
			// Filter source IPs to only include devices from the same user
			filteredIPs := filterIPSetToSameUser(ips, nodes, types.UserID(node.User().ID))
			srcIPs.AddSet(filteredIPs)
		}
	}

	srcSet, err := srcIPs.IPSet()
	if err != nil {
		return nil, err
	}

	if srcSet == nil || len(srcSet.Prefixes()) == 0 {
		return nil, nil
	}

	protocols, _, err := parseProtocol(acl.Protocol)
	if err != nil {
		return nil, fmt.Errorf("parsing policy, protocol err: %w ", err)
	}

	var destPorts []tailcfg.NetPortRange

	for _, dest := range acl.Destinations {
		if ag, ok := dest.Alias.(*AutoGroup); ok && ag.Is(AutoGroupSelf) {
			for _, n := range nodes.All() {
				if n.User().ID == node.User().ID && !n.IsTagged() {
					for _, port := range dest.Ports {
						for _, ip := range n.IPs() {
							pr := tailcfg.NetPortRange{
								IP:    ip.String(),
								Ports: port,
							}
							destPorts = append(destPorts, pr)
						}
					}
				}
			}
		} else {
			ips, err := dest.Resolve(pol, users, nodes)
			if err != nil {
				log.Trace().Err(err).Msgf("resolving destination ips")
				continue
			}

			if ips == nil {
				log.Debug().Msgf("destination resolved to nil ips: %v", dest)
				continue
			}

			prefixes := ips.Prefixes()

			for _, pref := range prefixes {
				for _, port := range dest.Ports {
					pr := tailcfg.NetPortRange{
						IP:    pref.String(),
						Ports: port,
					}
					destPorts = append(destPorts, pr)
				}
			}
		}
	}

	if len(destPorts) == 0 {
		return &tailcfg.FilterRule{}, nil
	}

	return &tailcfg.FilterRule{
		SrcIPs:   ipSetToPrefixStringList(srcSet),
		DstPorts: destPorts,
		IPProto:  protocols,
	}, nil
}

// resolveACLSources resolves ACL sources to an IPSet
func resolveACLSources(pol *Policy, sources []Alias, users types.Users, nodes views.Slice[types.NodeView]) (*netipx.IPSet, error) {
	var srcIPs netipx.IPSetBuilder

	for _, src := range sources {
		ips, err := src.Resolve(pol, users, nodes)
		if err != nil {
			log.Trace().Err(err).Msgf("resolving source ips")
			continue
		}

		if ips != nil {
			srcIPs.AddSet(ips)
		}
	}

	return srcIPs.IPSet()
}

// filterIPSetToSameUser filters an IPSet to only include nodes from the specified user
func filterIPSetToSameUser(ipSet *netipx.IPSet, nodes views.Slice[types.NodeView], userID types.UserID) *netipx.IPSet {
	var filteredIPs netipx.IPSetBuilder

	for _, node := range nodes.All() {
		if node.User().ID == uint(userID) && !node.IsTagged() {
			// Check if any of this node's IPs are in the original IPSet
			for _, ip := range node.IPs() {
				if ipSet.Contains(ip) {
					filteredIPs.Add(ip)
				}
			}
		}
	}

	set, _ := filteredIPs.IPSet()
	return set
}

func sshAction(accept bool, duration time.Duration) tailcfg.SSHAction {
	return tailcfg.SSHAction{
		Reject:                   !accept,
		Accept:                   accept,
		SessionDuration:          duration,
		AllowAgentForwarding:     true,
		AllowLocalPortForwarding: true,
	}
}

func (pol *Policy) compileSSHPolicy(
	users types.Users,
	node types.NodeView,
	nodes views.Slice[types.NodeView],
) (*tailcfg.SSHPolicy, error) {
	if pol == nil || pol.SSHs == nil || len(pol.SSHs) == 0 {
		return nil, nil
	}

	log.Trace().Msgf("compiling SSH policy for node %q", node.Hostname())

	var rules []*tailcfg.SSHRule

	for index, rule := range pol.SSHs {
		var dest netipx.IPSetBuilder
		for _, src := range rule.Destinations {
			ips, err := src.Resolve(pol, users, nodes)
			if err != nil {
				log.Trace().Err(err).Msgf("resolving destination ips")
			}
			dest.AddSet(ips)
		}

		destSet, err := dest.IPSet()
		if err != nil {
			return nil, err
		}

		if !node.InIPSet(destSet) {
			continue
		}

		var action tailcfg.SSHAction
		switch rule.Action {
		case "accept":
			action = sshAction(true, 0)
		case "check":
			action = sshAction(true, time.Duration(rule.CheckPeriod))
		default:
			return nil, fmt.Errorf("parsing SSH policy, unknown action %q, index: %d: %w", rule.Action, index, err)
		}

		var principals []*tailcfg.SSHPrincipal
		srcIPs, err := rule.Sources.Resolve(pol, users, nodes)
		if err != nil {
			log.Trace().Err(err).Msgf("SSH policy compilation failed resolving source ips for rule %+v", rule)
			continue // Skip this rule if we can't resolve sources
		}

		for addr := range util.IPSetAddrIter(srcIPs) {
			principals = append(principals, &tailcfg.SSHPrincipal{
				NodeIP: addr.String(),
			})
		}

		userMap := make(map[string]string, len(rule.Users))
		for _, user := range rule.Users {
			userMap[user.String()] = "="
		}
		rules = append(rules, &tailcfg.SSHRule{
			Principals: principals,
			SSHUsers:   userMap,
			Action:     &action,
		})
	}

	return &tailcfg.SSHPolicy{
		Rules: rules,
	}, nil
}

func ipSetToPrefixStringList(ips *netipx.IPSet) []string {
	var out []string

	if ips == nil {
		return out
	}

	for _, pref := range ips.Prefixes() {
		out = append(out, pref.String())
	}

	return out
}
