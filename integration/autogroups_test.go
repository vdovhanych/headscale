package integration

import (
	"fmt"
	"testing"

	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/stretchr/testify/assert"
	"tailscale.com/tailcfg"
	"tailscale.com/types/ptr"
)

func TestAutoGroups(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	spec := ScenarioSpec{
		Users: []string{"user1", "user2", "user3"},
	}

	scenario, err := NewScenario(spec)
	assertNoErr(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{},
		hsic.WithTestName("autogroups"),
		hsic.WithConfigEnv(map[string]string{
			"HEADSCALE_POLICY_MODE":            "database",
			"HEADSCALE_EXPERIMENTAL_POLICY_V2": "true",
		}),
	)
	assertNoErr(t, err)

	headscale, err := scenario.Headscale()
	assertNoErr(t, err)

	// Create nodes for each user
	err = scenario.CreateTailscaleNodesInUser("user1", "all", 2, []tsic.Option{})
	assertNoErr(t, err)
	err = scenario.CreateTailscaleNodesInUser("user2", "all", 2, []tsic.Option{})
	assertNoErr(t, err)
	err = scenario.CreateTailscaleNodesInUser("user3", "all", 2, []tsic.Option{})
	assertNoErr(t, err)

	// Get the clients from the scenario
	user1Clients := scenario.users["user1"].Clients
	user2Clients := scenario.users["user2"].Clients
	user3Clients := scenario.users["user3"].Clients

	// Tag some nodes
	for _, client := range user1Clients {
		client.SetTags([]string{"tag:test"})
		break // Only tag first node
	}
	for _, client := range user2Clients {
		client.SetTags([]string{"tag:test"})
		break // Only tag first node
	}
	for _, client := range user3Clients {
		client.SetTags([]string{"tag:test"})
		break // Only tag first node
	}

	// Start all nodes
	key, err := scenario.CreatePreAuthKey("user1", true, false)
	assertNoErr(t, err)
	err = scenario.RunTailscaleUp("user1", headscale.GetEndpoint(), key.GetKey())
	assertNoErr(t, err)

	key, err = scenario.CreatePreAuthKey("user2", true, false)
	assertNoErr(t, err)
	err = scenario.RunTailscaleUp("user2", headscale.GetEndpoint(), key.GetKey())
	assertNoErr(t, err)

	key, err = scenario.CreatePreAuthKey("user3", true, false)
	assertNoErr(t, err)
	err = scenario.RunTailscaleUp("user3", headscale.GetEndpoint(), key.GetKey())
	assertNoErr(t, err)

	// Test autogroup:self
	p := policyv2.Policy{
		ACLs: []policyv2.ACL{
			{
				Action:  "accept",
				Sources: []policyv2.Alias{ptr.To(policyv2.AutoGroup(policyv2.AutoGroupSelf))},
				Destinations: []policyv2.AliasWithPorts{
					{
						Alias: ptr.To(policyv2.AutoGroup(policyv2.AutoGroupSelf)),
						Ports: []tailcfg.PortRange{tailcfg.PortRangeAny},
					},
				},
			},
		},
	}

	err = headscale.SetPolicy(&p)
	assertNoErr(t, err)

	// Verify that each user can only access their own nodes
	for _, client := range user1Clients {
		// Should be able to access own nodes
		for _, peer := range user1Clients {
			fqdn, err := peer.FQDN()
			assertNoErr(t, err)

			url := fmt.Sprintf("http://%s/etc/hostname", fqdn)
			result, err := client.Curl(url)
			assert.Len(t, result, 13)
			assertNoErr(t, err)
		}

		// Should not be able to access other users' nodes
		for _, peer := range append(user2Clients, user3Clients...) {
			fqdn, err := peer.FQDN()
			assertNoErr(t, err)

			url := fmt.Sprintf("http://%s/etc/hostname", fqdn)
			result, err := client.Curl(url)
			assert.Empty(t, result)
			assert.Error(t, err)
		}
	}

	// Test autogroup:member
	p = policyv2.Policy{
		ACLs: []policyv2.ACL{
			{
				Action:  "accept",
				Sources: []policyv2.Alias{ptr.To(policyv2.AutoGroup(policyv2.AutoGroupMember))},
				Destinations: []policyv2.AliasWithPorts{
					{
						Alias: ptr.To(policyv2.AutoGroup(policyv2.AutoGroupMember)),
						Ports: []tailcfg.PortRange{tailcfg.PortRangeAny},
					},
				},
			},
		},
	}

	err = headscale.SetPolicy(&p)
	assertNoErr(t, err)

	// Verify that untagged nodes can access each other
	for _, client := range append(user1Clients[1:], user2Clients[1:], user3Clients[1:]...) {
		for _, peer := range append(user1Clients[1:], user2Clients[1:], user3Clients[1:]...) {
			fqdn, err := peer.FQDN()
			assertNoErr(t, err)

			url := fmt.Sprintf("http://%s/etc/hostname", fqdn)
			result, err := client.Curl(url)
			assert.Len(t, result, 13)
			assertNoErr(t, err)
		}

		// Should not be able to access tagged nodes
		for _, peer := range []*tsic.TailscaleInContainer{user1Clients[0], user2Clients[0], user3Clients[0]} {
			fqdn, err := peer.FQDN()
			assertNoErr(t, err)

			url := fmt.Sprintf("http://%s/etc/hostname", fqdn)
			result, err := client.Curl(url)
			assert.Empty(t, result)
			assert.Error(t, err)
		}
	}

	// Test autogroup:tagged
	p = policyv2.Policy{
		ACLs: []policyv2.ACL{
			{
				Action:  "accept",
				Sources: []policyv2.Alias{ptr.To(policyv2.AutoGroup(policyv2.AutoGroupTagged))},
				Destinations: []policyv2.AliasWithPorts{
					{
						Alias: ptr.To(policyv2.AutoGroup(policyv2.AutoGroupTagged)),
						Ports: []tailcfg.PortRange{tailcfg.PortRangeAny},
					},
				},
			},
		},
	}

	err = headscale.SetPolicy(&p)
	assertNoErr(t, err)

	// Verify that tagged nodes can access each other
	for _, client := range []*tsic.TailscaleInContainer{user1Clients[0], user2Clients[0], user3Clients[0]} {
		for _, peer := range []*tsic.TailscaleInContainer{user1Clients[0], user2Clients[0], user3Clients[0]} {
			fqdn, err := peer.FQDN()
			assertNoErr(t, err)

			url := fmt.Sprintf("http://%s/etc/hostname", fqdn)
			result, err := client.Curl(url)
			assert.Len(t, result, 13)
			assertNoErr(t, err)
		}

		// Should not be able to access untagged nodes
		for _, peer := range append(user1Clients[1:], user2Clients[1:], user3Clients[1:]...) {
			fqdn, err := peer.FQDN()
			assertNoErr(t, err)

			url := fmt.Sprintf("http://%s/etc/hostname", fqdn)
			result, err := client.Curl(url)
			assert.Empty(t, result)
			assert.Error(t, err)
		}
	}

	// Test autogroup:danger-all
	p = policyv2.Policy{
		ACLs: []policyv2.ACL{
			{
				Action:  "accept",
				Sources: []policyv2.Alias{ptr.To(policyv2.AutoGroup(policyv2.AutoGroupDangerAll))},
				Destinations: []policyv2.AliasWithPorts{
					{
						Alias: ptr.To(policyv2.AutoGroup(policyv2.AutoGroupDangerAll)),
						Ports: []tailcfg.PortRange{tailcfg.PortRangeAny},
					},
				},
			},
		},
	}

	err = headscale.SetPolicy(&p)
	assertNoErr(t, err)

	// Verify that all nodes can access each other
	allClients := append(append(user1Clients, user2Clients...), user3Clients...)
	for _, client := range allClients {
		for _, peer := range allClients {
			fqdn, err := peer.FQDN()
			assertNoErr(t, err)

			url := fmt.Sprintf("http://%s/etc/hostname", fqdn)
			result, err := client.Curl(url)
			assert.Len(t, result, 13)
			assertNoErr(t, err)
		}
	}
}
