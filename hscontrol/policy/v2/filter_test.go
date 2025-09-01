package v2

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/juanfont/headscale/hscontrol/types"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
)

// aliasWithPorts creates an AliasWithPorts structure from an alias and ports.
func aliasWithPorts(alias Alias, ports ...tailcfg.PortRange) AliasWithPorts {
	return AliasWithPorts{
		Alias: alias,
		Ports: ports,
	}
}

func TestParsing(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "testuser"},
	}
	tests := []struct {
		name    string
		format  string
		acl     string
		want    []tailcfg.FilterRule
		wantErr bool
	}{
		{
			name:   "invalid-hujson",
			format: "hujson",
			acl: `
{
		`,
			want:    []tailcfg.FilterRule{},
			wantErr: true,
		},
		// The new parser will ignore all that is irrelevant
		// 		{
		// 			name:   "valid-hujson-invalid-content",
		// 			format: "hujson",
		// 			acl: `
		// {
		//   "valid_json": true,
		//   "but_a_policy_though": false
		// }
		// 				`,
		// 			want:    []tailcfg.FilterRule{},
		// 			wantErr: true,
		// 		},
		// 		{
		// 			name:   "invalid-cidr",
		// 			format: "hujson",
		// 			acl: `
		// {"example-host-1": "100.100.100.100/42"}
		// 				`,
		// 			want:    []tailcfg.FilterRule{},
		// 			wantErr: true,
		// 		},
		{
			name:   "basic-rule",
			format: "hujson",
			acl: `
{
	"hosts": {
		"host-1": "100.100.100.100",
		"subnet-1": "100.100.101.100/24",
	},

	"acls": [
		{
			"action": "accept",
			"src": [
				"subnet-1",
				"192.168.1.0/24"
			],
			"dst": [
				"*:22,3389",
				"host-1:*",
			],
		},
	],
}
		`,
			want: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"100.100.101.0/24", "192.168.1.0/24"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "0.0.0.0/0", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						{IP: "0.0.0.0/0", Ports: tailcfg.PortRange{First: 3389, Last: 3389}},
						{IP: "::/0", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						{IP: "::/0", Ports: tailcfg.PortRange{First: 3389, Last: 3389}},
						{IP: "100.100.100.100/32", Ports: tailcfg.PortRangeAny},
					},
				},
			},
			wantErr: false,
		},
		{
			name:   "parse-protocol",
			format: "hujson",
			acl: `
{
	"hosts": {
		"host-1": "100.100.100.100",
		"subnet-1": "100.100.101.100/24",
	},

	"acls": [
		{
			"Action": "accept",
			"src": [
				"*",
			],
			"proto": "tcp",
			"dst": [
				"host-1:*",
			],
		},
		{
			"Action": "accept",
			"src": [
				"*",
			],
			"proto": "udp",
			"dst": [
				"host-1:53",
			],
		},
		{
			"Action": "accept",
			"src": [
				"*",
			],
			"proto": "icmp",
			"dst": [
				"host-1:*",
			],
		},
	],
}`,
			want: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"0.0.0.0/0", "::/0"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.100.100.100/32", Ports: tailcfg.PortRangeAny},
					},
					IPProto: []int{protocolTCP},
				},
				{
					SrcIPs: []string{"0.0.0.0/0", "::/0"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.100.100.100/32", Ports: tailcfg.PortRange{First: 53, Last: 53}},
					},
					IPProto: []int{protocolUDP},
				},
				{
					SrcIPs: []string{"0.0.0.0/0", "::/0"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.100.100.100/32", Ports: tailcfg.PortRangeAny},
					},
					IPProto: []int{protocolICMP, protocolIPv6ICMP},
				},
			},
			wantErr: false,
		},
		{
			name:   "port-wildcard",
			format: "hujson",
			acl: `
{
	"hosts": {
		"host-1": "100.100.100.100",
		"subnet-1": "100.100.101.100/24",
	},

	"acls": [
		{
			"Action": "accept",
			"src": [
				"*",
			],
			"dst": [
				"host-1:*",
			],
		},
	],
}
`,
			want: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"0.0.0.0/0", "::/0"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.100.100.100/32", Ports: tailcfg.PortRangeAny},
					},
				},
			},
			wantErr: false,
		},
		{
			name:   "port-range",
			format: "hujson",
			acl: `
{
	"hosts": {
		"host-1": "100.100.100.100",
		"subnet-1": "100.100.101.100/24",
	},

	"acls": [
		{
			"action": "accept",
			"src": [
				"subnet-1",
			],
			"dst": [
				"host-1:5400-5500",
			],
		},
	],
}
`,
			want: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"100.100.101.0/24"},
					DstPorts: []tailcfg.NetPortRange{
						{
							IP:    "100.100.100.100/32",
							Ports: tailcfg.PortRange{First: 5400, Last: 5500},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name:   "port-group",
			format: "hujson",
			acl: `
{
	"groups": {
		"group:example": [
			"testuser@",
		],
	},

	"hosts": {
		"host-1": "100.100.100.100",
		"subnet-1": "100.100.101.100/24",
	},

	"acls": [
		{
			"action": "accept",
			"src": [
				"group:example",
			],
			"dst": [
				"host-1:*",
			],
		},
	],
}
`,
			want: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"200.200.200.200/32"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.100.100.100/32", Ports: tailcfg.PortRangeAny},
					},
				},
			},
			wantErr: false,
		},
		{
			name:   "port-user",
			format: "hujson",
			acl: `
{
	"hosts": {
		"host-1": "100.100.100.100",
		"subnet-1": "100.100.101.100/24",
	},

	"acls": [
		{
			"action": "accept",
			"src": [
				"testuser@",
			],
			"dst": [
				"host-1:*",
			],
		},
	],
}
`,
			want: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"200.200.200.200/32"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.100.100.100/32", Ports: tailcfg.PortRangeAny},
					},
				},
			},
			wantErr: false,
		},
		{
			name:   "ipv6",
			format: "hujson",
			acl: `
{
	"hosts": {
		"host-1": "100.100.100.100/32",
		"subnet-1": "100.100.101.100/24",
	},

	"acls": [
		{
			"action": "accept",
			"src": [
				"*",
			],
			"dst": [
				"host-1:*",
			],
		},
	],
}
`,
			want: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"0.0.0.0/0", "::/0"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.100.100.100/32", Ports: tailcfg.PortRangeAny},
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pol, err := unmarshalPolicy([]byte(tt.acl))
			if tt.wantErr && err == nil {
				t.Errorf("parsing() error = %v, wantErr %v", err, tt.wantErr)

				return
			} else if !tt.wantErr && err != nil {
				t.Errorf("parsing() error = %v, wantErr %v", err, tt.wantErr)

				return
			}

			if err != nil {
				return
			}

			rules, err := pol.compileFilterRules(
				users,
				types.Nodes{
					&types.Node{
						IPv4: ap("100.100.100.100"),
					},
					&types.Node{
						IPv4:     ap("200.200.200.200"),
						User:     users[0],
						Hostinfo: &tailcfg.Hostinfo{},
					},
				}.ViewSlice())

			if (err != nil) != tt.wantErr {
				t.Errorf("parsing() error = %v, wantErr %v", err, tt.wantErr)

				return
			}

			if diff := cmp.Diff(tt.want, rules); diff != "" {
				t.Errorf("parsing() unexpected result (-want +got):\n%s", diff)
			}
		})
	}
}

func TestCompileFilterRulesForNodeWithAutogroupSelf(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "user1"},
		{Model: gorm.Model{ID: 2}, Name: "user2"},
	}

	nodes := types.Nodes{
		{
			User: users[0],
			IPv4: ap("100.64.0.1"),
		},
		{
			User: users[0],
			IPv4: ap("100.64.0.2"),
		},
		{
			User: users[1],
			IPv4: ap("100.64.0.3"),
		},
		{
			User: users[1],
			IPv4: ap("100.64.0.4"),
		},
		// Tagged device for user1 (should be excluded from autogroup:self)
		{
			User:       users[0],
			IPv4:       ap("100.64.0.5"),
			ForcedTags: []string{"tag:test"},
		},
		// Tagged device for user2 (should be excluded from autogroup:self)
		{
			User:       users[1],
			IPv4:       ap("100.64.0.6"),
			ForcedTags: []string{"tag:test"},
		},
	}

	// Test: Tailscale intended usage pattern (autogroup:member + autogroup:self)
	policy2 := &Policy{
		ACLs: []ACL{
			{
				Action:  "accept",
				Sources: []Alias{agp("autogroup:member")},
				Destinations: []AliasWithPorts{
					aliasWithPorts(agp("autogroup:self"), tailcfg.PortRangeAny),
				},
			},
		},
	}

	// Validate the policy first
	err := policy2.validate()
	if err != nil {
		t.Fatalf("policy validation failed: %v", err)
	}

	// Test compilation for user1's first node
	node1 := nodes[0].View()

	rules, err := policy2.compileFilterRulesForNode(users, node1, nodes.ViewSlice())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}

	// Check that the rule includes:
	// - Sources: only user1's untagged devices (autogroup:member filtered to same user due to autogroup:self)
	// - Destinations: only user1's untagged devices (autogroup:self excludes tagged devices)
	rule := rules[0]

	// Sources should include only untagged devices from the same user as the destination
	// Since we're testing for user1's node, sources should only include user1's devices
	// This is the key behavior of autogroup:self - it filters sources to the same user
	expectedSourceIPs := []string{"100.64.0.1", "100.64.0.2"}

	for _, expectedIP := range expectedSourceIPs {
		found := false

		addr := netip.MustParseAddr(expectedIP)
		for _, prefix := range rule.SrcIPs {
			pref := netip.MustParsePrefix(prefix)
			if pref.Contains(addr) {
				found = true
				break
			}
		}

		if !found {
			t.Errorf("expected source IP %s to be covered by generated prefixes %v", expectedIP, rule.SrcIPs)
		}
	}

	// Verify that other users' devices and tagged devices are NOT included in sources
	excludedSourceIPs := []string{"100.64.0.3", "100.64.0.4", "100.64.0.5", "100.64.0.6"}
	for _, excludedIP := range excludedSourceIPs {
		addr := netip.MustParseAddr(excludedIP)
		for _, prefix := range rule.SrcIPs {
			pref := netip.MustParsePrefix(prefix)
			if pref.Contains(addr) {
				t.Errorf("SECURITY: source IP %s should NOT be included (tagged device) but found in prefix %s", excludedIP, prefix)
			}
		}
	}

	// Destinations should only include user1's untagged devices
	expectedDestIPs := []string{"100.64.0.1", "100.64.0.2"}

	actualDestIPs := make([]string, 0, len(rule.DstPorts))
	for _, dst := range rule.DstPorts {
		actualDestIPs = append(actualDestIPs, dst.IP)
	}

	for _, expectedIP := range expectedDestIPs {
		found := false

		for _, actualIP := range actualDestIPs {
			if actualIP == expectedIP {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected destination IP %s to be included, got: %v", expectedIP, actualDestIPs)
		}
	}

	// Verify that other users' devices and tagged devices are NOT in destinations
	excludedDestIPs := []string{"100.64.0.3", "100.64.0.4", "100.64.0.5", "100.64.0.6"}
	for _, excludedIP := range excludedDestIPs {
		for _, actualIP := range actualDestIPs {
			if actualIP == excludedIP {
				t.Errorf("SECURITY: destination IP %s should NOT be included (other user or tagged device) but found in destinations", excludedIP)
			}
		}
	}

	t.Run("username source with autogroup:self destination", func(t *testing.T) {
		// Test with specific username as source
		policy := &Policy{
			ACLs: []ACL{
				{
					Action:  "accept",
					Sources: []Alias{up("user1@")},
					Destinations: []AliasWithPorts{
						aliasWithPorts(agp("autogroup:self"), tailcfg.PortRangeAny),
					},
				},
			},
		}

		// Validate the policy first
		err := policy.validate()
		if err != nil {
			t.Fatalf("policy validation failed: %v", err)
		}

		// Test compilation for user1's first node
		node1 := nodes[0].View()

		rules, err := policy.compileFilterRulesForNode(users, node1, nodes.ViewSlice())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(rules) != 1 {
			t.Fatalf("expected 1 rule, got %d", len(rules))
		}

		rule := rules[0]

		// Since sources is user1@ and destination is autogroup:self for user1's node,
		// sources should include only user1's untagged devices
		expectedSourceIPs := []string{"100.64.0.1", "100.64.0.2"}

		for _, expectedIP := range expectedSourceIPs {
			found := false

			addr := netip.MustParseAddr(expectedIP)
			for _, prefix := range rule.SrcIPs {
				pref := netip.MustParsePrefix(prefix)
				if pref.Contains(addr) {
					found = true
					break
				}
			}

			if !found {
				t.Errorf("expected source IP %s to be covered by generated prefixes %v", expectedIP, rule.SrcIPs)
			}
		}
	})

	t.Run("no autogroup:self in destinations - standard behavior", func(t *testing.T) {
		// Test normal ACL without autogroup:self to ensure we don't break existing behavior
		policy := &Policy{
			ACLs: []ACL{
				{
					Action:  "accept",
					Sources: []Alias{agp("autogroup:member")},
					Destinations: []AliasWithPorts{
						aliasWithPorts(agp("autogroup:member"), tailcfg.PortRangeAny),
					},
				},
			},
		}

		// Validate the policy first
		err := policy.validate()
		if err != nil {
			t.Fatalf("policy validation failed: %v", err)
		}

		// Test compilation for user1's first node
		node1 := nodes[0].View()

		rules, err := policy.compileFilterRulesForNode(users, node1, nodes.ViewSlice())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(rules) != 1 {
			t.Fatalf("expected 1 rule, got %d", len(rules))
		}

		rule := rules[0]

		// Without autogroup:self, all untagged devices should be included in both sources and destinations
		expectedIPs := []string{"100.64.0.1", "100.64.0.2", "100.64.0.3", "100.64.0.4"}

		// Check sources
		for _, expectedIP := range expectedIPs {
			found := false

			addr := netip.MustParseAddr(expectedIP)
			for _, prefix := range rule.SrcIPs {
				pref := netip.MustParsePrefix(prefix)
				if pref.Contains(addr) {
					found = true
					break
				}
			}

			if !found {
				t.Errorf("expected source IP %s to be covered by generated prefixes %v", expectedIP, rule.SrcIPs)
			}
		}

		// Check destinations - need to check if IPs are covered by CIDR prefixes
		actualDestIPs := make([]string, 0, len(rule.DstPorts))
		for _, dst := range rule.DstPorts {
			actualDestIPs = append(actualDestIPs, dst.IP)
		}

		for _, expectedIP := range expectedIPs {
			found := false

			addr := netip.MustParseAddr(expectedIP)
			for _, destCIDR := range actualDestIPs {
				prefix := netip.MustParsePrefix(destCIDR)
				if prefix.Contains(addr) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected destination IP %s to be covered by generated prefixes %v", expectedIP, actualDestIPs)
			}
		}
	})
}

func TestAutogroupSelfInSourceIsRejected(t *testing.T) {
	// Test that autogroup:self cannot be used in sources (per Tailscale spec)
	policy := &Policy{
		ACLs: []ACL{
			{
				Action:  "accept",
				Sources: []Alias{agp("autogroup:self")}, // This should be rejected
				Destinations: []AliasWithPorts{
					aliasWithPorts(agp("autogroup:member"), tailcfg.PortRangeAny),
				},
			},
		},
	}

	// This should fail validation because autogroup:self is not allowed in sources
	err := policy.validate()
	if err == nil {
		t.Error("expected validation error when using autogroup:self in sources")
	}
	if !strings.Contains(err.Error(), "autogroup:self") {
		t.Errorf("expected error message to mention autogroup:self, got: %v", err)
	}
}
