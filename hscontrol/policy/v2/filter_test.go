package v2

import (
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
	}

	policy := &Policy{
		ACLs: []ACL{
			{
				Action:  "accept",
				Sources: []Alias{agp("autogroup:self")},
				Destinations: []AliasWithPorts{
					aliasWithPorts(agp("autogroup:self"), tailcfg.PortRangeAny),
				},
			},
		},
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

	// Check that the rule includes only user1's devices (SECURITY)
	rule := rules[0]
	if !contains(rule.SrcIPs, "100.64.0.1/32") {
		t.Error("expected rule to contain 100.64.0.1/32")
	}
	if !contains(rule.SrcIPs, "100.64.0.2/32") {
		t.Error("expected rule to contain 100.64.0.2/32")
	}
	if contains(rule.SrcIPs, "100.64.0.3/32") {
		t.Error("SECURITY: expected rule to NOT contain 100.64.0.3/32 (different user)")
	}
	if contains(rule.SrcIPs, "100.64.0.4/32") {
		t.Error("SECURITY: expected rule to NOT contain 100.64.0.4/32 (different user)")
	}

	// Check destinations
	for _, dst := range rule.DstPorts {
		if dst.IP != "100.64.0.1" && dst.IP != "100.64.0.2" {
			t.Errorf("SECURITY: unexpected destination IP: %s (should only be user1's devices)", dst.IP)
		}
	}

	// Test compilation for user2's first node
	node3 := nodes[2].View()
	rules, err = policy.compileFilterRulesForNode(users, node3, nodes.ViewSlice())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}

	// Check that the rule includes only user2's devices (SECURITY)
	rule = rules[0]
	if !contains(rule.SrcIPs, "100.64.0.3/32") {
		t.Error("expected rule to contain 100.64.0.3/32")
	}
	if !contains(rule.SrcIPs, "100.64.0.4/32") {
		t.Error("expected rule to contain 100.64.0.4/32")
	}
	if contains(rule.SrcIPs, "100.64.0.1/32") {
		t.Error("SECURITY: expected rule to NOT contain 100.64.0.1/32 (different user)")
	}
	if contains(rule.SrcIPs, "100.64.0.2/32") {
		t.Error("SECURITY: expected rule to NOT contain 100.64.0.2/32 (different user)")
	}

	// Check destinations
	for _, dst := range rule.DstPorts {
		if dst.IP != "100.64.0.3" && dst.IP != "100.64.0.4" {
			t.Errorf("SECURITY: unexpected destination IP: %s (should only be user2's devices)", dst.IP)
		}
	}
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
