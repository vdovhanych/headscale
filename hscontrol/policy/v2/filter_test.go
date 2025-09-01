package v2

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/juanfont/headscale/hscontrol/types"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
)

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

func TestAutogroupSelfFiltering(t *testing.T) {
	user1 := types.User{Model: gorm.Model{ID: 1}, Name: "user1"}
	user2 := types.User{Model: gorm.Model{ID: 2}, Name: "user2"}
	users := types.Users{user1, user2}

	// Create nodes for testing
	node1User1 := &types.Node{
		ID:       1,
		IPv4:     ap("100.64.0.1"),
		User:     user1,
		Hostinfo: &tailcfg.Hostinfo{},
	}
	
	node2User1 := &types.Node{
		ID:       2,
		IPv4:     ap("100.64.0.2"),
		User:     user1,
		Hostinfo: &tailcfg.Hostinfo{},
	}
	
	node3User2 := &types.Node{
		ID:       3,
		IPv4:     ap("100.64.0.3"),
		User:     user2,
		Hostinfo: &tailcfg.Hostinfo{},
	}
	
	// Tagged node (should be excluded from autogroup:self)
	taggedNode := &types.Node{
		ID:       4,
		IPv4:     ap("100.64.0.4"),
		User:     user1,
		Hostinfo: &tailcfg.Hostinfo{},
		ForcedTags: []string{"tag:server"},
	}

	allNodes := types.Nodes{node1User1, node2User1, node3User2, taggedNode}

	tests := []struct {
		name         string
		policy       string
		targetNode   types.NodeView
		wantSrcIPs   []string
		wantDstIPs   []string
		expectRule   bool
	}{
		{
			name: "autogroup:self-basic-same-user",
			policy: `{
				"acls": [
					{
						"action": "accept",
						"src": ["autogroup:member"],
						"dst": ["autogroup:self:*"]
					}
				]
			}`,
			targetNode: node1User1.View(),
			// Sources should be filtered to only include user1 devices (excluding tagged)
			wantSrcIPs: []string{"100.64.0.1/32", "100.64.0.2/32"},
			// Destination should be user1 devices only (excluding tagged)
			wantDstIPs: []string{"100.64.0.1/32", "100.64.0.2/32"},
			expectRule: true,
		},
		{
			name: "autogroup:self-different-user-perspective",
			policy: `{
				"acls": [
					{
						"action": "accept",
						"src": ["autogroup:member"],
						"dst": ["autogroup:self:*"]
					}
				]
			}`,
			targetNode: node3User2.View(),
			// Sources should be filtered to only include user2 devices
			wantSrcIPs: []string{"100.64.0.3/32"},
			// Destination should be user2 devices only
			wantDstIPs: []string{"100.64.0.3/32"},
			expectRule: true,
		},
		{
			name: "autogroup:self-tagged-node",
			policy: `{
				"acls": [
					{
						"action": "accept",
						"src": ["autogroup:member"],
						"dst": ["autogroup:self:*"]
					}
				]
			}`,
			targetNode: taggedNode.View(),
			// Tagged nodes should not get any autogroup:self rules
			expectRule: false,
		},
		{
			name: "autogroup:self-with-specific-user-source",
			policy: `{
				"acls": [
					{
						"action": "accept",
						"src": ["user1@"],
						"dst": ["autogroup:self:*"]
					}
				]
			}`,
			targetNode: node1User1.View(),
			// Only user1 devices should be in sources, filtered for same user
			wantSrcIPs: []string{"100.64.0.1/32", "100.64.0.2/32"},
			// Destination should be user1 devices only (excluding tagged)
			wantDstIPs: []string{"100.64.0.1/32", "100.64.0.2/32"},
			expectRule: true,
		},
		{
			name: "autogroup:self-mixed-sources",
			policy: `{
				"acls": [
					{
						"action": "accept",
						"src": ["user1@", "user2@"],
						"dst": ["autogroup:self:*"]
					}
				]
			}`,
			targetNode: node1User1.View(),
			// Sources should be filtered to only user1 devices when autogroup:self is destination
			wantSrcIPs: []string{"100.64.0.1/32", "100.64.0.2/32"},
			// Destination should be user1 devices only (excluding tagged)
			wantDstIPs: []string{"100.64.0.1/32", "100.64.0.2/32"},
			expectRule: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pol, err := unmarshalPolicy([]byte(tt.policy))
			if err != nil {
				t.Fatalf("failed to parse policy: %v", err)
			}

			rules, err := pol.compileFilterRulesForNode(users, allNodes.ViewSlice(), tt.targetNode)
			if err != nil {
				t.Fatalf("failed to compile filter rules: %v", err)
			}

			if !tt.expectRule {
				if len(rules) > 0 {
					t.Errorf("expected no rules for tagged node, got %d rules", len(rules))
				}
				return
			}

			if len(rules) != 1 {
				t.Fatalf("expected 1 rule, got %d", len(rules))
			}

			rule := rules[0]

			// Check source IPs
			if diff := cmp.Diff(tt.wantSrcIPs, rule.SrcIPs); diff != "" {
				t.Errorf("unexpected source IPs (-want +got):\n%s", diff)
			}

			// Check destination IPs
			actualDstIPs := make([]string, len(rule.DstPorts))
			for i, dst := range rule.DstPorts {
				actualDstIPs[i] = dst.IP
			}
			if diff := cmp.Diff(tt.wantDstIPs, actualDstIPs); diff != "" {
				t.Errorf("unexpected destination IPs (-want +got):\n%s", diff)
			}
		})
	}
}

func TestPolicyManagerFilterForNode(t *testing.T) {
	user1 := types.User{Model: gorm.Model{ID: 1}, Name: "user1"}
	user2 := types.User{Model: gorm.Model{ID: 2}, Name: "user2"}
	users := []types.User{user1, user2}

	node1User1 := &types.Node{
		ID:       1,
		IPv4:     ap("100.64.0.1"),
		User:     user1,
		Hostinfo: &tailcfg.Hostinfo{},
	}
	
	node2User2 := &types.Node{
		ID:       2,
		IPv4:     ap("100.64.0.2"),
		User:     user2,
		Hostinfo: &tailcfg.Hostinfo{},
	}

	nodes := types.Nodes{node1User1, node2User2}.ViewSlice()
	
	policy := `{
		"acls": [
			{
				"action": "accept",
				"src": ["autogroup:member"],
				"dst": ["autogroup:self:*"]
			}
		]
	}`

	pm, err := NewPolicyManager([]byte(policy), users, nodes)
	if err != nil {
		t.Fatalf("failed to create policy manager: %v", err)
	}

	// Test FilterForNode for user1's node
	rules1, err := pm.FilterForNode(node1User1.View())
	if err != nil {
		t.Fatalf("failed to get filter for node1: %v", err)
	}

	// Test FilterForNode for user2's node  
	rules2, err := pm.FilterForNode(node2User2.View())
	if err != nil {
		t.Fatalf("failed to get filter for node2: %v", err)
	}

	// Rules should be different for different users
	if len(rules1) != 1 || len(rules2) != 1 {
		t.Fatalf("expected 1 rule each, got %d and %d", len(rules1), len(rules2))
	}

	// User1's rule should only include user1's IP in both src and dst
	if rules1[0].SrcIPs[0] != "100.64.0.1/32" || rules1[0].DstPorts[0].IP != "100.64.0.1/32" {
		t.Errorf("user1 rule incorrect: src=%v, dst=%v", rules1[0].SrcIPs, rules1[0].DstPorts[0].IP)
	}

	// User2's rule should only include user2's IP in both src and dst
	if rules2[0].SrcIPs[0] != "100.64.0.2/32" || rules2[0].DstPorts[0].IP != "100.64.0.2/32" {
		t.Errorf("user2 rule incorrect: src=%v, dst=%v", rules2[0].SrcIPs, rules2[0].DstPorts[0].IP)
	}

	// Test caching - second call should return cached result
	rules1Cached, err := pm.FilterForNode(node1User1.View())
	if err != nil {
		t.Fatalf("failed to get cached filter for node1: %v", err)
	}

	if diff := cmp.Diff(rules1, rules1Cached); diff != "" {
		t.Errorf("cached rules differ from original (-want +got):\n%s", diff)
	}
}
