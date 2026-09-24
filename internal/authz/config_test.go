// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package authz

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/agent-substrate/substrate/internal/principal"
)

var (
	testProviders  = []string{"kubernetes", "google"}
	testRuleGroups = []string{"google/basicblock"}
)

func TestLoadConfigRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authorization.yaml")
	if err := os.WriteFile(path, []byte("mode: enforce\nglobal:\n  owner: [google:a@b]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("LoadConfig() error = %v, want unknown-field error", err)
	}
}

func TestValidate(t *testing.T) {
	valid := func() *Config {
		return &Config{
			Mode: ModeEnforce,
			Global: GlobalBindings{
				Owners:           []string{"mtls:spiffe://cluster.local/ns/ate-system/sa/atelet", "kubernetes:system:serviceaccount:ate-system:ate-client"},
				AtespaceCreators: []string{"group:google/basicblock"},
				Connectors:       []string{"kubernetes:system:serviceaccount:internal-preview:preview-proxy"},
			},
			Atespaces: map[string]AtespaceBindings{"bb-dev": {Viewers: []string{"group:authenticated", "group:google"}}},
		}
	}
	if err := valid().Validate(testProviders, testRuleGroups); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{"no mode", func(c *Config) { c.Mode = "" }},
		{"unknown mode", func(c *Config) { c.Mode = "permissive" }},
		{"unknown provider", func(c *Config) { c.Global.Owners = []string{"github:someone"} }},
		{"unknown group", func(c *Config) { c.Global.AtespaceCreators = []string{"group:google/everyone"} }},
		{"unknown connector provider", func(c *Config) { c.Global.Connectors = []string{"github:someone"} }},
		{"missing provider", func(c *Config) { c.Global.Viewers = []string{"paul@basicblock.io"} }},
		{"empty ID", func(c *Config) { c.Global.Viewers = []string{"google:"} }},
		{"invalid atespace", func(c *Config) { c.Atespaces["Bad_Name"] = AtespaceBindings{} }},
		{"bad atespace binding", func(c *Config) { c.Atespaces["eve-demo"] = AtespaceBindings{Editors: []string{"nope"}} }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := valid()
			tt.mutate(cfg)
			if err := cfg.Validate(testProviders, testRuleGroups); err == nil {
				t.Fatal("Validate() succeeded, want error")
			}
		})
	}
}

func TestConfigTuples(t *testing.T) {
	cfg := &Config{
		Mode: ModeEnforce,
		Global: GlobalBindings{
			Owners:           []string{"kubernetes:system:serviceaccount:ate-system:ate-client"},
			AtespaceCreators: []string{"group:google/basicblock"},
			Connectors:       []string{"kubernetes:system:serviceaccount:internal-preview:preview-proxy"},
		},
		Atespaces: map[string]AtespaceBindings{"eve-demo": {Editors: []string{"kubernetes:system:serviceaccount:internal-eve-demo:eve-demo"}}},
	}
	got := cfg.tuples()
	want := []tuple{
		{User: "user:kubernetes/system%3Aserviceaccount%3Aate-system%3Aate-client", Relation: "owner", Object: "global:root"},
		{User: "group:google/basicblock#member", Relation: "atespace_creator", Object: "global:root"},
		{User: "user:kubernetes/system%3Aserviceaccount%3Ainternal-preview%3Apreview-proxy", Relation: "connector", Object: "global:root"},
		{User: "user:kubernetes/system%3Aserviceaccount%3Ainternal-eve-demo%3Aeve-demo", Relation: "editor", Object: "atespace:eve-demo"},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("tuples() = %+v\nwant %+v", got, want)
	}
	for _, tt := range want {
		if !managed(tt) {
			t.Errorf("managed(%+v) = false", tt)
		}
	}
	for _, tt := range []tuple{
		{User: "user:x", Relation: "creator", Object: "atespace:a"},
		{User: "atespace:a", Relation: "parent_atespace", Object: "actor:a/b"},
	} {
		if managed(tt) {
			t.Errorf("managed(%+v) = true", tt)
		}
	}
}

func TestPrincipalEncoding(t *testing.T) {
	user, err := PrincipalUser(principal.PrincipalInfo{Provider: principal.ProviderMTLS, ID: "spiffe://cluster.local/ns/ate-system/sa/atelet"})
	if err != nil {
		t.Fatal(err)
	}
	if user != "user:mtls/spiffe%3A//cluster.local/ns/ate-system/sa/atelet" {
		t.Fatalf("PrincipalUser() = %q", user)
	}
	if got := referenceUser("mtls:spiffe://cluster.local/ns/ate-system/sa/atelet"); got != user {
		t.Fatalf("referenceUser() = %q, want the PrincipalUser %q", got, user)
	}
	if got := escape("a%b c#d:e\n"); got != "a%25b%20c%23d%3Ae%0A" {
		t.Fatalf("escape() = %q", got)
	}
	if _, err := PrincipalUser(principal.PrincipalInfo{ID: "x"}); err == nil {
		t.Fatal("PrincipalUser() without a provider succeeded")
	}
}

func TestObjectsCarryTheirParents(t *testing.T) {
	o := ActorObject("dev-a", "w")
	if o.ID != "actor:dev-a/w" {
		t.Fatalf("ActorObject().ID = %q", o.ID)
	}
	want := []tuple{
		{User: "atespace:dev-a", Relation: "parent_atespace", Object: "actor:dev-a/w"},
		{User: "global:root", Relation: "parent_global", Object: "atespace:dev-a"},
	}
	if !slices.Equal(o.structural, want) {
		t.Fatalf("structural = %+v, want %+v", o.structural, want)
	}
}
