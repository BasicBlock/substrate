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
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/agent-substrate/substrate/internal/principal"
)

func TestLoadConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "authorization.yaml")
	const body = `
mode: enforce
global:
  owners: ["google:alice@example.com"]
  viewers: ["group:authenticated"]
  atespaceCreators: ["group:google/basicblock"]
atespaces:
  team1:
    owners: ["kubernetes:system:serviceaccount:ns:sa"]
    editors: ["mtls:spiffe://ns/sa"]
    viewers: ["group:google"]
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Mode != ModeEnforce {
		t.Errorf("Mode = %q, want %q", cfg.Mode, ModeEnforce)
	}
	if len(cfg.Global.Owners) != 1 || cfg.Global.Owners[0] != "google:alice@example.com" {
		t.Errorf("Global.Owners = %v", cfg.Global.Owners)
	}
	b, ok := cfg.Atespaces["team1"]
	if !ok {
		t.Fatalf("Atespaces[team1] missing")
	}
	if len(b.Owners) != 1 || b.Owners[0] != "kubernetes:system:serviceaccount:ns:sa" {
		t.Errorf("Atespaces[team1].Owners = %v", b.Owners)
	}

	// Unknown fields are rejected (UnmarshalStrict).
	if err := os.WriteFile(path, []byte(body+"\nbogus: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("expected LoadConfig to reject an unknown field")
	}
}

func TestConfigValidate(t *testing.T) {
	providers := []string{"google", "kubernetes"}
	ruleGroups := []string{"google/basicblock"}

	valid := &Config{
		Mode: ModeEnforce,
		Global: GlobalBindings{
			Owners:           []string{"google:alice@example.com"},
			Viewers:          []string{"group:authenticated"},
			AtespaceCreators: []string{"group:google/basicblock"},
			Connectors:       []string{"kubernetes:system:serviceaccount:internal-preview:preview-proxy"},
		},
		Atespaces: map[string]AtespaceBindings{
			"team1": {
				Owners:  []string{"kubernetes:system:serviceaccount:ns:sa"},
				Editors: []string{"mtls:spiffe://ns/sa"},
				Viewers: []string{"group:google"},
			},
		},
		AtespacePatterns: map[string]AtespaceBindings{
			"dev-*": {Editors: []string{"kubernetes:system:serviceaccount:internal-eve:devbox-reaper"}},
		},
	}
	if err := valid.Validate(providers, ruleGroups); err != nil {
		t.Fatalf("Validate(valid config) = %v, want nil", err)
	}

	tests := []struct {
		name string
		cfg  Config
	}{
		{"missing mode", Config{}},
		{"bad mode", Config{Mode: "sometimes"}},
		{"unknown provider", Config{Mode: ModeEnforce, Global: GlobalBindings{Owners: []string{"github:alice"}}}},
		{"unknown group", Config{Mode: ModeEnforce, Global: GlobalBindings{Owners: []string{"group:nope"}}}},
		{"unknown connector provider", Config{Mode: ModeEnforce, Global: GlobalBindings{Connectors: []string{"github:someone"}}}},
		{"malformed ref", Config{Mode: ModeEnforce, Global: GlobalBindings{Owners: []string{"alice@example.com"}}}},
		{"empty id", Config{Mode: ModeEnforce, Global: GlobalBindings{Owners: []string{"google:"}}}},
		{"invalid atespace name", Config{Mode: ModeEnforce, Atespaces: map[string]AtespaceBindings{"Bad Name!": {}}}},
		{"pattern without a star", Config{Mode: ModeEnforce, AtespacePatterns: map[string]AtespaceBindings{"dev-": {}}}},
		{"pattern that is only a star", Config{Mode: ModeEnforce, AtespacePatterns: map[string]AtespaceBindings{"*": {}}}},
		{"star inside a pattern", Config{Mode: ModeEnforce, AtespacePatterns: map[string]AtespaceBindings{"d*v-*": {}}}},
		{"pattern no atespace name starts with", Config{Mode: ModeEnforce, AtespacePatterns: map[string]AtespaceBindings{"Dev_*": {}}}},
		{"bad pattern binding", Config{Mode: ModeEnforce, AtespacePatterns: map[string]AtespaceBindings{"ci-*": {Viewers: []string{"nope"}}}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.cfg.Validate(providers, ruleGroups); err == nil {
				t.Fatalf("Validate(%+v) = nil, want an error", tc.cfg)
			}
		})
	}
}

func TestConfigTuples(t *testing.T) {
	cfg := &Config{
		Mode: ModeEnforce,
		Global: GlobalBindings{
			Owners:           []string{"google:alice@example.com"},
			AtespaceCreators: []string{"group:google/basicblock"},
			Connectors:       []string{"kubernetes:system:serviceaccount:internal-preview:preview-proxy"},
		},
		Atespaces: map[string]AtespaceBindings{
			"team1": {Owners: []string{"mtls:spiffe://ns/sa"}},
		},
		AtespacePatterns: map[string]AtespaceBindings{
			"dev-*": {Editors: []string{"kubernetes:system:serviceaccount:internal-eve:devbox-reaper"}},
			"ci-*":  {Viewers: []string{"group:google/basicblock"}},
		},
	}
	tuples := cfg.tuples()

	want := map[bindingKey]bool{
		{user: "user:alice@example.com", relation: RoleOwner, object: GlobalRootObject}:                  true,
		{user: "group:google/basicblock#member", relation: "atespace_creator", object: GlobalRootObject}: true,
		// The "kubernetes" provider segment is dropped, like every other
		// principal reference (see configMember's doc comment).
		{user: "user:system%3Aserviceaccount%3Ainternal-preview%3Apreview-proxy", relation: "connector", object: GlobalRootObject}: true,
		{user: "user:spiffe%3A//ns/sa", relation: RoleOwner, object: "atespace:team1"}:                                            true,
		{user: "group:google/basicblock#member", relation: RoleViewer, object: "atespace_pattern:ci-"}:                           true,
		{user: "user:system%3Aserviceaccount%3Ainternal-eve%3Adevbox-reaper", relation: RoleEditor, object: "atespace_pattern:dev-"}: true,
	}
	if len(tuples) != len(want) {
		t.Fatalf("len(tuples) = %d, want %d (%+v)", len(tuples), len(want), tuples)
	}
	for _, tu := range tuples {
		k := bindingKey{tu.GetUser(), tu.GetRelation(), tu.GetObject()}
		if !want[k] {
			t.Errorf("unexpected tuple %+v", k)
		}
	}

	// A principal's own formatUser(p.ID) (what Check() looks the caller up
	// by) matches the tuple a "<provider>:<id>" binding produced, dropping
	// the provider segment.
	if got, want := formatUser("alice@example.com"), "user:alice@example.com"; got != want {
		t.Errorf("formatUser(id) = %q, want %q", got, want)
	}
}

func TestManaged(t *testing.T) {
	tests := []struct {
		k    bindingKey
		want bool
	}{
		{bindingKey{"user:a", RoleOwner, GlobalRootObject}, true},
		{bindingKey{"user:a", RoleViewer, GlobalRootObject}, true},
		{bindingKey{"user:a", "atespace_creator", GlobalRootObject}, true},
		{bindingKey{"user:a", "can_create_atespace", GlobalRootObject}, false},
		{bindingKey{"user:a", RoleOwner, "atespace:team1"}, true},
		{bindingKey{"user:a", RoleEditor, "atespace:team1"}, true},
		{bindingKey{"user:a", RoleViewer, "atespace:team1"}, true},
		{bindingKey{"user:a", "creator", "atespace:team1"}, false},
		{bindingKey{"group:x#member", "member", "group:x"}, false},
		{bindingKey{"user:a", RoleOwner, "atespace_pattern:dev-"}, true},
		{bindingKey{"user:a", RoleEditor, "atespace_pattern:dev-"}, true},
		{bindingKey{"user:a", RoleViewer, "atespace_pattern:dev-"}, true},
		{bindingKey{"atespace_pattern:dev-", "parent_pattern", "atespace:dev-a"}, false},
	}
	for _, tc := range tests {
		if got := managed(tc.k); got != tc.want {
			t.Errorf("managed(%+v) = %v, want %v", tc.k, got, tc.want)
		}
	}
}

// TestReconcileConfigAndAtespaceLifecycle exercises ReconcileConfig,
// RecordCreator and ForgetCreators against a real embedded OpenFGA/Postgres
// instance.
func TestReconcileConfigAndAtespaceLifecycle(t *testing.T) {
	ctx := context.Background()
	pool := startPostgres(t)

	fgaServer, err := NewOpenFGAServer(pool)
	if err != nil {
		t.Fatalf("NewOpenFGAServer: %v", err)
	}
	t.Cleanup(fgaServer.Close)

	authorizer, _, err := New(ctx, pool, fgaServer, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	cfg := &Config{
		Mode: ModeEnforce,
		Global: GlobalBindings{
			Owners: []string{"google:alice@example.com"},
		},
		Atespaces: map[string]AtespaceBindings{
			"team1": {Viewers: []string{"google:bob@example.com"}},
		},
	}
	if err := authorizer.ReconcileConfig(ctx, cfg); err != nil {
		t.Fatalf("ReconcileConfig: %v", err)
	}
	if authorizer.Mode() != ModeEnforce {
		t.Errorf("Mode() = %q, want %q", authorizer.Mode(), ModeEnforce)
	}

	alice := principal.InjectContext(ctx, principal.PrincipalInfo{ID: "alice@example.com", Kind: principal.KindJWT, Provider: "google"})
	bob := principal.InjectContext(ctx, principal.PrincipalInfo{ID: "bob@example.com", Kind: principal.KindJWT, Provider: "google"})
	carol := principal.InjectContext(ctx, principal.PrincipalInfo{ID: "carol@example.com", Kind: principal.KindJWT, Provider: "google"})

	if err := authorizer.Check(alice, RelationCanDelete, AtespaceObject("team1")); err != nil {
		t.Errorf("alice (config global owner) should be able to delete team1: %v", err)
	}
	if err := authorizer.Check(bob, RelationCanGet, AtespaceObject("team1")); err != nil {
		t.Errorf("bob (config atespace viewer) should be able to get team1: %v", err)
	}
	if err := authorizer.Check(carol, RelationCanGet, AtespaceObject("team1")); err == nil {
		t.Errorf("carol should not be able to get team1")
	}

	// carol creates "team2" and becomes its owner via RecordCreator.
	if err := authorizer.Check(carol, RelationCanGet, AtespaceObject("team2")); err == nil {
		t.Fatalf("carol should not yet have access to team2")
	}
	if err := authorizer.RecordCreator(ctx, principal.PrincipalInfo{ID: "carol@example.com"}, "team2"); err != nil {
		t.Fatalf("RecordCreator: %v", err)
	}
	if err := authorizer.Check(carol, RelationCanDelete, AtespaceObject("team2")); err != nil {
		t.Errorf("carol (creator) should be able to delete team2: %v", err)
	}

	// Deleting team2 forgets carol's creator record.
	if err := authorizer.ForgetCreators(ctx, "team2"); err != nil {
		t.Fatalf("ForgetCreators: %v", err)
	}
	if err := authorizer.Check(carol, RelationCanDelete, AtespaceObject("team2")); err == nil {
		t.Errorf("carol should have lost access to team2 after ForgetCreators")
	}

	// A second ReconcileConfig with bob dropped from team1's viewers removes
	// his binding, and alice remains the global owner (idempotent).
	cfg2 := &Config{
		Mode: ModeEnforce,
		Global: GlobalBindings{
			Owners: []string{"google:alice@example.com"},
		},
	}
	if err := authorizer.ReconcileConfig(ctx, cfg2); err != nil {
		t.Fatalf("ReconcileConfig (2nd): %v", err)
	}
	if err := authorizer.Check(bob, RelationCanGet, AtespaceObject("team1")); err == nil {
		t.Errorf("bob should have lost team1 viewer access once reconciled away")
	}
	if err := authorizer.Check(alice, RelationCanDelete, AtespaceObject("team1")); err != nil {
		t.Errorf("alice should still be the global owner: %v", err)
	}
}

// TestConnectorsConnectEverywhereAndNothingElse verifies the global connectors
// list grants can_connect on actors in any atespace, including one never
// mentioned in configuration, and nothing else: no other actor relation, no
// atespace role, and no global role.
func TestConnectorsConnectEverywhereAndNothingElse(t *testing.T) {
	ctx := context.Background()
	pool := startPostgres(t)

	fgaServer, err := NewOpenFGAServer(pool)
	if err != nil {
		t.Fatalf("NewOpenFGAServer: %v", err)
	}
	t.Cleanup(fgaServer.Close)

	authorizer, _, err := New(ctx, pool, fgaServer, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	cfg := &Config{
		Mode:   ModeEnforce,
		Global: GlobalBindings{Connectors: []string{"kubernetes:system:serviceaccount:internal-preview:preview-proxy"}},
	}
	if err := authorizer.ReconcileConfig(ctx, cfg); err != nil {
		t.Fatalf("ReconcileConfig: %v", err)
	}

	proxy := principal.InjectContext(ctx, principal.PrincipalInfo{ID: "system:serviceaccount:internal-preview:preview-proxy", Kind: principal.KindJWT, Provider: "kubernetes"})

	// can_connect on actors in atespaces the connector was never bound to,
	// created on demand.
	for _, atespace := range []string{"dev-alice", "dev-someone-new"} {
		if err := authorizer.Check(proxy, "can_connect", ActorObject(atespace, "box")); err != nil {
			t.Errorf("connector cannot can_connect on an actor in unbound atespace %q: %v", atespace, err)
		}
	}

	// Nothing else on the actor.
	for _, relation := range []string{RelationCanGet, RelationCanUpdate, RelationCanDelete, RelationCanResume, RelationCanSuspend, RelationCanRevert} {
		if err := authorizer.Check(proxy, relation, ActorObject("dev-alice", "box")); err == nil {
			t.Errorf("connector has unexpected actor relation %q", relation)
		}
	}

	// Nothing on the atespace.
	for _, relation := range []string{RoleOwner, RoleEditor, RoleViewer, RelationCanGet, RelationCanDelete, RelationCanCreateActor, RelationCanCreateActorTemplate} {
		if err := authorizer.Check(proxy, relation, AtespaceObject("dev-alice")); err == nil {
			t.Errorf("connector has unexpected atespace relation %q", relation)
		}
	}

	// Nothing on the global scope beyond the connector relation itself.
	for _, relation := range []string{RoleOwner, RoleViewer, "atespace_creator", RelationCanCreateAtespace, RelationCanGet, RelationCanCreateAccessPolicy, RelationCanGetAccessPolicy} {
		if err := authorizer.Check(proxy, relation, GlobalRootObject); err == nil {
			t.Errorf("connector has unexpected global relation %q", relation)
		}
	}

	// Reconciling a config without the connector removes it.
	empty := &Config{Mode: ModeEnforce}
	if err := authorizer.ReconcileConfig(ctx, empty); err != nil {
		t.Fatalf("ReconcileConfig (empty): %v", err)
	}
	if err := authorizer.Check(proxy, "can_connect", ActorObject("dev-alice", "box")); err == nil {
		t.Error("a removed connector binding kept access")
	}
}

// TestAtespacePatternsBindEveryMatchingAtespace verifies a pattern binding
// grants its role in every atespace whose name starts with the pattern's
// prefix, including ones never mentioned in configuration, and nowhere else:
// not in other atespaces, not beyond the role, and not globally.
func TestAtespacePatternsBindEveryMatchingAtespace(t *testing.T) {
	ctx := context.Background()
	pool := startPostgres(t)

	fgaServer, err := NewOpenFGAServer(pool)
	if err != nil {
		t.Fatalf("NewOpenFGAServer: %v", err)
	}
	t.Cleanup(fgaServer.Close)

	authorizer, _, err := New(ctx, pool, fgaServer, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	cfg := &Config{
		Mode: ModeEnforce,
		AtespacePatterns: map[string]AtespaceBindings{
			"dev-*": {
				Editors: []string{"kubernetes:system:serviceaccount:internal-eve:devbox-reaper"},
				Viewers: []string{"google:rita@basicblock.io"},
			},
		},
	}
	if err := authorizer.ReconcileConfig(ctx, cfg); err != nil {
		t.Fatalf("ReconcileConfig: %v", err)
	}

	reaper := principal.InjectContext(ctx, principal.PrincipalInfo{ID: "system:serviceaccount:internal-eve:devbox-reaper", Kind: principal.KindJWT, Provider: "kubernetes"})
	reader := principal.InjectContext(ctx, principal.PrincipalInfo{ID: "rita@basicblock.io", Kind: principal.KindJWT, Provider: "google"})

	// Editor on actors in every matching atespace, created on demand.
	for _, atespace := range []string{"dev-alice", "dev-someone-new"} {
		for _, relation := range []string{RelationCanGet, RelationCanUpdate, RelationCanDelete, RelationCanSuspend, RelationCanResume, RelationCanRevert} {
			if err := authorizer.Check(reaper, relation, ActorObject(atespace, "box")); err != nil {
				t.Errorf("pattern editor lacks %q on an actor in %q: %v", relation, atespace, err)
			}
		}
		if err := authorizer.Check(reaper, RelationCanGet, AtespaceObject(atespace)); err != nil {
			t.Errorf("pattern editor cannot get atespace %q: %v", atespace, err)
		}
	}

	// An editor, not an owner: it cannot delete the atespace itself.
	if err := authorizer.Check(reaper, RelationCanDelete, AtespaceObject("dev-alice")); err == nil {
		t.Error("pattern editor can delete a matching atespace")
	}

	// Nothing in atespaces the pattern does not match, even ones that share
	// letters with its prefix.
	for _, atespace := range []string{"eve", "ci", "development", "bb-dev"} {
		for _, relation := range []string{RelationCanGet, RelationCanDelete} {
			if err := authorizer.Check(reaper, relation, ActorObject(atespace, "box")); err == nil {
				t.Errorf("pattern editor has %q on an actor in unmatched atespace %q", relation, atespace)
			}
		}
	}

	// Nothing global: no listing across atespaces, no workers.
	for _, relation := range []string{RoleOwner, RoleViewer, RelationCanGet, RelationCanCreateAtespace} {
		if err := authorizer.Check(reaper, relation, GlobalRootObject); err == nil {
			t.Errorf("pattern editor has unexpected global relation %q", relation)
		}
	}

	// A pattern viewer reads matching atespaces and changes nothing.
	if err := authorizer.Check(reader, RelationCanGet, ActorObject("dev-alice", "box")); err != nil {
		t.Errorf("pattern viewer cannot get an actor in a matching atespace: %v", err)
	}
	if err := authorizer.Check(reader, RelationCanDelete, ActorObject("dev-alice", "box")); err == nil {
		t.Error("pattern viewer can delete an actor")
	}

	// Reconciling a config without the pattern removes it.
	empty := &Config{Mode: ModeEnforce}
	if err := authorizer.ReconcileConfig(ctx, empty); err != nil {
		t.Fatalf("ReconcileConfig (empty): %v", err)
	}
	if err := authorizer.Check(reaper, RelationCanDelete, ActorObject("dev-alice", "box")); err == nil {
		t.Error("a removed pattern binding kept access")
	}
}
