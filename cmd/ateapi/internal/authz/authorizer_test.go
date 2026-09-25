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

package authz_test

import (
	"context"
	"sync"
	"testing"

	"github.com/agent-substrate/substrate/cmd/ateapi/internal/authz"
	"github.com/agent-substrate/substrate/cmd/ateapi/internal/authz/authztest"
	"github.com/agent-substrate/substrate/internal/principal"
	"github.com/jackc/pgx/v5/pgxpool"
)

func user(provider, id string, groups ...string) principal.PrincipalInfo {
	return principal.PrincipalInfo{Provider: provider, ID: id, Groups: append([]string{principal.GroupAuthenticated, provider}, groups...)}
}

func allowed(t *testing.T, a *authz.Authorizer, p principal.PrincipalInfo, object authz.Object, relation string) bool {
	t.Helper()
	ok, _, err := a.Allowed(context.Background(), p, []authz.Check{{Object: object, Relation: relation}})
	if err != nil {
		t.Fatal(err)
	}
	return ok
}

func newServer(t *testing.T, pool *pgxpool.Pool) *authz.Server {
	t.Helper()
	srv, err := authz.NewServer(context.Background(), pool)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	return srv
}

func TestReconcileKeepsCreatorsAndDropsRemovedBindings(t *testing.T) {
	ctx := context.Background()
	pool := authztest.StartPostgres(t)
	admin := user("google", "admin@example.com")
	dev := user("google", "dev@example.com", "google/example")
	anyone := user("kubernetes", "system:serviceaccount:default:default")

	first := &authz.Config{
		Mode: authz.ModeEnforce,
		Global: authz.GlobalBindings{
			Owners:           []string{"google:admin@example.com"},
			AtespaceCreators: []string{"group:google/example"},
		},
		Atespaces: map[string]authz.AtespaceBindings{"templates": {Viewers: []string{"group:authenticated"}}},
	}
	a, err := authz.NewAuthorizer(ctx, newServer(t, pool), first)
	if err != nil {
		t.Fatal(err)
	}
	if !allowed(t, a, admin, authz.ActorObject("anywhere", "x"), "can_delete") {
		t.Error("global owner cannot delete an actor anywhere")
	}
	if !allowed(t, a, anyone, authz.ActorTemplateObject("templates", "t"), "can_get") {
		t.Error("group:authenticated viewer cannot read a template")
	}
	if !allowed(t, a, dev, authz.Global(), "can_create_atespace") || allowed(t, a, anyone, authz.Global(), "can_create_atespace") {
		t.Error("atespace creation does not follow the claim rule group")
	}
	if err := a.RecordCreator(ctx, dev, "dev-space"); err != nil {
		t.Fatal(err)
	}
	if !allowed(t, a, dev, authz.ActorObject("dev-space", "w"), "can_resume") || allowed(t, a, anyone, authz.ActorObject("dev-space", "w"), "can_get") {
		t.Error("creator ownership is wrong")
	}

	// A new config without the owner and the template viewers, reconciled by
	// two replicas at once.
	second := &authz.Config{Mode: authz.ModeEnforce, Global: authz.GlobalBindings{AtespaceCreators: []string{"group:google/example"}}}
	var wg sync.WaitGroup
	var authorizers [2]*authz.Authorizer
	var errs [2]error
	for i := range authorizers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			authorizers[i], errs[i] = authz.NewAuthorizer(ctx, newServer(t, pool), second)
		}()
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	b := authorizers[0]
	if allowed(t, b, admin, authz.ActorObject("anywhere", "x"), "can_delete") {
		t.Error("a removed global owner kept access")
	}
	if allowed(t, b, anyone, authz.ActorTemplateObject("templates", "t"), "can_get") {
		t.Error("a removed viewer binding kept access")
	}
	if !allowed(t, b, dev, authz.ActorObject("dev-space", "w"), "can_resume") {
		t.Error("reconciliation removed a creator")
	}

	if err := b.ForgetCreators(ctx, "dev-space"); err != nil {
		t.Fatal(err)
	}
	if allowed(t, b, dev, authz.ActorObject("dev-space", "w"), "can_get") {
		t.Error("a forgotten creator kept access")
	}
}

// TestConnectorsConnectEverywhereAndNothingElse verifies the global connectors
// list grants can_connect on actors in any atespace, including one never
// mentioned in configuration, and nothing else: no other actor relation, no
// atespace role, and no global role.
func TestConnectorsConnectEverywhereAndNothingElse(t *testing.T) {
	ctx := context.Background()
	pool := authztest.StartPostgres(t)
	proxy := user("kubernetes", "system:serviceaccount:internal-preview:preview-proxy")

	cfg := &authz.Config{
		Mode:   authz.ModeEnforce,
		Global: authz.GlobalBindings{Connectors: []string{"kubernetes:system:serviceaccount:internal-preview:preview-proxy"}},
	}
	a, err := authz.NewAuthorizer(ctx, newServer(t, pool), cfg)
	if err != nil {
		t.Fatal(err)
	}

	// can_connect on actors in atespaces the connector was never bound to,
	// created on demand.
	for _, atespace := range []string{"dev-alice", "dev-someone-new"} {
		if !allowed(t, a, proxy, authz.ActorObject(atespace, "box"), "can_connect") {
			t.Errorf("connector cannot can_connect on an actor in unbound atespace %q", atespace)
		}
	}

	// Nothing else on the actor.
	for _, relation := range []string{"can_get", "can_update", "can_delete", "can_resume", "can_suspend", "can_revert"} {
		if allowed(t, a, proxy, authz.ActorObject("dev-alice", "box"), relation) {
			t.Errorf("connector has unexpected actor relation %q", relation)
		}
	}

	// Nothing on the atespace.
	for _, relation := range []string{"owner", "editor", "viewer", "can_get", "can_update", "can_delete", "can_create_actor", "can_create_actor_template"} {
		if allowed(t, a, proxy, authz.AtespaceObject("dev-alice"), relation) {
			t.Errorf("connector has unexpected atespace relation %q", relation)
		}
	}

	// Nothing on the global scope beyond the connector relation itself.
	for _, relation := range []string{"owner", "viewer", "atespace_creator", "can_create_atespace", "can_get", "can_set_policy", "can_get_policy"} {
		if allowed(t, a, proxy, authz.Global(), relation) {
			t.Errorf("connector has unexpected global relation %q", relation)
		}
	}

	// Reconciling a config without the connector removes it.
	empty := &authz.Config{Mode: authz.ModeEnforce}
	b, err := authz.NewAuthorizer(ctx, newServer(t, pool), empty)
	if err != nil {
		t.Fatal(err)
	}
	if allowed(t, b, proxy, authz.ActorObject("dev-alice", "box"), "can_connect") {
		t.Error("a removed connector binding kept access")
	}
}

// TestAtespacePatternsBindEveryMatchingAtespace verifies a pattern binding
// grants its role in every atespace whose name starts with the pattern's
// prefix, including ones never mentioned in configuration, and nowhere else:
// not in other atespaces, not beyond the role, and not globally.
func TestAtespacePatternsBindEveryMatchingAtespace(t *testing.T) {
	ctx := context.Background()
	pool := authztest.StartPostgres(t)
	reaper := user("kubernetes", "system:serviceaccount:internal-eve:devbox-reaper")
	reader := user("google", "rita@basicblock.io")

	cfg := &authz.Config{
		Mode: authz.ModeEnforce,
		AtespacePatterns: map[string]authz.AtespaceBindings{
			"dev-*": {
				Editors: []string{"kubernetes:system:serviceaccount:internal-eve:devbox-reaper"},
				Viewers: []string{"google:rita@basicblock.io"},
			},
		},
	}
	a, err := authz.NewAuthorizer(ctx, newServer(t, pool), cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Editor on actors in every matching atespace, created on demand.
	for _, atespace := range []string{"dev-alice", "dev-someone-new"} {
		for _, relation := range []string{"can_get", "can_update", "can_delete", "can_suspend", "can_resume", "can_revert"} {
			if !allowed(t, a, reaper, authz.ActorObject(atespace, "box"), relation) {
				t.Errorf("pattern editor lacks %q on an actor in %q", relation, atespace)
			}
		}
		if !allowed(t, a, reaper, authz.AtespaceObject(atespace), "can_get") {
			t.Errorf("pattern editor cannot get atespace %q", atespace)
		}
	}

	// An editor, not an owner: it cannot delete the atespace itself.
	if allowed(t, a, reaper, authz.AtespaceObject("dev-alice"), "can_delete") {
		t.Error("pattern editor can delete a matching atespace")
	}

	// Nothing in atespaces the pattern does not match, even ones that share
	// letters with its prefix.
	for _, atespace := range []string{"eve", "ci", "development", "bb-dev"} {
		for _, relation := range []string{"can_get", "can_delete"} {
			if allowed(t, a, reaper, authz.ActorObject(atespace, "box"), relation) {
				t.Errorf("pattern editor has %q on an actor in unmatched atespace %q", relation, atespace)
			}
		}
	}

	// Nothing global: no listing across atespaces, no workers.
	for _, relation := range []string{"owner", "viewer", "can_get", "can_create_atespace"} {
		if allowed(t, a, reaper, authz.Global(), relation) {
			t.Errorf("pattern editor has unexpected global relation %q", relation)
		}
	}

	// A pattern viewer reads matching atespaces and changes nothing.
	if !allowed(t, a, reader, authz.ActorObject("dev-alice", "box"), "can_get") {
		t.Error("pattern viewer cannot get an actor in a matching atespace")
	}
	if allowed(t, a, reader, authz.ActorObject("dev-alice", "box"), "can_delete") {
		t.Error("pattern viewer can delete an actor")
	}

	// Reconciling a config without the pattern removes it.
	empty := &authz.Config{Mode: authz.ModeEnforce}
	b, err := authz.NewAuthorizer(ctx, newServer(t, pool), empty)
	if err != nil {
		t.Fatal(err)
	}
	if allowed(t, b, reaper, authz.ActorObject("dev-alice", "box"), "can_delete") {
		t.Error("a removed pattern binding kept access")
	}
}
