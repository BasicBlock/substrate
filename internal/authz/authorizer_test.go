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

	"github.com/agent-substrate/substrate/internal/authz"
	"github.com/agent-substrate/substrate/internal/authz/authztest"
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
	cfg, err := pgxpool.ParseConfig(pool.Config().ConnString())
	if err != nil {
		t.Fatal(err)
	}
	dedicated, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := authz.NewServer(context.Background(), dedicated)
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
