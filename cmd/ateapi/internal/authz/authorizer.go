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
	"fmt"
	"log/slog"
	"strings"

	"github.com/agent-substrate/substrate/internal/apierror"
	"github.com/agent-substrate/substrate/internal/principal"
	"github.com/jackc/pgx/v5/pgxpool"
	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"github.com/openfga/openfga/pkg/server"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// Authorizer is the read-only policy decision point that evaluates runtime
// OpenFGA permissions against Substrate's store and authorization model.
type Authorizer struct {
	fgaServer *server.Server
	storeID   string
	modelID   string

	// pool lets RecordCreator, ForgetCreators and ReconcileConfig open their
	// own short transactions: the datastore's Read and Write RPCs require an
	// active pgx.Tx in context (see datastore.go), and none of their callers
	// (the gRPC interceptor, main at startup) has one of its own to offer.
	pool *pgxpool.Pool

	// mode records the --authorization-config mode ReconcileConfig last
	// applied, for introspection; the interceptor is given it explicitly
	// rather than reading it back from here.
	mode Mode

	// bootstrapOwners holds the OpenFGA user strings of the server-configured
	// global owners. They hold owner on global:root through a contextual tuple
	// on every Check rather than a stored tuple, so they are not part of any
	// AccessPolicy, cannot be revoked through the API, and lose access once
	// the server runs without them in its configuration.
	bootstrapOwners map[string]struct{}

	// patterns are the prefixes of the --authorization-config's
	// atespacePatterns, set by ReconcileConfig. An atespace whose name starts
	// with one is placed under its "atespace_pattern:<prefix>" object
	// (parent_pattern) by a contextual tuple on every Check, the same way
	// every atespace is placed under global:root.
	patterns []string
}

// Mode returns the mode ReconcileConfig last applied, or "" if it was never
// called.
func (a *Authorizer) Mode() Mode { return a.mode }

// Check verifies that the principal in ctx has relation on object.
// Structural hierarchy links (global:root as parent_global of every atespace,
// and each atespace as parent_atespace of its actors and actor templates) and
// the caller's bootstrap owner grant, if any, are injected as OpenFGA
// ContextualTuples at evaluation time rather than persisted in the tuple table.
func (a *Authorizer) Check(ctx context.Context, relation, object string) error {
	if IsBypassed(ctx) {
		return nil
	}
	if a == nil || a.fgaServer == nil {
		return apierror.Internal("authz: authorizer is not initialized")
	}
	p, ok := principal.FromContext(ctx)
	if !ok || p.ID == "" {
		return apierror.Unauthenticated("unauthenticated: missing principal in context")
	}
	user := formatUser(p.ID)
	allowed, err := a.checkRaw(ctx, user, p.Groups, relation, object)
	if err != nil {
		return err
	}
	if !allowed {
		return apierror.PermissionDenied("permission denied: principal %q lacks %q on %q", user, relation, object)
	}
	return nil
}

func (a *Authorizer) checkRaw(ctx context.Context, user string, groups []string, relation, object string) (bool, error) {
	tuples := a.contextualTuples(object)
	// The principal's group memberships (GroupAuthenticated, its JWT provider,
	// and any named claim rule it satisfied) are supplied with the check
	// rather than stored, so a role binding can name a group no member of it
	// has ever called with.
	for _, g := range groups {
		tuples = append(tuples, &openfgav1.TupleKey{
			User:     user,
			Relation: "member",
			Object:   GroupObject(g),
		})
	}
	// A Check only evaluates the caller, so only the caller's own bootstrap
	// grant can affect the result.
	if _, ok := a.bootstrapOwners[user]; ok {
		tuples = append(tuples, &openfgav1.TupleKey{
			User:     user,
			Relation: RoleOwner,
			Object:   GlobalRootObject,
		})
	}
	var ctxTuples *openfgav1.ContextualTupleKeys
	if len(tuples) > 0 {
		ctxTuples = &openfgav1.ContextualTupleKeys{TupleKeys: tuples}
	}
	resp, err := a.fgaServer.Check(ctx, &openfgav1.CheckRequest{
		StoreId:              a.storeID,
		AuthorizationModelId: a.modelID,
		TupleKey: &openfgav1.CheckRequestTupleKey{
			User:     user,
			Relation: relation,
			Object:   object,
		},
		ContextualTuples: ctxTuples,
	})
	if err != nil {
		return false, err
	}
	return resp.GetAllowed(), nil
}

// contextualTuples synthesizes the invariant structural hierarchy tuples for an
// object so OpenFGA can traverse parent-child inheritance (e.g. `owner from parent_global`
// in model.fga) in memory during Check evaluation without persisting structural
// tuples in PostgreSQL.
//
// Why contextual tuples are used instead of storing parent links in the database:
//  1. Deterministic structure: Every `atespace:<name>` unconditionally has
//     `global:root` as its `parent_global`, and every `actor:<atespace>/<name>`
//     and `actor_template:<atespace>/<name>` has `atespace:<atespace>` as its
//     `parent_atespace`. Because these relationships are derived purely from the
//     object type/ID, storing a row per resource in the OpenFGA `tuple` table
//     would be redundant.
//  2. No write amplification on create: `CreateAtespace`, `CreateActorTemplate`,
//     and `CreateActor` can insert their rows without opening an OpenFGA write
//     transaction just to link the parent.
//
// An atespace matching one of a.patterns' prefixes gets a parent_pattern
// tuple the same way, so a binding on "atespace_pattern:<prefix>" reaches
// every atespace whose name starts with it, including one created after the
// binding, without storing a tuple per atespace either.
func (a *Authorizer) contextualTuples(object string) []*openfgav1.TupleKey {
	objectType, id, _ := strings.Cut(object, ":")
	switch objectType {
	case "atespace":
		return a.atespaceTuples(object)
	case "actor", "actor_template":
		atespace, _, ok := strings.Cut(id, "/")
		if !ok {
			return nil
		}
		// atespacedID escapes the atespace the same way AtespaceObject does.
		parent := "atespace:" + atespace
		return append([]*openfgav1.TupleKey{{User: parent, Relation: "parent_atespace", Object: object}}, a.atespaceTuples(parent)...)
	}
	return nil
}

// atespaceTuples links an atespace object to global:root and to every pattern
// its name matches.
func (a *Authorizer) atespaceTuples(atespaceObject string) []*openfgav1.TupleKey {
	return append([]*openfgav1.TupleKey{parentGlobalTuple(atespaceObject)}, a.patternParents(atespaceObject)...)
}

// parentGlobalTuple links an atespace object to global:root.
func parentGlobalTuple(atespaceObject string) *openfgav1.TupleKey {
	return &openfgav1.TupleKey{
		User:     GlobalRootObject,
		Relation: "parent_global",
		Object:   atespaceObject,
	}
}

// patternParents returns the contextual tuples placing atespaceObject
// ("atespace:<name>") under every configured pattern its name matches.
func (a *Authorizer) patternParents(atespaceObject string) []*openfgav1.TupleKey {
	name := strings.TrimPrefix(atespaceObject, "atespace:")
	var out []*openfgav1.TupleKey
	for _, prefix := range a.patterns {
		if strings.HasPrefix(name, prefix) {
			out = append(out, &openfgav1.TupleKey{
				User:     AtespacePatternObject(prefix),
				Relation: "parent_pattern",
				Object:   atespaceObject,
			})
		}
	}
	return out
}

// RecordCreator makes p the creator, and so an owner (model.fga: "owner:
// [user, group#member] or creator or owner from parent_global"), of a new
// atespace. It opens its own transaction, so creating an atespace and
// recording its creator are not atomic with each other; the interceptor that
// calls it after CreateAtespace's handler returns has no transaction of its
// own to join.
func (a *Authorizer) RecordCreator(ctx context.Context, p principal.PrincipalInfo, atespace string) error {
	user := formatUser(p.ID)
	return a.writeInTx(ctx, []*openfgav1.TupleKey{
		{User: user, Relation: "creator", Object: AtespaceObject(atespace)},
	}, nil)
}

// ForgetCreators removes the creator records of a deleted atespace, so a
// later atespace of the same name does not inherit them.
func (a *Authorizer) ForgetCreators(ctx context.Context, atespace string) error {
	creators, err := a.readInTx(ctx, &openfgav1.ReadRequestTupleKey{Object: AtespaceObject(atespace), Relation: "creator"})
	if err != nil {
		return err
	}
	if len(creators) == 0 {
		return nil
	}
	deletes := make([]*openfgav1.TupleKeyWithoutCondition, 0, len(creators))
	for _, t := range creators {
		deletes = append(deletes, &openfgav1.TupleKeyWithoutCondition{User: t.GetUser(), Relation: t.GetRelation(), Object: t.GetObject()})
	}
	return a.writeInTx(ctx, nil, deletes)
}

// ReconcileConfig writes and deletes the OpenFGA role-binding tuples cfg
// describes so the store exactly matches it, holding the provisioning
// advisory lock so replicas starting together do not interleave, and records
// cfg.Mode for Mode. It touches only the relations Config manages (global
// owner, viewer and atespace_creator; atespace owner, editor and viewer), so
// it never disturbs an atespace's "creator" tuple or a binding an
// AccessPolicy RPC wrote through PolicyManager on the same relation -- see
// Config's doc comment.
func (a *Authorizer) ReconcileConfig(ctx context.Context, cfg *Config) error {
	unlock, err := acquireInitLock(ctx, a.pool)
	if err != nil {
		return err
	}
	defer unlock()

	desired := cfg.tuples()
	want := make(map[bindingKey]bool, len(desired))
	for _, t := range desired {
		want[bindingKey{t.GetUser(), t.GetRelation(), t.GetObject()}] = true
	}

	stored, err := a.readInTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("reading stored authorization bindings: %w", err)
	}
	var deletes []*openfgav1.TupleKeyWithoutCondition
	for _, t := range stored {
		k := bindingKey{t.GetUser(), t.GetRelation(), t.GetObject()}
		if !managed(k) {
			continue
		}
		if want[k] {
			delete(want, k)
			continue
		}
		deletes = append(deletes, &openfgav1.TupleKeyWithoutCondition{User: t.GetUser(), Relation: t.GetRelation(), Object: t.GetObject()})
	}
	writes := make([]*openfgav1.TupleKey, 0, len(want))
	for k := range want {
		writes = append(writes, &openfgav1.TupleKey{User: k.user, Relation: k.relation, Object: k.object})
	}
	if err := a.writeInTx(ctx, writes, deletes); err != nil {
		return fmt.Errorf("reconciling authorization bindings: %w", err)
	}
	slog.InfoContext(ctx, "Reconciled authorization bindings",
		slog.Int("bindings", len(desired)), slog.Int("written", len(writes)), slog.Int("deleted", len(deletes)))
	a.mode = cfg.Mode
	a.patterns = cfg.patternPrefixes()
	return nil
}

// readInTx returns every stored tuple matching key (or every stored tuple
// when key is nil), in its own transaction.
func (a *Authorizer) readInTx(ctx context.Context, key *openfgav1.ReadRequestTupleKey) ([]*openfgav1.TupleKey, error) {
	tx, err := a.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op once Commit has succeeded
	ctx = ContextWithTx(ctx, tx)

	var out []*openfgav1.TupleKey
	var token string
	for {
		resp, err := a.fgaServer.Read(ctx, &openfgav1.ReadRequest{
			StoreId:           a.storeID,
			TupleKey:          key,
			PageSize:          wrapperspb.Int32(maxTuplesPerWrite),
			ContinuationToken: token,
		})
		if err != nil {
			return nil, fmt.Errorf("reading tuples: %w", err)
		}
		for _, t := range resp.GetTuples() {
			if k := t.GetKey(); k != nil {
				out = append(out, k)
			}
		}
		token = resp.GetContinuationToken()
		if token == "" {
			break
		}
	}
	return out, tx.Commit(ctx)
}

// writeInTx applies writes and deletes in batches, in its own transaction.
// Writing a stored tuple or deleting a missing one is not an error, so
// concurrent writers converge.
func (a *Authorizer) writeInTx(ctx context.Context, writes []*openfgav1.TupleKey, deletes []*openfgav1.TupleKeyWithoutCondition) error {
	tx, err := a.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op once Commit has succeeded
	ctx = ContextWithTx(ctx, tx)

	for len(writes) > 0 || len(deletes) > 0 {
		req := &openfgav1.WriteRequest{StoreId: a.storeID, AuthorizationModelId: a.modelID}
		if n := min(len(writes), maxTuplesPerWrite); n > 0 {
			req.Writes = &openfgav1.WriteRequestWrites{TupleKeys: writes[:n], OnDuplicate: "ignore"}
			writes = writes[n:]
		} else {
			n := min(len(deletes), maxTuplesPerWrite)
			req.Deletes = &openfgav1.WriteRequestDeletes{TupleKeys: deletes[:n], OnMissing: "ignore"}
			deletes = deletes[n:]
		}
		if _, err := a.fgaServer.Write(ctx, req); err != nil {
			return fmt.Errorf("writing tuples: %w", err)
		}
	}
	return tx.Commit(ctx)
}
