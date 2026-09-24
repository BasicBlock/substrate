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

	"github.com/agent-substrate/substrate/internal/principal"
	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// maxTuplesPerWrite is OpenFGA's default limit on one Write request.
const maxTuplesPerWrite = 100

// Authorizer answers whether a principal may make a call, using the embedded
// OpenFGA server and the role bindings of a Config.
type Authorizer struct {
	server *Server
	mode   Mode
	// patterns are the prefixes of the config's atespace patterns.
	patterns []string
}

// NewAuthorizer reconciles cfg's role bindings into server's store and returns
// an Authorizer for them. cfg must already be validated.
func NewAuthorizer(ctx context.Context, server *Server, cfg *Config) (*Authorizer, error) {
	if err := server.reconcile(ctx, cfg.tuples()); err != nil {
		return nil, fmt.Errorf("reconciling authorization bindings: %w", err)
	}
	return &Authorizer{server: server, mode: cfg.Mode, patterns: cfg.patternPrefixes()}, nil
}

// Mode returns what to do with a denied call.
func (a *Authorizer) Mode() Mode { return a.mode }

// Allowed reports whether p passes every check, and otherwise the first check
// it failed.
func (a *Authorizer) Allowed(ctx context.Context, p principal.PrincipalInfo, checks []Check) (bool, *Check, error) {
	user, err := PrincipalUser(p)
	if err != nil {
		return false, nil, err
	}
	groups := memberships(user, p)
	for i := range checks {
		allowed, err := a.server.check(ctx, user, checks[i], append(a.patternParents(checks[i].Object), groups...))
		if err != nil {
			return false, nil, err
		}
		if !allowed {
			return false, &checks[i], nil
		}
	}
	return true, nil, nil
}

// patternParents returns the contextual tuples placing an object's atespace
// under every configured pattern its name matches.
func (a *Authorizer) patternParents(o Object) []tuple {
	var out []tuple
	for _, prefix := range a.patterns {
		if o.atespace != "" && strings.HasPrefix(o.atespace, prefix) {
			out = append(out, tuple{User: atespacePatternObject(prefix), Relation: "parent_pattern", Object: AtespaceObject(o.atespace).ID})
		}
	}
	return out
}

// RecordCreator makes p the creator, and so an owner, of a new atespace.
func (a *Authorizer) RecordCreator(ctx context.Context, p principal.PrincipalInfo, atespace string) error {
	user, err := PrincipalUser(p)
	if err != nil {
		return err
	}
	return a.server.write(ctx, []tuple{{User: user, Relation: "creator", Object: AtespaceObject(atespace).ID}}, nil)
}

// ForgetCreators removes the creator records of a deleted atespace, so a
// later atespace of the same name does not inherit them.
func (a *Authorizer) ForgetCreators(ctx context.Context, atespace string) error {
	creators, err := a.server.read(ctx, &openfgav1.ReadRequestTupleKey{Object: AtespaceObject(atespace).ID, Relation: "creator"})
	if err != nil {
		return err
	}
	return a.server.write(ctx, nil, creators)
}

func (s *Server) check(ctx context.Context, user string, c Check, extra []tuple) (bool, error) {
	contextual := make([]*openfgav1.TupleKey, 0, len(c.Object.structural)+len(extra))
	for _, t := range append(c.Object.structural, extra...) {
		contextual = append(contextual, &openfgav1.TupleKey{User: t.User, Relation: t.Relation, Object: t.Object})
	}
	resp, err := s.fgaServer.Check(ctx, &openfgav1.CheckRequest{
		StoreId:              s.storeID,
		AuthorizationModelId: s.modelID,
		TupleKey:             &openfgav1.CheckRequestTupleKey{User: user, Relation: c.Relation, Object: c.Object.ID},
		ContextualTuples:     &openfgav1.ContextualTupleKeys{TupleKeys: contextual},
	})
	if err != nil {
		return false, fmt.Errorf("checking %s for %s: %w", c, user, err)
	}
	return resp.GetAllowed(), nil
}

// reconcile makes the stored role bindings exactly desired, holding the
// provisioning lock so replicas starting together do not interleave.
func (s *Server) reconcile(ctx context.Context, desired []tuple) error {
	unlock, err := acquireInitLock(ctx, s.pool)
	if err != nil {
		return err
	}
	defer unlock()

	stored, err := s.read(ctx, nil)
	if err != nil {
		return err
	}
	want := make(map[tuple]bool, len(desired))
	for _, t := range desired {
		want[t] = true
	}
	var deletes []tuple
	for _, t := range stored {
		if managed(t) && !want[t] {
			deletes = append(deletes, t)
		}
		delete(want, t)
	}
	var writes []tuple
	for _, t := range desired {
		if want[t] {
			writes = append(writes, t)
			delete(want, t)
		}
	}
	if err := s.write(ctx, writes, deletes); err != nil {
		return err
	}
	slog.InfoContext(ctx, "Reconciled authorization bindings",
		slog.Int("bindings", len(desired)), slog.Int("written", len(writes)), slog.Int("deleted", len(deletes)))
	return nil
}

// read returns every stored tuple matching key, or every tuple when key is nil.
func (s *Server) read(ctx context.Context, key *openfgav1.ReadRequestTupleKey) ([]tuple, error) {
	var out []tuple
	var token string
	for {
		resp, err := s.fgaServer.Read(ctx, &openfgav1.ReadRequest{
			StoreId:           s.storeID,
			TupleKey:          key,
			PageSize:          wrapperspb.Int32(maxTuplesPerWrite),
			ContinuationToken: token,
		})
		if err != nil {
			return nil, fmt.Errorf("reading tuples: %w", err)
		}
		for _, t := range resp.GetTuples() {
			k := t.GetKey()
			out = append(out, tuple{User: k.GetUser(), Relation: k.GetRelation(), Object: k.GetObject()})
		}
		token = resp.GetContinuationToken()
		if token == "" {
			return out, nil
		}
	}
}

// write applies writes and deletes in batches. Writing a stored tuple or
// deleting a missing one is not an error, so concurrent writers converge.
func (s *Server) write(ctx context.Context, writes, deletes []tuple) error {
	for len(writes) > 0 || len(deletes) > 0 {
		req := &openfgav1.WriteRequest{StoreId: s.storeID, AuthorizationModelId: s.modelID}
		if n := min(len(writes), maxTuplesPerWrite); n > 0 {
			keys := make([]*openfgav1.TupleKey, 0, n)
			for _, t := range writes[:n] {
				keys = append(keys, &openfgav1.TupleKey{User: t.User, Relation: t.Relation, Object: t.Object})
			}
			req.Writes = &openfgav1.WriteRequestWrites{TupleKeys: keys, OnDuplicate: "ignore"}
			writes = writes[n:]
		} else {
			n := min(len(deletes), maxTuplesPerWrite)
			keys := make([]*openfgav1.TupleKeyWithoutCondition, 0, n)
			for _, t := range deletes[:n] {
				keys = append(keys, &openfgav1.TupleKeyWithoutCondition{User: t.User, Relation: t.Relation, Object: t.Object})
			}
			req.Deletes = &openfgav1.WriteRequestDeletes{TupleKeys: keys, OnMissing: "ignore"}
			deletes = deletes[n:]
		}
		if _, err := s.fgaServer.Write(ctx, req); err != nil {
			return fmt.Errorf("writing tuples: %w", err)
		}
	}
	return nil
}
