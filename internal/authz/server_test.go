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
	"testing"

	"github.com/agent-substrate/substrate/internal/authz"
	"github.com/agent-substrate/substrate/internal/authz/authztest"
	"github.com/jackc/pgx/v5/pgxpool"
	openfgav1 "github.com/openfga/api/proto/openfga/v1"
)

func TestNewServer_NilPool(t *testing.T) {
	_, err := authz.NewServer(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error when pool is nil, got nil")
	}
}

func TestNewServer_InitializeAndCheck(t *testing.T) {
	pool := authztest.StartPostgres(t)
	ctx := context.Background()

	srv, err := authz.NewServer(ctx, pool)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	defer srv.Close()

	if srv.StoreID() == "" {
		t.Fatal("expected non-empty StoreID")
	}
	if srv.ModelID() == "" {
		t.Fatal("expected non-empty ModelID")
	}
	if srv.FGAServer() == nil {
		t.Fatal("expected non-nil FGAServer")
	}

	// Write relationship tuples and verify authorization checks against the model.
	_, err = srv.FGAServer().Write(ctx, &openfgav1.WriteRequest{
		StoreId:              srv.StoreID(),
		AuthorizationModelId: srv.ModelID(),
		Writes: &openfgav1.WriteRequestWrites{
			TupleKeys: []*openfgav1.TupleKey{
				{
					User:     "user:alice",
					Relation: "owner",
					Object:   "global:root",
				},
				{
					User:     "global:root",
					Relation: "parent_global",
					Object:   "atespace:space-1",
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("Write tuples failed: %v", err)
	}

	checkResp, err := srv.FGAServer().Check(ctx, &openfgav1.CheckRequest{
		StoreId:              srv.StoreID(),
		AuthorizationModelId: srv.ModelID(),
		TupleKey: &openfgav1.CheckRequestTupleKey{
			User:     "user:alice",
			Relation: "can_set_policy",
			Object:   "atespace:space-1",
		},
	})
	if err != nil {
		t.Fatalf("Check alice can_set_policy failed: %v", err)
	}
	if !checkResp.GetAllowed() {
		t.Errorf("expected alice to be allowed can_set_policy on atespace:space-1 via global owner inheritance")
	}

	checkBob, err := srv.FGAServer().Check(ctx, &openfgav1.CheckRequest{
		StoreId:              srv.StoreID(),
		AuthorizationModelId: srv.ModelID(),
		TupleKey: &openfgav1.CheckRequestTupleKey{
			User:     "user:bob",
			Relation: "can_set_policy",
			Object:   "atespace:space-1",
		},
	})
	if err != nil {
		t.Fatalf("Check bob can_set_policy failed: %v", err)
	}
	if checkBob.GetAllowed() {
		t.Errorf("expected bob to be denied can_set_policy on atespace:space-1")
	}

	// Create a second dedicated pool to test idempotent re-initialization after
	// closing the first server (since srv.Close() closes its dedicated pool).
	pool2, err := pgxpool.NewWithConfig(ctx, pool.Config())
	if err != nil {
		t.Fatalf("creating second pgxpool: %v", err)
	}
	srv.Close()

	// Verify idempotent re-initialization reuses the existing store and model.
	srv2, err := authz.NewServer(ctx, pool2)
	if err != nil {
		t.Fatalf("second NewServer failed: %v", err)
	}
	defer srv2.Close()

	if srv2.StoreID() != srv.StoreID() {
		t.Errorf("expected same StoreID %q on re-init, got %q", srv.StoreID(), srv2.StoreID())
	}
	if srv2.ModelID() != srv.ModelID() {
		t.Errorf("expected same ModelID %q on re-init, got %q", srv.ModelID(), srv2.ModelID())
	}
}
