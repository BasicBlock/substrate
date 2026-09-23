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
	"testing"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"sigs.k8s.io/yaml"
)

// modelTests is the shape of model_test.fga.yaml, the OpenFGA CLI's model
// test format.
type modelTests struct {
	Tuples []struct {
		User, Relation, Object string
	} `json:"tuples"`
	Tests []struct {
		Name  string `json:"name"`
		Check []struct {
			User       string          `json:"user"`
			Object     string          `json:"object"`
			Assertions map[string]bool `json:"assertions"`
		} `json:"check"`
	} `json:"tests"`
}

// TestModelAssertions runs model_test.fga.yaml against the embedded model.
func TestModelAssertions(t *testing.T) {
	b, err := os.ReadFile("model_test.fga.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var mt modelTests
	if err := yaml.Unmarshal(b, &mt); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	pool := startPostgres(t)

	fgaServer, err := NewOpenFGAServer(pool)
	if err != nil {
		t.Fatalf("NewOpenFGAServer failed: %v", err)
	}
	t.Cleanup(fgaServer.Close)

	storeID, modelID, err := EnsureStoreAndModel(ctx, pool, fgaServer)
	if err != nil {
		t.Fatalf("EnsureStoreAndModel failed: %v", err)
	}

	var keys []*openfgav1.TupleKey
	for _, tu := range mt.Tuples {
		keys = append(keys, &openfgav1.TupleKey{User: tu.User, Relation: tu.Relation, Object: tu.Object})
	}
	// The transactional datastore requires an active pgx.Tx on ctx (see
	// transactionalDatastore.Write in datastore.go); writes outside one fail
	// with ErrNoTransactionInContext.
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("pool.Begin failed: %v", err)
	}
	if _, err := fgaServer.Write(ContextWithTx(ctx, tx), &openfgav1.WriteRequest{
		StoreId: storeID, AuthorizationModelId: modelID,
		Writes: &openfgav1.WriteRequestWrites{TupleKeys: keys},
	}); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("writing model test tuples: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("tx.Commit failed: %v", err)
	}
	for _, test := range mt.Tests {
		for _, c := range test.Check {
			for relation, want := range c.Assertions {
				resp, err := fgaServer.Check(ctx, &openfgav1.CheckRequest{
					StoreId: storeID, AuthorizationModelId: modelID,
					TupleKey: &openfgav1.CheckRequestTupleKey{User: c.User, Relation: relation, Object: c.Object},
				})
				if err != nil {
					t.Fatalf("%s: check %s %s %s: %v", test.Name, c.User, relation, c.Object, err)
				}
				if resp.GetAllowed() != want {
					t.Errorf("%s: %s %s %s = %v, want %v", test.Name, c.User, relation, c.Object, resp.GetAllowed(), want)
				}
			}
		}
	}
}
