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

package controlapi

import (
	"context"
	"testing"

	"github.com/agent-substrate/substrate/cmd/ateapi/internal/store/storetest"
	"github.com/agent-substrate/substrate/internal/resources"
	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestDropSnapshotMemory_StateMatrix pins which actor states DropSnapshotMemory
// accepts: only SUSPENDED, the same precondition Suspend/Delete apply, since
// this rewrites the very snapshot a non-SUSPENDED actor's other state (a
// worker assignment, an in-progress upload) may be about to replace.
func TestDropSnapshotMemory_StateMatrix(t *testing.T) {
	for _, tc := range []struct {
		state   ateapipb.ActorState
		wantErr bool
	}{
		{ateapipb.ActorState_ACTOR_STATE_SUSPENDED, false},
		{ateapipb.ActorState_ACTOR_STATE_RUNNING, true},
		{ateapipb.ActorState_ACTOR_STATE_PAUSED, true},
		{ateapipb.ActorState_ACTOR_STATE_CRASHED, true},
		{ateapipb.ActorState_ACTOR_STATE_SUSPENDING, true},
	} {
		t.Run(tc.state.String(), func(t *testing.T) {
			ctx := context.Background()
			st, cleanup := storetest.SetupTestStore(t)
			defer cleanup()
			w, atelet := newWireCaptureWorkflow(t, st)

			actorRef := resources.ActorRef{Atespace: "team-a", Name: "id1"}
			seedWorkflowActor(t, ctx, st, actorRef, "ns", "tmpl1", tc.state, func(a *ateapipb.Actor) {
				a.Status.ExternalSnapshot = &ateapipb.ExternalSnapshot{
					SnapshotUri:  testSnapshotURIForDrop,
					ContentScope: ateapipb.SnapshotContentScope_SNAPSHOT_CONTENT_SCOPE_FULL,
				}
			})

			_, err := w.DropSnapshotMemory(ctx, actorRef)
			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Fatalf("DropSnapshotMemory = %v, wantErr %t", err, tc.wantErr)
			}
			if tc.wantErr {
				if got := status.Code(err); got != codes.FailedPrecondition {
					t.Errorf("status.Code = %v, want FailedPrecondition", got)
				}
				if atelet.droppedSnapshotMemory() != nil {
					t.Error("atelet.DropSnapshotMemory was called despite the precondition failing")
				}
			}
		})
	}
}

const testSnapshotURIForDrop = "gs://bucket/root/atespaces/team-a/actors/actor-uid-1/snapshots/snap-1"

// TestDropSnapshotMemory_Success covers the happy path end to end: atelet is
// called with the actor's external snapshot URI, and the actor's recorded
// scope becomes Filesystem.
func TestDropSnapshotMemory_Success(t *testing.T) {
	ctx := context.Background()
	st, cleanup := storetest.SetupTestStore(t)
	defer cleanup()
	w, atelet := newWireCaptureWorkflow(t, st)

	actorRef := resources.ActorRef{Atespace: "team-a", Name: "id1"}
	seedWorkflowActor(t, ctx, st, actorRef, "ns", "tmpl1", ateapipb.ActorState_ACTOR_STATE_SUSPENDED, func(a *ateapipb.Actor) {
		a.Status.ExternalSnapshot = &ateapipb.ExternalSnapshot{
			SnapshotUri:  testSnapshotURIForDrop,
			ContentScope: ateapipb.SnapshotContentScope_SNAPSHOT_CONTENT_SCOPE_FULL,
		}
	})

	actor, err := w.DropSnapshotMemory(ctx, actorRef)
	if err != nil {
		t.Fatalf("DropSnapshotMemory: %v", err)
	}

	if got := actor.GetStatus().GetExternalSnapshot().GetContentScope(); got != ateapipb.SnapshotContentScope_SNAPSHOT_CONTENT_SCOPE_FILESYSTEM {
		t.Errorf("recorded content scope = %v, want %v", got, ateapipb.SnapshotContentScope_SNAPSHOT_CONTENT_SCOPE_FILESYSTEM)
	}
	if got := actor.GetStatus().GetExternalSnapshot().GetSnapshotUri(); got != testSnapshotURIForDrop {
		t.Errorf("snapshot uri = %q, want it unchanged at %q", got, testSnapshotURIForDrop)
	}
	if got := actor.GetStatus().GetState(); got != ateapipb.ActorState_ACTOR_STATE_SUSPENDED {
		t.Errorf("state = %v, want it to stay SUSPENDED", got)
	}

	req := atelet.droppedSnapshotMemory()
	if req == nil {
		t.Fatal("atelet.DropSnapshotMemory was never called")
	}
	if req.GetSnapshotUri() != testSnapshotURIForDrop {
		t.Errorf("atelet request snapshot_uri = %q, want %q", req.GetSnapshotUri(), testSnapshotURIForDrop)
	}

	// Idempotent: calling again succeeds and re-invokes atelet's own
	// idempotent rewrite rather than short-circuiting on the ateapi side.
	if _, err := w.DropSnapshotMemory(ctx, actorRef); err != nil {
		t.Fatalf("second DropSnapshotMemory: %v", err)
	}
}

// TestDropSnapshotMemory_NoExternalSnapshot covers a SUSPENDED actor with
// nothing to narrow.
func TestDropSnapshotMemory_NoExternalSnapshot(t *testing.T) {
	ctx := context.Background()
	st, cleanup := storetest.SetupTestStore(t)
	defer cleanup()
	w, atelet := newWireCaptureWorkflow(t, st)

	actorRef := resources.ActorRef{Atespace: "team-a", Name: "id1"}
	seedWorkflowActor(t, ctx, st, actorRef, "ns", "tmpl1", ateapipb.ActorState_ACTOR_STATE_SUSPENDED)

	_, err := w.DropSnapshotMemory(ctx, actorRef)
	if got := status.Code(err); got != codes.FailedPrecondition {
		t.Fatalf("status.Code = %v (err %v), want FailedPrecondition", got, err)
	}
	if atelet.droppedSnapshotMemory() != nil {
		t.Error("atelet.DropSnapshotMemory was called despite there being no external snapshot")
	}
}

// TestDropSnapshotMemory_AteletFailure ensures an atelet-side rejection (e.g.
// the snapshot has no filesystem image) surfaces as an error and never
// updates the actor's recorded scope.
func TestDropSnapshotMemory_AteletFailure(t *testing.T) {
	ctx := context.Background()
	st, cleanup := storetest.SetupTestStore(t)
	defer cleanup()
	w, atelet := newWireCaptureWorkflow(t, st)
	atelet.dropSnapshotMemoryErr = status.Error(codes.FailedPrecondition, "full capture has no filesystem image")

	actorRef := resources.ActorRef{Atespace: "team-a", Name: "id1"}
	seedWorkflowActor(t, ctx, st, actorRef, "ns", "tmpl1", ateapipb.ActorState_ACTOR_STATE_SUSPENDED, func(a *ateapipb.Actor) {
		a.Status.ExternalSnapshot = &ateapipb.ExternalSnapshot{
			SnapshotUri:  testSnapshotURIForDrop,
			ContentScope: ateapipb.SnapshotContentScope_SNAPSHOT_CONTENT_SCOPE_FULL,
		}
	})

	if _, err := w.DropSnapshotMemory(ctx, actorRef); err == nil {
		t.Fatal("DropSnapshotMemory succeeded, want the atelet failure to propagate")
	}

	stored, err := st.GetActor(ctx, actorRef)
	if err != nil {
		t.Fatalf("GetActor: %v", err)
	}
	if got := stored.GetStatus().GetExternalSnapshot().GetContentScope(); got != ateapipb.SnapshotContentScope_SNAPSHOT_CONTENT_SCOPE_FULL {
		t.Errorf("content scope = %v, want it unchanged at FULL after an atelet failure", got)
	}
}
