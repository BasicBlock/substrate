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

	"github.com/agent-substrate/substrate/cmd/ateapi/internal/store"
	"github.com/agent-substrate/substrate/internal/apierror"
	"github.com/agent-substrate/substrate/internal/resources"
	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const testSnapshotURIForDrop = "gs://bucket/root/atespaces/team-a/actors/actor-uid-1/snapshots/snap-1"

// seedDroppableActor seeds an actor in state with a COMPLETED durable snapshot
// of the given fidelity.
func seedDroppableActor(t *testing.T, persistence store.Interface, state ateapipb.ActorState, fidelity ateapipb.SnapshotFidelity) resources.ActorRef {
	t.Helper()
	ctx := context.Background()
	actorRef := resources.ActorRef{Atespace: "team-a", Name: "id1"}
	seedWorkflowActor(t, ctx, persistence, actorRef, "ns", "tmpl1", state, func(a *ateapipb.Actor) {
		a.Status.LastAssignedGeneration = 1
		a.Status.Snapshots = []*ateapipb.Snapshot{
			newDurableSnapshot(1, ateapipb.SnapshotOwner_SNAPSHOT_OWNER_ACTOR, fidelity, "", "snap-1", testSnapshotURIForDrop, ateapipb.SnapshotStorageStatus_SNAPSHOT_STORAGE_STATUS_COMPLETED),
		}
	})
	return actorRef
}

// DropSnapshotMemory accepts only a SUSPENDED actor: it rewrites the very
// snapshot another state's pending work (a worker assignment, an upload in
// flight) may be about to replace.
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
			persistence := newTestPersistence(t)
			w, atelet := newWireCaptureWorkflow(t, persistence)
			actorRef := seedDroppableActor(t, persistence, tc.state, ateapipb.SnapshotFidelity_SNAPSHOT_FIDELITY_MEMORY)

			_, err := w.DropSnapshotMemory(context.Background(), actorRef)
			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Fatalf("DropSnapshotMemory = %v, wantErr %t", err, tc.wantErr)
			}
			if tc.wantErr {
				if got := apierror.Code(err); got != codes.FailedPrecondition {
					t.Errorf("code = %v, want FailedPrecondition", got)
				}
				if atelet.droppedSnapshotMemory() != nil {
					t.Error("atelet.DropSnapshotMemory was called despite the precondition failing")
				}
			}
		})
	}
}

// Atelet is called with the actor's durable snapshot URI, and the actor's
// snapshot is then recorded as ROOTFS, the rest unchanged.
func TestDropSnapshotMemory_Success(t *testing.T) {
	ctx := context.Background()
	persistence := newTestPersistence(t)
	w, atelet := newWireCaptureWorkflow(t, persistence)
	actorRef := seedDroppableActor(t, persistence, ateapipb.ActorState_ACTOR_STATE_SUSPENDED, ateapipb.SnapshotFidelity_SNAPSHOT_FIDELITY_MEMORY)

	actor, err := w.DropSnapshotMemory(ctx, actorRef)
	if err != nil {
		t.Fatalf("DropSnapshotMemory: %v", err)
	}
	snap := findLatestDurableSnapshot(actor.GetStatus(), ateapipb.SnapshotStorageStatus_SNAPSHOT_STORAGE_STATUS_COMPLETED)
	if snap.GetFidelity() != ateapipb.SnapshotFidelity_SNAPSHOT_FIDELITY_ROOTFS {
		t.Errorf("recorded fidelity = %v, want ROOTFS", snap.GetFidelity())
	}
	if got := snap.GetDurableSnapshot().GetObject().GetSnapshotUri(); got != testSnapshotURIForDrop {
		t.Errorf("snapshot uri = %q, want it unchanged at %q", got, testSnapshotURIForDrop)
	}
	if got := actor.GetStatus().GetState(); got != ateapipb.ActorState_ACTOR_STATE_SUSPENDED {
		t.Errorf("state = %v, want it to stay SUSPENDED", got)
	}
	if req := atelet.droppedSnapshotMemory(); req.GetSnapshotUri() != testSnapshotURIForDrop {
		t.Errorf("atelet request = %v, want the snapshot URI %q", req, testSnapshotURIForDrop)
	}

	// Idempotent: a repeat succeeds and asks atelet again, which finishes any
	// emptying an earlier call left.
	if _, err := w.DropSnapshotMemory(ctx, actorRef); err != nil {
		t.Fatalf("second DropSnapshotMemory: %v", err)
	}
}

func TestDropSnapshotMemory_NothingToDrop(t *testing.T) {
	ctx := context.Background()
	persistence := newTestPersistence(t)
	w, atelet := newWireCaptureWorkflow(t, persistence)

	t.Run("no durable snapshot", func(t *testing.T) {
		actorRef := resources.ActorRef{Atespace: "team-a", Name: "bare"}
		seedWorkflowActor(t, ctx, persistence, actorRef, "ns", "tmpl1", ateapipb.ActorState_ACTOR_STATE_SUSPENDED)
		if _, err := w.DropSnapshotMemory(ctx, actorRef); apierror.Code(err) != codes.FailedPrecondition {
			t.Fatalf("DropSnapshotMemory = %v, want FailedPrecondition", err)
		}
	})
	t.Run("a VOLUMES snapshot has no memory", func(t *testing.T) {
		actorRef := seedDroppableActor(t, persistence, ateapipb.ActorState_ACTOR_STATE_SUSPENDED, ateapipb.SnapshotFidelity_SNAPSHOT_FIDELITY_VOLUMES)
		if _, err := w.DropSnapshotMemory(ctx, actorRef); apierror.Code(err) != codes.FailedPrecondition {
			t.Fatalf("DropSnapshotMemory = %v, want FailedPrecondition", err)
		}
	})
	if atelet.droppedSnapshotMemory() != nil {
		t.Error("atelet.DropSnapshotMemory was called with nothing to drop")
	}
}

// An atelet-side refusal (the snapshot holds no root filesystem) surfaces with
// its code and leaves the recorded fidelity alone; the actor is not crashed.
func TestDropSnapshotMemory_AteletFailure(t *testing.T) {
	ctx := context.Background()
	persistence := newTestPersistence(t)
	w, atelet := newWireCaptureWorkflow(t, persistence)
	atelet.dropSnapshotMemoryErr = status.Error(codes.FailedPrecondition, "MEMORY snapshot holds no root filesystem to keep")
	actorRef := seedDroppableActor(t, persistence, ateapipb.ActorState_ACTOR_STATE_SUSPENDED, ateapipb.SnapshotFidelity_SNAPSHOT_FIDELITY_MEMORY)

	_, err := w.DropSnapshotMemory(ctx, actorRef)
	if apierror.Code(err) != codes.FailedPrecondition {
		t.Fatalf("DropSnapshotMemory = %v, want atelet's FailedPrecondition", err)
	}
	stored, err := persistence.GetActor(ctx, actorRef)
	if err != nil {
		t.Fatalf("GetActor: %v", err)
	}
	if got := stored.GetStatus().GetState(); got != ateapipb.ActorState_ACTOR_STATE_SUSPENDED {
		t.Errorf("state = %v after a failed drop, want SUSPENDED", got)
	}
	if got := findLatestDurableSnapshot(stored.GetStatus(), ateapipb.SnapshotStorageStatus_SNAPSHOT_STORAGE_STATUS_COMPLETED).GetFidelity(); got != ateapipb.SnapshotFidelity_SNAPSHOT_FIDELITY_MEMORY {
		t.Errorf("fidelity = %v, want it unchanged at MEMORY after an atelet failure", got)
	}

	atelet.dropSnapshotMemoryErr = status.Error(codes.Unavailable, "snapshot plugin down")
	if _, err := w.DropSnapshotMemory(ctx, actorRef); apierror.Code(err) != codes.Unavailable {
		t.Errorf("DropSnapshotMemory with an unavailable atelet = %v, want Unavailable (retriable, not a crash)", err)
	}
}
