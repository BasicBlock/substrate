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

// seedRunningOnWireWorker stores a MEMORY-committing template and a RUNNING
// actor on the worker newWireCaptureWorkflow's fake atelet serves.
func seedRunningOnWireWorker(t *testing.T, ctx context.Context, persistence store.Interface, actorRef resources.ActorRef) {
	t.Helper()
	if _, err := persistence.CreateActorTemplate(ctx, &ateapipb.ActorTemplate{
		Metadata: &ateapipb.ResourceMetadata{Atespace: actorRef.Atespace, Name: "tmpl1"},
		SnapshotConfig: &ateapipb.SnapshotConfig{
			StorageLocation:   testStorageLocation,
			PreferredFidelity: ateapipb.SnapshotFidelity_SNAPSHOT_FIDELITY_MEMORY,
		},
		SandboxConfig: &ateapipb.SandboxConfig{SandboxClass: ateapipb.SandboxClass_SANDBOX_CLASS_GVISOR, ConfigName: "gvisor"},
	}); err != nil {
		t.Fatalf("create template: %v", err)
	}
	assignment := wireTestAssignment()
	if _, err := persistence.CreateWorker(ctx, &ateapipb.Worker{
		Metadata:        &ateapipb.ResourceMetadata{Name: assignment.GetWorker().GetName()},
		WorkerNamespace: assignment.GetWorkerNamespace(),
		WorkerPool:      assignment.GetWorkerPool(),
		WorkerPod:       assignment.GetWorkerPod(),
		WorkerPodUid:    assignment.GetWorkerPodUid(),
		NodeName:        assignment.GetNodeName(),
		Status:          &ateapipb.WorkerStatus{},
	}); err != nil {
		t.Fatalf("CreateWorker: %v", err)
	}
	seedWorkflowActor(t, ctx, persistence, actorRef, actorRef.Atespace, "tmpl1", ateapipb.ActorState_ACTOR_STATE_RUNNING, func(a *ateapipb.Actor) {
		a.Status.WorkerAssignment = assignment
		a.Status.AssignedNode = assignment.GetNodeName()
	})
	actor, err := persistence.GetActor(ctx, actorRef)
	if err != nil {
		t.Fatal(err)
	}
	seedAssignment(t, persistence, assignment.GetWorker().GetName(), &ateapipb.ActorAssignment{
		Actor:    &ateapipb.ObjectRef{Atespace: actorRef.Atespace, Name: actorRef.Name},
		ActorUid: actor.GetMetadata().GetUid(),
	})
}

// A suspend whose upload fails, with atelet keeping the snapshot on the node,
// walks through to the retry that succeeds: the actor is never crashed while
// its snapshot survives.
func TestSuspendActor_UploadFailureKeepsTheActorPausedOnItsNode(t *testing.T) {
	ctx := context.Background()
	persistence := newTestPersistence(t)
	w, fake := newWireCaptureWorkflow(t, persistence)
	actorRef := resources.ActorRef{Atespace: "team-a", Name: "actor-1"}
	seedRunningOnWireWorker(t, ctx, persistence, actorRef)

	// 1. The upload fails; atelet keeps the snapshot on the node.
	fake.setCheckpointKeptOnNode()
	_, err := w.SuspendActor(ctx, actorRef)
	if apierror.Code(err) != codes.Unavailable {
		t.Fatalf("SuspendActor = %v, want Unavailable", err)
	}
	paused, err := persistence.GetActor(ctx, actorRef)
	if err != nil {
		t.Fatal(err)
	}
	if got := paused.GetStatus().GetState(); got != ateapipb.ActorState_ACTOR_STATE_PAUSED {
		t.Fatalf("state = %v, want PAUSED", got)
	}
	if paused.GetStatus().GetWorkerAssignment() != nil {
		t.Errorf("worker assignment = %v, want the worker freed", paused.GetStatus().GetWorkerAssignment())
	}
	kept := snapshotAtLatestGeneration(paused.GetStatus())
	if kept.GetLocality() != "node-1" {
		t.Errorf("kept snapshot locality = %q, want node-1", kept.GetLocality())
	}
	if kept.GetFidelity() != ateapipb.SnapshotFidelity_SNAPSHOT_FIDELITY_MEMORY {
		t.Errorf("kept snapshot fidelity = %v, want the commit fidelity MEMORY", kept.GetFidelity())
	}
	keptURI := kept.GetDurableSnapshot().GetObject().GetSnapshotUri()
	if keptURI == "" || kept.GetDurableSnapshot().GetStatus() != ateapipb.SnapshotStorageStatus_SNAPSHOT_STORAGE_STATUS_PENDING {
		t.Errorf("kept snapshot durable = %v, want its pending URI kept for the next upload", kept.GetDurableSnapshot())
	}

	// 2. The retry's upload fails transiently: the suspend stays retryable.
	fake.setSuspendErrs(nil, status.Error(codes.Unavailable, "gcs: 503"))
	if _, err := w.SuspendActor(ctx, actorRef); apierror.Code(err) != codes.Unavailable {
		t.Fatalf("retried SuspendActor = %v, want Unavailable", err)
	}
	upload := fake.lastUploadPaused()
	if upload.GetDestinationSnapshotUri() != keptURI || upload.GetLocalSnapshotName() != kept.GetUuid() {
		t.Errorf("upload request = %v, want %s from local snapshot %s", upload, keptURI, kept.GetUuid())
	}

	// 3. It fails for a reason that is not transient (the snapshot is still on
	// the node): the actor returns to PAUSED rather than crashing.
	fake.setSuspendErrs(nil, status.Error(codes.Internal, "gcs: bad request"))
	if _, err := w.SuspendActor(ctx, actorRef); apierror.Code(err) != codes.Unavailable {
		t.Fatalf("SuspendActor after a hard upload failure = %v, want Unavailable", err)
	}
	stillPaused, err := persistence.GetActor(ctx, actorRef)
	if err != nil {
		t.Fatal(err)
	}
	if got := stillPaused.GetStatus().GetState(); got != ateapipb.ActorState_ACTOR_STATE_PAUSED {
		t.Fatalf("state after a hard upload failure = %v, want PAUSED", got)
	}
	if got := snapshotAtLatestGeneration(stillPaused.GetStatus()).GetDurableSnapshot().GetObject().GetSnapshotUri(); got != keptURI {
		t.Errorf("snapshot URI = %q, want %q kept for the next retry", got, keptURI)
	}

	// 4. The upload goes through: SUSPENDED on the kept location.
	fake.setSuspendErrs(nil, nil)
	suspended, err := w.SuspendActor(ctx, actorRef)
	if err != nil {
		t.Fatalf("SuspendActor: %v", err)
	}
	if got := suspended.GetStatus().GetState(); got != ateapipb.ActorState_ACTOR_STATE_SUSPENDED {
		t.Fatalf("state = %v, want SUSPENDED", got)
	}
	done := findLatestDurableSnapshot(suspended.GetStatus(), ateapipb.SnapshotStorageStatus_SNAPSHOT_STORAGE_STATUS_COMPLETED)
	if done.GetDurableSnapshot().GetObject().GetSnapshotUri() != keptURI {
		t.Errorf("completed snapshot = %v, want the kept location %q", done, keptURI)
	}
}

// A re-entered suspend whose snapshot was already recorded as kept on the node
// finishes pausing the actor instead of checkpointing a workload that is gone.
func TestSuspendActor_ReentryAfterKeptOnNodeDoesNotCheckpointAgain(t *testing.T) {
	ctx := context.Background()
	persistence := newTestPersistence(t)
	w, fake := newWireCaptureWorkflow(t, persistence)
	actorRef := resources.ActorRef{Atespace: "team-a", Name: "actor-1"}
	seedRunningOnWireWorker(t, ctx, persistence, actorRef)

	actor, tmpl, err := w.loadActorForSuspend(ctx, actorRef)
	if err != nil {
		t.Fatal(err)
	}
	marked, err := w.ensureMarkedSuspending(ctx, actorRef, actor, tmpl)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.recordSnapshotKeptOnNode(ctx, actorRef, marked); err != nil {
		t.Fatalf("recordSnapshotKeptOnNode: %v", err)
	}

	if _, err := w.SuspendActor(ctx, actorRef); apierror.Code(err) != codes.Unavailable {
		t.Fatalf("SuspendActor = %v, want Unavailable (PAUSED on the node)", err)
	}
	if fake.checkpointRequest() != nil {
		t.Error("atelet.Checkpoint was called for a workload that is gone")
	}
	got, err := persistence.GetActor(ctx, actorRef)
	if err != nil {
		t.Fatal(err)
	}
	if got.GetStatus().GetState() != ateapipb.ActorState_ACTOR_STATE_PAUSED {
		t.Errorf("state = %v, want PAUSED", got.GetStatus().GetState())
	}
}

// The one upload failure that crashes a paused actor is atelet reporting its
// snapshot gone.
func TestSuspendActor_PausedSnapshotGoneCrashes(t *testing.T) {
	ctx := context.Background()
	persistence := newTestPersistence(t)
	w, fake := newWireCaptureWorkflow(t, persistence)
	actorRef := resources.ActorRef{Atespace: "team-a", Name: "actor-1"}
	seedRunningOnWireWorker(t, ctx, persistence, actorRef)

	fake.setCheckpointKeptOnNode()
	if _, err := w.SuspendActor(ctx, actorRef); apierror.Code(err) != codes.Unavailable {
		t.Fatalf("SuspendActor = %v, want Unavailable", err)
	}
	fake.setSuspendErrs(nil, status.Error(codes.NotFound, "local snapshot is gone and no uploaded copy exists"))
	if _, err := w.SuspendActor(ctx, actorRef); err == nil {
		t.Fatal("SuspendActor succeeded, want an error")
	}
	got, err := persistence.GetActor(ctx, actorRef)
	if err != nil {
		t.Fatal(err)
	}
	if got.GetStatus().GetState() != ateapipb.ActorState_ACTOR_STATE_CRASHED {
		t.Errorf("state = %v, want CRASHED", got.GetStatus().GetState())
	}
}

// A Checkpoint that fails the ordinary way still crashes the actor unless the
// failure is transient: the kept-on-node answer is the only addition.
func TestSuspendActor_CheckpointFailureStillCrashesUnlessTransient(t *testing.T) {
	for _, tc := range []struct {
		name      string
		err       error
		wantState ateapipb.ActorState
	}{
		{"internal", status.Error(codes.Internal, "ateom: pause failed"), ateapipb.ActorState_ACTOR_STATE_CRASHED},
		{"unavailable", status.Error(codes.Unavailable, "atelet restarting"), ateapipb.ActorState_ACTOR_STATE_SUSPENDING},
		{"deadline exceeded", status.Error(codes.DeadlineExceeded, "slow"), ateapipb.ActorState_ACTOR_STATE_SUSPENDING},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			persistence := newTestPersistence(t)
			w, fake := newWireCaptureWorkflow(t, persistence)
			actorRef := resources.ActorRef{Atespace: "team-a", Name: "actor-1"}
			seedRunningOnWireWorker(t, ctx, persistence, actorRef)

			fake.setSuspendErrs(tc.err, nil)
			if _, err := w.SuspendActor(ctx, actorRef); err == nil {
				t.Fatal("SuspendActor succeeded, want the checkpoint failure")
			}
			got, err := persistence.GetActor(ctx, actorRef)
			if err != nil {
				t.Fatal(err)
			}
			if got.GetStatus().GetState() != tc.wantState {
				t.Errorf("state = %v, want %v", got.GetStatus().GetState(), tc.wantState)
			}
		})
	}
}
