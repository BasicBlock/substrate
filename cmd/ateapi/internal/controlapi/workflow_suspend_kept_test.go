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
	"errors"
	"testing"

	"github.com/agent-substrate/substrate/cmd/ateapi/internal/store"
	"github.com/agent-substrate/substrate/cmd/ateapi/internal/store/storetest"
	"github.com/agent-substrate/substrate/internal/atelet"
	"github.com/agent-substrate/substrate/internal/objectstore/objectstoretest"
	"github.com/agent-substrate/substrate/internal/proto/ateletpb"
	"github.com/agent-substrate/substrate/internal/resources"
	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func (f *capturingAtelet) Checkpoint(ctx context.Context, req *ateletpb.CheckpointRequest) (*ateletpb.CheckpointResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.checkpointErr != nil {
		return nil, f.checkpointErr
	}
	return &ateletpb.CheckpointResponse{}, nil
}

func (f *capturingAtelet) UploadPausedCheckpoint(ctx context.Context, req *ateletpb.UploadPausedCheckpointRequest) (*ateletpb.UploadPausedCheckpointResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.uploadPaused = proto.Clone(req).(*ateletpb.UploadPausedCheckpointRequest)
	if f.uploadPausedErr != nil {
		return nil, f.uploadPausedErr
	}
	return &ateletpb.UploadPausedCheckpointResponse{}, nil
}

func (f *capturingAtelet) setSuspendErrs(checkpointErr, uploadPausedErr error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.checkpointErr = checkpointErr
	f.uploadPausedErr = uploadPausedErr
}

func (f *capturingAtelet) lastUploadPaused() *ateletpb.UploadPausedCheckpointRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.uploadPaused
}

// seedRunningOnWireWorker stores a FULL-committing template and a RUNNING
// actor on the worker newWireCaptureWorkflow's fake atelet serves.
func seedRunningOnWireWorker(t *testing.T, ctx context.Context, persistence store.Interface, actorRef resources.ActorRef) {
	t.Helper()
	if _, err := persistence.CreateActorTemplate(ctx, &ateapipb.ActorTemplate{
		Metadata: &ateapipb.ResourceMetadata{Atespace: actorRef.Atespace, Name: "tmpl1"},
		SnapshotConfig: &ateapipb.SnapshotConfig{
			StorageLocation: testStorageLocation,
			OnCommit:        ateapipb.SnapshotContentScope_SNAPSHOT_CONTENT_SCOPE_FULL,
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

// TestSuspendActor_UploadFailureKeepsTheActorPausedOnItsNode walks a suspend
// whose upload fails through to the retry that succeeds: the actor must never
// be crashed while its snapshot survives on the node.
func TestSuspendActor_UploadFailureKeepsTheActorPausedOnItsNode(t *testing.T) {
	ctx := context.Background()
	persistence := newTestPersistence(t)
	w, fake := newWireCaptureWorkflow(t, persistence)
	actorRef := resources.ActorRef{Atespace: "team-a", Name: "actor-1"}
	seedRunningOnWireWorker(t, ctx, persistence, actorRef)

	// 1. The upload fails; atelet keeps the snapshot on the node.
	fake.setSuspendErrs(atelet.SnapshotKeptOnNodeError(errors.New("gcs: 503")), nil)
	_, err := w.SuspendActor(ctx, actorRef)
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("SuspendActor = %v, want Unavailable", err)
	}
	paused, err := persistence.GetActor(ctx, actorRef)
	if err != nil {
		t.Fatal(err)
	}
	if got := paused.GetStatus().GetState(); got != ateapipb.ActorState_ACTOR_STATE_PAUSED {
		t.Fatalf("state = %v, want PAUSED", got)
	}
	kept := mustParseSnapshotURI(t, paused.GetStatus().GetInProgressSnapshotUri())
	local := paused.GetStatus().GetLocalSnapshotInfo()
	if local.GetSnapshotName() != kept.Name() || len(local.GetNodeVmsWithLocalSnapshots()) != 1 || local.GetNodeVmsWithLocalSnapshots()[0] != "node-1" {
		t.Errorf("LocalSnapshotInfo = %v, want snapshot %q on node-1", local, kept.Name())
	}
	if got := local.GetContentScope(); got != ateapipb.SnapshotContentScope_SNAPSHOT_CONTENT_SCOPE_FULL {
		t.Errorf("LocalSnapshotInfo.ContentScope = %v, want the commit scope FULL", got)
	}
	if paused.GetStatus().GetWorkerAssignment() != nil || paused.GetStatus().GetInProgressLocalSnapshotName() != "" {
		t.Errorf("status = %v, want the worker freed and the in-progress local name cleared", paused.GetStatus())
	}

	// 2. The retry's upload fails too: the actor stays PAUSED, still pointing
	// at the same location.
	fake.setSuspendErrs(nil, status.Error(codes.Unavailable, "gcs: 503"))
	if _, err := w.SuspendActor(ctx, actorRef); status.Code(err) != codes.Unavailable {
		t.Fatalf("retried SuspendActor = %v, want Unavailable", err)
	}
	upload := fake.lastUploadPaused()
	if upload.GetDestinationSnapshotUri() != kept.String() || upload.GetLocalSnapshotName() != kept.Name() {
		t.Errorf("upload request = %v, want %s from local snapshot %s", upload, kept, kept.Name())
	}
	stillPaused, err := persistence.GetActor(ctx, actorRef)
	if err != nil {
		t.Fatal(err)
	}
	if got := stillPaused.GetStatus().GetState(); got != ateapipb.ActorState_ACTOR_STATE_PAUSED {
		t.Fatalf("state after a failed retry = %v, want PAUSED", got)
	}
	if got := stillPaused.GetStatus().GetInProgressSnapshotUri(); got != kept.String() {
		t.Errorf("InProgressSnapshotUri = %q, want %q kept for the next retry", got, kept)
	}

	// 3. The upload goes through: SUSPENDED on the kept location.
	fake.setSuspendErrs(nil, nil)
	suspended, err := w.SuspendActor(ctx, actorRef)
	if err != nil {
		t.Fatalf("SuspendActor: %v", err)
	}
	if got := suspended.GetStatus().GetState(); got != ateapipb.ActorState_ACTOR_STATE_SUSPENDED {
		t.Fatalf("state = %v, want SUSPENDED", got)
	}
	if got := suspended.GetStatus().GetExternalSnapshot().GetSnapshotUri(); got != kept.String() {
		t.Errorf("ExternalSnapshot = %q, want %q", got, kept)
	}
}

// TestSuspendActor_PausedSnapshotGoneCrashes pins the one upload failure a
// paused actor is crashed for: atelet reporting its snapshot gone.
func TestSuspendActor_PausedSnapshotGoneCrashes(t *testing.T) {
	ctx := context.Background()
	persistence := newTestPersistence(t)
	w, fake := newWireCaptureWorkflow(t, persistence)
	actorRef := resources.ActorRef{Atespace: "team-a", Name: "actor-1"}
	seedRunningOnWireWorker(t, ctx, persistence, actorRef)

	fake.setSuspendErrs(atelet.SnapshotKeptOnNodeError(errors.New("gcs: 503")), nil)
	if _, err := w.SuspendActor(ctx, actorRef); status.Code(err) != codes.Unavailable {
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

// TestEnsureAteletSuspended_CommittedSnapshotIsNotCrashed verifies a
// Checkpoint that fails after its manifest landed finishes the suspend, and
// one that fails before it still crashes the actor.
func TestEnsureAteletSuspended_CommittedSnapshotIsNotCrashed(t *testing.T) {
	for _, tc := range []struct {
		name      string
		committed bool
		wantState ateapipb.ActorState
	}{
		{"manifest committed", true, ateapipb.ActorState_ACTOR_STATE_SUSPENDING},
		{"manifest missing", false, ateapipb.ActorState_ACTOR_STATE_CRASHED},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			persistence := newTestPersistence(t)
			w, fake := newWireCaptureWorkflow(t, persistence)
			objects := objectstoretest.New()
			w.objectStore = objects
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
			uri := mustParseSnapshotURI(t, marked.GetStatus().GetInProgressSnapshotUri())
			if tc.committed {
				objects.PutSnapshot(t, uri, "checkpoint.img.zstd", atelet.SnapshotManifestName)
			} else {
				objects.PutSnapshot(t, uri, "checkpoint.img.zstd")
			}
			fake.setSuspendErrs(status.Error(codes.Internal, "while resetting actor dirs: permission denied"), nil)

			_, err = w.ensureAteletSuspended(ctx, actorRef, marked, tmpl)
			if tc.committed && err != nil {
				t.Errorf("ensureAteletSuspended = %v, want the committed snapshot to finish the suspend", err)
			}
			if !tc.committed && err == nil {
				t.Error("ensureAteletSuspended succeeded without a committed snapshot")
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

// TestSuspendActor_PausedUploadCommittedBeforeFailing verifies a paused
// upload that failed after its manifest landed suspends the actor: atelet has
// pruned the local copy, so returning the actor to PAUSED would strand it.
func TestSuspendActor_PausedUploadCommittedBeforeFailing(t *testing.T) {
	ctx := context.Background()
	persistence := newTestPersistence(t)
	w, fake := newWireCaptureWorkflow(t, persistence)
	objects := objectstoretest.New()
	w.objectStore = objects
	actorRef := resources.ActorRef{Atespace: "team-a", Name: "actor-1"}
	seedRunningOnWireWorker(t, ctx, persistence, actorRef)

	fake.setSuspendErrs(atelet.SnapshotKeptOnNodeError(errors.New("gcs: 503")), nil)
	if _, err := w.SuspendActor(ctx, actorRef); status.Code(err) != codes.Unavailable {
		t.Fatalf("SuspendActor = %v, want Unavailable", err)
	}
	paused, err := persistence.GetActor(ctx, actorRef)
	if err != nil {
		t.Fatal(err)
	}
	kept := mustParseSnapshotURI(t, paused.GetStatus().GetInProgressSnapshotUri())

	objects.PutSnapshot(t, kept, "checkpoint.img.zstd", atelet.SnapshotManifestName)
	fake.setSuspendErrs(nil, status.Error(codes.DeadlineExceeded, "reply lost"))
	suspended, err := w.SuspendActor(ctx, actorRef)
	if err != nil {
		t.Fatalf("SuspendActor: %v", err)
	}
	if got := suspended.GetStatus().GetState(); got != ateapipb.ActorState_ACTOR_STATE_SUSPENDED {
		t.Fatalf("state = %v, want SUSPENDED", got)
	}
	if got := suspended.GetStatus().GetExternalSnapshot().GetSnapshotUri(); got != kept.String() {
		t.Errorf("ExternalSnapshot = %q, want %q", got, kept)
	}
}

func (f *capturingAtelet) ReclaimActor(ctx context.Context, req *ateletpb.ReclaimActorRequest) (*ateletpb.ReclaimActorResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reclaimed = append(f.reclaimed, req.GetActorUid())
	if f.reclaimErr != nil {
		return nil, f.reclaimErr
	}
	return &ateletpb.ReclaimActorResponse{}, nil
}

// TestDeleteReclaimsAPausedActorsLocalSnapshot verifies deleting a paused
// actor has the atelet on its snapshot's node reclaim it (#664), that a node
// which is gone, or an atelet predating ReclaimActor, does not block the
// delete, and that another failure does.
func TestDeleteReclaimsAPausedActorsLocalSnapshot(t *testing.T) {
	for _, tc := range []struct {
		name        string
		node        string
		reclaimErr  error
		wantCalled  bool
		wantFailure bool
	}{
		{"reclaimed", "node-1", nil, true, false},
		{"node gone", "node-gone", nil, false, false},
		{"atelet predates ReclaimActor", "node-1", status.Error(codes.Unimplemented, "unknown method"), true, false},
		{"atelet refuses", "node-1", status.Error(codes.FailedPrecondition, "a workload runs"), true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			persistence := newTestPersistence(t)
			w, fake := newWireCaptureWorkflow(t, persistence)
			fake.reclaimErr = tc.reclaimErr
			actor := storetest.MustCreateActor(t, ctx, persistence, &ateapipb.Actor{
				Metadata: &ateapipb.ResourceMetadata{Atespace: "team-a", Name: "paused-1"},
				Status: &ateapipb.ActorStatus{
					State:             ateapipb.ActorState_ACTOR_STATE_PAUSED,
					LocalSnapshotInfo: &ateapipb.LocalSnapshotInfo{SnapshotName: "snap-1", NodeVmsWithLocalSnapshots: []string{tc.node}},
				},
			})

			err := w.ensureLocalSnapshotsReclaimed(ctx, resources.ActorRef{Atespace: "team-a", Name: "paused-1"}, actor)
			if (err != nil) != tc.wantFailure {
				t.Errorf("ensureLocalSnapshotsReclaimed = %v, want failure %v", err, tc.wantFailure)
			}
			fake.mu.Lock()
			called := len(fake.reclaimed) == 1 && fake.reclaimed[0] == actor.GetMetadata().GetUid()
			fake.mu.Unlock()
			if called != tc.wantCalled {
				t.Errorf("reclaimed %v, want called %v", fake.reclaimed, tc.wantCalled)
			}
		})
	}
}
