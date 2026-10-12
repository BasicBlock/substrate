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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agent-substrate/substrate/cmd/ateapi/internal/store"
	"github.com/agent-substrate/substrate/cmd/ateapi/internal/store/storetest"
	"github.com/agent-substrate/substrate/internal/apierror"
	"github.com/agent-substrate/substrate/internal/ateattr"
	"github.com/agent-substrate/substrate/internal/objectstore/objectstoretest"
	"github.com/agent-substrate/substrate/internal/objectstoreplugin/objectstoreplugintest"
	"github.com/agent-substrate/substrate/internal/proto/ateletpb"
	"github.com/agent-substrate/substrate/internal/resources"
	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// redriveAtelet is an atelet whose calls succeed unless a test makes one fail,
// and which counts the calls it gets.
type redriveAtelet struct {
	ateletpb.UnimplementedAteomHerderServer

	mu             sync.Mutex
	errs           map[string]error
	calls          map[string]int
	lastCheckpoint *ateletpb.CheckpointRequest
	// keptOnNode makes Checkpoint answer that its upload failed and the
	// snapshot was kept on the node.
	keptOnNode bool
}

func newRedriveAtelet() *redriveAtelet {
	return &redriveAtelet{errs: map[string]error{}, calls: map[string]int{}}
}

// fail makes every later call of rpc return err, until it is called again with
// nil.
func (f *redriveAtelet) fail(rpc string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.errs[rpc] = err
}

// keepSnapshotsOnNode makes every later Checkpoint report that the snapshot
// could not be uploaded and was kept on the node, until it is called again with
// false.
func (f *redriveAtelet) keepSnapshotsOnNode(keep bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.keptOnNode = keep
}

// count is the number of calls rpc has had.
func (f *redriveAtelet) count(rpc string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[rpc]
}

func (f *redriveAtelet) serve(rpc string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls[rpc]++
	return f.errs[rpc]
}

func (f *redriveAtelet) Checkpoint(_ context.Context, req *ateletpb.CheckpointRequest) (*ateletpb.CheckpointResponse, error) {
	f.mu.Lock()
	f.lastCheckpoint = proto.Clone(req).(*ateletpb.CheckpointRequest)
	keptOnNode := f.keptOnNode
	f.mu.Unlock()
	if err := f.serve("Checkpoint"); err != nil {
		return nil, err
	}
	return &ateletpb.CheckpointResponse{SnapshotKeptOnNode: keptOnNode}, nil
}

func (f *redriveAtelet) UploadPausedCheckpoint(context.Context, *ateletpb.UploadPausedCheckpointRequest) (*ateletpb.UploadPausedCheckpointResponse, error) {
	if err := f.serve("UploadPausedCheckpoint"); err != nil {
		return nil, err
	}
	return &ateletpb.UploadPausedCheckpointResponse{}, nil
}

func (f *redriveAtelet) Terminate(context.Context, *ateletpb.TerminateRequest) (*ateletpb.TerminateResponse, error) {
	if err := f.serve("Terminate"); err != nil {
		return nil, err
	}
	return &ateletpb.TerminateResponse{}, nil
}

// redriveFixture is a control plane whose atelet is a redriveAtelet, with one
// worker that the actors it seeds run on.
type redriveFixture struct {
	t      *testing.T
	ctx    context.Context
	store  store.Interface
	w      *ActorWorkflow
	atelet *redriveAtelet
}

const redriveWorkerName = "worker-1"

func newRedriveFixture(t *testing.T) *redriveFixture {
	t.Helper()
	ctx := context.Background()
	persistence := newTestPersistence(t)
	atelet := newRedriveAtelet()
	w := newAteletBackedWorkflow(t, persistence, atelet)
	w.objectStorePlugin = objectstoreplugintest.ControlClient(objectstoretest.New())

	storetest.MustCreateAtespace(t, ctx, persistence, "ns")
	if _, err := persistence.CreateActorTemplate(ctx, &ateapipb.ActorTemplate{
		Metadata:       &ateapipb.ResourceMetadata{Atespace: "ns", Name: "tmpl1"},
		SnapshotConfig: &ateapipb.SnapshotConfig{StorageLocation: testStorageLocation},
		SandboxConfig:  &ateapipb.SandboxConfig{SandboxClass: ateapipb.SandboxClass_SANDBOX_CLASS_GVISOR, ConfigName: "gvisor"},
	}); err != nil {
		t.Fatalf("create template: %v", err)
	}
	assignment := wireTestAssignment()
	if _, err := persistence.CreateWorker(ctx, &ateapipb.Worker{
		Metadata:        &ateapipb.ResourceMetadata{Name: redriveWorkerName},
		WorkerNamespace: assignment.GetWorkerNamespace(),
		WorkerPool:      assignment.GetWorkerPool(),
		WorkerPod:       assignment.GetWorkerPod(),
		WorkerPodUid:    assignment.GetWorkerPodUid(),
		Status:          &ateapipb.WorkerStatus{},
	}); err != nil {
		t.Fatalf("create worker: %v", err)
	}
	return &redriveFixture{t: t, ctx: ctx, store: persistence, w: w, atelet: atelet}
}

// seedRunning stores an actor that is RUNNING on the fixture's worker.
func (f *redriveFixture) seedRunning(name string) resources.ActorRef {
	f.t.Helper()
	ref := resources.ActorRef{Atespace: "team-a", Name: name}
	created := storetest.MustCreateActor(f.t, f.ctx, f.store, &ateapipb.Actor{
		Metadata:      &ateapipb.ResourceMetadata{Atespace: ref.Atespace, Name: ref.Name},
		ActorTemplate: &ateapipb.ObjectRef{Atespace: "ns", Name: "tmpl1"},
		Status: &ateapipb.ActorStatus{
			State:            ateapipb.ActorState_ACTOR_STATE_RUNNING,
			AssignedNode:     wireTestAssignment().GetNodeName(),
			WorkerAssignment: wireTestAssignment(),
		},
	})
	seedAssignment(f.t, f.store, redriveWorkerName, &ateapipb.ActorAssignment{
		Actor:    &ateapipb.ObjectRef{Atespace: ref.Atespace, Name: ref.Name},
		ActorUid: created.GetMetadata().GetUid(),
	})
	return ref
}

func (f *redriveFixture) get(ref resources.ActorRef) *ateapipb.Actor {
	f.t.Helper()
	actor, err := f.store.GetActor(f.ctx, ref)
	if err != nil {
		f.t.Fatalf("GetActor(%s): %v", ref, err)
	}
	return actor
}

// strand runs op against atelet failing rpc with Unavailable, which a workflow
// answers by returning with the actor left in its transitional state, as it
// is when the process running it goes away at that point. It returns the
// actor as that left it, and fails the test unless it is in want.
func (f *redriveFixture) strand(ref resources.ActorRef, rpc string, want ateapipb.ActorState, op func() error) *ateapipb.Actor {
	f.t.Helper()
	f.atelet.fail(rpc, status.Error(codes.Unavailable, "atelet is going away"))
	defer f.atelet.fail(rpc, nil)
	if err := op(); err == nil {
		f.t.Fatalf("the operation succeeded although atelet failed %s", rpc)
	}
	actor := f.get(ref)
	if got := actor.GetStatus().GetState(); got != want {
		f.t.Fatalf("state after the interrupted operation = %v, want %v", got, want)
	}
	return actor
}

func (f *redriveFixture) strandSuspend(ref resources.ActorRef) *ateapipb.Actor {
	f.t.Helper()
	return f.strand(ref, "Checkpoint", ateapipb.ActorState_ACTOR_STATE_SUSPENDING, func() error {
		_, err := f.w.SuspendActor(f.ctx, ref)
		return err
	})
}

func (f *redriveFixture) redrive(observed *ateapipb.Actor, notUpdatedSince time.Time) (RedriveResult, error) {
	f.t.Helper()
	return f.w.RedriveActor(f.ctx, observed, notUpdatedSince)
}

// Cutoffs for notUpdatedSince: every record written so far has gone quiet, or
// none has.
func allQuiet() time.Time  { return time.Now().Add(time.Hour) }
func noneQuiet() time.Time { return time.Now().Add(-time.Hour) }

func assertRedrive(t *testing.T, got RedriveResult, err error, wantOp, wantOutcome string) {
	t.Helper()
	if err != nil {
		t.Fatalf("RedriveActor: %v", err)
	}
	if got.Operation != wantOp || got.Outcome != wantOutcome {
		t.Fatalf("RedriveActor = %+v, want operation %q outcome %q", got, wantOp, wantOutcome)
	}
}

// TestRedriveActor_FinishesAStrandedSuspend is the incident: a suspend is cut
// off after the actor is marked SUSPENDING, and the actor stays there until a
// re-drive runs the workflow again.
func TestRedriveActor_FinishesAStrandedSuspend(t *testing.T) {
	f := newRedriveFixture(t)
	ref := f.seedRunning("id1")
	stranded := f.strandSuspend(ref)
	inProgress := snapshotAtLatestGeneration(stranded.GetStatus()).GetDurableSnapshot().GetObject().GetSnapshotUri()
	if inProgress == "" {
		t.Fatal("the interrupted suspend recorded no in-progress snapshot")
	}

	result, err := f.redrive(stranded, allQuiet())
	assertRedrive(t, result, err, ateattr.OperationSuspend, ateattr.RedriveOutcomeCompleted)

	got := f.get(ref)
	if got.GetStatus().GetState() != ateapipb.ActorState_ACTOR_STATE_SUSPENDED {
		t.Errorf("state = %v, want SUSPENDED", got.GetStatus().GetState())
	}
	if got.GetStatus().GetWorkerAssignment() != nil {
		t.Errorf("the worker assignment was not cleared: %v", got.GetStatus().GetWorkerAssignment())
	}
	if _, err := f.store.FindWorkerHostingActor(f.ctx, got.GetMetadata().GetUid()); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("the worker still hosts the actor (FindWorkerHostingActor err = %v)", err)
	}
	// The re-entered workflow checkpoints to the location the first attempt
	// minted, and commits that snapshot.
	if got := f.atelet.lastCheckpoint.GetExternalConfig().GetSnapshotUri(); got != inProgress {
		t.Errorf("re-driven Checkpoint wrote to %q, want the recorded location %q", got, inProgress)
	}
	committed := findLatestDurableSnapshot(got.GetStatus(), ateapipb.SnapshotStorageStatus_SNAPSHOT_STORAGE_STATUS_COMPLETED)
	if committed.GetDurableSnapshot().GetObject().GetSnapshotUri() != inProgress {
		t.Errorf("committed snapshot = %v, want %q", committed, inProgress)
	}
}

// TestRedriveActor_LeavesAYoungActorAlone: a record written inside the minimum
// age may have a workflow advancing it, so nothing runs.
func TestRedriveActor_LeavesAYoungActorAlone(t *testing.T) {
	f := newRedriveFixture(t)
	ref := f.seedRunning("id1")
	stranded := f.strandSuspend(ref)
	checkpoints := f.atelet.count("Checkpoint")

	result, err := f.redrive(stranded, noneQuiet())
	assertRedrive(t, result, err, ateattr.OperationSuspend, ateattr.RedriveOutcomeSettled)

	if got := f.atelet.count("Checkpoint"); got != checkpoints {
		t.Errorf("atelet Checkpoint calls = %d, want %d: a young actor must not be touched", got, checkpoints)
	}
	if got := f.get(ref).GetStatus().GetState(); got != ateapipb.ActorState_ACTOR_STATE_SUSPENDING {
		t.Errorf("state = %v, want it left SUSPENDING", got)
	}
}

// TestRedriveActor_LeavesAnActorWithALiveWorkflowAlone: the lease is what
// tells a workflow that is running from one that stopped.
func TestRedriveActor_LeavesAnActorWithALiveWorkflowAlone(t *testing.T) {
	f := newRedriveFixture(t)
	ref := f.seedRunning("id1")
	stranded := f.strandSuspend(ref)
	checkpoints := f.atelet.count("Checkpoint")

	lease, err := f.store.AcquireLease(f.ctx, actorLeaseKey(ref))
	if err != nil {
		t.Fatalf("AcquireLease: %v", err)
	}
	result, err := f.redrive(stranded, allQuiet())
	assertRedrive(t, result, err, ateattr.OperationSuspend, ateattr.RedriveOutcomeBusy)
	if got := f.atelet.count("Checkpoint"); got != checkpoints {
		t.Errorf("atelet Checkpoint calls = %d, want %d: an actor under a live lease must not be touched", got, checkpoints)
	}
	if got := f.get(ref).GetStatus().GetState(); got != ateapipb.ActorState_ACTOR_STATE_SUSPENDING {
		t.Errorf("state = %v, want it left SUSPENDING", got)
	}

	// Once that workflow is gone, the same actor is finished.
	lease.Close()
	result, err = f.redrive(stranded, allQuiet())
	assertRedrive(t, result, err, ateattr.OperationSuspend, ateattr.RedriveOutcomeCompleted)
}

// TestRedriveActor_CrashesAnActorWhoseWorkloadIsGone: a first attempt that took
// the checkpoint and stopped before committing it leaves a workload atelet's
// Checkpoint cannot checkpoint again. The re-drive crashes the actor, as any
// failed Checkpoint does, and does not try again: the actor is out of the state
// the sweep looks for, and its owner can revert it.
func TestRedriveActor_CrashesAnActorWhoseWorkloadIsGone(t *testing.T) {
	f := newRedriveFixture(t)
	ref := f.seedRunning("id1")
	stranded := f.strandSuspend(ref)
	f.atelet.fail("Checkpoint", status.Error(codes.Unknown, "while calling ateom.CheckpointWorkload: while checkpointing pause: while running `runsc checkpoint`: exit status 128"))
	checkpoints := f.atelet.count("Checkpoint")

	result, err := f.redrive(stranded, allQuiet())
	assertRedrive(t, result, err, ateattr.OperationSuspend, ateattr.RedriveOutcomeCrashed)

	got := f.get(ref)
	if got.GetStatus().GetState() != ateapipb.ActorState_ACTOR_STATE_CRASHED {
		t.Fatalf("state = %v, want CRASHED", got.GetStatus().GetState())
	}
	if msg := got.GetStatus().GetCrash().GetMessage(); !strings.HasPrefix(msg, "suspend failed: atelet Checkpoint:") {
		t.Errorf("crash message = %q, want it to name the failed Checkpoint", msg)
	}
	if got.GetStatus().GetWorkerAssignment() != nil {
		t.Errorf("the crashed actor still holds its worker: %v", got.GetStatus().GetWorkerAssignment())
	}

	// A second look finds nothing to do, and calls nothing.
	result, err = f.redrive(stranded, allQuiet())
	assertRedrive(t, result, err, ateattr.OperationSuspend, ateattr.RedriveOutcomeSettled)
	if got := f.atelet.count("Checkpoint"); got != checkpoints+1 {
		t.Errorf("atelet Checkpoint calls = %d, want %d: the crashed actor must not be re-driven again", got, checkpoints+1)
	}

	// The owner recovers the actor.
	f.atelet.fail("Checkpoint", nil)
	if _, err := f.w.RevertActor(f.ctx, ref); err != nil {
		t.Fatalf("RevertActor: %v", err)
	}
	if got := f.get(ref).GetStatus().GetState(); got != ateapipb.ActorState_ACTOR_STATE_SUSPENDED {
		t.Errorf("state after revert = %v, want SUSPENDED", got)
	}
}

// TestRedriveActor_ReportsAFailureThatStaysRetryable: an error that says nothing
// about the workload, here atelet being unreachable, leaves the actor as it
// was and is returned for the caller to retry later.
func TestRedriveActor_ReportsAFailureThatStaysRetryable(t *testing.T) {
	f := newRedriveFixture(t)
	ref := f.seedRunning("id1")
	stranded := f.strandSuspend(ref)
	f.atelet.fail("Checkpoint", status.Error(codes.Unavailable, "atelet is restarting"))

	result, err := f.redrive(stranded, allQuiet())
	if err == nil {
		t.Fatal("RedriveActor succeeded although atelet is unavailable")
	}
	if result.Outcome != ateattr.RedriveOutcomeFailed {
		t.Errorf("outcome = %q, want %q", result.Outcome, ateattr.RedriveOutcomeFailed)
	}
	got := f.get(ref)
	if got.GetStatus().GetState() != ateapipb.ActorState_ACTOR_STATE_SUSPENDING || got.GetStatus().GetWorkerAssignment() == nil {
		t.Errorf("the actor must stay SUSPENDING on its worker for the retry, got %v with %v", got.GetStatus().GetState(), got.GetStatus().GetWorkerAssignment())
	}

	// Atelet recovers, and the next re-drive finishes it.
	f.atelet.fail("Checkpoint", nil)
	result, err = f.redrive(stranded, allQuiet())
	assertRedrive(t, result, err, ateattr.OperationSuspend, ateattr.RedriveOutcomeCompleted)
}

// TestRedriveActor_TreatsTransientAteletFailuresAsRetryable: a re-drive handles
// an atelet failure as the RPC's workflow does. Unavailable, Canceled and
// DeadlineExceeded say nothing about the workload, so the actor stays
// SUSPENDING on its worker for the retry; any other code crashes it.
func TestRedriveActor_TreatsTransientAteletFailuresAsRetryable(t *testing.T) {
	for _, tc := range []struct {
		code      codes.Code
		wantState ateapipb.ActorState
		wantOut   string
	}{
		{codes.Unavailable, ateapipb.ActorState_ACTOR_STATE_SUSPENDING, ateattr.RedriveOutcomeFailed},
		{codes.Canceled, ateapipb.ActorState_ACTOR_STATE_SUSPENDING, ateattr.RedriveOutcomeFailed},
		{codes.DeadlineExceeded, ateapipb.ActorState_ACTOR_STATE_SUSPENDING, ateattr.RedriveOutcomeFailed},
		{codes.Internal, ateapipb.ActorState_ACTOR_STATE_CRASHED, ateattr.RedriveOutcomeCrashed},
	} {
		t.Run(tc.code.String(), func(t *testing.T) {
			f := newRedriveFixture(t)
			ref := f.seedRunning("id1")
			stranded := f.strandSuspend(ref)
			f.atelet.fail("Checkpoint", status.Error(tc.code, "atelet said so"))

			result, err := f.redrive(stranded, allQuiet())
			if result.Outcome != tc.wantOut {
				t.Errorf("outcome = %q, want %q (err = %v)", result.Outcome, tc.wantOut, err)
			}
			if (err != nil) != (tc.wantOut == ateattr.RedriveOutcomeFailed) {
				t.Errorf("RedriveActor error = %v, want one only for a failure to retry", err)
			}
			got := f.get(ref)
			if got.GetStatus().GetState() != tc.wantState {
				t.Errorf("state = %v, want %v", got.GetStatus().GetState(), tc.wantState)
			}
			if tc.wantState == ateapipb.ActorState_ACTOR_STATE_SUSPENDING && got.GetStatus().GetWorkerAssignment() == nil {
				t.Error("the actor lost its worker, which the retry needs")
			}
		})
	}
}

// TestRedriveActor_PausesAnActorWhoseSnapshotAteletKeptOnTheNode: a suspend
// whose upload fails leaves the snapshot on the node, and the actor is paused
// on it rather than crashed, as it is when the suspend RPC runs the workflow.
// The re-drive has no caller to hand the Unavailable to, so it reports it as
// the failure it is; the actor has left SUSPENDING, so the next look finds
// nothing to finish.
func TestRedriveActor_PausesAnActorWhoseSnapshotAteletKeptOnTheNode(t *testing.T) {
	f := newRedriveFixture(t)
	ref := f.seedRunning("id1")
	stranded := f.strandSuspend(ref)
	f.atelet.keepSnapshotsOnNode(true)
	checkpoints := f.atelet.count("Checkpoint")

	result, err := f.redrive(stranded, allQuiet())
	if apierror.Code(err) != codes.Unavailable {
		t.Fatalf("RedriveActor error = %v, want Unavailable: the actor is paused with its upload undone", err)
	}
	if result.Operation != ateattr.OperationSuspend || result.Outcome != ateattr.RedriveOutcomeFailed {
		t.Errorf("RedriveActor = %+v, want the suspend reported as failed", result)
	}

	node := wireTestAssignment().GetNodeName()
	got := f.get(ref)
	if got.GetStatus().GetState() != ateapipb.ActorState_ACTOR_STATE_PAUSED {
		t.Fatalf("state = %v, want PAUSED on the node holding the snapshot", got.GetStatus().GetState())
	}
	if got.GetStatus().GetWorkerAssignment() != nil {
		t.Errorf("the paused actor still holds its worker: %v", got.GetStatus().GetWorkerAssignment())
	}
	if kept := snapshotAtLatestGeneration(got.GetStatus()); kept.GetLocality() != node || got.GetStatus().GetAssignedNode() != node {
		t.Errorf("kept snapshot locality = %q, assigned node = %q, want both %q", kept.GetLocality(), got.GetStatus().GetAssignedNode(), node)
	}
	if got := f.atelet.count("Checkpoint"); got != checkpoints+1 {
		t.Errorf("atelet Checkpoint calls = %d, want %d", got, checkpoints+1)
	}

	result, err = f.redrive(stranded, allQuiet())
	assertRedrive(t, result, err, ateattr.OperationSuspend, ateattr.RedriveOutcomeSettled)
	if got := f.atelet.count("Checkpoint"); got != checkpoints+1 {
		t.Errorf("atelet Checkpoint calls = %d, want %d: a paused actor must not be checkpointed", got, checkpoints+1)
	}
}

// TestRedriveActor_DoesNotCheckpointAgainAfterTheKeptSnapshotWasRecorded: an
// ate-api that went away after recording where atelet kept the snapshot, and
// before pausing the actor on it, leaves a workload that is gone. The re-drive
// pauses the actor instead of calling Checkpoint, which would crash it.
func TestRedriveActor_DoesNotCheckpointAgainAfterTheKeptSnapshotWasRecorded(t *testing.T) {
	f := newRedriveFixture(t)
	ref := f.seedRunning("id1")
	stranded := f.strandSuspend(ref)
	if err := f.w.recordSnapshotKeptOnNode(f.ctx, ref, stranded); err != nil {
		t.Fatalf("recordSnapshotKeptOnNode: %v", err)
	}
	checkpoints := f.atelet.count("Checkpoint")

	result, err := f.redrive(f.get(ref), allQuiet())
	if apierror.Code(err) != codes.Unavailable || result.Outcome != ateattr.RedriveOutcomeFailed {
		t.Fatalf("RedriveActor = %+v, %v, want the Unavailable a suspend ends with when its actor is paused on the node", result, err)
	}

	if got := f.get(ref).GetStatus().GetState(); got != ateapipb.ActorState_ACTOR_STATE_PAUSED {
		t.Errorf("state = %v, want PAUSED", got)
	}
	if got := f.atelet.count("Checkpoint"); got != checkpoints {
		t.Errorf("atelet Checkpoint calls = %d, want %d: the workload is gone", got, checkpoints)
	}
}

// TestRedriveActor_ReturnsAPausedActorToPausedWhenItsUploadFails: a stranded
// suspend of a paused actor uploads the snapshot on the node. Where upstream
// crashes the actor for any failure but a transient one, the snapshot is still
// on the node, so an upload that fails hard returns the actor to PAUSED for the
// next suspend to retry; only atelet reporting the snapshot gone crashes it.
func TestRedriveActor_ReturnsAPausedActorToPausedWhenItsUploadFails(t *testing.T) {
	for _, tc := range []struct {
		name      string
		err       error
		wantState ateapipb.ActorState
		wantOut   string
		wantErr   bool
	}{
		{"hard failure", status.Error(codes.Internal, "gcs: bad request"), ateapipb.ActorState_ACTOR_STATE_PAUSED, ateattr.RedriveOutcomeFailed, true},
		{"snapshot gone", status.Error(codes.NotFound, "local snapshot is gone and no uploaded copy exists"), ateapipb.ActorState_ACTOR_STATE_CRASHED, ateattr.RedriveOutcomeCrashed, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRedriveFixture(t)
			ref := f.seedRunning("id1")
			if _, err := f.w.PauseActor(f.ctx, ref); err != nil {
				t.Fatalf("PauseActor: %v", err)
			}
			stranded := f.strand(ref, "UploadPausedCheckpoint", ateapipb.ActorState_ACTOR_STATE_SUSPENDING, func() error {
				_, err := f.w.SuspendActor(f.ctx, ref)
				return err
			})
			f.atelet.fail("UploadPausedCheckpoint", tc.err)

			result, err := f.redrive(stranded, allQuiet())
			if result.Operation != ateattr.OperationSuspend || result.Outcome != tc.wantOut || (err != nil) != tc.wantErr {
				t.Errorf("RedriveActor = %+v, %v, want the suspend with outcome %q (error: %v)", result, err, tc.wantOut, tc.wantErr)
			}
			if got := f.get(ref).GetStatus().GetState(); got != tc.wantState {
				t.Errorf("state = %v, want %v", got, tc.wantState)
			}
		})
	}
}

// TestRedriveActor_ChecksTheActorAgainUnderTheLease: a decision made on an
// earlier look must not act on an actor that moved on since, or on a successor
// of the same name.
func TestRedriveActor_ChecksTheActorAgainUnderTheLease(t *testing.T) {
	f := newRedriveFixture(t)
	ref := f.seedRunning("id1")
	stale := f.strandSuspend(ref)

	// The owner's own retry finishes the suspend and resumes the actor.
	if _, err := f.w.SuspendActor(f.ctx, ref); err != nil {
		t.Fatalf("SuspendActor: %v", err)
	}
	f.seedRunningOver(ref)
	checkpoints := f.atelet.count("Checkpoint")

	result, err := f.redrive(stale, allQuiet())
	assertRedrive(t, result, err, ateattr.OperationSuspend, ateattr.RedriveOutcomeSettled)
	if got := f.get(ref).GetStatus().GetState(); got != ateapipb.ActorState_ACTOR_STATE_RUNNING {
		t.Errorf("state = %v: a stale re-drive suspended an actor that was running again", got)
	}
	if got := f.atelet.count("Checkpoint"); got != checkpoints {
		t.Errorf("atelet Checkpoint calls = %d, want %d", got, checkpoints)
	}

	// A successor with the same name and a new uid is not what was observed.
	if _, err := f.store.DeleteActor(f.ctx, ref, store.DeletePreconditions{}); err != nil {
		t.Fatalf("DeleteActor: %v", err)
	}
	successor := f.seedRunning("id1")
	f.strandSuspend(successor)
	result, err = f.redrive(stale, allQuiet())
	assertRedrive(t, result, err, ateattr.OperationSuspend, ateattr.RedriveOutcomeSettled)
	if got := f.get(ref).GetStatus().GetState(); got != ateapipb.ActorState_ACTOR_STATE_SUSPENDING {
		t.Errorf("state = %v: a re-drive observed on a previous incarnation acted on its successor", got)
	}

	// An actor that is gone is settled too.
	if _, err := f.store.DeleteActor(f.ctx, ref, store.DeletePreconditions{}); err != nil {
		t.Fatalf("DeleteActor: %v", err)
	}
	result, err = f.redrive(stale, allQuiet())
	assertRedrive(t, result, err, ateattr.OperationSuspend, ateattr.RedriveOutcomeSettled)
}

// seedRunningOver puts the stored actor ref back to RUNNING on the worker, as a
// resume that followed the suspend would.
func (f *redriveFixture) seedRunningOver(ref resources.ActorRef) {
	f.t.Helper()
	mustUpdateActorStatus(f.t, f.ctx, f.store, f.get(ref), func(status *ateapipb.ActorStatus) {
		status.State = ateapipb.ActorState_ACTOR_STATE_RUNNING
		status.AssignedNode = wireTestAssignment().GetNodeName()
		status.WorkerAssignment = wireTestAssignment()
	})
}

// TestRedriveActor_FinishesEachOperation covers the other operations a
// re-drive finishes.
func TestRedriveActor_FinishesEachOperation(t *testing.T) {
	tests := []struct {
		name        string
		wantOp      string
		wantRPC     string
		wantState   ateapipb.ActorState
		wantDeleted bool
		// strand leaves the actor in the middle of the operation, and returns
		// it as the interruption left it.
		strand func(f *redriveFixture, ref resources.ActorRef) *ateapipb.Actor
	}{
		{
			name:      "pause",
			wantOp:    ateattr.OperationPause,
			wantRPC:   "Checkpoint",
			wantState: ateapipb.ActorState_ACTOR_STATE_PAUSED,
			strand: func(f *redriveFixture, ref resources.ActorRef) *ateapipb.Actor {
				return f.strand(ref, "Checkpoint", ateapipb.ActorState_ACTOR_STATE_PAUSING, func() error {
					_, err := f.w.PauseActor(f.ctx, ref)
					return err
				})
			},
		},
		{
			// A suspend of a paused actor uploads the snapshot on its node
			// instead of checkpointing a workload.
			name:      "suspend of a paused actor",
			wantOp:    ateattr.OperationSuspend,
			wantRPC:   "UploadPausedCheckpoint",
			wantState: ateapipb.ActorState_ACTOR_STATE_SUSPENDED,
			strand: func(f *redriveFixture, ref resources.ActorRef) *ateapipb.Actor {
				if _, err := f.w.PauseActor(f.ctx, ref); err != nil {
					f.t.Fatalf("PauseActor: %v", err)
				}
				return f.strand(ref, "UploadPausedCheckpoint", ateapipb.ActorState_ACTOR_STATE_SUSPENDING, func() error {
					_, err := f.w.SuspendActor(f.ctx, ref)
					return err
				})
			},
		},
		{
			name:      "revert",
			wantOp:    ateattr.OperationRevert,
			wantRPC:   "Terminate",
			wantState: ateapipb.ActorState_ACTOR_STATE_SUSPENDED,
			strand: func(f *redriveFixture, ref resources.ActorRef) *ateapipb.Actor {
				return f.strand(ref, "Terminate", ateapipb.ActorState_ACTOR_STATE_REVERTING, func() error {
					_, err := f.w.RevertActor(f.ctx, ref)
					return err
				})
			},
		},
		{
			name:        "delete",
			wantOp:      ateattr.OperationDelete,
			wantRPC:     "Terminate",
			wantDeleted: true,
			strand: func(f *redriveFixture, ref resources.ActorRef) *ateapipb.Actor {
				return f.strand(ref, "Terminate", ateapipb.ActorState_ACTOR_STATE_DELETING, func() error {
					_, err := f.w.DeleteActor(f.ctx, ref, true, store.DeletePreconditions{})
					return err
				})
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newRedriveFixture(t)
			ref := f.seedRunning("id1")
			stranded := tt.strand(f, ref)
			calls := f.atelet.count(tt.wantRPC)

			result, err := f.redrive(stranded, allQuiet())
			assertRedrive(t, result, err, tt.wantOp, ateattr.RedriveOutcomeCompleted)

			if got := f.atelet.count(tt.wantRPC); got != calls+1 {
				t.Errorf("atelet %s calls = %d, want %d", tt.wantRPC, got, calls+1)
			}
			if tt.wantDeleted {
				if _, err := f.store.GetActor(f.ctx, ref); !errors.Is(err, store.ErrNotFound) {
					t.Errorf("GetActor after the re-driven delete = %v, want not found", err)
				}
				return
			}
			got := f.get(ref)
			if got.GetStatus().GetState() != tt.wantState {
				t.Errorf("state = %v, want %v", got.GetStatus().GetState(), tt.wantState)
			}
			if got.GetStatus().GetWorkerAssignment() != nil {
				t.Errorf("the worker assignment was not cleared: %v", got.GetStatus().GetWorkerAssignment())
			}
		})
	}
}

// TestRedriveActor_OnlyFinishesOperationsWithOneWayOut pins which states a
// re-drive acts on. RESUMING is the one transitional state it leaves alone: a
// resume is driven by the next request, and a re-drive would boot a workload
// no one asked for.
func TestRedriveActor_OnlyFinishesOperationsWithOneWayOut(t *testing.T) {
	redriven := map[ateapipb.ActorState]string{
		ateapipb.ActorState_ACTOR_STATE_SUSPENDING: ateattr.OperationSuspend,
		ateapipb.ActorState_ACTOR_STATE_PAUSING:    ateattr.OperationPause,
		ateapipb.ActorState_ACTOR_STATE_REVERTING:  ateattr.OperationRevert,
		ateapipb.ActorState_ACTOR_STATE_DELETING:   ateattr.OperationDelete,
	}
	for _, state := range allActorStates {
		t.Run(state.String(), func(t *testing.T) {
			op, ok := redriveOperation(state)
			if want, wantOK := redriven[state]; op != want || ok != wantOK {
				t.Errorf("redriveOperation(%v) = %q, %v, want %q, %v", state, op, ok, want, wantOK)
			}
			if ok {
				return
			}

			f := newRedriveFixture(t)
			ref := f.seedRunning("id1")
			mustUpdateActorStatus(t, f.ctx, f.store, f.get(ref), func(status *ateapipb.ActorStatus) { status.State = state })
			result, err := f.redrive(f.get(ref), allQuiet())
			assertRedrive(t, result, err, "", ateattr.RedriveOutcomeSettled)
			for _, rpc := range []string{"Checkpoint", "UploadPausedCheckpoint", "Terminate"} {
				if got := f.atelet.count(rpc); got != 0 {
					t.Errorf("atelet %s calls = %d, want none for a %v actor", rpc, got, state)
				}
			}
			if got := f.get(ref).GetStatus().GetState(); got != state {
				t.Errorf("state = %v, want it left %v", got, state)
			}
		})
	}
}

// TestRedriveActor_CountsEveryAttempt: each outcome lands on ate.actor.redrives
// under the operation the actor's state called for.
func TestRedriveActor_CountsEveryAttempt(t *testing.T) {
	f := newRedriveFixture(t)
	inst, reader := newTestInstruments(t)
	f.w.instruments = inst
	ref := f.seedRunning("id1")
	stranded := f.strandSuspend(ref)

	lease, err := f.store.AcquireLease(f.ctx, actorLeaseKey(ref))
	if err != nil {
		t.Fatalf("AcquireLease: %v", err)
	}
	_, _ = f.redrive(stranded, allQuiet())
	lease.Close()
	_, _ = f.redrive(stranded, noneQuiet())
	f.atelet.fail("Checkpoint", status.Error(codes.Unavailable, "atelet is restarting"))
	_, _ = f.redrive(stranded, allQuiet())
	f.atelet.fail("Checkpoint", nil)
	_, _ = f.redrive(stranded, allQuiet())

	want := map[string]int64{
		ateattr.RedriveOutcomeBusy:      1,
		ateattr.RedriveOutcomeSettled:   1,
		ateattr.RedriveOutcomeFailed:    1,
		ateattr.RedriveOutcomeCompleted: 1,
	}
	for outcome, n := range want {
		if got := redriveCount(t, reader, ateattr.OperationSuspend, outcome); got != n {
			t.Errorf("%s{operation=suspend, outcome=%s} = %d, want %d", actorRedrivesMetric, outcome, got, n)
		}
	}
}
