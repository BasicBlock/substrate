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
	"fmt"
	"log/slog"
	"time"

	"github.com/agent-substrate/substrate/cmd/ateapi/internal/store"
	"github.com/agent-substrate/substrate/internal/apierror"
	"github.com/agent-substrate/substrate/internal/ateattr"
	"github.com/agent-substrate/substrate/internal/resources"
	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	"google.golang.org/grpc/codes"
)

// A workflow commits its transitional state (SUSPENDING, PAUSING, REVERTING,
// DELETING) before it does the work, and holds the actor's lease while it
// runs. If the process running it goes away, or its caller cancels it, the
// state stays and the actor refuses every other operation. RedriveActor
// finishes the operation by running the same workflow again, which is safe
// because each step derives from the persisted actor whether its work is done.
//
// The four states are the ones a caller asked for and no other API leaves:
//
//   - SUSPENDING, PAUSING: the workflow checkpoints the workload again, or
//     uploads the node-local snapshot again. If the first attempt took the
//     checkpoint but did not commit it, the workload is gone and atelet's
//     Checkpoint cannot succeed (atelet is not yet idempotent, #372), so the
//     workflow crashes the actor, as it does for any failed Checkpoint, even
//     if the upload had completed: ate-api cannot tell. The owner then reverts
//     the actor to its last durable snapshot, and the re-drive does not retry
//     a workload that is gone. Once Checkpoint is idempotent the same
//     re-drive finishes the operation instead. The exception is a snapshot
//     atelet could not upload and kept on the node: once the first attempt
//     recorded where, or the re-driven Checkpoint reports it, the workflow
//     pauses the actor on that node and returns Unavailable, as it does for
//     its RPC. The actor has left SUSPENDING, so the re-drive reports that
//     failure once and nothing is left to retry; the owner suspends the
//     actor again to retry the upload.
//   - REVERTING, DELETING: every step is idempotent and needs no live worker.
//
// RESUMING is left alone. A resume is driven by demand: the router and every
// client that calls ResumeActor re-enter the workflow, which revalidates the
// worker and carries on. A re-drive with no one waiting would boot a sandbox
// nothing asked for, with its worker slot, egress and cost, and nothing would
// suspend it.

// redriveOperation returns the lifecycle operation that finishes an actor left
// in state, and false if state is not one a re-drive finishes.
func redriveOperation(state ateapipb.ActorState) (string, bool) {
	switch state {
	case ateapipb.ActorState_ACTOR_STATE_SUSPENDING:
		return ateattr.OperationSuspend, true
	case ateapipb.ActorState_ACTOR_STATE_REVERTING:
		return ateattr.OperationRevert, true
	case ateapipb.ActorState_ACTOR_STATE_DELETING:
		return ateattr.OperationDelete, true
	}
	return "", false
}

// isStranded reports whether actor is in a state a re-drive finishes and was
// last written no later than notUpdatedSince. A workflow writes the actor at
// each step that moves it on, so a record this quiet has no workflow
// advancing it.
func isStranded(actor *ateapipb.Actor, notUpdatedSince time.Time) bool {
	if _, ok := redriveOperation(actor.GetStatus().GetState()); !ok {
		return false
	}
	// A record with no update time reads as the Unix epoch, so as long
	// unwritten. The store always sets one.
	return !actor.GetMetadata().GetUpdateTime().AsTime().After(notUpdatedSince)
}

// RedriveResult reports what RedriveActor found.
type RedriveResult struct {
	// Operation is the lifecycle operation the actor's state called for
	// (ateattr.Operation*).
	Operation string
	// Outcome is one of ateattr.RedriveOutcome*.
	Outcome string
}

// RedriveActor finishes the operation that observed was left in the middle of.
// It takes the actor's lease, so it never runs beside a live workflow, and
// under the lease reads the actor again: if the actor is gone, replaced by a
// new incarnation, out of the transitional state, or written since
// notUpdatedSince, nothing runs. Otherwise it runs the workflow for the state
// on the lease it holds, so an actor whose owner finished the operation and
// resumed it is never suspended by a re-drive that decided earlier.
//
// An error means the workflow failed and left the actor in its state, so the
// caller should retry after a delay. A workflow that crashes the actor is no
// error: the actor left the state, and the outcome is Crashed.
func (w *ActorWorkflow) RedriveActor(ctx context.Context, observed *ateapipb.Actor, notUpdatedSince time.Time) (result RedriveResult, err error) {
	actorRef := resources.ActorRefFromActor(observed)
	result.Operation, _ = redriveOperation(observed.GetStatus().GetState())
	defer func() { w.instruments.recordRedrive(ctx, result.Operation, result.Outcome) }()

	lease, err := w.store.AcquireLease(ctx, actorLeaseKey(actorRef))
	if err != nil {
		if errors.Is(err, store.ErrLeaseConflict) {
			result.Outcome = ateattr.RedriveOutcomeBusy
			return result, nil
		}
		result.Outcome = ateattr.RedriveOutcomeFailed
		return result, fmt.Errorf("while acquiring lease: %w", err)
	}
	defer lease.Close()
	leaseCtx := lease.Context()

	actor, err := w.store.GetActor(leaseCtx, actorRef)
	if errors.Is(err, store.ErrNotFound) {
		result.Outcome = ateattr.RedriveOutcomeSettled
		return result, nil
	}
	if err != nil {
		result.Outcome = ateattr.RedriveOutcomeFailed
		return result, fmt.Errorf("while fetching actor: %w", err)
	}
	if actor.GetMetadata().GetUid() != observed.GetMetadata().GetUid() || !isStranded(actor, notUpdatedSince) {
		result.Outcome = ateattr.RedriveOutcomeSettled
		return result, nil
	}
	state := actor.GetStatus().GetState()
	result.Operation, _ = redriveOperation(state)

	attrs := append(ateattr.ActorLogAttrs(resources.ActorAttributionFromActor(actor)),
		slog.String(string(ateattr.ActorOperationNameKey), result.Operation),
		slog.String(string(ateattr.ActorStateKey), ateattr.ActorStateValue(state)),
		slog.Duration("idle", time.Since(actor.GetMetadata().GetUpdateTime().AsTime()).Round(time.Second)))
	slog.LogAttrs(ctx, slog.LevelWarn, "Re-driving an actor whose operation no workflow is running", attrs...)

	err = w.runRedrive(leaseCtx, actorRef, actor, result.Operation)
	switch {
	case err == nil:
		result.Outcome = ateattr.RedriveOutcomeCompleted
		slog.LogAttrs(ctx, slog.LevelInfo, "Finished an actor's operation by re-driving it",
			append(attrs, slog.String(string(ateattr.ActorRedriveOutcomeKey), result.Outcome))...)
		return result, nil
	case errors.Is(err, store.ErrNotFound) || apierror.Code(err) == codes.NotFound:
		// Deleted under the lease by the workflow itself: nothing is left.
		result.Outcome = ateattr.RedriveOutcomeSettled
		return result, nil
	}

	// A workflow that cannot finish crashes the actor, which leaves the
	// transitional state: retrying is pointless, and the owner reverts it.
	if latest, gerr := w.store.GetActor(leaseCtx, actorRef); gerr == nil && latest.GetStatus().GetState() == ateapipb.ActorState_ACTOR_STATE_CRASHED {
		result.Outcome = ateattr.RedriveOutcomeCrashed
		slog.LogAttrs(ctx, slog.LevelError, "Re-driving an actor's operation crashed it; RevertActor returns it to its last snapshot",
			append(attrs, slog.String(string(ateattr.ActorRedriveOutcomeKey), result.Outcome), slog.Any("err", err))...)
		return result, nil
	}
	result.Outcome = ateattr.RedriveOutcomeFailed
	return result, err
}

// runRedrive runs the workflow that finishes operation for actor, under the
// lease the caller holds.
func (w *ActorWorkflow) runRedrive(leaseCtx context.Context, actorRef resources.ActorRef, actor *ateapipb.Actor, operation string) error {
	held := holdingActorLease(leaseCtx)
	var err error
	switch operation {
	case ateattr.OperationSuspend:
		if latestSnapshotIsPendingLocal(actor.GetStatus()) {
			_, err = w.pauseActor(leaseCtx, actorRef, held)
		} else {
			_, err = w.suspendActor(leaseCtx, actorRef, held)
		}
	case ateattr.OperationRevert:
		_, err = w.revertActor(leaseCtx, actorRef, held)
	case ateattr.OperationDelete:
		// The state is DELETING already, so any_state has nothing to allow, and
		// the uid keeps the delete from reaching a successor of the same name.
		_, err = w.deleteActor(leaseCtx, actorRef, false, store.DeletePreconditions{UID: actor.GetMetadata().GetUid()}, held)
	default:
		err = fmt.Errorf("no workflow finishes operation %q", operation)
	}
	return err
}
