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
	"time"

	"github.com/agent-substrate/substrate/cmd/ateapi/internal/store"
	"github.com/agent-substrate/substrate/internal/apierror"
	"github.com/agent-substrate/substrate/internal/ateattr"
	"github.com/agent-substrate/substrate/internal/proto/ateletpb"
	"github.com/agent-substrate/substrate/internal/resources"
	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// DropSnapshotMemory downgrades a SUSPENDED actor's stored MEMORY snapshot to
// ROOTFS in place: atelet rewrites the snapshot's manifest and empties its
// memory objects (idempotently), and this workflow then records the lower
// fidelity on the actor's snapshot. Unlike suspend, resume and revert it never
// moves the actor out of SUSPENDED, so it needs no state of its own; the lease
// alone serializes it against a concurrent resume or delete.
func (w *ActorWorkflow) DropSnapshotMemory(ctx context.Context, actorRef resources.ActorRef) (_ *ateapipb.Actor, err error) {
	start := time.Now()
	var actor *ateapipb.Actor
	defer func() {
		w.instruments.recordLifecycleOp(ctx, ateattr.OperationDropSnapshotMemory, start, err, lifecycleOpAttrs(actor, nil, "", "")...)
	}()

	leaseCtx, lease, err := w.acquireActorLease(ctx, actorRef)
	if err != nil {
		return nil, err
	}
	defer lease.Close()

	actor, err = w.store.GetActor(leaseCtx, actorRef)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, apierror.NotFound("Actor %s not found", actorRef)
		}
		return nil, fmt.Errorf("while getting actor: %w", err)
	}
	if got := actor.GetStatus().GetState(); got != ateapipb.ActorState_ACTOR_STATE_SUSPENDED {
		return nil, apierror.FailedPrecondition("DropSnapshotMemory prerequisite not met for Actor: %s (got: %v, want %s)", actorRef, got, ateapipb.ActorState_ACTOR_STATE_SUSPENDED)
	}
	snap := findLatestDurableSnapshot(actor.GetStatus(), ateapipb.SnapshotStorageStatus_SNAPSHOT_STORAGE_STATUS_COMPLETED)
	if snap == nil {
		return nil, apierror.FailedPrecondition("actor %s has no durable snapshot to downgrade", actorRef)
	}
	switch snap.GetFidelity() {
	case ateapipb.SnapshotFidelity_SNAPSHOT_FIDELITY_MEMORY:
	case ateapipb.SnapshotFidelity_SNAPSHOT_FIDELITY_ROOTFS:
		// Recorded already; atelet finishes any emptying a previous call left.
	default:
		return nil, apierror.FailedPrecondition("actor %s's snapshot holds %s: only a MEMORY snapshot has memory to drop", actorRef, snap.GetFidelity())
	}

	if err := w.ensureSnapshotMemoryDropped(leaseCtx, snap.GetDurableSnapshot().GetObject().GetSnapshotUri()); err != nil {
		return nil, err
	}
	return w.ensureDroppedSnapshotRecorded(leaseCtx, actorRef, snap.GetUuid())
}

// ensureSnapshotMemoryDropped calls atelet's idempotent downgrade. Any
// reachable atelet can serve it: the actor is SUSPENDED, so it has no worker
// (and thus no node) of its own, and the work is object-storage I/O.
func (w *ActorWorkflow) ensureSnapshotMemoryDropped(ctx context.Context, snapshotURI string) (err error) {
	ctx, done := stepSpan(ctx, "DropSnapshotMemoryOnAtelet")
	defer func() { err = done(err) }()

	ateletConn, err := w.dialer.DialAnyAtelet()
	if err != nil {
		return fmt.Errorf("while dialing an atelet: %w", err)
	}
	client := ateletpb.NewAteomHerderClient(ateletConn)

	if _, err := client.DropSnapshotMemory(ctx, &ateletpb.DropSnapshotMemoryRequest{SnapshotUri: snapshotURI}); err != nil {
		return ateletCallError(ctx, "DropSnapshotMemory", err)
	}
	return nil
}

// ateletCallError reports a failed atelet call that must not crash the actor,
// with the code atelet gave it where that code means the same to this server's
// caller.
func ateletCallError(ctx context.Context, rpc string, err error) error {
	if ctx.Err() != nil {
		return fmt.Errorf("while calling atelet %s: %w: %w", rpc, err, ctx.Err())
	}
	switch status.Code(err) {
	case codes.Unavailable:
		return apierror.Unavailable("while calling atelet %s: %w", rpc, err)
	case codes.FailedPrecondition:
		return apierror.FailedPrecondition("atelet %s: %s", rpc, status.Convert(err).Message())
	case codes.InvalidArgument:
		return apierror.InvalidArgument("atelet %s: %s", rpc, status.Convert(err).Message())
	}
	return apierror.Internal("while calling atelet %s: %w", rpc, err)
}

// ensureDroppedSnapshotRecorded records the snapshot as ROOTFS, re-reading the
// actor first so an out-of-band change is not overwritten, as every other
// finalize step here does.
func (w *ActorWorkflow) ensureDroppedSnapshotRecorded(ctx context.Context, actorRef resources.ActorRef, snapshotUUID string) (_ *ateapipb.Actor, err error) {
	ctx, done := stepSpan(ctx, "RecordDroppedSnapshotMemory")
	defer func() { err = done(err) }()

	latestActor, err := w.store.GetActor(ctx, actorRef)
	if err != nil {
		return nil, err
	}
	if got := latestActor.GetStatus().GetState(); got != ateapipb.ActorState_ACTOR_STATE_SUSPENDED {
		return nil, apierror.FailedPrecondition("RecordDroppedSnapshotMemory prerequisite not met for Actor: %s (got: %v, want %s)", actorRef, got, ateapipb.ActorState_ACTOR_STATE_SUSPENDED)
	}
	latestSnap := findLatestDurableSnapshot(latestActor.GetStatus(), ateapipb.SnapshotStorageStatus_SNAPSHOT_STORAGE_STATUS_COMPLETED)
	if latestSnap == nil || latestSnap.GetUuid() != snapshotUUID {
		return nil, apierror.Aborted("actor %s's snapshot changed while its memory was being dropped, please retry", actorRef)
	}
	if latestSnap.GetFidelity() == ateapipb.SnapshotFidelity_SNAPSHOT_FIDELITY_ROOTFS {
		markSkipped(ctx, "actor's snapshot is already recorded as ROOTFS")
		return latestActor, nil
	}

	storedActor, err := w.store.UpdateActor(ctx, actorRef, store.PreconditionFrom(latestActor), func(toUpdate *ateapipb.Actor) error {
		if snap := findSnapshotByUUID(toUpdate.GetStatus().GetSnapshots(), snapshotUUID); snap != nil {
			snap.Fidelity = ateapipb.SnapshotFidelity_SNAPSHOT_FIDELITY_ROOTFS
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, store.ErrVersionConflict) {
			return nil, apierror.Aborted("concurrent update conflict, please retry")
		}
		return nil, err
	}
	return storedActor, nil
}

// findSnapshotByUUID returns the Snapshot in snapshots with the given uuid, or
// nil if none exists.
func findSnapshotByUUID(snapshots []*ateapipb.Snapshot, uuid string) *ateapipb.Snapshot {
	for _, snap := range snapshots {
		if snap.GetUuid() == uuid {
			return snap
		}
	}
	return nil
}
