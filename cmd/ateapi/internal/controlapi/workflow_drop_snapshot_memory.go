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
	"github.com/agent-substrate/substrate/internal/ateattr"
	"github.com/agent-substrate/substrate/internal/proto/ateletpb"
	"github.com/agent-substrate/substrate/internal/resources"
	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// DropSnapshotMemory converts a SUSPENDED actor's stored Full snapshot into a
// Filesystem one in place: atelet rewrites the snapshot's manifest and
// deletes its memory objects (kept idempotent there too), and this workflow
// then records the narrowed scope on the actor. Unlike Suspend/Resume/Revert
// this never moves the actor out of SUSPENDED, so it needs no intermediate
// state of its own -- the lease alone serializes it against a concurrent
// resume or delete.
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
			return nil, status.Errorf(codes.NotFound, "Actor %s not found", actorRef)
		}
		return nil, fmt.Errorf("while getting actor: %w", err)
	}
	if got := actor.GetStatus().GetState(); got != ateapipb.ActorState_ACTOR_STATE_SUSPENDED {
		return nil, status.Errorf(codes.FailedPrecondition, "DropSnapshotMemory prerequisite not met for Actor: %s (got: %v, want %s)", actorRef, got, ateapipb.ActorState_ACTOR_STATE_SUSPENDED)
	}
	snapshotURI := actor.GetStatus().GetExternalSnapshot().GetSnapshotUri()
	if snapshotURI == "" {
		return nil, status.Errorf(codes.FailedPrecondition, "actor %s has no external snapshot to narrow", actorRef)
	}

	if err := w.ensureSnapshotMemoryDropped(leaseCtx, snapshotURI); err != nil {
		return nil, err
	}

	return w.ensureDroppedSnapshotRecorded(leaseCtx, actorRef)
}

// ensureSnapshotMemoryDropped calls atelet's idempotent rewrite. Any reachable
// atelet can serve it: the actor is SUSPENDED, so it has no worker (and thus
// no node) of its own, and the work is pure object-storage I/O.
func (w *ActorWorkflow) ensureSnapshotMemoryDropped(ctx context.Context, snapshotURI string) (err error) {
	ctx, done := stepSpan(ctx, "DropSnapshotMemoryOnAtelet")
	defer func() { err = done(err) }()

	ateletConn, err := w.dialer.DialAnyAtelet()
	if err != nil {
		return fmt.Errorf("while dialing an atelet: %w", err)
	}
	client := ateletpb.NewAteomHerderClient(ateletConn)

	_, err = client.DropSnapshotMemory(ctx, &ateletpb.DropSnapshotMemoryRequest{SnapshotUri: snapshotURI})
	if err != nil {
		return fmt.Errorf("while dropping snapshot memory on atelet: %w", err)
	}
	return nil
}

// ensureDroppedSnapshotRecorded records the actor's external snapshot as
// Filesystem scope, re-reading first so an out-of-band change (unlikely for a
// SUSPENDED actor's snapshot, but the same discipline every other finalize
// step in this package follows) is not overwritten.
func (w *ActorWorkflow) ensureDroppedSnapshotRecorded(ctx context.Context, actorRef resources.ActorRef) (_ *ateapipb.Actor, err error) {
	ctx, done := stepSpan(ctx, "RecordDroppedSnapshotMemory")
	defer func() { err = done(err) }()

	latestActor, err := w.store.GetActor(ctx, actorRef)
	if err != nil {
		return nil, err
	}
	if got := latestActor.GetStatus().GetState(); got != ateapipb.ActorState_ACTOR_STATE_SUSPENDED {
		return nil, status.Errorf(codes.FailedPrecondition, "RecordDroppedSnapshotMemory prerequisite not met for Actor: %s (got: %v, want %s)", actorRef, got, ateapipb.ActorState_ACTOR_STATE_SUSPENDED)
	}
	if latestActor.GetStatus().GetExternalSnapshot().GetContentScope() == ateapipb.SnapshotContentScope_SNAPSHOT_CONTENT_SCOPE_FILESYSTEM {
		markSkipped(ctx, "actor's snapshot is already recorded as Filesystem scope")
		return latestActor, nil
	}

	storedActor, err := w.store.UpdateActor(ctx, actorRef, store.PreconditionFrom(latestActor), func(toUpdate *ateapipb.Actor) error {
		snapshot := proto.CloneOf(toUpdate.GetStatus().GetExternalSnapshot())
		snapshot.ContentScope = ateapipb.SnapshotContentScope_SNAPSHOT_CONTENT_SCOPE_FILESYSTEM
		toUpdate.Status.ExternalSnapshot = snapshot
		return nil
	})
	if err != nil {
		if errors.Is(err, store.ErrVersionConflict) {
			return nil, status.Error(codes.Aborted, "concurrent update conflict, please retry")
		}
		return nil, err
	}
	return storedActor, nil
}
