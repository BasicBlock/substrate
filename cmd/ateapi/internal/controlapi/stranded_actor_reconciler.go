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
	"log/slog"
	"sync"
	"time"

	"github.com/agent-substrate/substrate/cmd/ateapi/internal/store"
	"github.com/agent-substrate/substrate/internal/ateattr"
	"github.com/agent-substrate/substrate/internal/resources"
	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/workqueue"
)

const (
	// strandedActorListPageSize is the page size of the sweep over all actors.
	strandedActorListPageSize = 500

	// strandedActorWorkerCount is the number of goroutines re-driving actors,
	// which bounds the load a mass strand puts on atelet and the store.
	strandedActorWorkerCount = 4

	// redriveTimeout bounds one re-drive. It matches the deadline ate-api puts
	// on the RPC whose workflow a re-drive stands in for.
	redriveTimeout = 10 * time.Minute

	// A re-drive that fails is retried after redriveBackoffBase, then twice as
	// long after each failure, up to redriveBackoffMax. An actor that cannot be
	// finished, such as one on a node whose runtime no longer answers, costs
	// one attempt per redriveBackoffMax and stays visible in the logs and the
	// ate.actor.redrives counter.
	redriveBackoffBase = time.Minute
	redriveBackoffMax  = 30 * time.Minute
)

// strandedActorStore enumerates the exact storage methods needed by
// StrandedActorReconciler and nothing more.
type strandedActorStore interface {
	ListActors(ctx context.Context, atespace string, opts store.ListOptions) (store.ListResponse[*ateapipb.Actor], error)
	GetActor(ctx context.Context, actorRef resources.ActorRef) (*ateapipb.Actor, error)
}

// actorRedriver finishes the operation an actor was left in the middle of.
// *RPCService satisfies it.
type actorRedriver interface {
	RedriveActor(ctx context.Context, observed *ateapipb.Actor, notUpdatedSince time.Time) (RedriveResult, error)
}

// StrandedActorReconciler finishes the operations of actors that a workflow
// started and no workflow is running: an actor in SUSPENDING, PAUSING,
// REVERTING or DELETING whose record has not been written for minAge. See
// RedriveActor for why these four states and not RESUMING.
//
// Each resync reads every actor, and a stranded actor is re-driven only after
// it has been quiet for minAge, so minAge is the delay before it is noticed.
//
// TODO: Every ateapi replica runs this reconciler and lists every actor, with
// only a per-actor lease keeping them from re-driving the same one at once.
// Have a single elected leader run it, possibly by moving controller loops
// like this one out of the API server into their own Deployment, and index
// actors by state so that it need not read all of them.
type StrandedActorReconciler struct {
	persistence    strandedActorStore
	redriver       actorRedriver
	minAge         time.Duration
	resyncInterval time.Duration
	queue          workqueue.TypedInterface[resources.ActorRef]

	// now is time.Now, replaceable by tests.
	now func() time.Time

	// mu guards failures.
	mu sync.Mutex
	// failures holds an actor whose last re-drive failed until a re-drive
	// succeeds or the actor leaves the states a re-drive finishes. The queue
	// never retries: the sweep that finds the actor again does, once retryAt
	// passes.
	failures map[resources.ActorRef]redriveFailures
}

// redriveFailures is the backoff state of an actor whose re-drive keeps failing.
type redriveFailures struct {
	// attempts is the number of failed attempts in a row.
	attempts int
	// retryAt is when the next attempt may start.
	retryAt time.Time
}

// NewStrandedActorReconciler creates a StrandedActorReconciler. minAge is how
// long an actor's record must have gone unwritten before it is re-driven, and
// resyncInterval how often the actors are listed.
func NewStrandedActorReconciler(persistence strandedActorStore, redriver actorRedriver, minAge, resyncInterval time.Duration) *StrandedActorReconciler {
	return &StrandedActorReconciler{
		persistence:    persistence,
		redriver:       redriver,
		minAge:         minAge,
		resyncInterval: resyncInterval,
		queue:          workqueue.NewTyped[resources.ActorRef](),
		now:            time.Now,
		failures:       make(map[resources.ActorRef]redriveFailures),
	}
}

// Start launches the queue workers and the resync producer. There is no event
// source for a workflow that stopped, so the periodic list is the event
// source. Canceling ctx stops new re-drives; one in flight runs to the end,
// see reconcileOne.
func (r *StrandedActorReconciler) Start(ctx context.Context) {
	for range strandedActorWorkerCount {
		go wait.UntilWithContext(ctx, r.runWorker, time.Second)
	}
	go func() {
		<-ctx.Done()
		r.queue.ShutDown()
	}()
	// Jittered, so that replicas that started together do not list together.
	go wait.JitterUntilWithContext(ctx, r.resync, r.resyncInterval, 0.1, true)
}

// resync lists the actors and queues those a re-drive should finish. An actor
// whose last re-drive failed is queued again only once its backoff has passed.
func (r *StrandedActorReconciler) resync(ctx context.Context) {
	notUpdatedSince := r.now().Add(-r.minAge)
	waiting := make(map[resources.ActorRef]struct{})
	stranded, queued := 0, 0
	for token := ""; ; {
		page, err := r.persistence.ListActors(ctx, "", store.ListOptions{PageSize: strandedActorListPageSize, PageToken: token})
		if err != nil {
			slog.ErrorContext(ctx, "Failed to list actors for stranded-actor re-drive", slog.Any("err", err))
			return
		}
		for _, actor := range page.Items {
			if _, ok := redriveOperation(actor.GetStatus().GetState()); !ok {
				continue
			}
			ref := resources.ActorRefFromActor(actor)
			// Noted before the age check: a re-drive that fails partway can
			// still write the actor, and a record that looks young again is
			// no reason to forget how often it failed.
			waiting[ref] = struct{}{}
			if !isStranded(actor, notUpdatedSince) {
				continue
			}
			stranded++
			if r.backingOff(ref) {
				continue
			}
			r.queue.Add(ref)
			queued++
		}
		if !page.HasNextPage() {
			break
		}
		token = page.NextPageToken
	}
	r.forgetSettled(waiting)
	if stranded > 0 {
		slog.InfoContext(ctx, "Found actors whose operation no workflow is running",
			slog.Int("stranded", stranded), slog.Int("queued", queued))
	}
}

func (r *StrandedActorReconciler) runWorker(ctx context.Context) {
	for r.processNextWorkItem(ctx) {
	}
}

func (r *StrandedActorReconciler) processNextWorkItem(ctx context.Context) bool {
	ref, quit := r.queue.Get()
	if quit {
		return false
	}
	defer r.queue.Done(ref)

	r.reconcileOne(ctx, ref)
	return true
}

// reconcileOne re-drives one actor if it is still stranded, and records the
// failure if the re-drive fails.
//
// The re-drive does not follow ctx's cancellation: a shutdown signal would
// cancel the atelet call it is finishing and strand the actor again, as it
// would an RPC, which the server lets finish while it drains. If the process
// exits first, the next replica re-drives the actor.
func (r *StrandedActorReconciler) reconcileOne(ctx context.Context, ref resources.ActorRef) {
	if ctx.Err() != nil || r.backingOff(ref) {
		return
	}
	actor, err := r.persistence.GetActor(ctx, ref)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			r.forget(ref)
			return
		}
		slog.LogAttrs(ctx, slog.LevelError, "Failed to read an actor to re-drive", append(ateattr.ActorRefLogAttrs(ref), slog.Any("err", err))...)
		return
	}
	notUpdatedSince := r.now().Add(-r.minAge)
	if !isStranded(actor, notUpdatedSince) {
		// Finished, or moved on, since the sweep that queued it.
		r.forget(ref)
		return
	}

	workCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), redriveTimeout)
	defer cancel()
	result, err := r.redriver.RedriveActor(workCtx, actor, notUpdatedSince)
	if err == nil {
		// Finished, crashed, no longer waiting, or held by a live workflow: none
		// is a failure, and the next sweep looks again if the actor is still
		// quiet.
		r.forget(ref)
		return
	}
	failures := r.recordFailure(ref)
	delay := redriveBackoff(failures.attempts)
	slog.LogAttrs(ctx, slog.LevelError, "Failed to re-drive an actor's operation; retrying later",
		append(ateattr.ActorLogAttrs(resources.ActorAttributionFromActor(actor)),
			slog.String(string(ateattr.ActorOperationNameKey), result.Operation),
			slog.Int("attempts", failures.attempts),
			slog.Duration("retry_after", delay),
			slog.Any("err", err))...)
}

// backingOff reports whether the last re-drive of ref failed recently enough
// that the next attempt is not due.
func (r *StrandedActorReconciler) backingOff(ref resources.ActorRef) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	f, ok := r.failures[ref]
	return ok && r.now().Before(f.retryAt)
}

// recordFailure notes that a re-drive of ref failed and returns its backoff
// state.
func (r *StrandedActorReconciler) recordFailure(ref resources.ActorRef) redriveFailures {
	r.mu.Lock()
	defer r.mu.Unlock()
	f := r.failures[ref]
	f.attempts++
	f.retryAt = r.now().Add(redriveBackoff(f.attempts))
	r.failures[ref] = f
	return f
}

func (r *StrandedActorReconciler) forget(ref resources.ActorRef) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.failures, ref)
}

// forgetSettled drops the backoff state of every actor that is not in waiting,
// so that the table follows the actors that still need a re-drive.
func (r *StrandedActorReconciler) forgetSettled(waiting map[resources.ActorRef]struct{}) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for ref := range r.failures {
		if _, ok := waiting[ref]; !ok {
			delete(r.failures, ref)
		}
	}
}

// redriveBackoff is the delay after the attempts'th failure in a row.
func redriveBackoff(attempts int) time.Duration {
	delay := redriveBackoffBase
	for i := 1; i < attempts && delay < redriveBackoffMax; i++ {
		delay *= 2
	}
	return min(delay, redriveBackoffMax)
}
