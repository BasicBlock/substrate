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
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agent-substrate/substrate/cmd/ateapi/internal/store"
	"github.com/agent-substrate/substrate/internal/resources"
	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const testRedriveMinAge = 5 * time.Minute

// fakeActorStore is an in-memory strandedActorStore that pages by pageSize.
type fakeActorStore struct {
	mu       sync.Mutex
	actors   []*ateapipb.Actor
	pageSize int
	listErr  error
}

func (s *fakeActorStore) put(actor *ateapipb.Actor) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ref := resources.ActorRefFromActor(actor)
	for i, existing := range s.actors {
		if resources.ActorRefFromActor(existing) == ref {
			s.actors[i] = actor
			return
		}
	}
	s.actors = append(s.actors, actor)
}

func (s *fakeActorStore) ListActors(_ context.Context, _ string, opts store.ListOptions) (store.ListResponse[*ateapipb.Actor], error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listErr != nil {
		return store.ListResponse[*ateapipb.Actor]{}, s.listErr
	}
	start := 0
	if opts.PageToken != "" {
		start, _ = strconv.Atoi(opts.PageToken)
	}
	end := min(start+s.pageSize, len(s.actors))
	resp := store.ListResponse[*ateapipb.Actor]{Items: slices.Clone(s.actors[start:end])}
	if end < len(s.actors) {
		resp.NextPageToken = strconv.Itoa(end)
	}
	return resp, nil
}

func (s *fakeActorStore) GetActor(_ context.Context, ref resources.ActorRef) (*ateapipb.Actor, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, actor := range s.actors {
		if resources.ActorRefFromActor(actor) == ref {
			return proto.Clone(actor).(*ateapipb.Actor), nil
		}
	}
	return nil, store.ErrNotFound
}

// fakeRedriver records the actors it is asked to re-drive, and answers with
// result and err.
type fakeRedriver struct {
	mu     sync.Mutex
	calls  []resources.ActorRef
	result RedriveResult
	err    error
	// onCall runs inside each call, with the context the call got.
	onCall func(ctx context.Context)
}

func (f *fakeRedriver) RedriveActor(ctx context.Context, observed *ateapipb.Actor, _ time.Time) (RedriveResult, error) {
	f.mu.Lock()
	f.calls = append(f.calls, resources.ActorRefFromActor(observed))
	onCall, result, err := f.onCall, f.result, f.err
	f.mu.Unlock()
	if onCall != nil {
		onCall(ctx)
	}
	return result, err
}

func (f *fakeRedriver) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// fakeClock is a clock that only moves when a test moves it.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// updatedActor builds an actor in state whose record was last written at
// updated.
func updatedActor(name string, state ateapipb.ActorState, updated time.Time) *ateapipb.Actor {
	return &ateapipb.Actor{
		Metadata: &ateapipb.ResourceMetadata{
			Atespace:   "team-a",
			Name:       name,
			Uid:        "uid-" + name,
			Version:    1,
			UpdateTime: timestamppb.New(updated),
		},
		Status: &ateapipb.ActorStatus{State: state},
	}
}

func newTestStrandedReconciler(persistence strandedActorStore, redriver actorRedriver) (*StrandedActorReconciler, *fakeClock) {
	r := NewStrandedActorReconciler(persistence, redriver, testRedriveMinAge, time.Minute)
	clock := &fakeClock{now: time.Date(2026, 10, 9, 14, 30, 0, 0, time.UTC)}
	r.now = clock.Now
	return r, clock
}

// drain runs every item the queue holds. It never blocks: nothing else adds to
// the queue while a test runs.
func drain(ctx context.Context, r *StrandedActorReconciler) {
	for r.queue.Len() > 0 {
		r.processNextWorkItem(ctx)
	}
}

// queued returns what the queue holds, emptying it.
func queued(r *StrandedActorReconciler) []resources.ActorRef {
	var refs []resources.ActorRef
	for r.queue.Len() > 0 {
		ref, _ := r.queue.Get()
		refs = append(refs, ref)
		r.queue.Done(ref)
	}
	slices.SortFunc(refs, func(a, b resources.ActorRef) int { return strings.Compare(a.Name, b.Name) })
	return refs
}

func refsOf(names ...string) []resources.ActorRef {
	var refs []resources.ActorRef
	for _, name := range names {
		refs = append(refs, resources.ActorRef{Atespace: "team-a", Name: name})
	}
	return refs
}

func (r *StrandedActorReconciler) failureCount(ref resources.ActorRef) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.failures[ref].attempts
}

// TestStrandedActorReconciler_ResyncQueuesOnlyQuietTransitionalActors: the
// sweep, which pages through all the actors, queues the actors left in the
// four operations a re-drive finishes, once they have been quiet for the
// minimum age, and no others.
func TestStrandedActorReconciler_ResyncQueuesOnlyQuietTransitionalActors(t *testing.T) {
	st := &fakeActorStore{pageSize: 2}
	r, clock := newTestStrandedReconciler(st, &fakeRedriver{})
	quiet := clock.Now().Add(-testRedriveMinAge - time.Second)
	recent := clock.Now().Add(-testRedriveMinAge + time.Second)

	for _, actor := range []*ateapipb.Actor{
		updatedActor("suspending", ateapipb.ActorState_ACTOR_STATE_SUSPENDING, quiet),
		updatedActor("pausing", ateapipb.ActorState_ACTOR_STATE_SUSPENDING, quiet),
		updatedActor("reverting", ateapipb.ActorState_ACTOR_STATE_REVERTING, quiet),
		updatedActor("deleting", ateapipb.ActorState_ACTOR_STATE_DELETING, quiet),
		// Written inside the minimum age: a workflow may be advancing it.
		updatedActor("young-suspending", ateapipb.ActorState_ACTOR_STATE_SUSPENDING, recent),
		// Driven by the next request instead.
		updatedActor("resuming", ateapipb.ActorState_ACTOR_STATE_RESUMING, quiet),
		updatedActor("running", ateapipb.ActorState_ACTOR_STATE_RUNNING, quiet),
		updatedActor("suspended", ateapipb.ActorState_ACTOR_STATE_SUSPENDED, quiet),
		updatedActor("paused", ateapipb.ActorState_ACTOR_STATE_SUSPENDED, quiet),
		updatedActor("crashed", ateapipb.ActorState_ACTOR_STATE_CRASHED, quiet),
	} {
		st.put(actor)
	}

	r.resync(context.Background())

	got := queued(r)
	want := refsOf("deleting", "pausing", "reverting", "suspending")
	if !slices.Equal(got, want) {
		t.Errorf("queued = %v, want %v", got, want)
	}
}

func TestStrandedActorReconciler_ResyncLeavesTheStateAloneWhenListingFails(t *testing.T) {
	st := &fakeActorStore{pageSize: 10}
	r, clock := newTestStrandedReconciler(st, &fakeRedriver{err: errors.New("atelet is down")})
	st.put(updatedActor("a", ateapipb.ActorState_ACTOR_STATE_SUSPENDING, clock.Now().Add(-time.Hour)))
	r.resync(context.Background())
	drain(context.Background(), r)
	if r.failureCount(refsOf("a")[0]) != 1 {
		t.Fatalf("setup: want one recorded failure")
	}

	st.listErr = errors.New("the store is down")
	r.resync(context.Background())

	if got := queued(r); len(got) != 0 {
		t.Errorf("queued = %v after a failed listing, want nothing", got)
	}
	if r.failureCount(refsOf("a")[0]) != 1 {
		t.Errorf("a failed listing dropped the backoff state: it says nothing about the actors")
	}
}

// TestStrandedActorReconciler_BacksOffAFailingRedrive: an actor that cannot be
// finished is attempted again only after a delay that doubles from
// redriveBackoffBase to redriveBackoffMax, however often the sweep finds it.
func TestStrandedActorReconciler_BacksOffAFailingRedrive(t *testing.T) {
	ctx := context.Background()
	st := &fakeActorStore{pageSize: 10}
	redriver := &fakeRedriver{err: errors.New("runsc state: context deadline exceeded")}
	r, clock := newTestStrandedReconciler(st, redriver)
	ref := refsOf("stuck")[0]
	st.put(updatedActor("stuck", ateapipb.ActorState_ACTOR_STATE_DELETING, clock.Now().Add(-time.Hour)))

	// The sweep runs every 10 seconds of simulated time for five hours, far
	// more often than any backoff, and the attempts it lets through are timed.
	const step = 10 * time.Second
	start := clock.Now()
	var attemptedAt []time.Duration
	for clock.Now().Sub(start) < 5*time.Hour {
		before := redriver.callCount()
		r.resync(ctx)
		drain(ctx, r)
		if redriver.callCount() > before {
			attemptedAt = append(attemptedAt, clock.Now().Sub(start))
		}
		clock.advance(step)
	}

	wantGaps := []time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 16 * time.Minute, 30 * time.Minute, 30 * time.Minute, 30 * time.Minute}
	if len(attemptedAt) < len(wantGaps)+1 {
		t.Fatalf("attempts at %v: too few for five hours", attemptedAt)
	}
	if attemptedAt[0] != 0 {
		t.Errorf("first attempt at %v, want at once", attemptedAt[0])
	}
	for i, want := range wantGaps {
		if gap := attemptedAt[i+1] - attemptedAt[i]; gap < want || gap > want+step {
			t.Errorf("gap before attempt %d = %v, want %v", i+2, gap, want)
		}
	}
	// The sixth attempt is at 31 minutes, and one more follows every half hour.
	if got := len(attemptedAt); got > 14 {
		t.Errorf("%d attempts in 5 hours of sweeps every %v, want at most 14: the failing actor is being retried too often", got, step)
	}
	if got := r.failureCount(ref); got != len(attemptedAt) {
		t.Errorf("recorded failures = %d, want %d", got, len(attemptedAt))
	}
}

// TestStrandedActorReconciler_KeepsTheBackoffOfAnActorThatLooksYoung: a failed
// re-drive can have written the record, which makes the actor look young for
// the minimum age. That must not reset the backoff.
func TestStrandedActorReconciler_KeepsTheBackoffOfAnActorThatLooksYoung(t *testing.T) {
	ctx := context.Background()
	st := &fakeActorStore{pageSize: 10}
	redriver := &fakeRedriver{err: errors.New("detaching a volume failed")}
	r, clock := newTestStrandedReconciler(st, redriver)
	ref := refsOf("a")[0]
	st.put(updatedActor("a", ateapipb.ActorState_ACTOR_STATE_DELETING, clock.Now().Add(-time.Hour)))

	r.resync(ctx)
	drain(ctx, r)
	if got := r.failureCount(ref); got != 1 {
		t.Fatalf("failures = %d, want 1", got)
	}

	// The failed attempt wrote the record.
	st.put(updatedActor("a", ateapipb.ActorState_ACTOR_STATE_DELETING, clock.Now()))
	clock.advance(redriveBackoffBase + time.Second)
	r.resync(ctx)
	if got := queued(r); len(got) != 0 {
		t.Fatalf("queued = %v while the record is young", got)
	}
	if got := r.failureCount(ref); got != 1 {
		t.Errorf("failures = %d while the actor looks young, want the count kept at 1", got)
	}

	// Once it is quiet again the next attempt is the second, not a first.
	clock.advance(testRedriveMinAge)
	r.resync(ctx)
	drain(ctx, r)
	if got := r.failureCount(ref); got != 2 {
		t.Errorf("failures = %d after the second attempt, want 2", got)
	}
}

// TestStrandedActorReconciler_ForgetsAnActorThatIsNoLongerWaiting: the table
// of failures follows the actors that still wait for a re-drive.
func TestStrandedActorReconciler_ForgetsAnActorThatIsNoLongerWaiting(t *testing.T) {
	ctx := context.Background()
	st := &fakeActorStore{pageSize: 10}
	redriver := &fakeRedriver{err: errors.New("atelet is down")}
	r, clock := newTestStrandedReconciler(st, redriver)
	ref := refsOf("a")[0]
	st.put(updatedActor("a", ateapipb.ActorState_ACTOR_STATE_SUSPENDING, clock.Now().Add(-time.Hour)))
	r.resync(ctx)
	drain(ctx, r)
	if got := r.failureCount(ref); got != 1 {
		t.Fatalf("failures = %d, want 1", got)
	}

	// Its owner finishes the suspend, and later it is stranded again: that is
	// a new story and starts without a delay.
	st.put(updatedActor("a", ateapipb.ActorState_ACTOR_STATE_SUSPENDED, clock.Now()))
	r.resync(ctx)
	if got := r.failureCount(ref); got != 0 {
		t.Errorf("failures = %d for an actor that is SUSPENDED, want it forgotten", got)
	}
	st.put(updatedActor("a", ateapipb.ActorState_ACTOR_STATE_SUSPENDING, clock.Now()))
	clock.advance(testRedriveMinAge + time.Second)
	r.resync(ctx)
	if got := queued(r); !slices.Equal(got, []resources.ActorRef{ref}) {
		t.Errorf("queued = %v, want %v", got, []resources.ActorRef{ref})
	}
}

// TestStrandedActorReconciler_SkipsAnActorThatSettledBeforeItsTurn: the worker
// looks at the actor again when it takes it off the queue.
func TestStrandedActorReconciler_SkipsAnActorThatSettledBeforeItsTurn(t *testing.T) {
	ctx := context.Background()
	st := &fakeActorStore{pageSize: 10}
	redriver := &fakeRedriver{}
	r, clock := newTestStrandedReconciler(st, redriver)
	st.put(updatedActor("a", ateapipb.ActorState_ACTOR_STATE_SUSPENDING, clock.Now().Add(-time.Hour)))
	st.put(updatedActor("b", ateapipb.ActorState_ACTOR_STATE_SUSPENDING, clock.Now().Add(-time.Hour)))
	r.resync(ctx)

	st.put(updatedActor("a", ateapipb.ActorState_ACTOR_STATE_SUSPENDED, clock.Now()))
	st.mu.Lock()
	st.actors = slices.DeleteFunc(st.actors, func(a *ateapipb.Actor) bool { return a.GetMetadata().GetName() == "b" })
	st.mu.Unlock()
	drain(ctx, r)

	if got := redriver.callCount(); got != 0 {
		t.Errorf("re-drive calls = %d, want none: both actors left the state while queued", got)
	}
}

// TestStrandedActorReconciler_ReDriveOutlivesTheShutdownSignal: canceling
// the reconciler's context stops it taking new work but does not cut off a
// re-drive in flight, which would cancel the atelet call it is finishing.
func TestStrandedActorReconciler_ReDriveOutlivesTheShutdownSignal(t *testing.T) {
	st := &fakeActorStore{pageSize: 10}
	redriver := &fakeRedriver{}
	r, clock := newTestStrandedReconciler(st, redriver)
	ref := refsOf("a")[0]
	st.put(updatedActor("a", ateapipb.ActorState_ACTOR_STATE_SUSPENDING, clock.Now().Add(-time.Hour)))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	redriver.onCall = func(workCtx context.Context) {
		cancel()
		if err := workCtx.Err(); err != nil {
			t.Errorf("the re-drive's context ended with the shutdown signal: %v", err)
		}
		if deadline, ok := workCtx.Deadline(); !ok || time.Until(deadline) > redriveTimeout {
			t.Errorf("re-drive deadline = %v, %v; want one within %v", deadline, ok, redriveTimeout)
		}
	}
	r.reconcileOne(ctx, ref)
	if got := redriver.callCount(); got != 1 {
		t.Fatalf("re-drive calls = %d, want 1", got)
	}

	r.reconcileOne(ctx, ref)
	if got := redriver.callCount(); got != 1 {
		t.Errorf("re-drive calls = %d after shutdown, want no new one", got)
	}
}

// TestStrandedActorReconciler_StartSweepsUntilCancelled runs the loops for real.
func TestStrandedActorReconciler_StartSweepsUntilCancelled(t *testing.T) {
	st := &fakeActorStore{pageSize: 10}
	redriver := &fakeRedriver{}
	r := NewStrandedActorReconciler(st, redriver, testRedriveMinAge, 10*time.Millisecond)
	st.put(updatedActor("a", ateapipb.ActorState_ACTOR_STATE_SUSPENDING, time.Now().Add(-time.Hour)))
	redriver.onCall = func(context.Context) {
		// The re-drive finishes the suspend.
		st.put(updatedActor("a", ateapipb.ActorState_ACTOR_STATE_SUSPENDED, time.Now()))
	}

	ctx, cancel := context.WithCancel(context.Background())
	r.Start(ctx)
	waitFor(t, "the stranded actor to be re-driven", func() bool { return redriver.callCount() == 1 })
	// Later sweeps find nothing to do.
	time.Sleep(100 * time.Millisecond)
	if got := redriver.callCount(); got != 1 {
		t.Errorf("re-drive calls = %d, want 1", got)
	}

	cancel()
	waitFor(t, "the queue to shut down", r.queue.ShuttingDown)
}

func waitFor(t *testing.T, what string, done func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !done() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestRedriveBackoff(t *testing.T) {
	tests := []struct {
		attempts int
		want     time.Duration
	}{
		{0, time.Minute},
		{1, time.Minute},
		{2, 2 * time.Minute},
		{3, 4 * time.Minute},
		{5, 16 * time.Minute},
		{6, 30 * time.Minute},
		{7, 30 * time.Minute},
		{1000, 30 * time.Minute},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprint(tt.attempts), func(t *testing.T) {
			if got := redriveBackoff(tt.attempts); got != tt.want {
				t.Errorf("redriveBackoff(%d) = %v, want %v", tt.attempts, got, tt.want)
			}
		})
	}
}

// The tests below run the reconciler over the real workflows and store.

// newRealStrandedReconciler returns a reconciler over f, and the clock it reads.
// The clock starts an hour ahead of the real one, so the records the fixture
// has written count as quiet.
func newRealStrandedReconciler(f *redriveFixture) (*StrandedActorReconciler, *fakeClock) {
	r := NewStrandedActorReconciler(f.store, f.w, testRedriveMinAge, time.Minute)
	clock := &fakeClock{now: time.Now().Add(time.Hour)}
	r.now = clock.Now
	return r, clock
}

func TestStrandedActorReconciler_FinishesAStrandedSuspend(t *testing.T) {
	f := newRedriveFixture(t)
	ref := f.seedRunning("id1")
	f.strandSuspend(ref)
	r, _ := newRealStrandedReconciler(f)

	r.resync(f.ctx)
	drain(f.ctx, r)

	if got := f.get(ref).GetStatus().GetState(); got != ateapipb.ActorState_ACTOR_STATE_SUSPENDED {
		t.Errorf("state = %v, want SUSPENDED", got)
	}
	// Nothing is left to find.
	r.resync(f.ctx)
	if got := queued(r); len(got) != 0 {
		t.Errorf("queued = %v after the actor was finished", got)
	}
}

func TestStrandedActorReconciler_LeavesAYoungActorAlone(t *testing.T) {
	f := newRedriveFixture(t)
	ref := f.seedRunning("id1")
	f.strandSuspend(ref)
	checkpoints := f.atelet.count("Checkpoint")
	r, clock := newRealStrandedReconciler(f)
	clock.now = time.Now()

	r.resync(f.ctx)
	drain(f.ctx, r)

	if got := f.atelet.count("Checkpoint"); got != checkpoints {
		t.Errorf("atelet Checkpoint calls = %d, want %d", got, checkpoints)
	}
	if got := f.get(ref).GetStatus().GetState(); got != ateapipb.ActorState_ACTOR_STATE_SUSPENDING {
		t.Errorf("state = %v, want it left SUSPENDING", got)
	}
}

func TestStrandedActorReconciler_LeavesAnActorWithALiveWorkflowAlone(t *testing.T) {
	f := newRedriveFixture(t)
	ref := f.seedRunning("id1")
	f.strandSuspend(ref)
	checkpoints := f.atelet.count("Checkpoint")
	r, _ := newRealStrandedReconciler(f)

	lease, err := f.store.AcquireLease(f.ctx, actorLeaseKey(ref))
	if err != nil {
		t.Fatalf("AcquireLease: %v", err)
	}
	for range 3 {
		r.resync(f.ctx)
		drain(f.ctx, r)
	}
	if got := f.atelet.count("Checkpoint"); got != checkpoints {
		t.Errorf("atelet Checkpoint calls = %d, want %d while a workflow holds the lease", got, checkpoints)
	}
	if got := r.failureCount(ref); got != 0 {
		t.Errorf("a live workflow is no failure, but %d were recorded: the actor would back off", got)
	}

	// The workflow ends, and the next sweep finishes the actor at once.
	lease.Close()
	r.resync(f.ctx)
	drain(f.ctx, r)
	if got := f.get(ref).GetStatus().GetState(); got != ateapipb.ActorState_ACTOR_STATE_SUSPENDED {
		t.Errorf("state = %v, want SUSPENDED", got)
	}
}

// TestStrandedActorReconciler_DoesNotHotLoopOnAFailingRedrive: with atelet
// unreachable, sweeps that come as often as they like cause one call to atelet
// per backoff.
func TestStrandedActorReconciler_DoesNotHotLoopOnAFailingRedrive(t *testing.T) {
	f := newRedriveFixture(t)
	ref := f.seedRunning("id1")
	f.strandSuspend(ref)
	f.atelet.fail("Checkpoint", status.Error(codes.Unavailable, "atelet is gone"))
	strandCalls := f.atelet.count("Checkpoint")
	r, clock := newRealStrandedReconciler(f)

	for range 10 {
		r.resync(f.ctx)
		drain(f.ctx, r)
	}
	if got := f.atelet.count("Checkpoint") - strandCalls; got != 1 {
		t.Errorf("atelet Checkpoint calls in ten sweeps = %d, want 1", got)
	}
	if got := f.get(ref).GetStatus().GetState(); got != ateapipb.ActorState_ACTOR_STATE_SUSPENDING {
		t.Errorf("state = %v, want it left SUSPENDING for the retry", got)
	}

	clock.advance(redriveBackoffBase + time.Second)
	for range 10 {
		r.resync(f.ctx)
		drain(f.ctx, r)
	}
	if got := f.atelet.count("Checkpoint") - strandCalls; got != 2 {
		t.Errorf("atelet Checkpoint calls after the backoff = %d, want 2", got)
	}

	// Atelet comes back, and the actor is finished when its backoff ends.
	f.atelet.fail("Checkpoint", nil)
	clock.advance(2*redriveBackoffBase + time.Second)
	r.resync(f.ctx)
	drain(f.ctx, r)
	if got := f.get(ref).GetStatus().GetState(); got != ateapipb.ActorState_ACTOR_STATE_SUSPENDED {
		t.Errorf("state = %v, want SUSPENDED", got)
	}
	if got := r.failureCount(ref); got != 0 {
		t.Errorf("failures = %d after the actor was finished, want 0", got)
	}
}
