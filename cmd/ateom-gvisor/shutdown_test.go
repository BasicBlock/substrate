//go:build linux

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

package main

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeRuntime stands in for *runsc. It records the signals killContainer
// delivers and unblocks cmdWait when the container is configured to die on one
// of them. The embedded interface is nil, so any other command panics.
type fakeRuntime struct {
	containerRuntime

	mu      sync.Mutex
	signals []string

	// exitOn is the signal that makes the container exit. Empty means it never
	// does, which is how the wedged-sandbox case is set up.
	exitOn string
	// waitErr is what cmdWait reports once it unblocks, standing in for a
	// `runsc wait` that failed rather than a container that stopped.
	waitErr error
	// killErr maps a signal to the error cmdKill returns for it.
	killErr map[string]error

	exited     chan struct{}
	exitedOnce sync.Once
}

func newFakeRuntime(exitOn string, waitErr error, killErr map[string]error) *fakeRuntime {
	return &fakeRuntime{exitOn: exitOn, waitErr: waitErr, killErr: killErr, exited: make(chan struct{})}
}

func (f *fakeRuntime) cmdKill(_ context.Context, _, signal string) error {
	f.mu.Lock()
	f.signals = append(f.signals, signal)
	f.mu.Unlock()

	if f.exitOn == signal {
		f.exitedOnce.Do(func() { close(f.exited) })
	}
	return f.killErr[signal]
}

func (f *fakeRuntime) cmdWait(ctx context.Context, _ string) error {
	select {
	case <-f.exited:
		return f.waitErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (f *fakeRuntime) sentSignals() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.signals...)
}

// TestKillContainer covers the SIGTERM-then-SIGKILL escalation against the
// shared drain deadline. The deadlines here are milliseconds rather than the
// production grace period, which is what the package-level vars are for.
func TestKillContainer(t *testing.T) {
	tests := []struct {
		name string
		// exitOn, waitErr and killErr configure the fake runtime.
		exitOn  string
		waitErr error
		killErr map[string]error
		// deadlineIn is the drain deadline relative to the start of the call. A
		// negative value is a deadline the caller has already spent elsewhere.
		deadlineIn  time.Duration
		wantSignals []string
		wantErr     string
	}{
		{
			name:        "container exits on SIGTERM inside the deadline",
			exitOn:      "SIGTERM",
			deadlineIn:  time.Minute,
			wantSignals: []string{"SIGTERM"},
		},
		{
			name:        "container ignoring SIGTERM is killed at the deadline",
			exitOn:      "SIGKILL",
			deadlineIn:  20 * time.Millisecond,
			wantSignals: []string{"SIGTERM", "SIGKILL"},
		},
		{
			// The lock wait ate the whole grace period, so the container gets
			// SIGTERM and no time at all before the escalation.
			name:        "deadline already spent leaves no grace",
			exitOn:      "SIGKILL",
			deadlineIn:  -time.Second,
			wantSignals: []string{"SIGTERM", "SIGKILL"},
		},
		{
			name:        "container surviving SIGKILL is reported",
			deadlineIn:  20 * time.Millisecond,
			wantSignals: []string{"SIGTERM", "SIGKILL"},
			wantErr:     "failed to exit even after SIGKILL",
		},
		{
			name:        "undeliverable SIGTERM does not escalate",
			killErr:     map[string]error{"SIGTERM": errors.New("sandbox gone")},
			deadlineIn:  time.Minute,
			wantSignals: []string{"SIGTERM"},
			wantErr:     "failed to propagate SIGTERM",
		},
		{
			// A failing `runsc wait` says nothing about the container, so the
			// caller is told rather than the container killed.
			name:        "failed wait does not escalate",
			exitOn:      "SIGTERM",
			waitErr:     errors.New("runsc wait exploded"),
			deadlineIn:  time.Minute,
			wantSignals: []string{"SIGTERM"},
			wantErr:     "wait failed",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			origKillTimeout := containerKillTimeout
			containerKillTimeout = 20 * time.Millisecond
			t.Cleanup(func() { containerKillTimeout = origKillTimeout })

			// A cancelled context is what releases a cmdWait the fake never
			// unblocks, so the wait goroutine does not outlive the test.
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)

			f := newFakeRuntime(tc.exitOn, tc.waitErr, tc.killErr)
			err := killContainer(ctx, f, "counter", time.Now().Add(tc.deadlineIn))

			switch {
			case tc.wantErr == "" && err != nil:
				t.Errorf("killContainer() = %v, want nil", err)
			case tc.wantErr != "" && err == nil:
				t.Errorf("killContainer() = nil, want error containing %q", tc.wantErr)
			case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
				t.Errorf("killContainer() = %v, want error containing %q", err, tc.wantErr)
			}

			if got := f.sentSignals(); !reflect.DeepEqual(got, tc.wantSignals) {
				t.Errorf("signals delivered = %v, want %v", got, tc.wantSignals)
			}
		})
	}
}

// TestKillContainerHonorsParentCancellation asserts that a cancelled shutdown
// context stops the drain instead of escalating: ateom is going away anyway, and
// the containers go down with the pod.
func TestKillContainerHonorsParentCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	f := newFakeRuntime("", nil, nil)

	// Cancel once SIGTERM has been delivered and the wait is under way.
	go func() {
		for {
			if len(f.sentSignals()) > 0 {
				cancel()
				return
			}
			time.Sleep(time.Millisecond)
		}
	}()

	err := killContainer(ctx, f, "counter", time.Now().Add(time.Minute))
	if !errors.Is(err, context.Canceled) {
		t.Errorf("killContainer() = %v, want context.Canceled", err)
	}
	if got := f.sentSignals(); !reflect.DeepEqual(got, []string{"SIGTERM"}) {
		t.Errorf("signals delivered = %v, want [SIGTERM]", got)
	}
}

// TestAwaitSessionEnd covers the drain's head start for suspends: an idle
// worker has nothing to wait for, checkpoints that unhost every actor end the
// wait, and a session nothing ends is given up on at the deadline.
func TestAwaitSessionEnd(t *testing.T) {
	defer func(old time.Duration) { drainPollInterval = old }(drainPollInterval)
	drainPollInterval = 5 * time.Millisecond
	ctx := context.Background()
	hosting := func(uids ...string) *AteomService {
		s := &AteomService{actors: map[string]*hostedActor{}}
		for _, uid := range uids {
			s.actors[uid] = &hostedActor{session: &workloadSession{}}
		}
		return s
	}

	t.Run("idle worker", func(t *testing.T) {
		if !hosting().awaitSessionEnd(ctx, time.Now()) {
			t.Error("awaitSessionEnd with no session = false, want true")
		}
	})

	t.Run("suspended while waiting", func(t *testing.T) {
		s := hosting("actor-a", "actor-b")
		go func() {
			// As CheckpointWorkload does, through terminateWorkload: each
			// checkpoint unhosts its actor.
			for _, uid := range []string{"actor-a", "actor-b"} {
				time.Sleep(20 * time.Millisecond)
				if err := s.unhostActor(ctx, uid); err != nil {
					t.Errorf("unhostActor(%s): %v", uid, err)
				}
			}
		}()
		if !s.awaitSessionEnd(ctx, time.Now().Add(10*time.Second)) {
			t.Error("awaitSessionEnd after the checkpoints = false, want true")
		}
	})

	t.Run("never suspended", func(t *testing.T) {
		s := hosting("actor-a")
		start := time.Now()
		if s.awaitSessionEnd(ctx, start.Add(50*time.Millisecond)) {
			t.Error("awaitSessionEnd with a live session = true, want false")
		}
		if waited := time.Since(start); waited < 50*time.Millisecond {
			t.Errorf("awaitSessionEnd returned after %v, before its deadline", waited)
		}
	})

	t.Run("cancelled", func(t *testing.T) {
		s := hosting("actor-a")
		ctx, cancel := context.WithCancel(ctx)
		cancel()
		start := time.Now()
		if s.awaitSessionEnd(ctx, start.Add(10*time.Second)) {
			t.Error("awaitSessionEnd with a cancelled context = true, want false")
		}
		if waited := time.Since(start); waited > 5*time.Second {
			t.Errorf("awaitSessionEnd ignored cancellation for %v", waited)
		}
	})
}
