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
	"maps"
	"slices"
	"testing"
	"time"

	"github.com/agent-substrate/substrate/internal/proto/ateompb"
)

// fakeRunsc stands in for *runsc. containers is the set runsc has a record of;
// calls logs every command.
type fakeRunsc struct {
	containers map[string]bool
	calls      []string
}

func newFakeRunsc(containers ...string) *fakeRunsc {
	f := &fakeRunsc{containers: map[string]bool{}}
	for _, name := range containers {
		f.containers[name] = true
	}
	return f
}

func (f *fakeRunsc) cmdState(_ context.Context, name string) error {
	f.calls = append(f.calls, "state "+name)
	if !f.containers[name] {
		return errors.New("exit status 128")
	}
	return nil
}

func (f *fakeRunsc) cmdDelete(_ context.Context, name string) error {
	f.calls = append(f.calls, "delete "+name)
	if !f.containers[name] {
		return errors.New("exit status 128")
	}
	delete(f.containers, name)
	return nil
}

func (f *fakeRunsc) cmdKill(_ context.Context, name, signal string) error {
	f.calls = append(f.calls, "kill "+name+" "+signal)
	return nil
}

func (f *fakeRunsc) cmdWait(_ context.Context, name string) error {
	f.calls = append(f.calls, "wait "+name)
	return nil
}

func (f *fakeRunsc) cmdList(context.Context) ([]string, error) {
	f.calls = append(f.calls, "list")
	return slices.Sorted(maps.Keys(f.containers)), nil
}

func assertCalls(t *testing.T, f *fakeRunsc, want ...string) {
	t.Helper()
	if !slices.Equal(f.calls, want) {
		t.Errorf("runsc calls = %v, want %v", f.calls, want)
	}
}

var appContainers = []*ateompb.Container{{Name: "app"}}

func TestCleanupContainers_DeletesEveryContainerRunscKnows(t *testing.T) {
	f := newFakeRunsc("app", "_pause")

	if err := cleanupContainers(context.Background(), f, appContainers); err != nil {
		t.Fatalf("cleanupContainers: %v", err)
	}

	// Happy path: no `runsc list` at all.
	assertCalls(t, f, "state app", "state _pause", "delete app", "delete _pause")
	if len(f.containers) != 0 {
		t.Errorf("containers survived cleanup: %v", slices.Sorted(maps.Keys(f.containers)))
	}
	if err := cleanupContainers(context.Background(), f, appContainers); err != nil {
		t.Fatalf("repeated cleanupContainers: %v", err)
	}
}

func TestCleanupContainers_SkipsContainersRunscHasNoRecordOf(t *testing.T) {
	f := newFakeRunsc("app")

	if err := cleanupContainers(context.Background(), f, appContainers); err != nil {
		t.Fatalf("cleanupContainers: %v", err)
	}

	assertCalls(t, f, "state app", "state _pause", "list", "delete app")
}

func TestCleanupContainers_SucceedsWhenEverythingIsAlreadyGone(t *testing.T) {
	f := newFakeRunsc()

	if err := cleanupContainers(context.Background(), f, appContainers); err != nil {
		t.Fatalf("cleanupContainers: %v", err)
	}

	assertCalls(t, f, "state app", "list", "state _pause", "list")
}

// The pause container is the sandbox: it must outlive the deletes of the
// containers inside it, so stopping the actor leaves it to cleanup.
func TestStopContainersLeavesTheSandboxToCleanup(t *testing.T) {
	f := newFakeRunsc()
	stopContainers(context.Background(), f, appContainers)
	var want []string
	for _, c := range appContainers {
		want = append(want, "kill "+c.GetName()+" SIGKILL", "wait "+c.GetName())
	}
	assertCalls(t, f, want...)
}

// hungWaitRunsc is a fakeRunsc whose `runsc wait` blocks until its context
// ends, as it does when the sandbox it waits on never answers.
type hungWaitRunsc struct{ *fakeRunsc }

func (f hungWaitRunsc) cmdWait(ctx context.Context, name string) error {
	f.calls = append(f.calls, "wait "+name)
	<-ctx.Done()
	return ctx.Err()
}

// shortenContainerKillTimeout makes a wait after SIGKILL give up in
// milliseconds rather than seconds.
func shortenContainerKillTimeout(t *testing.T) {
	t.Helper()
	orig := containerKillTimeout
	containerKillTimeout = 20 * time.Millisecond
	t.Cleanup(func() { containerKillTimeout = orig })
}

// A container that does not stop must not hold up the ones after it, nor leave
// the caller's deadline spent before the deletes run.
func TestStopContainersBoundsEachWait(t *testing.T) {
	shortenContainerKillTimeout(t)
	f := hungWaitRunsc{newFakeRunsc("one", "two", "_pause")}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stopContainers(ctx, f, []*ateompb.Container{{Name: "one"}, {Name: "two"}})

	assertCalls(t, f.fakeRunsc, "kill one SIGKILL", "wait one", "kill two SIGKILL", "wait two")
	if err := ctx.Err(); err != nil {
		t.Errorf("stopping the containers spent the caller's deadline: %v", err)
	}
}

// A MEMORY checkpoint has already killed the sandbox, and a `runsc wait` on it
// is never answered: teardown deletes the containers without stopping them.
func TestTeardownContainers_EndedSandboxIsNotStopped(t *testing.T) {
	shortenContainerKillTimeout(t)
	f := hungWaitRunsc{newFakeRunsc("app", "_pause")}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := teardownContainers(ctx, f, appContainers, sandboxEnded); err != nil {
		t.Fatalf("teardownContainers: %v", err)
	}

	assertCalls(t, f.fakeRunsc, "state app", "state _pause", "delete app", "delete _pause")
	if len(f.containers) != 0 {
		t.Errorf("containers survived teardown: %v", slices.Sorted(maps.Keys(f.containers)))
	}
	if err := ctx.Err(); err != nil {
		t.Errorf("teardown spent its deadline: %v", err)
	}
}

// Terminating a live sandbox still kills each container and waits for it to
// stop before deleting anything.
func TestTeardownContainers_LiveSandboxIsStoppedThenDeleted(t *testing.T) {
	f := newFakeRunsc("app", "_pause")

	if err := teardownContainers(context.Background(), f, appContainers, sandboxLive); err != nil {
		t.Fatalf("teardownContainers: %v", err)
	}

	assertCalls(t, f, "kill app SIGKILL", "wait app", "state app", "state _pause", "delete app", "delete _pause")
	if len(f.containers) != 0 {
		t.Errorf("containers survived teardown: %v", slices.Sorted(maps.Keys(f.containers)))
	}
}

// A live sandbox that stops answering costs one bounded wait per container,
// not the whole teardown deadline, so the deletes still run.
func TestTeardownContainers_LiveSandboxWithHungWaitIsStillDeleted(t *testing.T) {
	shortenContainerKillTimeout(t)
	f := hungWaitRunsc{newFakeRunsc("app", "_pause")}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := teardownContainers(ctx, f, appContainers, sandboxLive); err != nil {
		t.Fatalf("teardownContainers: %v", err)
	}

	assertCalls(t, f.fakeRunsc, "kill app SIGKILL", "wait app", "state app", "state _pause", "delete app", "delete _pause")
	if len(f.containers) != 0 {
		t.Errorf("containers survived teardown: %v", slices.Sorted(maps.Keys(f.containers)))
	}
	if err := ctx.Err(); err != nil {
		t.Errorf("the hung wait spent the teardown deadline: %v", err)
	}
}

// A MEMORY checkpoint and a ROOTFS one (fscheckpoint without -leave-running)
// end the sandbox; a VOLUMES one resumes it.
func TestSandboxAfterCheckpoint(t *testing.T) {
	for _, tc := range []struct {
		fidelity ateompb.SnapshotFidelity
		want     sandboxState
	}{
		{ateompb.SnapshotFidelity_SNAPSHOT_FIDELITY_MEMORY, sandboxEnded},
		{ateompb.SnapshotFidelity_SNAPSHOT_FIDELITY_VOLUMES, sandboxLive},
		{ateompb.SnapshotFidelity_SNAPSHOT_FIDELITY_UNSPECIFIED, sandboxLive},
	} {
		if got := sandboxAfterCheckpoint(tc.fidelity); got != tc.want {
			t.Errorf("sandboxAfterCheckpoint(%v) = %v, want %v", tc.fidelity, got, tc.want)
		}
	}
}
