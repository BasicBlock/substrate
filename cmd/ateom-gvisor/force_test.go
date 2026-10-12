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
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/agent-substrate/substrate/internal/ocispec"
	"github.com/agent-substrate/substrate/internal/proto/ateompb"
	"github.com/agent-substrate/substrate/internal/roottest"
	"golang.org/x/sys/unix"
)

// noUnmount is an unmount that finds no mounts to detach.
func noUnmount(string) error { return nil }

// fakeProc writes a /proc entry for pid with args as its command line; a
// killed process turns into a zombie, as the reaper would find it.
func fakeProc(t *testing.T, root string, pid int, args ...string) {
	t.Helper()
	dir := filepath.Join(root, strconv.Itoa(pid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cmdline"), []byte(strings.Join(args, "\x00")+"\x00"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "status"), []byte("Name:\trunsc\nState:\tS (sleeping)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestForceStopKillsTheActorsSandboxOnly(t *testing.T) {
	actorsRoot := t.TempDir()
	const uid, other = "actor-uid", "other-uid"
	actorDirs := &ateompb.ActorDirs{RootDir: filepath.Join(actorsRoot, uid)}
	otherDirs := &ateompb.ActorDirs{RootDir: filepath.Join(actorsRoot, other)}

	procRoot, cgroupRoot := t.TempDir(), t.TempDir()
	root := runscStateDir(actorDirs)
	fakeProc(t, procRoot, 101, "/runsc", "-log-format", "json", "-root", root, "list", "-quiet")
	fakeProc(t, procRoot, 102, "runsc-sandbox", "--root="+root, "boot")
	fakeProc(t, procRoot, 103, "/runsc", "-root", runscStateDir(otherDirs), "state", "pause")
	fakeProc(t, procRoot, 104, "/ateom-gvisor")
	for _, name := range []string{"app", ocispec.PauseContainer} {
		leaf := filepath.Join(cgroupRoot, ocispec.GVisorCgroupLeaf(uid, name))
		if err := os.MkdirAll(leaf, 0o755); err != nil {
			t.Fatal(err)
		}
		// cgroupfs provides both; KillLeafUnder writes the one and polls the other.
		for file, content := range map[string]string{"cgroup.kill": "", "cgroup.events": "populated 0\nfrozen 0\n"} {
			if err := os.WriteFile(filepath.Join(leaf, file), []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := os.MkdirAll(filepath.Join(root, "stale-container"), 0o700); err != nil {
		t.Fatal(err)
	}

	var killed []int
	f := sandboxForcer{procRoot: procRoot, cgroupRoot: cgroupRoot, unmount: noUnmount, kill: func(pid int) error {
		killed = append(killed, pid)
		// The reaper has yet to collect it.
		return os.WriteFile(filepath.Join(procRoot, strconv.Itoa(pid), "status"), []byte("State:\tZ (zombie)\n"), 0o644)
	}}
	if err := f.forceStop(context.Background(), uid, actorDirs, []string{"app"}); err != nil {
		t.Fatalf("forceStop: %v", err)
	}

	slices.Sort(killed)
	if !slices.Equal(killed, []int{101, 102}) {
		t.Errorf("killed %v, want only the actor's runsc processes 101 and 102", killed)
	}
	for _, name := range []string{"app", ocispec.PauseContainer} {
		got, err := os.ReadFile(filepath.Join(cgroupRoot, ocispec.GVisorCgroupLeaf(uid, name), "cgroup.kill"))
		if err != nil || string(got) != "1" {
			t.Errorf("%s cgroup.kill = %q, %v; want 1", name, got, err)
		}
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Errorf("runsc root holds %v (%v), want it emptied", entries, err)
	}
}

func TestForceStopWithNothingLeft(t *testing.T) {
	actorDirs := &ateompb.ActorDirs{RootDir: filepath.Join(t.TempDir(), "actor-uid")}

	f := sandboxForcer{procRoot: t.TempDir(), cgroupRoot: t.TempDir(), unmount: noUnmount, kill: func(int) error {
		t.Error("killed a process when none was the actor's")
		return nil
	}}
	if err := f.forceStop(context.Background(), "actor-uid", actorDirs, []string{"app"}); err != nil {
		t.Fatalf("forceStop with no sandbox left: %v", err)
	}
}

// runscRootWithNullNetns makes the runsc root of a fresh actor, holding the
// null-netns file runsc keeps there (a mount point once runsc has run), and
// returns the root and the file.
func runscRootWithNullNetns(t *testing.T) (actorDirs *ateompb.ActorDirs, root, nullNetns string) {
	t.Helper()
	actorDirs = &ateompb.ActorDirs{RootDir: filepath.Join(t.TempDir(), "actor-uid")}
	root = runscStateDir(actorDirs)
	nullNetns = filepath.Join(root, "null-netns")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(nullNetns, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	return actorDirs, root, nullNetns
}

// forcerWithNothingToKill is a forcer that finds no processes or cgroups of
// the actor, so that only what it does to the runsc root is under test.
func forcerWithNothingToKill(t *testing.T, unmount func(dir string) error) sandboxForcer {
	t.Helper()
	return sandboxForcer{procRoot: t.TempDir(), cgroupRoot: t.TempDir(), unmount: unmount, kill: func(pid int) error {
		t.Errorf("killed process %d when none was the actor's", pid)
		return nil
	}}
}

// runsc leaves a mount in its root, and a mount point cannot be unlinked, so
// the mounts must be detached before the root is removed. Which root is
// detached matters too: it is the actor's own.
func TestForceStopDetachesTheRunscRootsMountsBeforeRemovingIt(t *testing.T) {
	actorDirs, root, nullNetns := runscRootWithNullNetns(t)

	var detached []string
	f := forcerWithNothingToKill(t, func(dir string) error {
		if _, err := os.Lstat(nullNetns); err != nil {
			t.Errorf("the runsc root was emptied before its mounts were detached: %v", err)
		}
		detached = append(detached, dir)
		return nil
	})
	if err := f.forceStop(context.Background(), "actor-uid", actorDirs, []string{"app"}); err != nil {
		t.Fatalf("forceStop: %v", err)
	}

	if !slices.Equal(detached, []string{root}) {
		t.Errorf("detached mounts under %v, want only the actor's runsc root %q", detached, root)
	}
	if entries, err := os.ReadDir(root); err != nil || len(entries) != 0 {
		t.Errorf("runsc root holds %v (%v), want it emptied and recreated", entries, err)
	}
}

// A mount that will not detach is an error of the forced teardown, as any
// other step's is, but does not stop the root from being emptied.
func TestForceStopReportsMountsItCannotDetachAndStillEmptiesTheRunscRoot(t *testing.T) {
	actorDirs, root, nullNetns := runscRootWithNullNetns(t)

	f := forcerWithNothingToKill(t, func(string) error { return errors.New("umount2: operation not permitted") })
	err := f.forceStop(context.Background(), "actor-uid", actorDirs, []string{"app"})

	if err == nil || !strings.Contains(err.Error(), "while unmounting under runsc state "+root) {
		t.Errorf("forceStop = %v, want it to report the mounts it could not detach", err)
	}
	if _, statErr := os.Lstat(nullNetns); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("null-netns survived the forced teardown (Lstat err = %v)", statErr)
	}
}

// The production failure, with a real mount: unlinking a runsc root whose
// null-netns is mounted fails with EBUSY, and the forcer, which detaches the
// mounts first, removes it.
func TestForceStopRemovesARunscRootWhoseNullNetnsIsMounted(t *testing.T) {
	roottest.Require(t, "bind mount")
	actorDirs, root, nullNetns := runscRootWithNullNetns(t)
	source := filepath.Join(t.TempDir(), "netns")
	if err := os.WriteFile(source, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount(source, nullNetns, "", unix.MS_BIND, ""); err != nil {
		t.Skipf("cannot bind mount here: %v", err)
	}
	t.Cleanup(func() { _ = unix.Unmount(nullNetns, unix.MNT_DETACH) })
	if err := os.RemoveAll(root); !errors.Is(err, syscall.EBUSY) {
		t.Skipf("this environment does not pin a mounted file (RemoveAll err = %v), so there is no failure to cure", err)
	}

	f := newSandboxForcer(t.TempDir())
	f.procRoot = t.TempDir()
	if err := f.forceStop(context.Background(), "actor-uid", actorDirs, []string{"app"}); err != nil {
		t.Fatalf("forceStop: %v", err)
	}
	if entries, err := os.ReadDir(root); err != nil || len(entries) != 0 {
		t.Errorf("runsc root holds %v (%v), want it emptied and recreated", entries, err)
	}
}

func TestNamesRunscRoot(t *testing.T) {
	const root = "/var/lib/ateom-gvisor/actors/u/runsc-state"
	for _, tc := range []struct {
		args []string
		want bool
	}{
		{[]string{"runsc", "-root", root, "list"}, true},
		{[]string{"runsc", "--root", root, "list"}, true},
		{[]string{"runsc-gofer", "--root=" + root, "gofer"}, true},
		{[]string{"runsc", "-root", root + "-other", "list"}, false},
		{[]string{"runsc", "-root"}, false},
		{[]string{"sh", "-c", "echo " + root}, false},
	} {
		if got := namesRunscRoot(tc.args, root); got != tc.want {
			t.Errorf("namesRunscRoot(%q) = %v, want %v", tc.args, got, tc.want)
		}
	}
}
