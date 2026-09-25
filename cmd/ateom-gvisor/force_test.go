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
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/agent-substrate/substrate/internal/ateompath"
	"github.com/agent-substrate/substrate/internal/ocispec"
)

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
	actorsDir := ateompath.ActorsDir
	ateompath.ActorsDir = t.TempDir()
	t.Cleanup(func() { ateompath.ActorsDir = actorsDir })

	const uid, other = "actor-uid", "other-uid"
	procRoot, cgroupRoot := t.TempDir(), t.TempDir()
	root := ateompath.RunSCStateDir(uid)
	fakeProc(t, procRoot, 101, "/runsc", "-log-format", "json", "-root", root, "list", "-quiet")
	fakeProc(t, procRoot, 102, "runsc-sandbox", "--root="+root, "boot")
	fakeProc(t, procRoot, 103, "/runsc", "-root", ateompath.RunSCStateDir(other), "state", "pause")
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
	f := sandboxForcer{procRoot: procRoot, cgroupRoot: cgroupRoot, kill: func(pid int) error {
		killed = append(killed, pid)
		// The reaper has yet to collect it.
		return os.WriteFile(filepath.Join(procRoot, strconv.Itoa(pid), "status"), []byte("State:\tZ (zombie)\n"), 0o644)
	}}
	if err := f.forceStop(context.Background(), uid, []string{"app"}); err != nil {
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
	actorsDir := ateompath.ActorsDir
	ateompath.ActorsDir = t.TempDir()
	t.Cleanup(func() { ateompath.ActorsDir = actorsDir })

	f := sandboxForcer{procRoot: t.TempDir(), cgroupRoot: t.TempDir(), kill: func(int) error {
		t.Error("killed a process when none was the actor's")
		return nil
	}}
	if err := f.forceStop(context.Background(), "actor-uid", []string{"app"}); err != nil {
		t.Fatalf("forceStop with no sandbox left: %v", err)
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
