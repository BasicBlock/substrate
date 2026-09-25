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
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/agent-substrate/substrate/internal/ateompath"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// actorDirAged writes an actor directory with a checkpoint and bundle files,
// every entry last changed age ago.
func actorDirAged(t *testing.T, actorUID string, age time.Duration, extra ...string) {
	t.Helper()
	root := ateompath.ActorPath(actorUID)
	for _, rel := range append([]string{"checkpoint-state/checkpoint.img", "bundles/app/upper/file"}, extra...) {
		path := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	when := time.Now().Add(-age)
	if err := filepath.WalkDir(root, func(path string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return os.Chtimes(path, when, when)
	}); err != nil {
		t.Fatal(err)
	}
}

func TestSweepOrphanedActors(t *testing.T) {
	useTempNodeDirs(t)
	const day = 24 * time.Hour
	actorDirAged(t, "orphan", day)
	actorDirAged(t, "recent", time.Minute)
	actorDirAged(t, "paused", day, "local-checkpoint/snap-1/manifest.json")
	actorDirAged(t, "running", day)
	actorDirAged(t, "in-flight", day)

	s := &AteomHerder{
		systemInfoVolumes: newSystemInfoVolumeRefresher(nil, nil),
		activity: fakeAteoms(t, map[string]func() ([]string, error){
			"pod-1": func() ([]string, error) { return []string{"running"}, nil },
		}),
	}
	defer s.activity.hold("in-flight")()

	removed, err := s.sweepOrphanedActors(context.Background(), 6*time.Hour, time.Now())
	if err != nil {
		t.Fatalf("sweepOrphanedActors: %v", err)
	}
	if !slices.Equal(removed, []string{"orphan"}) {
		t.Errorf("removed %v, want only the orphan", removed)
	}
	for _, kept := range []string{"recent", "paused", "running", "in-flight"} {
		if _, err := os.Stat(ateompath.ActorPath(kept)); err != nil {
			t.Errorf("%s was removed: %v", kept, err)
		}
	}
	if _, err := os.Stat(ateompath.ActorPath("orphan")); !os.IsNotExist(err) {
		t.Errorf("the orphan survived (stat err = %v)", err)
	}
}

func TestSweepOrphanedActorsSweepsNothingItCannotVouchFor(t *testing.T) {
	useTempNodeDirs(t)
	actorDirAged(t, "orphan", 24*time.Hour)
	s := &AteomHerder{
		systemInfoVolumes: newSystemInfoVolumeRefresher(nil, nil),
		activity: fakeAteoms(t, map[string]func() ([]string, error){
			"pod-1": func() ([]string, error) { return nil, status.Error(codes.DeadlineExceeded, "timeout") },
		}),
	}
	if _, err := s.sweepOrphanedActors(context.Background(), 6*time.Hour, time.Now()); err == nil {
		t.Error("sweep succeeded although an ateom could not say what it runs")
	}
	if _, err := os.Stat(ateompath.ActorPath("orphan")); err != nil {
		t.Errorf("an actor dir was removed without knowing it was unused: %v", err)
	}
}
