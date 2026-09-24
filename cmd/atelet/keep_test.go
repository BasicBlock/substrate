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
	"testing"

	"github.com/agent-substrate/substrate/internal/ateompath"
	"github.com/agent-substrate/substrate/internal/resources"
)

// TestKeepCheckpointOnNode verifies a checkpoint that failed to upload lands
// as a local snapshot named after its in-progress snapshot URI, manifest
// included, where a paused resume or a later suspend's upload finds it.
func TestKeepCheckpointOnNode(t *testing.T) {
	actorsDir := ateompath.ActorsDir
	ateompath.ActorsDir = t.TempDir()
	t.Cleanup(func() { ateompath.ActorsDir = actorsDir })

	req := validCheckpointRequest()
	checkpointDir := ateompath.CheckpointStateDir(req.GetActorUid())
	rec := &sandboxAssetsRecord{
		SandboxClass:  "gvisor",
		PauseImage:    testPauseImage,
		Scope:         "full",
		SnapshotFiles: []string{"checkpoint.img", "fs/fscheckpoint.pb"},
	}
	writeLocalSnapshot(t, checkpointDir, sandboxAssetsRecord{}, map[string]string{
		"checkpoint.img":     "memory",
		"fs/fscheckpoint.pb": "filesystem",
	})

	s := &AteomHerder{gcsClient: &recordingObjectStorage{}}
	if err := s.keepCheckpointOnNode(context.Background(), req, checkpointDir, rec); err != nil {
		t.Fatalf("keepCheckpointOnNode: %v", err)
	}

	uri, err := resources.ParseSnapshotURI(testSnapshotURI)
	if err != nil {
		t.Fatal(err)
	}
	kept := ateompath.LocalSnapshotDir(req.GetActorUid(), uri.Name())
	for name, want := range map[string]string{"checkpoint.img": "memory", "fs/fscheckpoint.pb": "filesystem"} {
		got, err := os.ReadFile(filepath.Join(kept, name))
		if err != nil {
			t.Fatalf("kept snapshot is missing %s: %v", name, err)
		}
		if string(got) != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	manifest, err := os.ReadFile(filepath.Join(kept, sandboxManifestName))
	if err != nil {
		t.Fatalf("kept snapshot has no manifest: %v", err)
	}
	got, err := unmarshalSandboxRecord(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if got.Scope != "full" || len(got.SnapshotFiles) != 2 {
		t.Errorf("manifest = %+v, want the checkpoint's scope and files", got)
	}
}

func TestKeepCheckpointOnNodeRefusesGoldenActors(t *testing.T) {
	actorsDir := ateompath.ActorsDir
	ateompath.ActorsDir = t.TempDir()
	t.Cleanup(func() { ateompath.ActorsDir = actorsDir })

	req := validCheckpointRequest()
	req.Atespace = resources.GoldenActorAtespace
	s := &AteomHerder{gcsClient: &recordingObjectStorage{}}
	if err := s.keepCheckpointOnNode(context.Background(), req, ateompath.CheckpointStateDir(req.GetActorUid()), &sandboxAssetsRecord{}); err == nil {
		t.Fatal("kept a golden actor's checkpoint, which can never be paused")
	}
	if entries, _ := os.ReadDir(ateompath.LocalCheckpointsDir(req.GetActorUid())); len(entries) != 0 {
		t.Errorf("wrote %v for a golden actor", entries)
	}
}
