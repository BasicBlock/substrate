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
	"encoding/json"
	"slices"
	"testing"

	"github.com/agent-substrate/substrate/internal/ateattr"
	"github.com/agent-substrate/substrate/internal/ateompath"
	"github.com/agent-substrate/substrate/internal/proto/ateletpb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// gvisorFSManifestFile is the relative snapshot-file name of a gVisor
// filesystem image's manifest, as it appears in a sandboxAssetsRecord's
// SnapshotFiles.
var gvisorFSManifestFile = ateompath.GVisorFSCheckpointDir + "/" + ateompath.GVisorFSCheckpointManifestFile

// newRecordingSnapshot builds a recordingObjectStorage holding rec's manifest
// and one object per rec.SnapshotFiles entry at testSnapshotPath, keyed the
// way uploadSnapshot writes them.
func newRecordingSnapshot(t *testing.T, rec sandboxAssetsRecord) *recordingObjectStorage {
	t.Helper()
	manifest, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshaling manifest: %v", err)
	}
	objects := map[string][]byte{testSnapshotPath + "/" + sandboxManifestName: manifest}
	for _, f := range rec.SnapshotFiles {
		objects[testSnapshotPath+"/"+f+".zstd"] = []byte("content of " + f)
	}
	return &recordingObjectStorage{objects: objects}
}

func TestDropSnapshotMemory(t *testing.T) {
	ctx := context.Background()

	t.Run("narrows a full gvisor snapshot and deletes the memory objects", func(t *testing.T) {
		store := newRecordingSnapshot(t, sandboxAssetsRecord{
			SandboxClass: "gvisor",
			PauseImage:   testPauseImage,
			SnapshotFiles: []string{
				"checkpoint.img", "pages_meta.img", "pages.img",
				gvisorFSManifestFile, ateompath.DurableDirTarFile,
			},
			Scope: ateattr.SnapshotScopeFull,
		})
		s := &AteomHerder{gcsClient: store}

		if _, err := s.DropSnapshotMemory(ctx, &ateletpb.DropSnapshotMemoryRequest{SnapshotUri: testSnapshotURI}); err != nil {
			t.Fatalf("DropSnapshotMemory: %v", err)
		}

		rec, err := unmarshalSandboxRecord(store.objects[testSnapshotPath+"/"+sandboxManifestName])
		if err != nil {
			t.Fatalf("unmarshalSandboxRecord: %v", err)
		}
		if rec.Scope != ateattr.SnapshotScopeFilesystem {
			t.Errorf("rewritten manifest scope = %q, want %q", rec.Scope, ateattr.SnapshotScopeFilesystem)
		}
		wantFiles := []string{gvisorFSManifestFile, ateompath.DurableDirTarFile}
		if !slices.Equal(rec.SnapshotFiles, wantFiles) {
			t.Errorf("rewritten manifest files = %v, want %v", rec.SnapshotFiles, wantFiles)
		}
		for _, gone := range []string{"checkpoint.img", "pages_meta.img", "pages.img"} {
			if _, ok := store.objects[testSnapshotPath+"/"+gone+".zstd"]; ok {
				t.Errorf("memory object %q still present after DropSnapshotMemory", gone)
			}
		}
		for _, kept := range wantFiles {
			if _, ok := store.objects[testSnapshotPath+"/"+kept+".zstd"]; !ok {
				t.Errorf("kept object %q missing after DropSnapshotMemory", kept)
			}
		}
	})

	t.Run("idempotent: an already-filesystem snapshot succeeds without changes", func(t *testing.T) {
		rec := sandboxAssetsRecord{
			SandboxClass:  "gvisor",
			PauseImage:    testPauseImage,
			SnapshotFiles: []string{gvisorFSManifestFile, ateompath.DurableDirTarFile},
			Scope:         ateattr.SnapshotScopeFilesystem,
		}
		store := newRecordingSnapshot(t, rec)
		before := len(store.objects)
		s := &AteomHerder{gcsClient: store}

		if _, err := s.DropSnapshotMemory(ctx, &ateletpb.DropSnapshotMemoryRequest{SnapshotUri: testSnapshotURI}); err != nil {
			t.Fatalf("DropSnapshotMemory: %v", err)
		}
		if got := len(store.objects); got != before {
			t.Errorf("object count changed from %d to %d for an already-narrowed snapshot", before, got)
		}
	})

	t.Run("data scope has no memory to drop", func(t *testing.T) {
		store := newRecordingSnapshot(t, sandboxAssetsRecord{
			SandboxClass:  "gvisor",
			PauseImage:    testPauseImage,
			SnapshotFiles: []string{ateompath.DurableDirTarFile},
			Scope:         ateattr.SnapshotScopeData,
		})
		s := &AteomHerder{gcsClient: store}

		_, err := s.DropSnapshotMemory(ctx, &ateletpb.DropSnapshotMemoryRequest{SnapshotUri: testSnapshotURI})
		if got := status.Code(err); got != codes.FailedPrecondition {
			t.Fatalf("status.Code = %v (err %v), want FailedPrecondition", got, err)
		}
	})

	t.Run("full capture without a filesystem image is refused", func(t *testing.T) {
		store := newRecordingSnapshot(t, sandboxAssetsRecord{
			SandboxClass:  "gvisor",
			PauseImage:    testPauseImage,
			SnapshotFiles: []string{"checkpoint.img", "pages_meta.img", "pages.img"},
			Scope:         ateattr.SnapshotScopeFull,
		})
		s := &AteomHerder{gcsClient: store}

		_, err := s.DropSnapshotMemory(ctx, &ateletpb.DropSnapshotMemoryRequest{SnapshotUri: testSnapshotURI})
		if got := status.Code(err); got != codes.FailedPrecondition {
			t.Fatalf("status.Code = %v (err %v), want FailedPrecondition", got, err)
		}
		// Refusing must not touch anything already stored.
		if len(store.objects) != 4 {
			t.Errorf("object count = %d, want unchanged at 4", len(store.objects))
		}
	})

	t.Run("empty snapshot_uri is rejected", func(t *testing.T) {
		s := &AteomHerder{gcsClient: &recordingObjectStorage{}}
		_, err := s.DropSnapshotMemory(ctx, &ateletpb.DropSnapshotMemoryRequest{})
		if got := status.Code(err); got != codes.InvalidArgument {
			t.Fatalf("status.Code = %v (err %v), want InvalidArgument", got, err)
		}
	})
}
