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
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/agent-substrate/substrate/internal/ateompath"
	"github.com/agent-substrate/substrate/internal/ocispec"
	"github.com/agent-substrate/substrate/internal/proto/ateompb"
)

func TestFsCheckpointTargets(t *testing.T) {
	tests := []struct {
		name       string
		containers []*ateompb.Container
		want       []string
	}{
		{
			name: "pause only",
			want: []string{ocispec.PauseContainer + ":/"},
		},
		{
			name:       "pause plus application containers",
			containers: []*ateompb.Container{{Name: "app"}, {Name: "sidecar"}},
			want:       []string{ocispec.PauseContainer + ":/", "app:/", "sidecar:/"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := fsCheckpointTargets(tt.containers)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("fsCheckpointTargets() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestResolveFSRestorePath(t *testing.T) {
	writeManifest := func(t *testing.T, dir string) {
		t.Helper()
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatalf("MkdirAll(%q): %v", dir, err)
		}
		manifest := filepath.Join(dir, ateompath.GVisorFSCheckpointManifestFile)
		if err := os.WriteFile(manifest, []byte("fake"), 0o600); err != nil {
			t.Fatalf("WriteFile(%q): %v", manifest, err)
		}
	}

	t.Run("standalone Filesystem capture (flat layout)", func(t *testing.T) {
		checkpointDir := t.TempDir()
		writeManifest(t, checkpointDir)

		got, err := resolveFSRestorePath(checkpointDir)
		if err != nil {
			t.Fatalf("resolveFSRestorePath: %v", err)
		}
		if got != checkpointDir {
			t.Errorf("resolveFSRestorePath() = %q, want %q", got, checkpointDir)
		}
	})

	t.Run("Full capture's nested filesystem image wins over a flat one", func(t *testing.T) {
		checkpointDir := t.TempDir()
		nested := ateompath.GVisorFSCheckpointPath(checkpointDir)
		writeManifest(t, nested)

		got, err := resolveFSRestorePath(checkpointDir)
		if err != nil {
			t.Fatalf("resolveFSRestorePath: %v", err)
		}
		if got != nested {
			t.Errorf("resolveFSRestorePath() = %q, want %q", got, nested)
		}
	})

	t.Run("no filesystem checkpoint present", func(t *testing.T) {
		checkpointDir := t.TempDir()

		if _, err := resolveFSRestorePath(checkpointDir); err == nil {
			t.Fatal("resolveFSRestorePath() = nil error, want an error")
		}
	})
}

func TestListSnapshotFilesIncludesNestedFilesystemImage(t *testing.T) {
	dir := t.TempDir()
	for _, f := range []string{"checkpoint.img", "pages_meta.img", "pages.img"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o600); err != nil {
			t.Fatalf("WriteFile(%q): %v", f, err)
		}
	}
	fsDir := ateompath.GVisorFSCheckpointPath(dir)
	if err := os.MkdirAll(fsDir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	for _, f := range []string{ateompath.GVisorFSCheckpointManifestFile, "multitar.img", "pages_meta.img", "pages.img"} {
		if err := os.WriteFile(filepath.Join(fsDir, f), []byte("x"), 0o600); err != nil {
			t.Fatalf("WriteFile(fs/%q): %v", f, err)
		}
	}

	got, err := listSnapshotFiles(dir)
	if err != nil {
		t.Fatalf("listSnapshotFiles: %v", err)
	}
	want := []string{
		"checkpoint.img",
		"fs/fscheckpoint.pb",
		"fs/multitar.img",
		"fs/pages.img",
		"fs/pages_meta.img",
		"pages.img",
		"pages_meta.img",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("listSnapshotFiles() = %v, want %v", got, want)
	}
}

func TestListSnapshotFilesWithoutFilesystemImage(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "checkpoint.img"), []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	got, err := listSnapshotFiles(dir)
	if err != nil {
		t.Fatalf("listSnapshotFiles: %v", err)
	}
	want := []string{"checkpoint.img"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("listSnapshotFiles() = %v, want %v", got, want)
	}
}
