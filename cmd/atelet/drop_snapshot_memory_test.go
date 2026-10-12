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
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/agent-substrate/substrate/internal/apierror"
	"github.com/agent-substrate/substrate/internal/ateattr"
	"github.com/agent-substrate/substrate/internal/proto/ateletpb"
	"github.com/agent-substrate/substrate/internal/resources"
	"google.golang.org/grpc/codes"
)

// failingPutStorage fails stores of the objects whose name contains failOn,
// while failOn is set.
type failingPutStorage struct {
	*orderedObjectStorage
	failOn string
}

func (f *failingPutStorage) PutObject(ctx context.Context, bucket, object string, r io.Reader) error {
	if f.failOn != "" && strings.Contains(object, f.failOn) {
		return errors.New("storage unavailable")
	}
	return f.orderedObjectStorage.PutObject(ctx, bucket, object, r)
}

// uploadedSnapshot uploads a snapshot of the given files and fidelity to the
// store and returns its URI. rootfs and data name the subsets of files.
func uploadedSnapshot(t *testing.T, s *AteomHerder, fidelity string, files, rootfs, data []string) resources.SnapshotURI {
	t.Helper()
	uri, err := resources.ParseSnapshotURI(pausedSnapshotURI)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for _, f := range files {
		if err := os.WriteFile(dir+"/"+f, []byte("contents of "+f), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	rec := sandboxAssetsRecord{
		SandboxClass: "gvisor", PauseImage: testPauseImage, Fidelity: fidelity,
		SnapshotFiles: files, RootfsSnapshotFiles: rootfs, DataSnapshotFiles: data,
	}
	if err := s.uploadSnapshot(t.Context(), uri, dir, &rec, "ate-demo", "counter"); err != nil {
		t.Fatalf("uploadSnapshot: %v", err)
	}
	return uri
}

func storedObject(store *orderedObjectStorage, uri resources.SnapshotURI, name string) ([]byte, bool) {
	objectURI, _ := uri.ObjectURI(name)
	rest := strings.TrimPrefix(objectURI, "gs://")
	bucket, object, _ := strings.Cut(rest, "/")
	store.mu.Lock()
	defer store.mu.Unlock()
	b, ok := store.data[bucket+"/"+object]
	return b, ok
}

func fetchedManifest(t *testing.T, s *AteomHerder, uri resources.SnapshotURI) *sandboxAssetsRecord {
	t.Helper()
	raw, err := s.fetchManifest(t.Context(), uri.String())
	if err != nil {
		t.Fatalf("fetchManifest: %v", err)
	}
	rec, err := unmarshalSandboxRecord(raw)
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

func TestDropSnapshotMemoryDowngradesToRootfs(t *testing.T) {
	store := &orderedObjectStorage{}
	s := newPluginHerder(t, store)
	uri := uploadedSnapshot(t, s, ateattr.SnapshotFidelityMemory,
		[]string{"checkpoint.img", "pages.img", "rootfs.pages.img", "durable-dirs.tar"},
		[]string{"rootfs.pages.img", "durable-dirs.tar"},
		[]string{"durable-dirs.tar"})

	if _, err := s.DropSnapshotMemory(t.Context(), &ateletpb.DropSnapshotMemoryRequest{SnapshotUri: uri.String()}); err != nil {
		t.Fatalf("DropSnapshotMemory: %v", err)
	}

	rec := fetchedManifest(t, s, uri)
	if rec.Fidelity != ateattr.SnapshotFidelityRootfs {
		t.Errorf("manifest fidelity = %q, want rootfs", rec.Fidelity)
	}
	if want := []string{"rootfs.pages.img", "durable-dirs.tar"}; !slices.Equal(rec.SnapshotFiles, want) {
		t.Errorf("manifest files = %v, want %v", rec.SnapshotFiles, want)
	}
	if len(rec.DroppedSnapshotFiles) != 0 {
		t.Errorf("manifest still lists dropped files %v after emptying them", rec.DroppedSnapshotFiles)
	}
	if !slices.Equal(rec.DataSnapshotFiles, []string{"durable-dirs.tar"}) {
		t.Errorf("manifest data files = %v, want the durable tar kept", rec.DataSnapshotFiles)
	}
	for _, name := range []string{"checkpoint.img.zstd", "pages.img.zstd"} {
		got, ok := storedObject(store, uri, name)
		if !ok {
			t.Fatalf("%s is gone; want it emptied in place", name)
		}
		if bytes.Contains(got, []byte("contents of")) {
			t.Errorf("%s still holds the memory image", name)
		}
	}
	for _, name := range []string{"rootfs.pages.img.zstd", "durable-dirs.tar.zstd"} {
		if _, ok := storedObject(store, uri, name); !ok {
			t.Errorf("%s was lost; the downgrade must keep it", name)
		}
	}
}

func TestDropSnapshotMemoryIsIdempotent(t *testing.T) {
	store := &orderedObjectStorage{}
	s := newPluginHerder(t, store)
	uri := uploadedSnapshot(t, s, ateattr.SnapshotFidelityMemory,
		[]string{"checkpoint.img", "rootfs.pages.img"}, []string{"rootfs.pages.img"}, nil)
	for i := 0; i < 2; i++ {
		if _, err := s.DropSnapshotMemory(t.Context(), &ateletpb.DropSnapshotMemoryRequest{SnapshotUri: uri.String()}); err != nil {
			t.Fatalf("DropSnapshotMemory call %d: %v", i+1, err)
		}
	}
	if rec := fetchedManifest(t, s, uri); rec.Fidelity != ateattr.SnapshotFidelityRootfs || !slices.Equal(rec.SnapshotFiles, []string{"rootfs.pages.img"}) {
		t.Errorf("manifest after two calls = %+v, want ROOTFS holding only the root filesystem", rec)
	}
}

// Failing to empty the memory objects does not undo the downgrade, and a repeat
// of the call finishes the emptying.
func TestDropSnapshotMemoryRetriesEmptyingTheMemoryObjects(t *testing.T) {
	store := &failingPutStorage{orderedObjectStorage: &orderedObjectStorage{}}
	s := newPluginHerder(t, store)
	uri := uploadedSnapshot(t, s, ateattr.SnapshotFidelityMemory,
		[]string{"checkpoint.img", "rootfs.pages.img"}, []string{"rootfs.pages.img"}, nil)

	store.failOn = "checkpoint.img"
	if _, err := s.DropSnapshotMemory(t.Context(), &ateletpb.DropSnapshotMemoryRequest{SnapshotUri: uri.String()}); err != nil {
		t.Fatalf("DropSnapshotMemory with an unavailable store: %v, want the downgrade to stand", err)
	}
	rec := fetchedManifest(t, s, uri)
	if rec.Fidelity != ateattr.SnapshotFidelityRootfs || !slices.Equal(rec.DroppedSnapshotFiles, []string{"checkpoint.img"}) {
		t.Fatalf("manifest = %+v, want ROOTFS still listing checkpoint.img as dropped", rec)
	}
	if got, _ := storedObject(store.orderedObjectStorage, uri, "checkpoint.img.zstd"); !bytes.Contains(got, []byte("contents of")) {
		t.Fatal("memory object was emptied despite the failure")
	}

	store.failOn = ""
	if _, err := s.DropSnapshotMemory(t.Context(), &ateletpb.DropSnapshotMemoryRequest{SnapshotUri: uri.String()}); err != nil {
		t.Fatalf("repeated DropSnapshotMemory: %v", err)
	}
	if got, _ := storedObject(store.orderedObjectStorage, uri, "checkpoint.img.zstd"); bytes.Contains(got, []byte("contents of")) {
		t.Error("the repeat did not empty the memory object")
	}
	if rec := fetchedManifest(t, s, uri); len(rec.DroppedSnapshotFiles) != 0 {
		t.Errorf("manifest still lists %v after the repeat finished", rec.DroppedSnapshotFiles)
	}
}

func TestDropSnapshotMemoryRefusals(t *testing.T) {
	for _, tc := range []struct {
		name     string
		fidelity string
		files    []string
		rootfs   []string
	}{
		{"nothing to drop from a VOLUMES snapshot", ateattr.SnapshotFidelityVolumes, []string{"durable-dirs.tar"}, nil},
		{"no root filesystem to keep", ateattr.SnapshotFidelityMemory, []string{"checkpoint.img"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := &orderedObjectStorage{}
			s := newPluginHerder(t, store)
			uri := uploadedSnapshot(t, s, tc.fidelity, tc.files, tc.rootfs, nil)
			_, err := s.DropSnapshotMemory(t.Context(), &ateletpb.DropSnapshotMemoryRequest{SnapshotUri: uri.String()})
			if apierror.Code(err) != codes.FailedPrecondition {
				t.Errorf("DropSnapshotMemory = %v, want FailedPrecondition", err)
			}
			if rec := fetchedManifest(t, s, uri); rec.Fidelity != tc.fidelity || !slices.Equal(rec.SnapshotFiles, tc.files) {
				t.Errorf("a refused call changed the manifest to %+v", rec)
			}
		})
	}
}

func TestDropSnapshotMemoryRejectsABadURI(t *testing.T) {
	s := newPluginHerder(t, &orderedObjectStorage{})
	_, err := s.DropSnapshotMemory(t.Context(), &ateletpb.DropSnapshotMemoryRequest{SnapshotUri: "not-a-snapshot-uri"})
	if apierror.Code(err) != codes.InvalidArgument {
		t.Errorf("DropSnapshotMemory = %v, want InvalidArgument", err)
	}
}
