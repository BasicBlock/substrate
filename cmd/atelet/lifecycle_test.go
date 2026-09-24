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
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/agent-substrate/substrate/internal/ateompath"
	"github.com/agent-substrate/substrate/internal/proto/ateletpb"
	"github.com/agent-substrate/substrate/internal/proto/ateompb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// useTempNodeDirs roots atelet's on-node state in temp directories so a test
// can drive the real filesystem layout. Not parallel-safe: the paths are
// process-global.
func useTempNodeDirs(t *testing.T) {
	t.Helper()
	root := t.TempDir()
	origActors, origStatic := ateompath.ActorsDir, ateompath.StaticFilesDir
	ateompath.ActorsDir = filepath.Join(root, "actors")
	ateompath.StaticFilesDir = filepath.Join(root, "static-files")
	t.Cleanup(func() {
		ateompath.ActorsDir, ateompath.StaticFilesDir = origActors, origStatic
	})
}

// fakeAteom is a fake ateom in a worker pod. It writes the files a
// real checkpoint would leave in the checkpoint-state dir, and reads back
// what a restore was handed.
type fakeAteom struct {
	ateompb.UnimplementedAteomServer
	// snapshotFiles are written at checkpoint and reported back to atelet as
	// the exact set the snapshot consists of.
	snapshotFiles map[string]string
	// restored holds the file contents staged into the restore-state dir by
	// the most recent RestoreWorkload.
	restored map[string]string
	// failRestoreScope, when not SNAPSHOT_SCOPE_UNSPECIFIED, makes
	// RestoreWorkload fail for that one scope and succeed for any other, so a
	// test can simulate a Full restore's memory restore failing (e.g. an
	// incompatible CPU feature set) and observe atelet's Filesystem fallback.
	failRestoreScope ateompb.SnapshotScope
	// restoreScopes records, in order, every scope RestoreWorkload was
	// called with, so a test can assert a fallback actually retried with a
	// different scope rather than just succeeding on the first try.
	restoreScopes []ateompb.SnapshotScope
}

func (f *fakeAteom) RunWorkload(context.Context, *ateompb.RunWorkloadRequest) (*ateompb.RunWorkloadResponse, error) {
	return &ateompb.RunWorkloadResponse{}, nil
}

func (f *fakeAteom) CheckpointWorkload(_ context.Context, req *ateompb.CheckpointWorkloadRequest) (*ateompb.CheckpointWorkloadResponse, error) {
	dir := ateompath.CheckpointStateDir(req.GetActorUid())
	names := make([]string, 0, len(f.snapshotFiles))
	for name, body := range f.snapshotFiles {
		// A gVisor Full checkpoint's filesystem image nests under a
		// subdirectory (ateompath.GVisorFSCheckpointDir); create it.
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	return &ateompb.CheckpointWorkloadResponse{SnapshotFiles: names}, nil
}

func (f *fakeAteom) RestoreWorkload(_ context.Context, req *ateompb.RestoreWorkloadRequest) (*ateompb.RestoreWorkloadResponse, error) {
	f.restoreScopes = append(f.restoreScopes, req.GetScope())
	if f.failRestoreScope != ateompb.SnapshotScope_SNAPSHOT_SCOPE_UNSPECIFIED && req.GetScope() == f.failRestoreScope {
		return nil, status.Error(codes.Internal, "simulated runsc restore failure (e.g. an incompatible CPU feature set)")
	}
	dir := ateompath.RestoreStateDir(req.GetActorUid())
	f.restored = map[string]string{}
	for name := range f.snapshotFiles {
		body, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		f.restored[name] = string(body)
	}
	return &ateompb.RestoreWorkloadResponse{}, nil
}

func (f *fakeAteom) TerminateWorkload(context.Context, *ateompb.TerminateWorkloadRequest) (*ateompb.TerminateWorkloadResponse, error) {
	return &ateompb.TerminateWorkloadResponse{}, nil
}

// serveFakeAteom serves ateom on a unix socket and points atelet's dialer at
// it. The socket lives in its own short temp dir.
func serveFakeAteom(t *testing.T, f *fakeAteom) {
	t.Helper()
	dir, err := os.MkdirTemp("", "ateom-")
	if err != nil {
		t.Fatalf("creating socket dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	sock := filepath.Join(dir, "ateom.sock")
	lis, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listening on %q: %v", sock, err)
	}
	srv := grpc.NewServer()
	ateompb.RegisterAteomServer(srv, f)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	orig := ateomSocketPath
	ateomSocketPath = func(string) string { return sock }
	t.Cleanup(func() { ateomSocketPath = orig })
}

// TestLocalSnapshotGC walks an actor through
// run -> pause -> resume -> terminate over atelet's RPC surface and ensures that
// the local snapshot is garbage collected after the actor is terminated.
func TestLocalSnapshotGC(t *testing.T) {
	useTempNodeDirs(t)
	ctx := t.Context()

	const (
		atespace     = "ate-demo"
		actorName    = "counter"
		actorUID     = "actor-uid-1"
		ateomUID     = "ateom-uid-1"
		snapshotName = "pause-snap-1"
	)

	ateom := &fakeAteom{snapshotFiles: map[string]string{"checkpoint.img": "guest-memory"}}
	serveFakeAteom(t, ateom)

	host := imageVolumeTestRegistry(t)
	image := host + "/actor:v1"
	pushTestImage(t, image, singleFileLayer(t, "bin/app", "app"))

	// A single "runsc" asset served from a fake bucket: enough to exercise the
	// content-addressed asset fetch without a gVisor release tarball.
	runsc := []byte("runsc binary")
	s := &AteomHerder{
		ateomDialer:       newAteomDialer(1),
		imageCache:        newImageVolumeStore(t),
		anonGCSClient:     fakeObjectStorage{data: runsc},
		systemInfoVolumes: newSystemInfoVolumeRefresher(nil, nil),
	}
	sandboxAssets := &ateletpb.SandboxAssets{
		SandboxClass: "gvisor",
		PauseImage:   image,
		Assets: map[string]*ateletpb.ArchAssets{
			runtime.GOARCH: {Files: map[string]*ateletpb.AssetFile{
				runscAssetName: {
					Url:    "gs://test-bucket/runsc",
					Sha256: fmt.Sprintf("%x", sha256.Sum256(runsc)),
				},
			}},
		},
	}
	spec := &ateletpb.WorkloadSpec{
		Containers: []*ateletpb.Container{{Name: "app", Image: image, Command: []string{"/bin/app"}}},
	}

	if _, err := s.Run(ctx, &ateletpb.RunRequest{
		Atespace:              atespace,
		ActorName:             actorName,
		ActorUid:              actorUID,
		ActorTemplateAtespace: "default",
		ActorTemplateName:     "counter",
		TargetAteomUid:        ateomUID,
		SandboxAssets:         sandboxAssets,
		Spec:                  spec,
	}); err != nil {
		t.Fatalf("Run: %v", err)
	}

	// Pause: a local checkpoint, which leaves the snapshot on this node.
	if _, err := s.Checkpoint(ctx, &ateletpb.CheckpointRequest{
		Atespace:              atespace,
		ActorName:             actorName,
		ActorUid:              actorUID,
		ActorTemplateAtespace: "default",
		ActorTemplateName:     "counter",
		TargetAteomUid:        ateomUID,
		Spec:                  spec,
		Scope:                 ateletpb.SnapshotScope_SNAPSHOT_SCOPE_FULL,
		Type:                  ateletpb.CheckpointType_CHECKPOINT_TYPE_LOCAL,
		Config: &ateletpb.CheckpointRequest_LocalConfig{
			LocalConfig: &ateletpb.LocalCheckpointConfiguration{SnapshotName: snapshotName},
		},
	}); err != nil {
		t.Fatalf("Checkpoint: %v", err)
	}
	snapshotFile := filepath.Join(ateompath.LocalSnapshotDir(actorUID, snapshotName), "checkpoint.img")
	if _, err := os.Stat(snapshotFile); err != nil {
		t.Fatalf("pause did not write the local snapshot: %v", err)
	}

	// Resume: restores from that local snapshot.
	if _, err := s.Restore(ctx, &ateletpb.RestoreRequest{
		Atespace:              atespace,
		ActorName:             actorName,
		ActorUid:              actorUID,
		ActorTemplateAtespace: "default",
		ActorTemplateName:     "counter",
		TargetAteomUid:        ateomUID,
		Spec:                  spec,
		Scope:                 ateletpb.SnapshotScope_SNAPSHOT_SCOPE_FULL,
		Type:                  ateletpb.CheckpointType_CHECKPOINT_TYPE_LOCAL,
		Config: &ateletpb.RestoreRequest_LocalConfig{
			LocalConfig: &ateletpb.LocalCheckpointConfiguration{SnapshotName: snapshotName},
		},
	}); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if got := ateom.restored["checkpoint.img"]; got != "guest-memory" {
		t.Fatalf("restore staged %q for ateom, want the pause snapshot's %q", got, "guest-memory")
	}

	// Terminate: the actor is gone, and so should its snapshot be.
	if _, err := s.Terminate(ctx, &ateletpb.TerminateRequest{
		Atespace:              atespace,
		ActorName:             actorName,
		ActorUid:              actorUID,
		ActorTemplateAtespace: "default",
		ActorTemplateName:     "counter",
		TargetAteomUid:        ateomUID,
		Spec:                  spec,
	}); err != nil {
		t.Fatalf("Terminate: %v", err)
	}

	localDir := ateompath.LocalCheckpointsDir(actorUID)
	if _, err := os.Stat(localDir); !os.IsNotExist(err) {
		leaked, _ := filepath.Glob(filepath.Join(localDir, "*", "*"))
		t.Errorf("local checkpoint dir survived terminate (stat err = %v), leaked files: %v", err, leaked)
	}

	// Terminate is the only chance to reclaim the actor's directory: nothing
	// else on the node deletes it.
	actorDir := ateompath.ActorPath(actorUID)
	if entries, err := os.ReadDir(actorDir); err == nil {
		left := make([]string, 0, len(entries))
		for _, e := range entries {
			left = append(left, e.Name())
		}
		t.Errorf("actor dir %s survived terminate with %d entries: %v", actorDir, len(left), left)
	} else if !os.IsNotExist(err) {
		t.Errorf("reading actor dir %s: %v", actorDir, err)
	}
}

// TestRestoreFallsBackToFilesystemWhenFullRestoreFails walks an actor through
// run -> pause (Full, with a filesystem image) -> resume, where ateom's
// memory restore fails (simulating an incompatible CPU feature set). The
// snapshot carries a filesystem image, so atelet must fall back to a cold
// boot from it instead of failing the resume, and report that it did.
func TestRestoreFallsBackToFilesystemWhenFullRestoreFails(t *testing.T) {
	useTempNodeDirs(t)
	ctx := t.Context()

	const (
		atespace     = "ate-demo"
		actorName    = "counter"
		actorUID     = "actor-uid-1"
		ateomUID     = "ateom-uid-1"
		snapshotName = "pause-snap-1"
	)

	fsManifest := ateompath.GVisorFSCheckpointDir + "/" + ateompath.GVisorFSCheckpointManifestFile
	ateom := &fakeAteom{
		snapshotFiles: map[string]string{
			"checkpoint.img": "guest-memory",
			fsManifest:       "fs-manifest",
		},
		failRestoreScope: ateompb.SnapshotScope_SNAPSHOT_SCOPE_FULL,
	}
	serveFakeAteom(t, ateom)

	host := imageVolumeTestRegistry(t)
	image := host + "/actor:v1"
	pushTestImage(t, image, singleFileLayer(t, "bin/app", "app"))

	runsc := []byte("runsc binary")
	s := &AteomHerder{
		ateomDialer:       newAteomDialer(1),
		imageCache:        newImageVolumeStore(t),
		anonGCSClient:     fakeObjectStorage{data: runsc},
		systemInfoVolumes: newSystemInfoVolumeRefresher(nil, nil),
	}
	sandboxAssets := &ateletpb.SandboxAssets{
		SandboxClass: "gvisor",
		PauseImage:   image,
		Assets: map[string]*ateletpb.ArchAssets{
			runtime.GOARCH: {Files: map[string]*ateletpb.AssetFile{
				runscAssetName: {
					Url:    "gs://test-bucket/runsc",
					Sha256: fmt.Sprintf("%x", sha256.Sum256(runsc)),
				},
			}},
		},
	}
	spec := &ateletpb.WorkloadSpec{
		Containers: []*ateletpb.Container{{Name: "app", Image: image, Command: []string{"/bin/app"}}},
	}

	if _, err := s.Run(ctx, &ateletpb.RunRequest{
		Atespace:              atespace,
		ActorName:             actorName,
		ActorUid:              actorUID,
		ActorTemplateAtespace: "default",
		ActorTemplateName:     "counter",
		TargetAteomUid:        ateomUID,
		SandboxAssets:         sandboxAssets,
		Spec:                  spec,
	}); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if _, err := s.Checkpoint(ctx, &ateletpb.CheckpointRequest{
		Atespace:              atespace,
		ActorName:             actorName,
		ActorUid:              actorUID,
		ActorTemplateAtespace: "default",
		ActorTemplateName:     "counter",
		TargetAteomUid:        ateomUID,
		Spec:                  spec,
		Scope:                 ateletpb.SnapshotScope_SNAPSHOT_SCOPE_FULL,
		Type:                  ateletpb.CheckpointType_CHECKPOINT_TYPE_LOCAL,
		Config: &ateletpb.CheckpointRequest_LocalConfig{
			LocalConfig: &ateletpb.LocalCheckpointConfiguration{SnapshotName: snapshotName},
		},
	}); err != nil {
		t.Fatalf("Checkpoint: %v", err)
	}
	if _, err := os.Stat(filepath.Join(ateompath.LocalSnapshotDir(actorUID, snapshotName), fsManifest)); err != nil {
		t.Fatalf("pause did not write the filesystem image alongside the Full snapshot: %v", err)
	}

	resp, err := s.Restore(ctx, &ateletpb.RestoreRequest{
		Atespace:              atespace,
		ActorName:             actorName,
		ActorUid:              actorUID,
		ActorTemplateAtespace: "default",
		ActorTemplateName:     "counter",
		TargetAteomUid:        ateomUID,
		Spec:                  spec,
		Scope:                 ateletpb.SnapshotScope_SNAPSHOT_SCOPE_FULL,
		Type:                  ateletpb.CheckpointType_CHECKPOINT_TYPE_LOCAL,
		Config: &ateletpb.RestoreRequest_LocalConfig{
			LocalConfig: &ateletpb.LocalCheckpointConfiguration{SnapshotName: snapshotName},
		},
	})
	if err != nil {
		t.Fatalf("Restore: %v, want the Filesystem fallback to succeed", err)
	}
	if !resp.GetRestoredViaFilesystemFallback() {
		t.Error("RestoredViaFilesystemFallback = false, want true")
	}
	wantScopes := []ateompb.SnapshotScope{
		ateompb.SnapshotScope_SNAPSHOT_SCOPE_FULL,
		ateompb.SnapshotScope_SNAPSHOT_SCOPE_FILESYSTEM,
	}
	if len(ateom.restoreScopes) != len(wantScopes) {
		t.Fatalf("ateom.RestoreWorkload called with scopes %v, want %v", ateom.restoreScopes, wantScopes)
	}
	for i, want := range wantScopes {
		if ateom.restoreScopes[i] != want {
			t.Errorf("ateom.RestoreWorkload call %d scope = %v, want %v", i, ateom.restoreScopes[i], want)
		}
	}
}

// A restore that fails before atelet records the sandbox binaries leaves no
// sandbox record, and ateom has already torn down whatever it started. Delete
// must still reclaim the actor, and a retried Terminate must succeed: the
// record is gone after the first one too.
func TestTerminateWithoutSandboxRecord(t *testing.T) {
	useTempNodeDirs(t)
	ctx := t.Context()

	const actorUID = "actor-uid-never-started"
	ateom := &fakeAteom{}
	serveFakeAteom(t, ateom)

	actorDir := ateompath.ActorPath(actorUID)
	if err := os.MkdirAll(filepath.Join(actorDir, "bundles"), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	s := &AteomHerder{
		ateomDialer:       newAteomDialer(1),
		systemInfoVolumes: newSystemInfoVolumeRefresher(nil, nil),
	}
	req := &ateletpb.TerminateRequest{
		Atespace:              "ate-demo",
		ActorName:             "never-started",
		ActorUid:              actorUID,
		ActorTemplateAtespace: "default",
		ActorTemplateName:     "counter",
		TargetAteomUid:        "ateom-uid-1",
		Spec:                  &ateletpb.WorkloadSpec{Containers: []*ateletpb.Container{{Name: "app", Image: "example.invalid/app:v1"}}},
	}
	for attempt := 1; attempt <= 2; attempt++ {
		if _, err := s.Terminate(ctx, req); err != nil {
			t.Fatalf("Terminate attempt %d: %v", attempt, err)
		}
	}
	if _, err := os.Stat(actorDir); !os.IsNotExist(err) {
		t.Errorf("actor dir survived terminate (stat err = %v)", err)
	}
}
