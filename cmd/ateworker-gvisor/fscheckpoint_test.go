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
	"reflect"
	"testing"

	"github.com/agent-substrate/substrate/internal/ocispec"
	"github.com/agent-substrate/substrate/internal/proto/ateworkerpb"
)

func TestFsCheckpointTargets(t *testing.T) {
	tests := []struct {
		name       string
		containers []*ateworkerpb.Container
		want       []string
	}{
		{
			name: "pause only",
			want: []string{ocispec.PauseContainer + ":/"},
		},
		{
			name:       "pause plus application containers",
			containers: []*ateworkerpb.Container{{Name: "app"}, {Name: "sidecar"}},
			want:       []string{ocispec.PauseContainer + ":/", "app:/", "sidecar:/"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := fsCheckpointTargets(tt.containers); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("fsCheckpointTargets() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRootfsCheckpointArgs(t *testing.T) {
	r := &runsc{actorDirs: testActorDirs}
	got := r.rootfsCheckpointArgs("/cp/scratch", []string{"_pause:/", "app:/"}, true)
	want := []string{
		"-log-format", "json",
		"--alsologtostderr",
		"-root", runscStateDir(testActorDirs),
		"fscheckpoint",
		"-image-path", "/cp/scratch",
		"-leave-running",
		"-path", "_pause:/",
		"-path", "app:/",
		"_pause",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("rootfsCheckpointArgs() =\n%v\nwant\n%v", got, want)
	}
	if got := r.rootfsCheckpointArgs("/cp/scratch", nil, false); slicesContains(got, "-leave-running") {
		t.Errorf("rootfsCheckpointArgs(leaveRunning=false) = %v, want no -leave-running", got)
	}
}

func slicesContains(args []string, arg string) bool {
	for _, a := range args {
		if a == arg {
			return true
		}
	}
	return false
}

// fakeFsRunsc writes a runsc that, for fscheckpoint, writes the given files into
// its -image-path (or fails with status 1 when none are given and fail is set).
func fakeFsRunsc(t *testing.T, files []string, fail bool) *runsc {
	t.Helper()
	script := "#!/bin/sh\n" +
		"while [ $# -gt 0 ]; do if [ \"$1\" = -image-path ]; then dir=$2; fi; shift; done\n" +
		"mkdir -p \"$dir\" || exit 1\n"
	for _, f := range files {
		script += "echo " + f + " > \"$dir/" + f + "\"\n"
	}
	if fail {
		script += "exit 1\n"
	}
	path := filepath.Join(t.TempDir(), "runsc")
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return &runsc{path: path, actorDirs: testActorDirs}
}

func TestCaptureRootfsFlattensTheImageIntoTheCheckpointDir(t *testing.T) {
	dir := t.TempDir()
	rcmd := fakeFsRunsc(t, []string{"fscheckpoint.pb", "pages.img", "pages_meta.img"}, false)

	files, err := captureRootfs(context.Background(), rcmd, dir, nil, true)
	if err != nil {
		t.Fatalf("captureRootfs: %v", err)
	}
	want := []string{"rootfs.fscheckpoint.pb", "rootfs.pages.img", "rootfs.pages_meta.img"}
	if !reflect.DeepEqual(files, want) {
		t.Errorf("captureRootfs() = %v, want %v", files, want)
	}
	for _, f := range want {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("%s not in the checkpoint dir: %v", f, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, fsCheckpointScratchDir)); !os.IsNotExist(err) {
		t.Errorf("scratch dir survived: %v", err)
	}
}

func TestCaptureRootfsFailureLeavesNothingBehind(t *testing.T) {
	dir := t.TempDir()
	// A memory image already in the directory must survive a failed capture.
	if err := os.WriteFile(filepath.Join(dir, "checkpoint.img"), []byte("m"), 0o600); err != nil {
		t.Fatal(err)
	}
	rcmd := fakeFsRunsc(t, []string{"pages.img"}, true)

	files, err := captureRootfs(context.Background(), rcmd, dir, nil, true)
	if err == nil || files != nil {
		t.Fatalf("captureRootfs() = %v, %v; want no files and an error", files, err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 || entries[0].Name() != "checkpoint.img" {
		t.Errorf("checkpoint dir after a failed capture = %v, want only checkpoint.img", entries)
	}
}

func TestCaptureRootfsWithNoFilesFails(t *testing.T) {
	if _, err := captureRootfs(context.Background(), fakeFsRunsc(t, nil, false), t.TempDir(), nil, false); err == nil {
		t.Error("captureRootfs() with an empty image = nil error")
	}
}

func TestStageRootfsRestoreLaysFilesOutUnderTheirOwnNames(t *testing.T) {
	dir := t.TempDir()
	for _, f := range []string{"checkpoint.img", "pages.img", "rootfs.fscheckpoint.pb", "rootfs.pages.img"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte(f), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// A stale staging dir from an earlier attempt is replaced.
	stale := filepath.Join(dir, fsRestoreStagingDir)
	if err := os.MkdirAll(stale, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stale, "stale"), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	staging, err := stageRootfsRestore(dir)
	if err != nil {
		t.Fatalf("stageRootfsRestore: %v", err)
	}
	entries, err := os.ReadDir(staging)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if want := []string{"fscheckpoint.pb", "pages.img"}; !reflect.DeepEqual(names, want) {
		t.Errorf("staged files = %v, want %v", names, want)
	}
	if got, _ := os.ReadFile(filepath.Join(staging, "pages.img")); string(got) != "rootfs.pages.img" {
		t.Errorf("staged pages.img = %q, want the rootfs image's", got)
	}
}

func TestStageRootfsRestoreWithoutAnImageFails(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "checkpoint.img"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := stageRootfsRestore(dir); err == nil {
		t.Error("stageRootfsRestore() without rootfs.* files = nil error")
	}
}
