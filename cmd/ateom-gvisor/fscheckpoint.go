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
	"fmt"
	"os"
	"path/filepath"

	"github.com/agent-substrate/substrate/internal/ocispec"
	"github.com/agent-substrate/substrate/internal/proto/ateompb"
)

// gvisorFSCheckpointDir and gvisorFSCheckpointManifestFile mirror
// cmd/atelet/internal/ateletpath's GVisorFSCheckpointDir and
// GVisorFSCheckpointManifestFile. Duplicated rather than imported: that
// package is internal to cmd/atelet, which cmd/ateom-gvisor cannot reach, and
// atelet<->ateom path-sharing here is otherwise done by the caller filling
// ActorDirs on the request rather than a shared path-helper package (see
// CheckpointWorkload/RestoreWorkload, which take every actor directory from
// the request). These two are fixed subdirectory/filename constants both
// sides must agree on, not actor-specific paths, so a small duplication is
// simpler than threading a new shared package through the internal boundary.
const (
	gvisorFSCheckpointDir          = "fs"
	gvisorFSCheckpointManifestFile = "fscheckpoint.pb"
)

// hasGVisorFSCheckpoint reports whether dir directly holds a gVisor
// filesystem checkpoint (its manifest file at the top level of dir).
func hasGVisorFSCheckpoint(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, gvisorFSCheckpointManifestFile))
	return err == nil
}

// gvisorFSCheckpointPath returns the directory a Full checkpoint's
// filesystem image is written under, given the checkpoint's own top-level
// directory.
func gvisorFSCheckpointPath(checkpointDir string) string {
	return filepath.Join(checkpointDir, gvisorFSCheckpointDir)
}

// fsCheckpointTargets builds the fscheckpoint `-path` targets for every
// container in the sandbox -- the pause (root) container plus each
// application container, each as "<container>:/" -- rather than relying on
// fscheckpoint's own default (which saves only the one container named on
// its command line). Explicit targets avoid depending on undocumented
// multi-container default behavior for a mechanism gVisor itself marks
// experimental.
func fsCheckpointTargets(containers []*ateompb.Container) []string {
	targets := []string{ocispec.PauseContainer + ":/"}
	for _, c := range containers {
		targets = append(targets, c.GetName()+":/")
	}
	return targets
}

// resolveFSRestorePath returns the directory to pass as
// `create -fs-restore-image-path` for a Filesystem-scope restore, whether the
// snapshot being restored is a standalone Filesystem capture (files directly
// under checkpointDir) or a Full capture's filesystem-fallback image (nested
// under gvisorFSCheckpointDir, alongside the memory checkpoint's own files).
// Detected the same way runsc's own restore auto-detects a checkpoint's
// filesystem image: by the manifest file's presence.
func resolveFSRestorePath(checkpointDir string) (string, error) {
	nested := gvisorFSCheckpointPath(checkpointDir)
	if hasGVisorFSCheckpoint(nested) {
		return nested, nil
	}
	if hasGVisorFSCheckpoint(checkpointDir) {
		return checkpointDir, nil
	}
	return "", fmt.Errorf("no gVisor filesystem checkpoint found under %q or %q", checkpointDir, nested)
}
