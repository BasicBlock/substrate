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

	"github.com/agent-substrate/substrate/internal/ateompath"
	"github.com/agent-substrate/substrate/internal/ocispec"
	"github.com/agent-substrate/substrate/internal/proto/ateompb"
)

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
// under ateompath.GVisorFSCheckpointDir, alongside the memory checkpoint's
// own files). Detected the same way runsc's own restore auto-detects a
// checkpoint's filesystem image: by the manifest file's presence.
func resolveFSRestorePath(checkpointDir string) (string, error) {
	nested := ateompath.GVisorFSCheckpointPath(checkpointDir)
	if ateompath.HasGVisorFSCheckpoint(nested) {
		return nested, nil
	}
	if ateompath.HasGVisorFSCheckpoint(checkpointDir) {
		return checkpointDir, nil
	}
	return "", fmt.Errorf("no gVisor filesystem checkpoint found under %q or %q", checkpointDir, nested)
}
