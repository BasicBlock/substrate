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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/agent-substrate/substrate/internal/ocispec"
	"github.com/agent-substrate/substrate/internal/proto/ateompb"
)

// runsc fscheckpoint saves the root filesystem changes of every container in a
// sandbox as a directory of files, apart from the memory checkpoint. They are
// shipped in the snapshot beside the memory image and any durable-dir tars as
// flat files named rootfsFilePrefix + the name runsc gave them, because
// snapshot files are base names in one directory. Restoring at ROOTFS stages
// them back under their own names for `runsc create -fs-restore-image-path`.
const (
	// rootfsFilePrefix names the root filesystem checkpoint's files in the
	// snapshot.
	rootfsFilePrefix = "rootfs."

	// fsCheckpointScratchDir is where runsc writes a root filesystem checkpoint
	// before its files are renamed into the checkpoint directory.
	fsCheckpointScratchDir = "rootfs-capture"

	// fsRestoreStagingDir is where a restore lays the root filesystem
	// checkpoint's files out under their own names.
	fsRestoreStagingDir = "rootfs-restore"
)

// fsCheckpointTargets builds the fscheckpoint `-path` targets for every
// container in the sandbox, the pause (root) container and each application
// container, each as "<container>:/". fscheckpoint otherwise saves only the
// container named on its command line.
func fsCheckpointTargets(containers []*ateompb.Container) []string {
	targets := []string{ocispec.PauseContainer + ":/"}
	for _, c := range containers {
		targets = append(targets, c.GetName()+":/")
	}
	return targets
}

// captureRootfs saves the sandbox's root filesystem changes into checkpointDir
// as rootfs.* files and returns their names. With leaveRunning the sandbox
// keeps running afterward; otherwise runsc ends it. A failed capture leaves no
// files behind.
func captureRootfs(ctx context.Context, rcmd *runsc, checkpointDir string, containers []*ateompb.Container, leaveRunning bool) (files []string, err error) {
	scratch := filepath.Join(checkpointDir, fsCheckpointScratchDir)
	if err := os.RemoveAll(scratch); err != nil {
		return nil, fmt.Errorf("while clearing %s: %w", scratch, err)
	}
	defer func() {
		_ = os.RemoveAll(scratch)
		if err != nil {
			for _, name := range files {
				_ = os.Remove(filepath.Join(checkpointDir, name))
			}
			files = nil
		}
	}()
	if err := rcmd.cmdFsCheckpoint(ctx, ocispec.PauseContainer, scratch, fsCheckpointTargets(containers), leaveRunning); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(scratch)
	if err != nil {
		return nil, fmt.Errorf("while listing the root filesystem checkpoint: %w", err)
	}
	for _, e := range entries {
		if !e.Type().IsRegular() {
			return nil, fmt.Errorf("root filesystem checkpoint entry %q is not a regular file", e.Name())
		}
		name := rootfsFilePrefix + e.Name()
		if err := os.Rename(filepath.Join(scratch, e.Name()), filepath.Join(checkpointDir, name)); err != nil {
			return nil, fmt.Errorf("while moving %q into the checkpoint: %w", e.Name(), err)
		}
		files = append(files, name)
	}
	if len(files) == 0 {
		return nil, errors.New("root filesystem checkpoint wrote no files")
	}
	slices.Sort(files)
	return files, nil
}

// stageRootfsRestore lays the rootfs.* files in restoreDir out under their own
// names in a fresh directory, as `runsc create -fs-restore-image-path` reads
// them, and returns it. The files are hard links, so the snapshot is not
// changed or copied.
func stageRootfsRestore(restoreDir string) (string, error) {
	staging := filepath.Join(restoreDir, fsRestoreStagingDir)
	if err := os.RemoveAll(staging); err != nil {
		return "", fmt.Errorf("while clearing %s: %w", staging, err)
	}
	if err := os.MkdirAll(staging, 0o700); err != nil {
		return "", err
	}
	entries, err := os.ReadDir(restoreDir)
	if err != nil {
		return "", err
	}
	linked := 0
	for _, e := range entries {
		name, ok := strings.CutPrefix(e.Name(), rootfsFilePrefix)
		if !ok || !e.Type().IsRegular() {
			continue
		}
		if err := os.Link(filepath.Join(restoreDir, e.Name()), filepath.Join(staging, name)); err != nil {
			return "", fmt.Errorf("while staging %q: %w", e.Name(), err)
		}
		linked++
	}
	if linked == 0 {
		return "", fmt.Errorf("no root filesystem checkpoint files (%s*) in %q", rootfsFilePrefix, restoreDir)
	}
	return staging, nil
}
