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

// Package ateletpath is atelet's on-node layout: the per-actor directories
// it passes to ateom as ActorDirs, and the directories only atelet uses.
package ateletpath

import (
	"os"
	"path/filepath"

	"github.com/agent-substrate/substrate/internal/nodepath"
	"github.com/agent-substrate/substrate/internal/proto/ateompb"
)

var (
	// ImageCacheDir is the node-local OCI image layer cache (see
	// internal/imagecache). It lives under BasePath so the cached layer
	// directories are visible at the same path in atelet (which writes them)
	// and in every ateom pod (which mounts them as overlay lowerdirs).
	ImageCacheDir = filepath.Join(nodepath.BasePath, "image-cache")
)

func RunSCBinaryPath(sha256 string) string {
	return filepath.Join(nodepath.StaticFilesDir, "runsc-"+sha256)
}

// GVisorReleaseDir is the directory a gVisor release tarball (gvisor.tar.bz2,
// containing runsc plus its gvisor-bin/ helper binaries) is extracted into,
// content-addressed by the tarball's sha256. runsc requires the gvisor-bin/
// subdirectory to sit next to it, so the whole release is kept together under
// one directory rather than as loose files in StaticFilesDir.
func GVisorReleaseDir(sha256 string) string {
	return filepath.Join(nodepath.StaticFilesDir, "gvisor-"+sha256)
}

func ActorPath(actorUID string) string {
	return filepath.Join(
		nodepath.ActorsDir,
		actorUID,
	)
}

// ActorSandboxAssetsFile is the per-actor file where atelet records the sandbox
// binaries (class + content-addressed asset set, for this node's architecture)
// the actor is currently running. It is written at Run/Restore and read at
// Checkpoint (when the request no longer carries the sandbox config). It lives
// directly under ActorPath — NOT under a subdir wiped by atelet's
// resetActorDirs — so it survives between Run and a later Checkpoint.
func ActorSandboxAssetsFile(actorUID string) string {
	return filepath.Join(
		ActorPath(actorUID),
		"sandbox-assets.json",
	)
}

func OCIBundleDir(actorUID string) string {
	return filepath.Join(
		ActorPath(actorUID),
		"bundles",
	)
}

func OCIBundlePath(actorUID, containerName string) string {
	return filepath.Join(
		OCIBundleDir(actorUID),
		containerName,
	)
}

func CheckpointStateDir(actorUID string) string {
	return filepath.Join(
		ActorPath(actorUID),
		"checkpoint-state",
	)
}

func LocalCheckpointsDir(actorUID string) string {
	return filepath.Join(
		ActorPath(actorUID),
		"local-checkpoint",
	)
}

// LocalSnapshotDir is the directory holding one named local (pause) snapshot
// of an actor: the checkpoint files plus their manifest.
func LocalSnapshotDir(actorUID, snapshotName string) string {
	return filepath.Join(LocalCheckpointsDir(actorUID), snapshotName)
}

// DurableDirTarFile is the snapshot file holding the tar of an
// actor's durable-dir volumes (entries are <volumeName>/... relative to
// DurableDirVolumeMountsDir). Written by ateom-microvm at checkpoint; a DATA
// snapshot consists of this file alone, so atelet uses the name to carve the
// durable data out of a FULL snapshot's file set.
const DurableDirTarFile = "durable-dir.tar"

// GVisorFSCheckpointDir is the subdirectory a gVisor Full checkpoint's
// filesystem image lands in, alongside the memory checkpoint's own top-level
// files (checkpoint.img, pages_meta.img, pages.img) -- separate because
// runsc's own `checkpoint -fs-checkpoint-paths` combined capture reuses the
// pages_meta.img/pages.img basenames for the filesystem image's own pages.
// A standalone Filesystem-scope capture (no memory checkpoint to collide
// with) instead writes its files directly at the snapshot root. This
// directory name is a coupling to runsc's own
// pkg/sentry/state/checkpointfiles.FSCheckpointDir; a runsc upgrade that
// renames it must update this constant too.
const GVisorFSCheckpointDir = "fs"

// GVisorFSCheckpointManifestFile is the filesystem checkpoint's manifest,
// present exactly when a filesystem image exists: at the snapshot root for a
// standalone Filesystem-scope capture, or under GVisorFSCheckpointDir for a
// Full capture that also carries one. Coupled to runsc's own
// pkg/sentry/state/checkpointfiles.FSCheckpointManifestFileName.
const GVisorFSCheckpointManifestFile = "fscheckpoint.pb"

// GVisorFSCheckpointPath returns the directory a Full checkpoint's filesystem
// image is written under, given the checkpoint's own top-level directory.
func GVisorFSCheckpointPath(checkpointDir string) string {
	return filepath.Join(checkpointDir, GVisorFSCheckpointDir)
}

// HasGVisorFSCheckpoint reports whether dir directly holds a gVisor
// filesystem checkpoint (its manifest file at the top level of dir) -- true
// for a standalone Filesystem-scope capture's own directory, or for the
// nested GVisorFSCheckpointDir of a Full capture that also carries one.
func HasGVisorFSCheckpoint(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, GVisorFSCheckpointManifestFile))
	return err == nil
}

// DurableDirVolumeMountsDir is the directory where individual durable-dir
// volumes are mounted.
func DurableDirVolumeMountsDir(actorUID string) string {
	return filepath.Join(
		ActorPath(actorUID),
		"durable-dir",
	)
}

// DurableDirVolumeMountPoint returns the path where a specific durable-dir volume is mounted on the nodeVM.
func DurableDirVolumeMountPoint(actorUID, volumeName string) string {
	return filepath.Join(
		DurableDirVolumeMountsDir(actorUID),
		volumeName,
	)
}

// SystemInfoVolumeRootsDir is the directory containing the per-volume root
// directories of system-info volumes. Snapshots must capture durable-dir
// data but never system-info contents, which atelet regenerates on every
// Run/Restore; each sandbox class excludes them differently:
//
//   - micro-VM captures by location: its checkpoint tars all of
//     DurableDirVolumeMountsDir (see ateom-microvm's tarDurableVolumes), so
//     system-info roots are excluded by living in this separate directory.
//   - gVisor captures by declaration: durable mounts are registered with
//     the sandbox (mount-hint annotations for FULL checkpoints, the
//     enumerated durable mount paths for DATA fscheckpoints); system-info
//     mounts are plain undeclared binds, never captured regardless of host
//     layout.
//
// The separate directory is therefore critical only for micro-VM.
func SystemInfoVolumeRootsDir(actorUID string) string {
	return filepath.Join(
		ActorPath(actorUID),
		"system-info",
	)
}

// SystemInfoVolumeRoot returns the host path of the root directory for a
// specific system-info volume.
func SystemInfoVolumeRoot(actorUID, volumeName string) string {
	return filepath.Join(
		SystemInfoVolumeRootsDir(actorUID),
		volumeName,
	)
}

// RestoreStateDir is the local directory to use to restore an actor from a
// checkpoint downloaded from GCS.
//
// We need to use a different path from CheckpointStateDir, because using `runsc
// restore -direct -background` means that runsc starts executing first, then
// demand-pages in parts of the checkpoint file as they are needed.  To know
// when the background reading is finished, we would need to run `runsc wait
// -checkpoint`, which will block until the read is done.  Alternatively, we can
// make sure we write the suspension checkpoint to a different location.  This
// will work properly, with `runsc checkpoint` paging in any data that hasn't
// yet been loaded.
func RestoreStateDir(actorUID string) string {
	return filepath.Join(
		ActorPath(actorUID),
		"restore-state",
	)
}

func VolumesDir(actorUID string) string {
	return filepath.Join(
		ActorPath(actorUID),
		"volumes",
	)
}

func VolumeHostPath(actorUID, volumeName string) string {
	return filepath.Join(
		VolumesDir(actorUID),
		volumeName,
	)
}

// ActorDirs is the directory set atelet passes to ateom for an actor. ateom
// takes these from the request rather than deriving them from the actor UID.
func ActorDirs(actorUID string) *ateompb.ActorDirs {
	return &ateompb.ActorDirs{
		RootDir:                   ActorPath(actorUID),
		OciBundleDir:              OCIBundleDir(actorUID),
		CheckpointDir:             CheckpointStateDir(actorUID),
		RestoreDir:                RestoreStateDir(actorUID),
		DurableDirVolumeMountsDir: DurableDirVolumeMountsDir(actorUID),
		SystemInfoVolumeRootsDir:  SystemInfoVolumeRootsDir(actorUID),
		VolumesDir:                VolumesDir(actorUID),
	}
}
