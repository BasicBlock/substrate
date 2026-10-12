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
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"

	"github.com/agent-substrate/substrate/internal/apierror"
	"github.com/agent-substrate/substrate/internal/ateattr"
	"github.com/agent-substrate/substrate/internal/objectstoreplugin"
	"github.com/agent-substrate/substrate/internal/proto/ateletpb"
	"github.com/agent-substrate/substrate/internal/resources"
)

// DropSnapshotMemory downgrades a stored external MEMORY snapshot to ROOTFS in
// place: the manifest comes to list only the root filesystem and durable data,
// and the memory objects are emptied. It drives no ateom, it only moves bytes
// through the snapshot plugin, so any atelet can serve it for any actor's
// snapshot, not only one on the actor's node, which a SUSPENDED actor does not
// have.
//
// The snapshot plugin API has no per-file delete, so a dropped file is
// overwritten with an empty one, which frees its storage.
//
// The manifest is the commit marker and is rewritten before any object is
// emptied: a failure after it leaves a manifest that correctly describes a
// ROOTFS snapshot (a restore never asks for the memory files), with at worst
// memory objects not yet emptied. The manifest then records them in
// droppedSnapshotFiles, so a repeat of this call finishes the emptying, and a
// last manifest write clears the list.
func (s *AteomHerder) DropSnapshotMemory(ctx context.Context, req *ateletpb.DropSnapshotMemoryRequest) (*ateletpb.DropSnapshotMemoryResponse, error) {
	uri, err := resources.ParseSnapshotURI(req.GetSnapshotUri())
	if err != nil {
		return nil, apierror.InvalidArgument("snapshot_uri: %v", err)
	}

	raw, err := s.fetchManifest(ctx, uri.String())
	if err != nil {
		return nil, fmt.Errorf("while fetching snapshot manifest: %w", objectstoreplugin.CallError(err))
	}
	rec, err := unmarshalSandboxRecord(raw)
	if err != nil {
		return nil, apierror.FailedPrecondition("snapshot manifest: %v", err)
	}

	switch rec.Fidelity {
	case ateattr.SnapshotFidelityMemory:
		if len(rec.RootfsSnapshotFiles) == 0 {
			return nil, apierror.FailedPrecondition("MEMORY snapshot holds no root filesystem to keep (its capture predates root filesystem snapshots, or that capture failed); it must be recaptured")
		}
		dropped := slices.DeleteFunc(slices.Clone(rec.SnapshotFiles), func(f string) bool {
			return slices.Contains(rec.RootfsSnapshotFiles, f)
		})
		rec.SnapshotFiles = slices.Clone(rec.RootfsSnapshotFiles)
		rec.Fidelity = ateattr.SnapshotFidelityRootfs
		rec.DroppedSnapshotFiles = dropped
		if err := s.uploadManifestRecord(ctx, uri, rec); err != nil {
			return nil, err
		}
	case ateattr.SnapshotFidelityRootfs:
		// Already downgraded; finish emptying anything a previous call left.
	default:
		return nil, apierror.FailedPrecondition("snapshot holds %q: only a MEMORY snapshot has memory to drop", rec.Fidelity)
	}

	if len(rec.DroppedSnapshotFiles) == 0 {
		return &ateletpb.DropSnapshotMemoryResponse{}, nil
	}
	if err := s.emptySnapshotFiles(ctx, uri, rec.DroppedSnapshotFiles); err != nil {
		// Best-effort: the snapshot is already ROOTFS, and a repeat of this
		// call retries.
		slog.WarnContext(ctx, "Downgraded a snapshot to ROOTFS, but could not empty its memory objects; repeat DropSnapshotMemory to retry",
			slog.String("snapshot_uri", uri.String()), slog.Any("files", rec.DroppedSnapshotFiles), slog.Any("err", err))
		return &ateletpb.DropSnapshotMemoryResponse{}, nil
	}
	rec.DroppedSnapshotFiles = nil
	if err := s.uploadManifestRecord(ctx, uri, rec); err != nil {
		slog.WarnContext(ctx, "Emptied a snapshot's memory objects, but could not clear them from its manifest; repeating DropSnapshotMemory empties them again",
			slog.String("snapshot_uri", uri.String()), slog.Any("err", err))
	}
	return &ateletpb.DropSnapshotMemoryResponse{}, nil
}

// uploadManifestRecord uploads rec as the snapshot's manifest.
func (s *AteomHerder) uploadManifestRecord(ctx context.Context, uri resources.SnapshotURI, rec *sandboxAssetsRecord) error {
	manifest, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("while marshaling snapshot manifest: %w", err)
	}
	if err := s.uploadManifest(ctx, uri.String(), manifest); err != nil {
		return fmt.Errorf("while uploading snapshot manifest: %w", objectstoreplugin.CallError(err))
	}
	return nil
}

// emptySnapshotFiles overwrites the named files of a snapshot with empty ones.
func (s *AteomHerder) emptySnapshotFiles(ctx context.Context, uri resources.SnapshotURI, files []string) error {
	dir, err := s.snapshotScratch()
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	for _, name := range files {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			return fmt.Errorf("while staging an empty %s: %w", name, err)
		}
	}
	return s.uploadSnapshotFiles(ctx, uri.String(), dir, files)
}
