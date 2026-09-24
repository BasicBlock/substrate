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
	"slices"

	"github.com/agent-substrate/substrate/cmd/atelet/internal/ategcs"
	"github.com/agent-substrate/substrate/internal/ateattr"
	"github.com/agent-substrate/substrate/internal/proto/ateletpb"
	"github.com/agent-substrate/substrate/internal/resources"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// DropSnapshotMemory rewrites a stored external snapshot's manifest in place,
// narrowing a Full capture to Filesystem scope and deleting the now-unused
// memory objects. It drives no ateom: this is pure object-storage rewriting,
// so any atelet can serve it for any actor's snapshot, not only one on the
// actor's node -- which the actor, being SUSPENDED, does not have anyway.
//
// The manifest rewrite is the commit point and happens before any object is
// deleted: a crash or failure after it leaves the manifest correctly
// describing a Filesystem snapshot (a subsequent restore never looks for the
// deleted files), with at worst leaked memory objects an operator can
// re-invoke this RPC to finish cleaning up (best-effort; see below). Deleting
// first and rewriting the manifest second would risk the opposite failure: a
// manifest still listing memory files a concurrent restore cannot fetch
// because they are already gone.
func (s *AteomHerder) DropSnapshotMemory(ctx context.Context, req *ateletpb.DropSnapshotMemoryRequest) (*ateletpb.DropSnapshotMemoryResponse, error) {
	if err := validateDropSnapshotMemoryRequest(req); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	uri, err := resources.ParseSnapshotURI(req.GetSnapshotUri())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	manifestURI, err := uri.ObjectURI(sandboxManifestName)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	manifest, err := ategcs.FetchFromGCS(ctx, s.gcsClient, manifestURI)
	if err != nil {
		return nil, fmt.Errorf("while fetching snapshot manifest: %w", err)
	}
	rec, err := unmarshalSandboxRecord(manifest)
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "while unmarshalling snapshot manifest: %v", err)
	}

	// Idempotent: a snapshot already narrowed succeeds without rewriting
	// anything. It may still carry leaked memory objects from an earlier
	// attempt whose object deletions failed after its manifest rewrite
	// committed; best-effort clean those up too rather than reporting done.
	if rec.Scope == ateattr.SnapshotScopeFilesystem {
		deleteObjectsNotIn(ctx, s.gcsClient, uri, staleFullOnlyFiles, rec.SnapshotFiles)
		return &ateletpb.DropSnapshotMemoryResponse{}, nil
	}
	if rec.Scope != ateattr.SnapshotScopeFull {
		return nil, status.Errorf(codes.FailedPrecondition, "snapshot scope %q cannot be narrowed to %s (only a %s snapshot can)", rec.Scope, ateattr.SnapshotScopeFilesystem, ateattr.SnapshotScopeFull)
	}

	before := slices.Clone(rec.SnapshotFiles)
	if err := narrowFullCaptureToFilesystem(rec); err != nil {
		return nil, err
	}

	manifestBytes, err := json.Marshal(rec)
	if err != nil {
		return nil, fmt.Errorf("while marshaling narrowed snapshot manifest: %w", err)
	}
	if err := ategcs.SendBytesToGCS(ctx, s.gcsClient, manifestURI, manifestBytes); err != nil {
		return nil, fmt.Errorf("while uploading narrowed snapshot manifest: %w", err)
	}

	deleteObjectsNotIn(ctx, s.gcsClient, uri, before, rec.SnapshotFiles)
	return &ateletpb.DropSnapshotMemoryResponse{}, nil
}

// staleFullOnlyFiles are the memory checkpoint's own top-level files a stale,
// already-Filesystem manifest might still have lying around in storage from
// an interrupted earlier narrow (its own SnapshotFiles list no longer names
// them, so there is nothing else to diff against).
var staleFullOnlyFiles = []string{"checkpoint.img", "pages_meta.img", "pages.img"}

// deleteObjectsNotIn best-effort deletes, under uri, every name in before
// that is absent from after. Failures are logged, not returned: the manifest
// rewrite (already committed by the time this runs) is what a restore
// depends on, so a stuck delete leaves only reclaimable storage, not a
// correctness problem, and a later DropSnapshotMemory retries it.
func deleteObjectsNotIn(ctx context.Context, client ategcs.ObjectStorage, uri resources.SnapshotURI, before, after []string) {
	for _, name := range before {
		if slices.Contains(after, name) {
			continue
		}
		objectURI, err := uri.ObjectURI(name + ".zstd")
		if err != nil {
			slog.WarnContext(ctx, "Failed to address stale snapshot object for deletion", slog.String("file", name), slog.Any("err", err))
			continue
		}
		if err := ategcs.DeleteIfExists(ctx, client, objectURI); err != nil {
			slog.WarnContext(ctx, "Failed to delete stale snapshot object; it will be retried on the next DropSnapshotMemory call",
				slog.String("file", name), slog.Any("err", err))
		}
	}
}

func validateDropSnapshotMemoryRequest(req *ateletpb.DropSnapshotMemoryRequest) error {
	if req.GetSnapshotUri() == "" {
		return fmt.Errorf("snapshot_uri must not be empty")
	}
	return nil
}
