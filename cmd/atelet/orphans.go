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
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/agent-substrate/substrate/internal/ateompath"
	"github.com/agent-substrate/substrate/internal/resources"
	"github.com/spf13/pflag"
)

var (
	orphanSweepPeriod = pflag.Duration("orphan-sweep-period", time.Hour, "How often to remove actor directories nothing on the node uses, starting at atelet start. 0 disables the sweep.")
	orphanGrace       = pflag.Duration("orphan-grace", 6*time.Hour, "An unused actor directory is removed only once nothing in it has changed for this long.")
)

// runOrphanSweep removes orphaned actor directories at start and every
// period, until ctx ends.
func (s *AteomHerder) runOrphanSweep(ctx context.Context, period, grace time.Duration) {
	if period <= 0 {
		return
	}
	for {
		if removed, err := s.sweepOrphanedActors(ctx, grace, time.Now()); err != nil {
			slog.WarnContext(ctx, "Orphaned actor sweep skipped", slog.Any("err", err))
		} else if len(removed) > 0 {
			slog.InfoContext(ctx, "Orphaned actor sweep complete", slog.Any("removed", removed))
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(period):
		}
	}
}

// sweepOrphanedActors removes the directories actors left on this node when
// their worker died, was evicted, or crashed mid-operation: nothing removes
// those otherwise, and each can hold a whole uncompressed checkpoint, its
// rootfs writes, and pins on the image cache's layers. A directory goes only
// if no ateom here runs the actor, no RPC for it is in flight (the sweep
// claims it, holding new ones off), it holds no pause snapshot (a PAUSED
// actor's only copy of its state), and nothing in it changed for grace. It
// sweeps nothing when it cannot tell what the node's ateoms run.
func (s *AteomHerder) sweepOrphanedActors(ctx context.Context, grace time.Duration, now time.Time) ([]string, error) {
	entries, err := os.ReadDir(ateompath.ActorsDir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("while listing actor directories: %w", err)
	}
	running, err := s.activity.running(ctx)
	if err != nil {
		return nil, fmt.Errorf("cannot tell which actors run on this node: %w", err)
	}
	var removed []string
	for _, entry := range entries {
		actorUID := entry.Name()
		if !entry.IsDir() || !resources.IsValidResourceName(actorUID) || running[actorUID] {
			continue
		}
		release, ok := s.activity.claim(actorUID)
		if !ok {
			continue
		}
		orphaned, err := orphanedSince(actorUID, now.Add(-grace))
		if err == nil && orphaned {
			s.systemInfoVolumes.Deregister(actorUID)
			err = removeActorDirs(actorUID)
			if err == nil {
				slog.InfoContext(ctx, "Removed an orphaned actor directory", slog.String("actorUID", actorUID))
				removed = append(removed, actorUID)
			}
		}
		release()
		if err != nil {
			slog.WarnContext(ctx, "Failed to sweep an actor directory", slog.String("actorUID", actorUID), slog.Any("err", err))
		}
	}
	return removed, nil
}

// orphanedSince reports whether actorUID's directory holds no pause snapshot
// and nothing in it changed after cutoff.
func orphanedSince(actorUID string, cutoff time.Time) (bool, error) {
	snapshots, err := os.ReadDir(ateompath.LocalCheckpointsDir(actorUID))
	if err != nil && !os.IsNotExist(err) {
		return false, err
	}
	if len(snapshots) > 0 {
		return false, nil
	}
	errRecent := errors.New("recently changed")
	err = filepath.WalkDir(ateompath.ActorPath(actorUID), func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.ModTime().After(cutoff) {
			return errRecent
		}
		return nil
	})
	if errors.Is(err, errRecent) {
		return false, nil
	}
	return err == nil, err
}
