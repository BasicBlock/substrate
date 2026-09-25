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
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/agent-substrate/substrate/internal/ateomcgroup"
	"github.com/agent-substrate/substrate/internal/ateompath"
	"github.com/agent-substrate/substrate/internal/ocispec"
)

// forceExitWait bounds how long forceStopSandbox waits for killed processes to
// exit.
const forceExitWait = 10 * time.Second

// sandboxForcer kills what is left of an actor's sandbox when runsc cannot
// tear it down itself. Its roots are fields so tests can point it at a fake
// /proc and cgroup tree.
type sandboxForcer struct {
	procRoot   string
	cgroupRoot string
	kill       func(pid int) error
}

func newSandboxForcer(cgroupRoot string) sandboxForcer {
	return sandboxForcer{
		procRoot:   "/proc",
		cgroupRoot: cgroupRoot,
		kill:       func(pid int) error { return syscall.Kill(pid, syscall.SIGKILL) },
	}
}

// forceStop kills an actor's sandbox without runsc: every process in the
// actor's container cgroups (cgroup.kill), and every process started with the
// actor's runsc root -- the sandbox, its gofers, and any runsc command still
// holding the container's lock, which run in ateom's own cgroup -- then
// empties the runsc root so no stale record of the containers remains, and
// removes the emptied cgroups. Only this actor's leaves and processes are
// touched, so the other actors a worker hosts keep running. A hung runsc
// otherwise fails every teardown, leaving the worker's slot unusable and the
// actor stuck deleting until its pod is deleted.
func (f sandboxForcer) forceStop(ctx context.Context, actorUID string, containers []string) error {
	var errs []error
	killCtx, cancel := context.WithTimeout(ctx, forceExitWait)
	defer cancel()
	leaves := make([]string, 0, len(containers)+1)
	for _, name := range append(containers, ocispec.PauseContainer) {
		leaf := ocispec.GVisorCgroupLeaf(actorUID, name)
		leaves = append(leaves, filepath.Join(f.cgroupRoot, leaf))
		if err := ateomcgroup.KillLeafUnder(killCtx, f.cgroupRoot, leaf); err != nil {
			errs = append(errs, err)
		}
	}

	runscRoot := ateompath.RunSCStateDir(actorUID)
	pids, err := f.processesWithRunscRoot(runscRoot)
	if err != nil {
		errs = append(errs, err)
	}
	for _, pid := range pids {
		if err := f.kill(pid); err != nil && !errors.Is(err, syscall.ESRCH) {
			errs = append(errs, fmt.Errorf("while killing runsc process %d: %w", pid, err))
		}
	}
	if left := f.waitForExit(ctx, pids); len(left) > 0 {
		errs = append(errs, fmt.Errorf("runsc processes %v did not exit within %s", left, forceExitWait))
	}

	if err := os.RemoveAll(runscRoot); err != nil {
		errs = append(errs, fmt.Errorf("while removing runsc state %s: %w", runscRoot, err))
	} else if err := os.MkdirAll(runscRoot, 0o700); err != nil {
		errs = append(errs, fmt.Errorf("while recreating runsc state %s: %w", runscRoot, err))
	}
	for _, leaf := range leaves {
		// rmdir, not RemoveAll: a cgroup directory is removed empty, as a whole.
		if err := os.Remove(leaf); err != nil && !errors.Is(err, os.ErrNotExist) {
			slog.WarnContext(ctx, "Failed to remove a forced sandbox's cgroup", slog.String("cgroup", leaf), slog.Any("err", err))
		}
	}
	slog.WarnContext(ctx, "Forced an actor's sandbox down without runsc",
		slog.String("actorUID", actorUID), slog.Any("killedPIDs", pids), slog.Any("err", errors.Join(errs...)))
	return errors.Join(errs...)
}

// processesWithRunscRoot returns the processes whose command line passes
// root as runsc's -root flag, which every runsc invocation for the actor does,
// the sandbox and gofers it re-executes included.
func (f sandboxForcer) processesWithRunscRoot(root string) ([]int, error) {
	entries, err := os.ReadDir(f.procRoot)
	if err != nil {
		return nil, fmt.Errorf("while listing processes: %w", err)
	}
	var pids []int
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid == os.Getpid() {
			continue
		}
		cmdline, err := os.ReadFile(filepath.Join(f.procRoot, entry.Name(), "cmdline"))
		if err != nil {
			continue // exited since the listing
		}
		if namesRunscRoot(strings.Split(strings.TrimRight(string(cmdline), "\x00"), "\x00"), root) {
			pids = append(pids, pid)
		}
	}
	return pids, nil
}

func namesRunscRoot(args []string, root string) bool {
	for i, arg := range args {
		switch arg {
		case "-root", "--root":
			if i+1 < len(args) && args[i+1] == root {
				return true
			}
		case "-root=" + root, "--root=" + root:
			return true
		}
	}
	return false
}

// waitForExit waits until every pid has exited or is a zombie awaiting the
// reaper, and returns those still running when forceExitWait runs out.
func (f sandboxForcer) waitForExit(ctx context.Context, pids []int) []int {
	deadline := time.Now().Add(forceExitWait)
	for {
		var left []int
		for _, pid := range pids {
			if f.running(pid) {
				left = append(left, pid)
			}
		}
		if len(left) == 0 || time.Now().After(deadline) || ctx.Err() != nil {
			return left
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (f sandboxForcer) running(pid int) bool {
	status, err := os.ReadFile(filepath.Join(f.procRoot, strconv.Itoa(pid), "status"))
	if err != nil {
		return false
	}
	for line := range strings.SplitSeq(string(status), "\n") {
		if state, ok := strings.CutPrefix(line, "State:"); ok {
			return !strings.HasPrefix(strings.TrimSpace(state), "Z")
		}
	}
	return true
}
