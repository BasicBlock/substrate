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
	"log/slog"
	"os"
	"path/filepath"

	"github.com/agent-substrate/substrate/internal/ocispec"
	"github.com/agent-substrate/substrate/internal/sizing"
)

// liftSandboxMemoryMax removes the sandbox leaf's hard memory limit once runsc
// create has booted the sentry. The declared size has already done its job
// there: runsc read memory.max to set the total memory the guest reports. Kept
// as a hard limit, it makes the kernel fail the sentry's memory-file
// allocations when the guest outgrows it, which kills guest processes. Lifted,
// memory.high (sizing.ApplyToOCISpec) throttles and reclaims above the
// declared size, swapping where the worker pod has swap, and the worker pod's
// own limit stays the hard bound.
//
// A failure is logged, not returned: the sandbox then keeps its hard limit, as
// before, rather than failing to start.
func liftSandboxMemoryMax(ctx context.Context, cgroupRoot, actorUID string, size sizing.SandboxSize) {
	if size.MemoryBytes <= 0 {
		return
	}
	path := filepath.Join(cgroupRoot, ocispec.GVisorCgroupLeaf(actorUID, sandboxCgroupContainer), "memory.max")
	if err := os.WriteFile(path, []byte("max"), 0o644); err != nil {
		slog.WarnContext(ctx, "could not lift the sandbox memory limit; it stays a hard limit",
			slog.String("path", path), slog.Any("err", err))
	}
}
