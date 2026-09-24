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
	"testing"

	"github.com/agent-substrate/substrate/internal/ocispec"
	"github.com/agent-substrate/substrate/internal/sizing"
)

func TestLiftSandboxMemoryMax(t *testing.T) {
	root := t.TempDir()
	leaf := filepath.Join(root, ocispec.GVisorCgroupLeaf("actor-uid", sandboxCgroupContainer))
	if err := os.MkdirAll(leaf, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(leaf, "memory.max"), []byte("8589934592"), 0o644); err != nil {
		t.Fatal(err)
	}

	liftSandboxMemoryMax(context.Background(), root, "actor-uid", sizing.SandboxSize{MemoryBytes: 8589934592})

	got, err := os.ReadFile(filepath.Join(leaf, "memory.max"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "max" {
		t.Errorf("memory.max = %q, want max", got)
	}
}

func TestLiftSandboxMemoryMaxLeavesUnsizedAndMissingLeavesAlone(t *testing.T) {
	root := t.TempDir()
	// No declared memory: nothing was limited, so nothing is written.
	liftSandboxMemoryMax(context.Background(), root, "actor-uid", sizing.SandboxSize{})
	if entries, _ := os.ReadDir(root); len(entries) != 0 {
		t.Errorf("wrote %v without a declared size", entries)
	}
	// A missing leaf (no delegation) only logs; it must not create one.
	liftSandboxMemoryMax(context.Background(), root, "actor-uid", sizing.SandboxSize{MemoryBytes: 1 << 30})
	if entries, _ := os.ReadDir(root); len(entries) != 0 {
		t.Errorf("created %v for a missing leaf", entries)
	}
}
