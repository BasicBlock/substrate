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
	"errors"
	"github.com/agent-substrate/substrate/cmd/atelet/internal/ateletpath"
	"github.com/agent-substrate/substrate/internal/proto/ateletpb"
	"os"
	"testing"
)

func TestFailedUploadKeepsRestorableCheckpoint(t *testing.T) {
	a := runPluginActor(t)
	a.store.putErr = errors.New("object store unavailable")
	resp, err := a.checkpoint(t, a.snapshot("kept-snapshot", 1), ateletpb.UploadMode_UPLOAD_MODE_IMMEDIATE)
	if err != nil {
		t.Fatalf("Checkpoint: %v; want the surviving local snapshot", err)
	}
	if got := resp.GetState().GetLatestLocal().GetSnapshot().GetSnapshotUuid(); got != "kept-snapshot" {
		t.Fatalf("latest local = %q", got)
	}
	if _, err := os.Stat(ateletpath.LocalSnapshotDir(pluginActorUID, "kept-snapshot")); err != nil {
		t.Fatal(err)
	}
	a.restoreLocal(t, "kept-snapshot", 1)
}
