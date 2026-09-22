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
	"testing"

	"github.com/agent-substrate/substrate/internal/ateerrors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestCrashUnlessTransient(t *testing.T) {
	ctx := context.Background()
	notReady := ateerrors.NewGRPCError(ctx, codes.Internal, ateerrors.ReasonWorkloadNotReady, nil, errors.New("readyz timed out"))
	for _, tc := range []struct {
		name      string
		err       error
		wantCrash bool
	}{
		{"restore spec rejected", status.Error(codes.Internal, "failed to validate restore spec"), true},
		{"unclassified plain error", errors.New("runsc restore exited 1"), true},
		{"reason without directive", notReady, true},
		{"worker draining", status.Error(codes.Unavailable, "worker draining"), false},
		{"caller cancelled", status.Error(codes.Canceled, "context canceled"), false},
		{"caller deadline", status.Error(codes.DeadlineExceeded, "deadline exceeded"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := crashUnlessTransient(ctx, tc.err, "while calling ateom.RestoreWorkload")
			if crash := ateerrors.ActorCrashRequested(got); crash != tc.wantCrash {
				t.Errorf("ActorCrashRequested = %v, want %v (err: %v)", crash, tc.wantCrash, got)
			}
		})
	}
	if got := ateerrors.ExtractReason(crashUnlessTransient(ctx, notReady, "x")); got != string(ateerrors.ReasonWorkloadNotReady) {
		t.Errorf("reason = %q, want the ateom reason %q preserved", got, ateerrors.ReasonWorkloadNotReady)
	}
}
