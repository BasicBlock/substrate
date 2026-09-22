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
	"fmt"

	"github.com/agent-substrate/substrate/internal/ateerrors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// crashUnlessTransient classifies a failed ateom RunWorkload or
// RestoreWorkload. Both handlers tear the workload down before returning an
// error, so a retry cannot adopt it: without the crash directive the control
// plane retries the start indefinitely while the actor keeps its worker
// assignment. Crashing releases the worker and keeps the actor's accepted
// snapshot for revert. Only failures that say nothing about the workload —
// the worker draining or unreachable, or the caller giving up — stay
// retriable.
func crashUnlessTransient(ctx context.Context, err error, msg string) error {
	wrapped := fmt.Errorf("%s: %w", msg, err)
	if ateerrors.ActorCrashRequested(err) {
		return wrapped
	}
	switch status.Code(err) {
	case codes.Unavailable, codes.Canceled, codes.DeadlineExceeded, codes.Aborted, codes.ResourceExhausted:
		return wrapped
	}
	return ateerrors.NewGRPCError(ctx, codes.DataLoss, ateerrors.Reason(ateerrors.ExtractReason(err)), ateerrors.ActorCrashedMetadata(), wrapped)
}
