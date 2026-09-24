// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package controlapi

import (
	"context"
	"time"
)

// detachedWorkflowTimeout bounds a workflow that no longer follows its caller.
// It matches ateom's own 30-minute workload grace period, which already
// bounds the checkpoint on the worker.
const detachedWorkflowTimeout = 30 * time.Minute

// detachedWorkflowContext keeps ctx's values (trace spans, identity) but not
// its cancellation or deadline, and applies detachedWorkflowTimeout instead.
func detachedWorkflowContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), detachedWorkflowTimeout)
}
