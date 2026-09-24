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
	"testing"
	"time"
)

type detachTestKey struct{}

func TestDetachedWorkflowContextOutlivesItsCaller(t *testing.T) {
	caller, cancelCaller := context.WithTimeout(context.WithValue(context.Background(), detachTestKey{}, "span"), time.Minute)
	workflow, cancel := detachedWorkflowContext(caller)
	defer cancel()

	cancelCaller()
	if err := caller.Err(); err == nil {
		t.Fatal("caller context should be cancelled")
	}
	if err := workflow.Err(); err != nil {
		t.Fatalf("workflow context ended with its caller: %v", err)
	}
	if got := workflow.Value(detachTestKey{}); got != "span" {
		t.Errorf("workflow context lost the caller's values: %v", got)
	}
	deadline, ok := workflow.Deadline()
	if !ok || time.Until(deadline) < detachedWorkflowTimeout-time.Minute {
		t.Errorf("workflow deadline = %v, %v; want about %v from now", deadline, ok, detachedWorkflowTimeout)
	}

	cancel()
	if workflow.Err() == nil {
		t.Error("workflow context should end when its own cancel is called")
	}
}
