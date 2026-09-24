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

package atelet

import (
	"errors"
	"fmt"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestSnapshotKeptOnNodeError(t *testing.T) {
	err := SnapshotKeptOnNodeError(errors.New("gcs: 503"))
	if got := status.Code(err); got != codes.Unavailable {
		t.Errorf("code = %v, want Unavailable", got)
	}
	// A wire round trip keeps only the status, which carries the reason.
	wire := status.Convert(err).Proto()
	if !IsSnapshotKeptOnNode(status.ErrorProto(wire)) {
		t.Errorf("the reason did not survive the wire")
	}
	if !IsSnapshotKeptOnNode(fmt.Errorf("while suspending: %w", err)) {
		t.Errorf("a wrapped error lost the reason")
	}
	for _, other := range []error{
		nil,
		errors.New("gcs: 503"),
		status.Error(codes.Unavailable, "snapshot kept on the node"),
	} {
		if IsSnapshotKeptOnNode(other) {
			t.Errorf("IsSnapshotKeptOnNode(%v) = true, want false", other)
		}
	}
}
