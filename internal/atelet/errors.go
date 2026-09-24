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

	epb "google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// SnapshotManifestName is the object/file name of a snapshot's manifest.
// atelet uploads it after every file it lists, so its presence in object
// storage means the snapshot is committed.
const SnapshotManifestName = "manifest.json"

const (
	// ErrorDomain is the ErrorInfo domain of the failures atelet classifies.
	ErrorDomain = "atelet.substrate.dev"

	// ReasonSnapshotKeptOnNode marks a suspend whose checkpoint succeeded but
	// whose upload did not: the snapshot is kept on the node as a local
	// snapshot named after the in-progress snapshot URI, so the actor can be
	// recorded PAUSED there instead of crashed, and uploaded by a later
	// suspend.
	ReasonSnapshotKeptOnNode = "SNAPSHOT_KEPT_ON_NODE"
)

// SnapshotKeptOnNodeError returns the Unavailable status a Checkpoint returns
// when it kept a snapshot it could not upload on the node.
func SnapshotKeptOnNodeError(cause error) error {
	st, err := status.New(codes.Unavailable, "snapshot kept on the node after its upload failed: "+cause.Error()).
		WithDetails(&epb.ErrorInfo{Domain: ErrorDomain, Reason: ReasonSnapshotKeptOnNode})
	if err != nil {
		// Only a detail that fails to marshal gets here; ErrorInfo always marshals.
		return status.Error(codes.Unavailable, cause.Error())
	}
	return st.Err()
}

// IsSnapshotKeptOnNode reports whether err is a SnapshotKeptOnNodeError.
func IsSnapshotKeptOnNode(err error) bool {
	var withStatus interface{ GRPCStatus() *status.Status }
	if !errors.As(err, &withStatus) {
		return false
	}
	for _, detail := range withStatus.GRPCStatus().Details() {
		if info, ok := detail.(*epb.ErrorInfo); ok && info.GetDomain() == ErrorDomain && info.GetReason() == ReasonSnapshotKeptOnNode {
			return true
		}
	}
	return false
}
