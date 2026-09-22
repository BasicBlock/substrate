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

package cmd

import (
	"testing"

	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/emptypb"
)

func TestEgressPolicyFromManifest(t *testing.T) {
	got, err := egressPolicyFromManifest([]byte(`rules:
- cidrs:
    cidrs: ["8.8.8.0/24"]
- hostnames:
    patterns: ["*.example.com"]
- all: {}
`), "workspaces")
	if err != nil {
		t.Fatalf("egressPolicyFromManifest: %v", err)
	}
	want := &ateapipb.EgressPolicy{
		Metadata: &ateapipb.ResourceMetadata{Atespace: "workspaces", Name: "default"},
		Rules: []*ateapipb.EgressRule{
			{Cidrs: &ateapipb.CIDRRule{Cidrs: []string{"8.8.8.0/24"}}},
			{Hostnames: &ateapipb.HostnameRule{Patterns: []string{"*.example.com"}}},
			{All: &emptypb.Empty{}},
		},
	}
	if diff := cmp.Diff(want, got, protocmp.Transform()); diff != "" {
		t.Errorf("egressPolicyFromManifest (-want +got):\n%s", diff)
	}
}

func TestEgressPolicyFromManifestRejectsUnknownFields(t *testing.T) {
	if _, err := egressPolicyFromManifest([]byte("rules:\n- cidr: {cidrs: [\"8.8.8.0/24\"]}\n"), "workspaces"); err == nil {
		t.Fatal("egressPolicyFromManifest accepted an unknown field")
	}
}

func TestEgressPolicyCommandArgs(t *testing.T) {
	runCommandArgsTests(t, []commandArgsTest{
		{name: "get", command: getEgressPolicyCmd, args: []string{"workspace"}},
		{name: "get without actor", command: getEgressPolicyCmd, wantErr: true},
		{name: "delete", command: deleteEgressPolicyCmd, args: []string{"workspace"}},
	})
}
