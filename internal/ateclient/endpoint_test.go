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

package ateclient

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEndpointTLSConfig(t *testing.T) {
	system, err := endpointTLSConfig("system")
	if err != nil || system.RootCAs != nil || system.ServerName != "" {
		t.Fatalf("system roots: %+v, %v; want system roots verifying the endpoint's own name", system, err)
	}
	empty := filepath.Join(t.TempDir(), "empty.pem")
	if err := os.WriteFile(empty, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := endpointTLSConfig(empty); err == nil {
		t.Fatal("a CA file without certificates was accepted")
	}
	if _, err := endpointTLSConfig(filepath.Join(t.TempDir(), "missing.pem")); err == nil {
		t.Fatal("a missing CA file was accepted")
	}
}

func TestDialDirectWithEndpointCANeedsToken(t *testing.T) {
	EndpointCAFile = "system"
	t.Cleanup(func() { EndpointCAFile = "" })
	if _, err := dialDirect(t.Context(), "", "", "substrate.example:443", "", false); err == nil {
		t.Fatal("dialDirect() without a token file succeeded")
	}
	client, err := dialDirect(t.Context(), "/nonexistent/kubeconfig", "", "substrate.example:443", filepath.Join(t.TempDir(), "token"), false)
	if err != nil {
		t.Fatalf("dialDirect() read Kubernetes configuration: %v", err)
	}
	client.Close()
}
