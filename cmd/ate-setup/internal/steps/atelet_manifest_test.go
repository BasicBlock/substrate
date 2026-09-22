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

package steps

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"
)

func TestAteletCanRestoreOCIFileMetadata(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(repoRoot(t), "manifests", "ate-install", "atelet.yaml"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	for _, document := range strings.Split(string(data), "\n---\n") {
		var resource struct {
			Kind string `yaml:"kind"`
			Spec struct {
				Template struct {
					Spec struct {
						Containers []corev1.Container `yaml:"containers"`
					} `yaml:"spec"`
				} `yaml:"template"`
			} `yaml:"spec"`
		}
		if err := yaml.Unmarshal([]byte(document), &resource); err != nil {
			t.Fatalf("Unmarshal: %v", err)
		}
		if resource.Kind != "DaemonSet" {
			continue
		}
		for _, container := range resource.Spec.Template.Spec.Containers {
			if container.Name != "atelet" {
				continue
			}
			if container.SecurityContext == nil || container.SecurityContext.Capabilities == nil {
				t.Fatal("atelet has no capability policy")
			}
			got := container.SecurityContext.Capabilities.Add
			if !slices.Contains(got, corev1.Capability("CHOWN")) {
				t.Fatalf("atelet added capabilities = %v, want CHOWN for OCI ownership restoration", got)
			}
			if !slices.Contains(got, corev1.Capability("FOWNER")) {
				t.Fatalf("atelet added capabilities = %v, want FOWNER for OCI mode restoration after chown", got)
			}
			return
		}
	}
	t.Fatal("atelet container not found")
}
