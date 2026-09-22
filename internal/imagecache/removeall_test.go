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

package imagecache

import (
	"os"
	"path/filepath"
	"testing"
)

// An unpacked image can contain restrictive directories owned by a non-root
// guest uid (e.g. /var/lib/postgresql as 999:999 0700). atelet runs as root
// with only CAP_CHOWN and CAP_FOWNER, so cleanup must not depend on
// CAP_DAC_OVERRIDE to traverse them. Full root passes regardless; run this
// with atelet's capability set to exercise the regression:
//
//	docker run --user 0 --cap-drop ALL --cap-add CHOWN --cap-add FOWNER ...
func TestRemoveAllWritableRemovesNonRootOwnedDirs(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to create non-root-owned directories")
	}
	top := filepath.Join(t.TempDir(), "layer")
	data := filepath.Join(top, "fs", "var", "lib", "postgresql", "data")
	if err := os.MkdirAll(data, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(data, "PG_VERSION"), []byte("18\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	for _, p := range []string{filepath.Join(data, "PG_VERSION"), data, filepath.Dir(data)} {
		if err := os.Lchown(p, 999, 999); err != nil {
			t.Fatalf("Lchown(%q): %v", p, err)
		}
	}
	for _, p := range []string{data, filepath.Dir(data)} {
		if err := os.Chmod(p, 0o700); err != nil {
			t.Fatalf("Chmod(%q): %v", p, err)
		}
	}

	if err := RemoveAllWritable(top); err != nil {
		t.Fatalf("RemoveAllWritable: %v", err)
	}
	if _, err := os.Lstat(top); !os.IsNotExist(err) {
		t.Fatalf("Lstat after removal = %v, want not exist", err)
	}
}
