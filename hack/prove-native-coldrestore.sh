#!/usr/bin/env bash

# Copyright 2026 The Agent Substrate Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# This experiment runs only on its owned disposable GitHub-hosted runner.
set -o errexit -o nounset -o pipefail
is_disposable_proof_runner() {
  [[ "${GITHUB_ACTIONS:-}" == true && "${SUBSTRATE_DISPOSABLE_PROOF:-}" == eng-4039 ]]
}
is_disposable_proof_runner || { echo 'This proof requires its disposable GitHub runner' >&2; exit 2; }
ROOT="$(git rev-parse --show-toplevel)"
cd "${ROOT}"
hack/create-kind-cluster.sh
go run ./cmd/ate-setup --kind deploy ate-system
go run ./cmd/ate-setup --kind deploy demo counter
hack/run-e2e-kind.sh ./internal/e2e/suites/demo -run '^TestSupplementalAssetRemovalRestoresRootFS$' -count=3 -shuffle=on -args --no-color --preview="${ATE_PREVIEW}"
go -C tools/junittool run . verify -manifest "${ARTIFACTS}/expected-junit.txt"
