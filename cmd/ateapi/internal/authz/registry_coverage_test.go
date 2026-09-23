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

package authz

import (
	"testing"

	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	"google.golang.org/grpc"
)

// An RPC without a rule is served to every authenticated principal, so adding
// one to a service must come with a rule for it.
func TestDefaultRPCPermissions_CoverEveryRPC(t *testing.T) {
	for _, svc := range []grpc.ServiceDesc{ateapipb.Control_ServiceDesc, ateapipb.WorkerService_ServiceDesc} {
		for _, m := range svc.Methods {
			full := "/" + svc.ServiceName + "/" + m.MethodName
			if _, ok := defaultRPCPermissions[full]; !ok {
				t.Errorf("%s has no rule in defaultRPCPermissions", full)
			}
		}
	}
}
