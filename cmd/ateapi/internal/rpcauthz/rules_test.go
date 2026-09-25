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

package rpcauthz

import (
	"slices"
	"testing"

	"github.com/agent-substrate/substrate/cmd/ateapi/internal/authz"
	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	"google.golang.org/grpc"
)

// Every method ate-api serves has a rule, so enforce mode never denies a
// method only because it was forgotten.
func TestEveryMethodHasARule(t *testing.T) {
	for _, desc := range []grpc.ServiceDesc{ateapipb.Control_ServiceDesc, ateapipb.WorkerService_ServiceDesc} {
		for _, m := range desc.Methods {
			method := "/" + desc.ServiceName + "/" + m.MethodName
			if _, ok := rules[method]; !ok {
				t.Errorf("no authorization rule for %s", method)
			}
		}
		for _, s := range desc.Streams {
			method := "/" + desc.ServiceName + "/" + s.StreamName
			if _, ok := rules[method]; !ok {
				t.Errorf("no authorization rule for %s", method)
			}
		}
	}
}

func describe(checks []authz.Check) []string {
	var out []string
	for _, c := range checks {
		out = append(out, c.String())
	}
	return out
}

func TestChecksFor(t *testing.T) {
	tests := []struct {
		method string
		req    any
		want   []string
	}{
		{ateapipb.Control_GetActor_FullMethodName, &ateapipb.GetActorRequest{Actor: ref("dev-a", "w")}, []string{"can_get on actor:dev-a/w"}},
		{ateapipb.Control_CreateActor_FullMethodName, newActor("dev-a", "w", ref("bb-dev", "t"), ref("tags", "g")), []string{
			"can_create_actor on atespace:dev-a", "can_get on actor_template:bb-dev/t", "can_get on atespace:tags"}},
		{ateapipb.Control_UpdateActor_FullMethodName, &ateapipb.UpdateActorRequest{Actor: &ateapipb.Actor{
			Metadata: &ateapipb.ResourceMetadata{Atespace: "dev-a", Name: "w"}, ActorTemplate: ref("bb-dev", "t2")}},
			[]string{"can_update on actor:dev-a/w", "can_get on actor_template:bb-dev/t2"}},
		{ateapipb.Control_PauseActor_FullMethodName, &ateapipb.PauseActorRequest{Actor: ref("a", "b")}, []string{"can_suspend on actor:a/b"}},
		{ateapipb.Control_DeleteActorEgressPolicy_FullMethodName, &ateapipb.DeleteActorEgressPolicyRequest{Actor: ref("a", "b")}, []string{"can_update on actor:a/b"}},
		{ateapipb.Control_ListActors_FullMethodName, &ateapipb.ListActorsRequest{Atespace: "dev-a"}, []string{"can_get on atespace:dev-a"}},
		{ateapipb.Control_ListActors_FullMethodName, &ateapipb.ListActorsRequest{}, []string{"can_get on global:root"}},
		{ateapipb.Control_ListActorTemplates_FullMethodName, &ateapipb.ListActorTemplatesRequest{}, []string{"can_get on global:root"}},
		{ateapipb.Control_CreateTag_FullMethodName, &ateapipb.CreateTagRequest{Tag: &ateapipb.Tag{
			Metadata: &ateapipb.ResourceMetadata{Atespace: "t", Name: "g"}, SourceActor: ref("a", "b")}},
			[]string{"can_update on atespace:t", "can_get on actor:a/b"}},
		{ateapipb.Control_DeleteTag_FullMethodName, &ateapipb.DeleteTagRequest{Tag: ref("t", "g")}, []string{"can_update on atespace:t"}},
		{ateapipb.Control_CreateAtespace_FullMethodName, newAtespace("x"), []string{"can_create_atespace on global:root"}},
		{ateapipb.Control_DeleteAtespace_FullMethodName, &ateapipb.DeleteAtespaceRequest{Atespace: ref("", "x")}, []string{"can_delete on atespace:x"}},
		{ateapipb.Control_CreateActorTemplate_FullMethodName, &ateapipb.CreateActorTemplateRequest{ActorTemplate: &ateapipb.ActorTemplate{
			Metadata: &ateapipb.ResourceMetadata{Atespace: "bb-dev", Name: "t"}}}, []string{"can_create_actor_template on atespace:bb-dev"}},
		{ateapipb.Control_DeleteActorTemplate_FullMethodName, &ateapipb.DeleteActorTemplateRequest{ActorTemplate: ref("bb-dev", "t")},
			[]string{"can_delete on actor_template:bb-dev/t"}},
		{ateapipb.Control_DrainWorker_FullMethodName, &ateapipb.DrainWorkerRequest{}, []string{"owner on global:root"}},
		{ateapipb.Control_MintActorJWT_FullMethodName, &ateapipb.MintActorJWTRequest{}, []string{"owner on global:root"}},
		{ateapipb.WorkerService_SetWorkerCapacity_FullMethodName, &ateapipb.SetWorkerCapacityRequest{}, nil},
	}
	for _, tt := range tests {
		got, err := checksFor(tt.method, tt.req)
		if err != nil {
			t.Errorf("checksFor(%s) error = %v", tt.method, err)
			continue
		}
		if !slices.Equal(describe(got), tt.want) {
			t.Errorf("checksFor(%s) = %q, want %q", tt.method, describe(got), tt.want)
		}
	}
}

func TestChecksForRejectsUnknownMethodsAndRequests(t *testing.T) {
	if _, err := checksFor("/ateapi.Control/NoSuchMethod", nil); err == nil {
		t.Error("checksFor(unknown method) succeeded")
	}
	if _, err := checksFor(ateapipb.Control_GetActor_FullMethodName, &ateapipb.DeleteActorRequest{}); err == nil {
		t.Error("checksFor(GetActor, DeleteActorRequest) succeeded")
	}
}
