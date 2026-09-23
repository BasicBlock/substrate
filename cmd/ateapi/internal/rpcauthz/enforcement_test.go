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
	"context"
	"testing"

	"github.com/agent-substrate/substrate/internal/ateapiauth"
	"github.com/agent-substrate/substrate/internal/authz"
	"github.com/agent-substrate/substrate/internal/authz/authztest"
	"github.com/agent-substrate/substrate/internal/principal"
	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Principals as ateapiauth authenticates them under testdata/authentication.yaml.
var (
	paul       = googleUser("paul@basicblock.io")
	alice      = googleUser("alice@basicblock.io")
	bob        = googleUser("bob@basicblock.io")
	ateClient  = kubernetesSA("ate-system", "ate-client")
	eveDemo    = kubernetesSA("internal-eve-demo", "eve-demo")
	anyPod     = kubernetesSA("default", "default")
	eveRuntime = principal.PrincipalInfo{
		ID: "eve-runtime@basicblock-internal.iam.gserviceaccount.com", Kind: principal.KindJWT, Provider: "google",
		Groups: []string{principal.GroupAuthenticated, "google", "google/service-accounts"},
	}
	controller = component("ate-controller")
	router     = component("atenet-router")
	egress     = component("atenet-egress")
	atelet     = component("atelet")
)

func googleUser(email string) principal.PrincipalInfo {
	return principal.PrincipalInfo{ID: email, Kind: principal.KindJWT, Provider: "google",
		Groups: []string{principal.GroupAuthenticated, "google", "google/basicblock"}}
}

func kubernetesSA(namespace, name string) principal.PrincipalInfo {
	return principal.PrincipalInfo{ID: "system:serviceaccount:" + namespace + ":" + name, Kind: principal.KindJWT,
		Provider: "kubernetes", Groups: []string{principal.GroupAuthenticated, "kubernetes"}}
}

func component(serviceAccount string) principal.PrincipalInfo {
	return principal.PrincipalInfo{ID: "spiffe://cluster.local/ns/ate-system/sa/" + serviceAccount, Kind: principal.KindMTLS,
		Provider: principal.ProviderMTLS, Groups: []string{principal.GroupAuthenticated, principal.ProviderMTLS}}
}

func ref(atespace, name string) *ateapipb.ObjectRef {
	return &ateapipb.ObjectRef{Atespace: atespace, Name: name}
}

func newActor(atespace, name string, template, tag *ateapipb.ObjectRef) *ateapipb.CreateActorRequest {
	return &ateapipb.CreateActorRequest{Actor: &ateapipb.Actor{
		Metadata:      &ateapipb.ResourceMetadata{Atespace: atespace, Name: name},
		ActorTemplate: template,
		SourceTag:     tag,
	}}
}

func newAtespace(name string) *ateapipb.CreateAtespaceRequest {
	return &ateapipb.CreateAtespaceRequest{Atespace: &ateapipb.Atespace{Metadata: &ateapipb.ResourceMetadata{Name: name}}}
}

// exampleAuthorizer reconciles testdata/authorization.yaml into a fresh store.
func exampleAuthorizer(t *testing.T) *authz.Authorizer {
	t.Helper()
	ctx := context.Background()
	authn, err := ateapiauth.LoadAuthenticationConfig("testdata/authentication.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := authz.LoadConfig("testdata/authorization.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(authn.GroupNames()); err != nil {
		t.Fatal(err)
	}
	srv, err := authz.NewServer(ctx, authztest.StartPostgres(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	a, err := authz.NewAuthorizer(ctx, srv, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

type call struct {
	who    principal.PrincipalInfo
	method string
	req    any
	want   codes.Code
}

func run(t *testing.T, a Authorizer, calls []call) {
	t.Helper()
	intercept := UnaryServerInterceptor(a)
	ok := func(context.Context, any) (any, error) { return struct{}{}, nil }
	for _, c := range calls {
		ctx := principal.InjectContext(context.Background(), c.who)
		_, err := intercept(ctx, c.req, &grpc.UnaryServerInfo{FullMethod: c.method}, ok)
		if got := status.Code(err); got != c.want {
			t.Errorf("%s %s(%v): %v (%v), want %v", c.who.ID, c.method, c.req, got, err, c.want)
		}
	}
}

func TestEnforcementExample(t *testing.T) {
	a := exampleAuthorizer(t)
	const (
		allow = codes.OK
		deny  = codes.PermissionDenied
	)
	// Atespaces the developers and the eve service account create; the
	// creators own them.
	run(t, a, []call{
		{alice, ateapipb.Control_CreateAtespace_FullMethodName, newAtespace("dev-alice"), allow},
		{bob, ateapipb.Control_CreateAtespace_FullMethodName, newAtespace("dev-bob"), allow},
		{eveRuntime, ateapipb.Control_CreateAtespace_FullMethodName, newAtespace("eve-gcp"), allow},
		{anyPod, ateapipb.Control_CreateAtespace_FullMethodName, newAtespace("squat"), deny},
		{eveDemo, ateapipb.Control_CreateAtespace_FullMethodName, newAtespace("eve-more"), deny},
	})

	t.Run("operators and platform admins", func(t *testing.T) {
		run(t, a, []call{
			{ateClient, ateapipb.Control_CreateActorTemplate_FullMethodName, &ateapipb.CreateActorTemplateRequest{
				ActorTemplate: &ateapipb.ActorTemplate{Metadata: &ateapipb.ResourceMetadata{Atespace: "bb-dev", Name: "t"}}}, allow},
			{ateClient, ateapipb.Control_CreateActorTemplate_FullMethodName, &ateapipb.CreateActorTemplateRequest{
				ActorTemplate: &ateapipb.ActorTemplate{Metadata: &ateapipb.ResourceMetadata{Atespace: "eve-demo", Name: "t"}}}, allow},
			{ateClient, ateapipb.Control_CreateAtespace_FullMethodName, newAtespace("eve-demo"), allow},
			{ateClient, ateapipb.Control_ListActors_FullMethodName, &ateapipb.ListActorsRequest{}, allow},
			{ateClient, ateapipb.Control_DeleteActor_FullMethodName, &ateapipb.DeleteActorRequest{Actor: ref("dev-alice", "x")}, allow},
			{paul, ateapipb.Control_GetActor_FullMethodName, &ateapipb.GetActorRequest{Actor: ref("dev-bob", "x")}, allow},
			{paul, ateapipb.Control_ListWorkers_FullMethodName, &ateapipb.ListWorkersRequest{}, allow},
		})
	})

	t.Run("substrate components", func(t *testing.T) {
		run(t, a, []call{
			{controller, ateapipb.Control_DrainWorker_FullMethodName, &ateapipb.DrainWorkerRequest{}, allow},
			{controller, ateapipb.Control_ListWorkerActorAssignments_FullMethodName, &ateapipb.ListWorkerActorAssignmentsRequest{}, allow},
			{controller, ateapipb.Control_SuspendActor_FullMethodName, &ateapipb.SuspendActorRequest{Actor: ref("dev-alice", "x")}, allow},
			{router, ateapipb.Control_ResumeActor_FullMethodName, &ateapipb.ResumeActorRequest{Actor: ref("eve-demo", "x")}, allow},
			{router, ateapipb.Control_GetActor_FullMethodName, &ateapipb.GetActorRequest{Actor: ref("dev-bob", "x")}, allow},
			{atelet, ateapipb.Control_ListWorkers_FullMethodName, &ateapipb.ListWorkersRequest{}, allow},
			{atelet, ateapipb.Control_ListActorTemplates_FullMethodName, &ateapipb.ListActorTemplatesRequest{}, allow},
			{atelet, ateapipb.Control_MintActorCertificate_FullMethodName, &ateapipb.MintActorCertificateRequest{Actor: ref("dev-alice", "x")}, allow},
			{egress, ateapipb.Control_MintActorJWT_FullMethodName, &ateapipb.MintActorJWTRequest{Actor: ref("eve-demo", "x")}, allow},
			{egress, ateapipb.Control_GetActorEgressPolicy_FullMethodName, &ateapipb.GetActorEgressPolicyRequest{Actor: ref("dev-alice", "x")}, allow},
			{atelet, ateapipb.WorkerService_SetWorkerCapacity_FullMethodName, &ateapipb.SetWorkerCapacityRequest{}, allow},
		})
	})

	t.Run("eve-demo editor", func(t *testing.T) {
		tag := &ateapipb.CreateTagRequest{Tag: &ateapipb.Tag{
			Metadata: &ateapipb.ResourceMetadata{Atespace: "eve-demo", Name: "tag"}, SourceActor: ref("eve-demo", "a")}}
		run(t, a, []call{
			{eveDemo, ateapipb.Control_ListActorTemplates_FullMethodName, &ateapipb.ListActorTemplatesRequest{Atespace: "eve-demo"}, allow},
			{eveDemo, ateapipb.Control_GetActorTemplate_FullMethodName, &ateapipb.GetActorTemplateRequest{ActorTemplate: ref("eve-demo", "t")}, allow},
			{eveDemo, ateapipb.Control_CreateActor_FullMethodName, newActor("eve-demo", "a", ref("eve-demo", "t"), nil), allow},
			{eveDemo, ateapipb.Control_CreateActor_FullMethodName, newActor("eve-demo", "b", ref("eve-demo", "t"), ref("eve-demo", "tag")), allow},
			{eveDemo, ateapipb.Control_GetActor_FullMethodName, &ateapipb.GetActorRequest{Actor: ref("eve-demo", "a")}, allow},
			{eveDemo, ateapipb.Control_SuspendActor_FullMethodName, &ateapipb.SuspendActorRequest{Actor: ref("eve-demo", "a")}, allow},
			{eveDemo, ateapipb.Control_RevertActor_FullMethodName, &ateapipb.RevertActorRequest{Actor: ref("eve-demo", "a")}, allow},
			{eveDemo, ateapipb.Control_DeleteActor_FullMethodName, &ateapipb.DeleteActorRequest{Actor: ref("eve-demo", "a"), AnyState: true}, allow},
			{eveDemo, ateapipb.Control_CreateActorEgressPolicy_FullMethodName, &ateapipb.CreateActorEgressPolicyRequest{Actor: ref("eve-demo", "a")}, allow},
			{eveDemo, ateapipb.Control_DeleteActorEgressPolicy_FullMethodName, &ateapipb.DeleteActorEgressPolicyRequest{Actor: ref("eve-demo", "a")}, allow},
			{eveDemo, ateapipb.Control_CreateTag_FullMethodName, tag, allow},
			{eveDemo, ateapipb.Control_GetTag_FullMethodName, &ateapipb.GetTagRequest{Tag: ref("eve-demo", "tag")}, allow},
			// Nothing outside eve-demo, and nothing global.
			{eveDemo, ateapipb.Control_GetActor_FullMethodName, &ateapipb.GetActorRequest{Actor: ref("dev-alice", "x")}, deny},
			{eveDemo, ateapipb.Control_CreateActor_FullMethodName, newActor("dev-alice", "a", ref("eve-demo", "t"), nil), deny},
			{eveDemo, ateapipb.Control_CreateActor_FullMethodName, newActor("eve-demo", "c", ref("bb-dev", "t"), nil), deny},
			{eveDemo, ateapipb.Control_CreateActor_FullMethodName, newActor("eve-demo", "d", ref("eve-demo", "t"), ref("dev-alice", "tag")), deny},
			{eveDemo, ateapipb.Control_ListActors_FullMethodName, &ateapipb.ListActorsRequest{}, deny},
			{eveDemo, ateapipb.Control_ListWorkers_FullMethodName, &ateapipb.ListWorkersRequest{}, deny},
			{eveDemo, ateapipb.Control_DeleteAtespace_FullMethodName, &ateapipb.DeleteAtespaceRequest{Atespace: ref("", "eve-demo")}, deny},
			{eveDemo, ateapipb.Control_MintActorJWT_FullMethodName, &ateapipb.MintActorJWTRequest{Actor: ref("eve-demo", "a")}, deny},
		})
	})

	t.Run("developers", func(t *testing.T) {
		run(t, a, []call{
			{alice, ateapipb.Control_GetActorTemplate_FullMethodName, &ateapipb.GetActorTemplateRequest{ActorTemplate: ref("bb-dev", "t")}, allow},
			{alice, ateapipb.Control_CreateActor_FullMethodName, newActor("dev-alice", "w", ref("bb-dev", "t"), nil), allow},
			{alice, ateapipb.Control_ResumeActor_FullMethodName, &ateapipb.ResumeActorRequest{Actor: ref("dev-alice", "w")}, allow},
			{alice, ateapipb.Control_CreateActorEgressPolicy_FullMethodName, &ateapipb.CreateActorEgressPolicyRequest{Actor: ref("dev-alice", "w")}, allow},
			{alice, ateapipb.Control_ListActors_FullMethodName, &ateapipb.ListActorsRequest{Atespace: "dev-alice"}, allow},
			{alice, ateapipb.Control_DeleteActor_FullMethodName, &ateapipb.DeleteActorRequest{Actor: ref("dev-alice", "w")}, allow},
			// Another developer's workspaces, the shared templates and the eve atespace are out of reach.
			{alice, ateapipb.Control_GetActor_FullMethodName, &ateapipb.GetActorRequest{Actor: ref("dev-bob", "w")}, deny},
			{alice, ateapipb.Control_ResumeActor_FullMethodName, &ateapipb.ResumeActorRequest{Actor: ref("dev-bob", "w")}, deny},
			{alice, ateapipb.Control_ListActors_FullMethodName, &ateapipb.ListActorsRequest{Atespace: "dev-bob"}, deny},
			{alice, ateapipb.Control_CreateActor_FullMethodName, newActor("dev-bob", "w", ref("bb-dev", "t"), nil), deny},
			{alice, ateapipb.Control_CreateActorTemplate_FullMethodName, &ateapipb.CreateActorTemplateRequest{
				ActorTemplate: &ateapipb.ActorTemplate{Metadata: &ateapipb.ResourceMetadata{Atespace: "bb-dev", Name: "t"}}}, deny},
			{alice, ateapipb.Control_GetActor_FullMethodName, &ateapipb.GetActorRequest{Actor: ref("eve-demo", "a")}, deny},
			{alice, ateapipb.Control_ListActors_FullMethodName, &ateapipb.ListActorsRequest{}, deny},
			{alice, ateapipb.Control_ListAtespaces_FullMethodName, &ateapipb.ListAtespacesRequest{}, deny},
		})
	})

	t.Run("unbound principals get nothing", func(t *testing.T) {
		run(t, a, []call{
			{anyPod, ateapipb.Control_GetActorTemplate_FullMethodName, &ateapipb.GetActorTemplateRequest{ActorTemplate: ref("bb-dev", "t")}, deny},
			{anyPod, ateapipb.Control_ResumeActor_FullMethodName, &ateapipb.ResumeActorRequest{Actor: ref("dev-alice", "w")}, deny},
			{anyPod, ateapipb.Control_GetAtespace_FullMethodName, &ateapipb.GetAtespaceRequest{Atespace: ref("", "eve-demo")}, deny},
			{anyPod, ateapipb.Control_ListActorTemplates_FullMethodName, &ateapipb.ListActorTemplatesRequest{}, deny},
		})
	})

	t.Run("an agent runtime owns what it creates", func(t *testing.T) {
		run(t, a, []call{
			{eveRuntime, ateapipb.Control_CreateActorTemplate_FullMethodName, &ateapipb.CreateActorTemplateRequest{
				ActorTemplate: &ateapipb.ActorTemplate{Metadata: &ateapipb.ResourceMetadata{Atespace: "eve-gcp", Name: "t"}}}, allow},
			{eveRuntime, ateapipb.Control_CreateActor_FullMethodName, newActor("eve-gcp", "a", ref("eve-gcp", "t"), nil), allow},
			{eveRuntime, ateapipb.Control_GetActor_FullMethodName, &ateapipb.GetActorRequest{Actor: ref("eve-demo", "a")}, deny},
			{eveRuntime, ateapipb.Control_GetActor_FullMethodName, &ateapipb.GetActorRequest{Actor: ref("dev-alice", "w")}, deny},
		})
	})

	t.Run("deleting an atespace forgets its creator", func(t *testing.T) {
		run(t, a, []call{
			{alice, ateapipb.Control_DeleteAtespace_FullMethodName, &ateapipb.DeleteAtespaceRequest{Atespace: ref("", "dev-alice")}, allow},
			{alice, ateapipb.Control_GetAtespace_FullMethodName, &ateapipb.GetAtespaceRequest{Atespace: ref("", "dev-alice")}, deny},
			{bob, ateapipb.Control_CreateAtespace_FullMethodName, newAtespace("dev-alice"), allow},
			{bob, ateapipb.Control_GetAtespace_FullMethodName, &ateapipb.GetAtespaceRequest{Atespace: ref("", "dev-alice")}, allow},
			{alice, ateapipb.Control_CreateActor_FullMethodName, newActor("dev-alice", "w", ref("bb-dev", "t"), nil), deny},
		})
	})
}
