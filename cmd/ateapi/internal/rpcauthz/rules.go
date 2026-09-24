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

// Package rpcauthz authorizes ate-api RPCs: every method maps to the checks a
// caller must pass, evaluated against the OpenFGA model in internal/authz.
package rpcauthz

import (
	"fmt"

	"github.com/agent-substrate/substrate/internal/authz"
	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	"google.golang.org/grpc/reflection/grpc_reflection_v1"
	"google.golang.org/grpc/reflection/grpc_reflection_v1alpha"
)

// A rule returns the checks a request must pass. The request is nil for
// streaming methods.
type rule func(req any) ([]authz.Check, error)

// handlerAuthorized marks a method whose handler authorizes the caller itself.
var handlerAuthorized rule = func(any) ([]authz.Check, error) { return nil, nil }

func one(object authz.Object, relation string) []authz.Check {
	return []authz.Check{{Object: object, Relation: relation}}
}

// onActor checks relation on the actor a request names.
func onActor[T interface{ GetActor() *ateapipb.ObjectRef }](relation string) rule {
	return func(req any) ([]authz.Check, error) {
		ref := req.(T).GetActor()
		return one(authz.ActorObject(ref.GetAtespace(), ref.GetName()), relation), nil
	}
}

// onTemplate checks relation on the actor template a request names.
func onTemplate[T interface{ GetActorTemplate() *ateapipb.ObjectRef }](relation string) rule {
	return func(req any) ([]authz.Check, error) {
		ref := req.(T).GetActorTemplate()
		return one(authz.ActorTemplateObject(ref.GetAtespace(), ref.GetName()), relation), nil
	}
}

// onListed checks relation on the atespace a list request names, and global
// viewing when it names none, which lists every atespace.
func onListed[T interface{ GetAtespace() string }](relation string) rule {
	return func(req any) ([]authz.Check, error) {
		if atespace := req.(T).GetAtespace(); atespace != "" {
			return one(authz.AtespaceObject(atespace), relation), nil
		}
		return one(authz.Global(), "can_get"), nil
	}
}

// global checks relation on the global scope.
func global(relation string) rule {
	return func(any) ([]authz.Check, error) { return one(authz.Global(), relation), nil }
}

// actorSources checks that the caller may read the template and the tag an
// actor is created or updated from, which can live in other atespaces.
func actorSources(actor *ateapipb.Actor) []authz.Check {
	var checks []authz.Check
	if t := actor.GetActorTemplate(); t != nil {
		checks = append(checks, authz.Check{Object: authz.ActorTemplateObject(t.GetAtespace(), t.GetName()), Relation: "can_get"})
	}
	if tag := actor.GetSourceTag(); tag != nil {
		checks = append(checks, authz.Check{Object: authz.AtespaceObject(tag.GetAtespace()), Relation: "can_get"})
	}
	return checks
}

// Tags have no type of their own: reading one needs can_get on its atespace,
// changing one can_update.
var rules = map[string]rule{
	ateapipb.Control_GetActor_FullMethodName: onActor[*ateapipb.GetActorRequest]("can_get"),
	ateapipb.Control_CreateActor_FullMethodName: func(req any) ([]authz.Check, error) {
		actor := req.(*ateapipb.CreateActorRequest).GetActor()
		atespace := authz.AtespaceObject(actor.GetMetadata().GetAtespace())
		return append(one(atespace, "can_create_actor"), actorSources(actor)...), nil
	},
	ateapipb.Control_UpdateActor_FullMethodName: func(req any) ([]authz.Check, error) {
		actor := req.(*ateapipb.UpdateActorRequest).GetActor()
		object := authz.ActorObject(actor.GetMetadata().GetAtespace(), actor.GetMetadata().GetName())
		return append(one(object, "can_update"), actorSources(actor)...), nil
	},
	ateapipb.Control_SuspendActor_FullMethodName: onActor[*ateapipb.SuspendActorRequest]("can_suspend"),
	// Pausing keeps a node-local snapshot: the same authority as suspending.
	ateapipb.Control_PauseActor_FullMethodName:  onActor[*ateapipb.PauseActorRequest]("can_suspend"),
	ateapipb.Control_ResumeActor_FullMethodName: onActor[*ateapipb.ResumeActorRequest]("can_resume"),
	ateapipb.Control_RevertActor_FullMethodName: onActor[*ateapipb.RevertActorRequest]("can_revert"),
	// The ingress gateway asks on its clients' behalf; the answer checks the
	// client's can_connect, and would otherwise reveal whether a token is valid.
	ateapipb.Control_CheckActorAccess_FullMethodName: global("owner"),
	ateapipb.Control_DeleteActor_FullMethodName:      onActor[*ateapipb.DeleteActorRequest]("can_delete"),
	// Dropping a snapshot's memory is a snapshot-management operation on the
	// actor's stored state, the same authority as suspending it.
	ateapipb.Control_DropSnapshotMemory_FullMethodName: onActor[*ateapipb.DropSnapshotMemoryRequest]("can_suspend"),

	ateapipb.Control_GetActorEgressPolicy_FullMethodName:    onActor[*ateapipb.GetActorEgressPolicyRequest]("can_get"),
	ateapipb.Control_CreateActorEgressPolicy_FullMethodName: onActor[*ateapipb.CreateActorEgressPolicyRequest]("can_update"),
	ateapipb.Control_UpdateActorEgressPolicy_FullMethodName: onActor[*ateapipb.UpdateActorEgressPolicyRequest]("can_update"),
	ateapipb.Control_DeleteActorEgressPolicy_FullMethodName: onActor[*ateapipb.DeleteActorEgressPolicyRequest]("can_update"),

	// Actor credentials are minted for Substrate's own components (the egress
	// gateway and atelet); the handlers keep their own transport checks.
	ateapipb.Control_MintActorJWT_FullMethodName:         global("owner"),
	ateapipb.Control_MintActorCertificate_FullMethodName: global("owner"),

	ateapipb.Control_CreateTag_FullMethodName: func(req any) ([]authz.Check, error) {
		tag := req.(*ateapipb.CreateTagRequest).GetTag()
		checks := one(authz.AtespaceObject(tag.GetMetadata().GetAtespace()), "can_update")
		if src := tag.GetSourceActor(); src != nil {
			checks = append(checks, authz.Check{Object: authz.ActorObject(src.GetAtespace(), src.GetName()), Relation: "can_get"})
		}
		return checks, nil
	},
	ateapipb.Control_GetTag_FullMethodName: func(req any) ([]authz.Check, error) {
		return one(authz.AtespaceObject(req.(*ateapipb.GetTagRequest).GetTag().GetAtespace()), "can_get"), nil
	},
	ateapipb.Control_ListTags_FullMethodName: onListed[*ateapipb.ListTagsRequest]("can_get"),
	ateapipb.Control_UpdateTag_FullMethodName: func(req any) ([]authz.Check, error) {
		return one(authz.AtespaceObject(req.(*ateapipb.UpdateTagRequest).GetTag().GetMetadata().GetAtespace()), "can_update"), nil
	},
	ateapipb.Control_DeleteTag_FullMethodName: func(req any) ([]authz.Check, error) {
		return one(authz.AtespaceObject(req.(*ateapipb.DeleteTagRequest).GetTag().GetAtespace()), "can_update"), nil
	},

	// Workers are cluster infrastructure.
	ateapipb.Control_ListWorkers_FullMethodName:                global("owner"),
	ateapipb.Control_GetWorker_FullMethodName:                  global("owner"),
	ateapipb.Control_CreateWorker_FullMethodName:               global("owner"),
	ateapipb.Control_UpdateWorker_FullMethodName:               global("owner"),
	ateapipb.Control_DeleteWorker_FullMethodName:               global("owner"),
	ateapipb.Control_DrainWorker_FullMethodName:                global("owner"),
	ateapipb.Control_ListWorkerActorAssignments_FullMethodName: global("owner"),

	ateapipb.Control_ListActors_FullMethodName: onListed[*ateapipb.ListActorsRequest]("can_get"),

	ateapipb.Control_CreateAtespace_FullMethodName: global("can_create_atespace"),
	ateapipb.Control_GetAtespace_FullMethodName: func(req any) ([]authz.Check, error) {
		return one(authz.AtespaceObject(req.(*ateapipb.GetAtespaceRequest).GetAtespace().GetName()), "can_get"), nil
	},
	ateapipb.Control_ListAtespaces_FullMethodName: global("can_get"),
	ateapipb.Control_DeleteAtespace_FullMethodName: func(req any) ([]authz.Check, error) {
		return one(authz.AtespaceObject(req.(*ateapipb.DeleteAtespaceRequest).GetAtespace().GetName()), "can_delete"), nil
	},

	ateapipb.Control_CreateActorTemplate_FullMethodName: func(req any) ([]authz.Check, error) {
		atespace := req.(*ateapipb.CreateActorTemplateRequest).GetActorTemplate().GetMetadata().GetAtespace()
		return one(authz.AtespaceObject(atespace), "can_create_actor_template"), nil
	},
	ateapipb.Control_GetActorTemplate_FullMethodName:    onTemplate[*ateapipb.GetActorTemplateRequest]("can_get"),
	ateapipb.Control_ListActorTemplates_FullMethodName:  onListed[*ateapipb.ListActorTemplatesRequest]("can_get"),
	ateapipb.Control_DeleteActorTemplate_FullMethodName: onTemplate[*ateapipb.DeleteActorTemplateRequest]("can_delete"),

	// Only atelet may report capacity, and only for its own node's workers
	// (cmd/ateapi/internal/ateletauth).
	ateapipb.WorkerService_SetWorkerCapacity_FullMethodName: handlerAuthorized,
	// Only atelet may mint an ateom-for-actor certificate; the handler
	// authenticates it by its SPIFFE ID (cmd/ateapi/internal/workerservice).
	ateapipb.WorkerService_MintAteomActorCertificate_FullMethodName: handlerAuthorized,

	// The API schema is public.
	grpc_reflection_v1.ServerReflection_ServerReflectionInfo_FullMethodName:      global("can_get"),
	grpc_reflection_v1alpha.ServerReflection_ServerReflectionInfo_FullMethodName: global("can_get"),
}

// checksFor returns the checks a call must pass, or an error when the method
// has no rule or the request does not have its method's type.
func checksFor(method string, req any) (checks []authz.Check, err error) {
	r, ok := rules[method]
	if !ok {
		return nil, fmt.Errorf("no authorization rule for %s", method)
	}
	defer func() {
		if recover() != nil {
			checks, err = nil, fmt.Errorf("unexpected request %T for %s", req, method)
		}
	}()
	return r(req)
}
