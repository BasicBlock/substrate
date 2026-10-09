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
	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// check is one relation to verify on an object.
type check struct {
	relation string
	object   string
}

// targetExtractor extracts the OpenFGA checks to verify for a request. A nil
// slice with a nil error (e.g. when a required resource identifier is
// missing on a malformed request) tells the interceptor to verify caller
// authentication and delegate to the handler, so standard field-validation
// errors (codes.InvalidArgument) are returned instead of PermissionDenied. A
// non-nil error (e.g. an unexpected request protobuf type) fails closed.
type targetExtractor func(req any) ([]check, error)

func globalRule[T any](relation string) targetExtractor {
	return func(req any) ([]check, error) {
		if _, ok := req.(T); !ok {
			return nil, status.Errorf(codes.Internal, "authz: unexpected request type %T", req)
		}
		return []check{{relation, GlobalRootObject}}, nil
	}
}

func atespaceRule[T any](relation string, getRef func(T) *ateapipb.ObjectRef) targetExtractor {
	return func(req any) ([]check, error) {
		r, ok := req.(T)
		if !ok {
			return nil, status.Errorf(codes.Internal, "authz: unexpected request type %T", req)
		}
		name := getRef(r).GetName()
		if name == "" {
			return nil, nil
		}
		return []check{{relation, AtespaceObject(name)}}, nil
	}
}

// actorRule checks relation on the actor a request names via a GetActor
// method returning *ObjectRef (every Actor RPC but Create and Update, whose
// requests carry the whole Actor instead).
func actorRule[T interface{ GetActor() *ateapipb.ObjectRef }](relation string) targetExtractor {
	return func(req any) ([]check, error) {
		r, ok := req.(T)
		if !ok {
			return nil, status.Errorf(codes.Internal, "authz: unexpected request type %T", req)
		}
		ref := r.GetActor()
		if ref.GetAtespace() == "" || ref.GetName() == "" {
			return nil, nil
		}
		return []check{{relation, ActorObject(ref.GetAtespace(), ref.GetName())}}, nil
	}
}

// actorTemplateRule checks relation on the actor template a request names via
// a GetActorTemplate method returning *ObjectRef.
func actorTemplateRule[T interface{ GetActorTemplate() *ateapipb.ObjectRef }](relation string) targetExtractor {
	return func(req any) ([]check, error) {
		r, ok := req.(T)
		if !ok {
			return nil, status.Errorf(codes.Internal, "authz: unexpected request type %T", req)
		}
		ref := r.GetActorTemplate()
		if ref.GetAtespace() == "" || ref.GetName() == "" {
			return nil, nil
		}
		return []check{{relation, ActorTemplateObject(ref.GetAtespace(), ref.GetName())}}, nil
	}
}

// listedRule checks relation on the atespace a list request names via
// GetAtespace() string, or can_get on the global scope when it names none,
// which lists across every atespace.
func listedRule[T interface{ GetAtespace() string }](relation string) targetExtractor {
	return func(req any) ([]check, error) {
		r, ok := req.(T)
		if !ok {
			return nil, status.Errorf(codes.Internal, "authz: unexpected request type %T", req)
		}
		if atespace := r.GetAtespace(); atespace != "" {
			return []check{{relation, AtespaceObject(atespace)}}, nil
		}
		return []check{{RelationCanGet, GlobalRootObject}}, nil
	}
}

// scopedRule checks relation on the atespace named by a request's resource
// ref via its Atespace field (an ObjectRef such as a Tag's, which also
// carries the resource's own Name within that atespace) — unlike
// atespaceRule, whose ref names the atespace itself through Name.
func scopedRule[T any](relation string, getRef func(T) *ateapipb.ObjectRef) targetExtractor {
	return func(req any) ([]check, error) {
		r, ok := req.(T)
		if !ok {
			return nil, status.Errorf(codes.Internal, "authz: unexpected request type %T", req)
		}
		atespace := getRef(r).GetAtespace()
		if atespace == "" {
			return nil, nil
		}
		return []check{{relation, AtespaceObject(atespace)}}, nil
	}
}

// actorSourceChecks requires can_get on the actor template and the source tag
// an actor is created or updated from, which can live in other atespaces.
func actorSourceChecks(actor *ateapipb.Actor) []check {
	var checks []check
	if t := actor.GetActorTemplate(); t.GetAtespace() != "" && t.GetName() != "" {
		checks = append(checks, check{RelationCanGet, ActorTemplateObject(t.GetAtespace(), t.GetName())})
	}
	if tag := actor.GetSourceTag(); tag.GetAtespace() != "" {
		checks = append(checks, check{RelationCanGet, AtespaceObject(tag.GetAtespace())})
	}
	return checks
}

// createActorRule checks can_create_actor on the atespace the new actor
// belongs to, plus actorSourceChecks for its template and source tag.
func createActorRule() targetExtractor {
	return func(req any) ([]check, error) {
		r, ok := req.(*ateapipb.CreateActorRequest)
		if !ok {
			return nil, status.Errorf(codes.Internal, "authz: unexpected request type %T", req)
		}
		actor := r.GetActor()
		atespace := actor.GetMetadata().GetAtespace()
		if atespace == "" {
			return nil, nil
		}
		checks := []check{{RelationCanCreateActor, AtespaceObject(atespace)}}
		return append(checks, actorSourceChecks(actor)...), nil
	}
}

// updateActorRule checks can_update on the actor, plus actorSourceChecks for
// its (possibly changed) template and source tag.
func updateActorRule() targetExtractor {
	return func(req any) ([]check, error) {
		r, ok := req.(*ateapipb.UpdateActorRequest)
		if !ok {
			return nil, status.Errorf(codes.Internal, "authz: unexpected request type %T", req)
		}
		actor := r.GetActor()
		meta := actor.GetMetadata()
		if meta.GetAtespace() == "" || meta.GetName() == "" {
			return nil, nil
		}
		checks := []check{{RelationCanUpdate, ActorObject(meta.GetAtespace(), meta.GetName())}}
		return append(checks, actorSourceChecks(actor)...), nil
	}
}

// createTagRule checks can_update on the atespace the new tag belongs to,
// plus can_get on its source actor, which can live in another atespace.
//
// Tags have no OpenFGA type of their own: reading one needs can_get on its
// atespace, changing one can_update.
func createTagRule() targetExtractor {
	return func(req any) ([]check, error) {
		r, ok := req.(*ateapipb.CreateTagRequest)
		if !ok {
			return nil, status.Errorf(codes.Internal, "authz: unexpected request type %T", req)
		}
		tag := r.GetTag()
		atespace := tag.GetMetadata().GetAtespace()
		if atespace == "" {
			return nil, nil
		}
		checks := []check{{RelationCanUpdate, AtespaceObject(atespace)}}
		if src := tag.GetSourceActor(); src.GetAtespace() != "" && src.GetName() != "" {
			checks = append(checks, check{RelationCanGet, ActorObject(src.GetAtespace(), src.GetName())})
		}
		return checks, nil
	}
}

// rpcRule is the permission rule for one RPC.
type rpcRule struct {
	extract targetExtractor
	// alwaysEnforce marks RPCs that are checked even when enforcement is
	// disabled. AccessPolicy RPCs set it so that nobody can grant themselves
	// access while enforcement is off and keep that grant once it is turned on.
	alwaysEnforce bool
}

func rule(extract targetExtractor) rpcRule {
	return rpcRule{extract: extract}
}

func governance(extract targetExtractor) rpcRule {
	return rpcRule{extract: extract, alwaysEnforce: true}
}

// handlerAuthorized marks a method whose handler authorizes the caller
// itself (such as an atelet SPIFFE-ID check), so the interceptor only
// requires a principal and otherwise steps aside.
func handlerAuthorized() targetExtractor {
	return func(any) ([]check, error) { return nil, nil }
}

// defaultRPCPermissions is the declarative registry mapping gRPC full method names
// to their required permission rules.
var defaultRPCPermissions = map[string]rpcRule{
	ateapipb.Control_CreateAtespace_FullMethodName:             rule(globalRule[*ateapipb.CreateAtespaceRequest](RelationCanCreateAtespace)),
	ateapipb.Control_ListAtespaces_FullMethodName:              rule(globalRule[*ateapipb.ListAtespacesRequest](RelationCanListAtespaces)),
	ateapipb.Control_GetAtespace_FullMethodName:                rule(atespaceRule(RelationCanGet, (*ateapipb.GetAtespaceRequest).GetAtespace)),
	ateapipb.Control_DeleteAtespace_FullMethodName:             rule(atespaceRule(RelationCanDelete, (*ateapipb.DeleteAtespaceRequest).GetAtespace)),
	ateapipb.Control_GetGlobalAccessPolicy_FullMethodName:      governance(globalRule[*ateapipb.GetGlobalAccessPolicyRequest](RelationCanGetAccessPolicy)),
	ateapipb.Control_CreateGlobalAccessPolicy_FullMethodName:   governance(globalRule[*ateapipb.CreateGlobalAccessPolicyRequest](RelationCanCreateAccessPolicy)),
	ateapipb.Control_UpdateGlobalAccessPolicy_FullMethodName:   governance(globalRule[*ateapipb.UpdateGlobalAccessPolicyRequest](RelationCanUpdateAccessPolicy)),
	ateapipb.Control_GetAtespaceAccessPolicy_FullMethodName:    governance(atespaceRule(RelationCanGetAccessPolicy, (*ateapipb.GetAtespaceAccessPolicyRequest).GetAtespace)),
	ateapipb.Control_CreateAtespaceAccessPolicy_FullMethodName: governance(atespaceRule(RelationCanCreateAccessPolicy, (*ateapipb.CreateAtespaceAccessPolicyRequest).GetAtespace)),
	ateapipb.Control_UpdateAtespaceAccessPolicy_FullMethodName: governance(atespaceRule(RelationCanUpdateAccessPolicy, (*ateapipb.UpdateAtespaceAccessPolicyRequest).GetAtespace)),
	ateapipb.Control_DeleteAtespaceAccessPolicy_FullMethodName: governance(atespaceRule(RelationCanDeleteAccessPolicy, (*ateapipb.DeleteAtespaceAccessPolicyRequest).GetAtespace)),

	// Actor lifecycle, scoped to its atespace.
	ateapipb.Control_GetActor_FullMethodName:     rule(actorRule[*ateapipb.GetActorRequest](RelationCanGet)),
	ateapipb.Control_CreateActor_FullMethodName:  rule(createActorRule()),
	ateapipb.Control_UpdateActor_FullMethodName:  rule(updateActorRule()),
	ateapipb.Control_SuspendActor_FullMethodName: rule(actorRule[*ateapipb.SuspendActorRequest](RelationCanSuspend)),
	// Pausing keeps a node-local snapshot: the same authority as suspending.
	ateapipb.Control_PauseActor_FullMethodName: rule(actorRule[*ateapipb.PauseActorRequest](RelationCanSuspend)),
	// Dropping a snapshot's memory is a snapshot-management operation on the
	// actor's stored state, the same authority as suspending it.
	ateapipb.Control_DropSnapshotMemory_FullMethodName: rule(actorRule[*ateapipb.DropSnapshotMemoryRequest](RelationCanSuspend)),
	ateapipb.Control_ResumeActor_FullMethodName:        rule(actorRule[*ateapipb.ResumeActorRequest](RelationCanResume)),
	ateapipb.Control_RevertActor_FullMethodName:        rule(actorRule[*ateapipb.RevertActorRequest](RelationCanRevert)),
	ateapipb.Control_DeleteActor_FullMethodName:        rule(actorRule[*ateapipb.DeleteActorRequest](RelationCanDelete)),

	// The ingress gateway asks on its clients' behalf; the answer checks the
	// client's can_connect, and would otherwise reveal whether a token is valid.
	ateapipb.Control_CheckActorAccess_FullMethodName: rule(globalRule[*ateapipb.CheckActorAccessRequest](RoleOwner)),

	ateapipb.Control_GetActorEgressPolicy_FullMethodName:    rule(actorRule[*ateapipb.GetActorEgressPolicyRequest](RelationCanGet)),
	ateapipb.Control_CreateActorEgressPolicy_FullMethodName: rule(actorRule[*ateapipb.CreateActorEgressPolicyRequest](RelationCanUpdate)),
	ateapipb.Control_UpdateActorEgressPolicy_FullMethodName: rule(actorRule[*ateapipb.UpdateActorEgressPolicyRequest](RelationCanUpdate)),
	ateapipb.Control_DeleteActorEgressPolicy_FullMethodName: rule(actorRule[*ateapipb.DeleteActorEgressPolicyRequest](RelationCanUpdate)),

	// Actor credentials are minted for Substrate's own components (the egress
	// gateway and atelet); only a global owner may ask for one.
	ateapipb.Control_MintActorJWT_FullMethodName:         rule(globalRule[*ateapipb.MintActorJWTRequest](RoleOwner)),
	ateapipb.Control_MintActorCertificate_FullMethodName: rule(globalRule[*ateapipb.MintActorCertificateRequest](RoleOwner)),

	// Tags have no type of their own: reading one needs can_get on its
	// atespace, changing one can_update.
	ateapipb.Control_CreateTag_FullMethodName: rule(createTagRule()),
	ateapipb.Control_GetTag_FullMethodName:    rule(scopedRule(RelationCanGet, (*ateapipb.GetTagRequest).GetTag)),
	ateapipb.Control_ListTags_FullMethodName:  rule(listedRule[*ateapipb.ListTagsRequest](RelationCanGet)),
	ateapipb.Control_UpdateTag_FullMethodName: rule(func(req any) ([]check, error) {
		r, ok := req.(*ateapipb.UpdateTagRequest)
		if !ok {
			return nil, status.Errorf(codes.Internal, "authz: unexpected request type %T", req)
		}
		atespace := r.GetTag().GetMetadata().GetAtespace()
		if atespace == "" {
			return nil, nil
		}
		return []check{{RelationCanUpdate, AtespaceObject(atespace)}}, nil
	}),
	ateapipb.Control_DeleteTag_FullMethodName: rule(scopedRule(RelationCanUpdate, (*ateapipb.DeleteTagRequest).GetTag)),

	// Workers are cluster infrastructure.
	ateapipb.Control_ListWorkers_FullMethodName:                rule(globalRule[*ateapipb.ListWorkersRequest](RoleOwner)),
	ateapipb.Control_GetWorker_FullMethodName:                  rule(globalRule[*ateapipb.GetWorkerRequest](RoleOwner)),
	ateapipb.Control_CreateWorker_FullMethodName:               rule(globalRule[*ateapipb.CreateWorkerRequest](RoleOwner)),
	ateapipb.Control_UpdateWorker_FullMethodName:               rule(globalRule[*ateapipb.UpdateWorkerRequest](RoleOwner)),
	ateapipb.Control_DeleteWorker_FullMethodName:               rule(globalRule[*ateapipb.DeleteWorkerRequest](RoleOwner)),
	ateapipb.Control_DrainWorker_FullMethodName:                rule(globalRule[*ateapipb.DrainWorkerRequest](RoleOwner)),
	ateapipb.Control_ListWorkerActorAssignments_FullMethodName: rule(globalRule[*ateapipb.ListWorkerActorAssignmentsRequest](RoleOwner)),

	ateapipb.Control_ListActors_FullMethodName: rule(listedRule[*ateapipb.ListActorsRequest](RelationCanGet)),

	ateapipb.Control_CreateActorTemplate_FullMethodName: rule(func(req any) ([]check, error) {
		r, ok := req.(*ateapipb.CreateActorTemplateRequest)
		if !ok {
			return nil, status.Errorf(codes.Internal, "authz: unexpected request type %T", req)
		}
		atespace := r.GetActorTemplate().GetMetadata().GetAtespace()
		if atespace == "" {
			return nil, nil
		}
		return []check{{RelationCanCreateActorTemplate, AtespaceObject(atespace)}}, nil
	}),
	ateapipb.Control_GetActorTemplate_FullMethodName:    rule(actorTemplateRule[*ateapipb.GetActorTemplateRequest](RelationCanGet)),
	ateapipb.Control_ListActorTemplates_FullMethodName:  rule(listedRule[*ateapipb.ListActorTemplatesRequest](RelationCanGet)),
	ateapipb.Control_DeleteActorTemplate_FullMethodName: rule(actorTemplateRule[*ateapipb.DeleteActorTemplateRequest](RelationCanDelete)),

	// atelet authenticates itself by SPIFFE ID in every handler here; none
	// needs a per-atespace or global OpenFGA check as well.
	ateapipb.WorkerService_SetWorkerCapacity_FullMethodName:         rule(handlerAuthorized()),
	ateapipb.WorkerService_MintAteomActorCertificate_FullMethodName: rule(handlerAuthorized()),
	ateapipb.WorkerService_RequestActorSuspend_FullMethodName:       rule(handlerAuthorized()),
}
