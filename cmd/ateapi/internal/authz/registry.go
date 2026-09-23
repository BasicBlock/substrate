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
	"slices"

	"github.com/agent-substrate/substrate/internal/apierror"
	"github.com/agent-substrate/substrate/internal/resources"
	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

// check is one OpenFGA permission check: the caller must have relation on object.
type check struct {
	relation string
	object   string
}

// checkExtractor returns the checks a request must pass; the interceptor allows
// the request only if all of them pass. Every resource identifier a check
// needs must be present and a valid resource name, otherwise the extractor
// returns codes.InvalidArgument: a check is never skipped, and OpenFGA never
// sees an object ID it would reject. Any other error (e.g., an unexpected
// request protobuf type) is codes.Internal, and the interceptor fails closed.
type checkExtractor func(req any) ([]check, error)

// checksOf adapts checksFor, written against the concrete request type T, into
// a checkExtractor.
func checksOf[T any](checksFor func(T) ([]check, field.ErrorList)) checkExtractor {
	return func(req any) ([]check, error) {
		r, ok := req.(T)
		if !ok {
			return nil, apierror.Internal("authz: unexpected request type %T", req)
		}
		checks, errs := checksFor(r)
		if len(errs) > 0 {
			return nil, resources.ToAPIError(errs)
		}
		return checks, nil
	}
}

// validateName requires name to be a non-empty, valid resource name.
func validateName(name string, fldPath *field.Path) field.ErrorList {
	if name == "" {
		return field.ErrorList{field.Required(fldPath, "")}
	}
	return resources.ValidateResourceName(name, fldPath)
}

func onGlobal(relation string) ([]check, field.ErrorList) {
	return []check{{relation: relation, object: GlobalRootObject}}, nil
}

func onAtespace(relation, atespace string, fldPath *field.Path) ([]check, field.ErrorList) {
	if errs := validateName(atespace, fldPath); len(errs) > 0 {
		return nil, errs
	}
	return []check{{relation: relation, object: AtespaceObject(atespace)}}, nil
}

// onAtespaceOrGlobal checks relation on the atespace, or on global:root when
// atespace is empty (List RPCs that span all atespaces).
func onAtespaceOrGlobal(relation, atespace string, fldPath *field.Path) ([]check, field.ErrorList) {
	if atespace == "" {
		return onGlobal(relation)
	}
	return onAtespace(relation, atespace, fldPath)
}

// resourceRef identifies an atespaced resource. Both *ateapipb.ObjectRef and
// *ateapipb.ResourceMetadata satisfy it, including as nil pointers.
type resourceRef interface {
	GetAtespace() string
	GetName() string
}

func validateRef(ref resourceRef, fldPath *field.Path) field.ErrorList {
	return append(
		validateName(ref.GetAtespace(), fldPath.Child("atespace")),
		validateName(ref.GetName(), fldPath.Child("name"))...,
	)
}

func onActor(relation string, ref resourceRef, fldPath *field.Path) ([]check, field.ErrorList) {
	if errs := validateRef(ref, fldPath); len(errs) > 0 {
		return nil, errs
	}
	return []check{{relation: relation, object: ActorObject(ref.GetAtespace(), ref.GetName())}}, nil
}

func onActorTemplate(relation string, ref resourceRef, fldPath *field.Path) ([]check, field.ErrorList) {
	if errs := validateRef(ref, fldPath); len(errs) > 0 {
		return nil, errs
	}
	return []check{{relation: relation, object: ActorTemplateObject(ref.GetAtespace(), ref.GetName())}}, nil
}

// both requires the checks from a and b, reporting the validation errors of
// both.
func both(aChecks []check, aErrs field.ErrorList, bChecks []check, bErrs field.ErrorList) ([]check, field.ErrorList) {
	if errs := append(aErrs, bErrs...); len(errs) > 0 {
		return nil, errs
	}
	return slices.Concat(aChecks, bChecks), nil
}

// onRefAtespace checks relation on the atespace an *ateapipb.ObjectRef or
// *ateapipb.ResourceMetadata names through its Atespace field, such as a tag's
// (a tag has no OpenFGA type of its own, so its atespace stands for it).
func onRefAtespace(relation string, ref resourceRef, fldPath *field.Path) ([]check, field.ErrorList) {
	return onAtespace(relation, ref.GetAtespace(), fldPath.Child("atespace"))
}

// actorOf is a request that names its actor by an *ateapipb.ObjectRef.
type actorOf interface{ GetActor() *ateapipb.ObjectRef }

// onNamedActor requires relation on the actor a request names.
func onNamedActor[T actorOf](relation string) rpcRule {
	return rule(checksOf(func(r T) ([]check, field.ErrorList) {
		return onActor(relation, r.GetActor(), field.NewPath("actor"))
	}))
}

// onGlobalOf requires relation on global:root for a request of type T. The
// relation may be an owner role: only global owners may make these calls.
func onGlobalOf[T any](relation string) rpcRule {
	return rule(checksOf(func(T) ([]check, field.ErrorList) {
		return onGlobal(relation)
	}))
}

// sourceTagChecks requires can_get on the atespace of the tag an actor is
// created or updated from, which can differ from the actor's own.
func sourceTagChecks(actor *ateapipb.Actor) ([]check, field.ErrorList) {
	tag := actor.GetSourceTag()
	if tag.GetAtespace() == "" {
		return nil, nil
	}
	return onAtespace(RelationCanGet, tag.GetAtespace(), field.NewPath("actor", "source_tag", "atespace"))
}

// handlerAuthorized marks a method whose handler authorizes the caller itself
// (such as an atelet SPIFFE-ID check), so the interceptor only requires a
// principal and otherwise steps aside.
func handlerAuthorized[T any]() rpcRule {
	return rule(checksOf(func(T) ([]check, field.ErrorList) { return nil, nil }))
}

// rpcRule is the permission rule for one RPC.
type rpcRule struct {
	extract checkExtractor
	// alwaysEnforce marks RPCs that are checked even when enforcement is
	// disabled. AccessPolicy RPCs set it so that nobody can grant themselves
	// access while enforcement is off and keep that grant once it is turned on.
	alwaysEnforce bool
}

func rule(extract checkExtractor) rpcRule {
	return rpcRule{extract: extract}
}

func governance(extract checkExtractor) rpcRule {
	return rpcRule{extract: extract, alwaysEnforce: true}
}

// defaultRPCPermissions is the declarative registry mapping gRPC full method names
// to their permission rules.
var defaultRPCPermissions = map[string]rpcRule{
	// Atespaces.
	ateapipb.Control_CreateAtespace_FullMethodName: rule(checksOf(func(*ateapipb.CreateAtespaceRequest) ([]check, field.ErrorList) {
		return onGlobal(RelationCanCreateAtespace)
	})),
	ateapipb.Control_ListAtespaces_FullMethodName: rule(checksOf(func(*ateapipb.ListAtespacesRequest) ([]check, field.ErrorList) {
		return onGlobal(RelationCanListAtespaces)
	})),
	ateapipb.Control_GetAtespace_FullMethodName: rule(checksOf(func(r *ateapipb.GetAtespaceRequest) ([]check, field.ErrorList) {
		return onAtespace(RelationCanGet, r.GetAtespace().GetName(), field.NewPath("atespace", "name"))
	})),
	ateapipb.Control_DeleteAtespace_FullMethodName: rule(checksOf(func(r *ateapipb.DeleteAtespaceRequest) ([]check, field.ErrorList) {
		return onAtespace(RelationCanDelete, r.GetAtespace().GetName(), field.NewPath("atespace", "name"))
	})),

	// Access policies.
	ateapipb.Control_GetGlobalAccessPolicy_FullMethodName: governance(checksOf(func(*ateapipb.GetGlobalAccessPolicyRequest) ([]check, field.ErrorList) {
		return onGlobal(RelationCanGetAccessPolicy)
	})),
	ateapipb.Control_CreateGlobalAccessPolicy_FullMethodName: governance(checksOf(func(*ateapipb.CreateGlobalAccessPolicyRequest) ([]check, field.ErrorList) {
		return onGlobal(RelationCanCreateAccessPolicy)
	})),
	ateapipb.Control_UpdateGlobalAccessPolicy_FullMethodName: governance(checksOf(func(*ateapipb.UpdateGlobalAccessPolicyRequest) ([]check, field.ErrorList) {
		return onGlobal(RelationCanUpdateAccessPolicy)
	})),
	ateapipb.Control_GetAtespaceAccessPolicy_FullMethodName: governance(checksOf(func(r *ateapipb.GetAtespaceAccessPolicyRequest) ([]check, field.ErrorList) {
		return onAtespace(RelationCanGetAccessPolicy, r.GetAtespace().GetName(), field.NewPath("atespace", "name"))
	})),
	ateapipb.Control_CreateAtespaceAccessPolicy_FullMethodName: governance(checksOf(func(r *ateapipb.CreateAtespaceAccessPolicyRequest) ([]check, field.ErrorList) {
		return onAtespace(RelationCanCreateAccessPolicy, r.GetAtespace().GetName(), field.NewPath("atespace", "name"))
	})),
	ateapipb.Control_UpdateAtespaceAccessPolicy_FullMethodName: governance(checksOf(func(r *ateapipb.UpdateAtespaceAccessPolicyRequest) ([]check, field.ErrorList) {
		return onAtespace(RelationCanUpdateAccessPolicy, r.GetAtespace().GetName(), field.NewPath("atespace", "name"))
	})),
	ateapipb.Control_DeleteAtespaceAccessPolicy_FullMethodName: governance(checksOf(func(r *ateapipb.DeleteAtespaceAccessPolicyRequest) ([]check, field.ErrorList) {
		return onAtespace(RelationCanDeleteAccessPolicy, r.GetAtespace().GetName(), field.NewPath("atespace", "name"))
	})),

	// Actor templates.
	ateapipb.Control_CreateActorTemplate_FullMethodName: rule(checksOf(func(r *ateapipb.CreateActorTemplateRequest) ([]check, field.ErrorList) {
		return onAtespace(RelationCanCreateActorTemplate, r.GetActorTemplate().GetMetadata().GetAtespace(), field.NewPath("actor_template", "metadata", "atespace"))
	})),
	ateapipb.Control_GetActorTemplate_FullMethodName: rule(checksOf(func(r *ateapipb.GetActorTemplateRequest) ([]check, field.ErrorList) {
		return onActorTemplate(RelationCanGet, r.GetActorTemplate(), field.NewPath("actor_template"))
	})),
	ateapipb.Control_ListActorTemplates_FullMethodName: rule(checksOf(func(r *ateapipb.ListActorTemplatesRequest) ([]check, field.ErrorList) {
		return onAtespaceOrGlobal(RelationCanListActorTemplates, r.GetAtespace(), field.NewPath("atespace"))
	})),
	ateapipb.Control_DeleteActorTemplate_FullMethodName: rule(checksOf(func(r *ateapipb.DeleteActorTemplateRequest) ([]check, field.ErrorList) {
		return onActorTemplate(RelationCanDelete, r.GetActorTemplate(), field.NewPath("actor_template"))
	})),

	// Actors. Creating or updating an actor also requires can_use_template on
	// the actor template it runs, which may live in another atespace.
	ateapipb.Control_CreateActor_FullMethodName: rule(checksOf(func(r *ateapipb.CreateActorRequest) ([]check, field.ErrorList) {
		actorChecks, actorErrs := onAtespace(RelationCanCreateActor, r.GetActor().GetMetadata().GetAtespace(), field.NewPath("actor", "metadata", "atespace"))
		templateChecks, templateErrs := onActorTemplate(RelationCanUseTemplate, r.GetActor().GetActorTemplate(), field.NewPath("actor", "actor_template"))
		tagChecks, tagErrs := sourceTagChecks(r.GetActor())
		return both(actorChecks, actorErrs, slices.Concat(templateChecks, tagChecks), append(templateErrs, tagErrs...))
	})),
	ateapipb.Control_GetActor_FullMethodName: rule(checksOf(func(r *ateapipb.GetActorRequest) ([]check, field.ErrorList) {
		return onActor(RelationCanGet, r.GetActor(), field.NewPath("actor"))
	})),
	ateapipb.Control_ListActors_FullMethodName: rule(checksOf(func(r *ateapipb.ListActorsRequest) ([]check, field.ErrorList) {
		return onAtespaceOrGlobal(RelationCanListActors, r.GetAtespace(), field.NewPath("atespace"))
	})),
	ateapipb.Control_UpdateActor_FullMethodName: rule(checksOf(func(r *ateapipb.UpdateActorRequest) ([]check, field.ErrorList) {
		actorChecks, actorErrs := onActor(RelationCanUpdate, r.GetActor().GetMetadata(), field.NewPath("actor", "metadata"))
		templateChecks, templateErrs := onActorTemplate(RelationCanUseTemplate, r.GetActor().GetActorTemplate(), field.NewPath("actor", "actor_template"))
		tagChecks, tagErrs := sourceTagChecks(r.GetActor())
		return both(actorChecks, actorErrs, slices.Concat(templateChecks, tagChecks), append(templateErrs, tagErrs...))
	})),
	ateapipb.Control_DeleteActor_FullMethodName: rule(checksOf(func(r *ateapipb.DeleteActorRequest) ([]check, field.ErrorList) {
		return onActor(RelationCanDelete, r.GetActor(), field.NewPath("actor"))
	})),

	// Actor lifecycle. Pausing keeps a node-local snapshot: the same authority
	// as suspending.
	ateapipb.Control_SuspendActor_FullMethodName: onNamedActor[*ateapipb.SuspendActorRequest](RelationCanSuspend),
	ateapipb.Control_PauseActor_FullMethodName:   onNamedActor[*ateapipb.PauseActorRequest](RelationCanSuspend),
	ateapipb.Control_ResumeActor_FullMethodName:  onNamedActor[*ateapipb.ResumeActorRequest](RelationCanResume),
	ateapipb.Control_RevertActor_FullMethodName:  onNamedActor[*ateapipb.RevertActorRequest](RelationCanRevert),

	// Egress policies belong to their actor: reading one needs can_get on it,
	// changing one can_update.
	ateapipb.Control_GetActorEgressPolicy_FullMethodName:    onNamedActor[*ateapipb.GetActorEgressPolicyRequest](RelationCanGet),
	ateapipb.Control_CreateActorEgressPolicy_FullMethodName: onNamedActor[*ateapipb.CreateActorEgressPolicyRequest](RelationCanUpdate),
	ateapipb.Control_UpdateActorEgressPolicy_FullMethodName: onNamedActor[*ateapipb.UpdateActorEgressPolicyRequest](RelationCanUpdate),
	ateapipb.Control_DeleteActorEgressPolicy_FullMethodName: onNamedActor[*ateapipb.DeleteActorEgressPolicyRequest](RelationCanUpdate),

	// The ingress gateway asks on its clients' behalf; the answer checks the
	// client's can_connect, and would otherwise reveal whether a token is valid.
	ateapipb.Control_CheckActorAccess_FullMethodName: onGlobalOf[*ateapipb.CheckActorAccessRequest](RoleOwner),

	// Actor credentials are minted for Substrate's own components (the egress
	// gateway and atelet); only a global owner may ask for one.
	ateapipb.Control_MintActorJWT_FullMethodName:         onGlobalOf[*ateapipb.MintActorJWTRequest](RoleOwner),
	ateapipb.Control_MintActorCertificate_FullMethodName: onGlobalOf[*ateapipb.MintActorCertificateRequest](RoleOwner),

	// Tags have no type of their own: reading one needs can_get on its
	// atespace, changing one can_update.
	ateapipb.Control_CreateTag_FullMethodName: rule(checksOf(func(r *ateapipb.CreateTagRequest) ([]check, field.ErrorList) {
		tag := r.GetTag()
		tagChecks, tagErrs := onRefAtespace(RelationCanUpdate, tag.GetMetadata(), field.NewPath("tag", "metadata"))
		// The source actor may live in another atespace.
		var srcChecks []check
		var srcErrs field.ErrorList
		if src := tag.GetSourceActor(); src.GetAtespace() != "" || src.GetName() != "" {
			srcChecks, srcErrs = onActor(RelationCanGet, src, field.NewPath("tag", "source_actor"))
		}
		return both(tagChecks, tagErrs, srcChecks, srcErrs)
	})),
	ateapipb.Control_GetTag_FullMethodName: rule(checksOf(func(r *ateapipb.GetTagRequest) ([]check, field.ErrorList) {
		return onRefAtespace(RelationCanGet, r.GetTag(), field.NewPath("tag"))
	})),
	ateapipb.Control_ListTags_FullMethodName: rule(checksOf(func(r *ateapipb.ListTagsRequest) ([]check, field.ErrorList) {
		return onAtespaceOrGlobal(RelationCanGet, r.GetAtespace(), field.NewPath("atespace"))
	})),
	ateapipb.Control_UpdateTag_FullMethodName: rule(checksOf(func(r *ateapipb.UpdateTagRequest) ([]check, field.ErrorList) {
		return onRefAtespace(RelationCanUpdate, r.GetTag().GetMetadata(), field.NewPath("tag", "metadata"))
	})),
	ateapipb.Control_DeleteTag_FullMethodName: rule(checksOf(func(r *ateapipb.DeleteTagRequest) ([]check, field.ErrorList) {
		return onRefAtespace(RelationCanUpdate, r.GetTag(), field.NewPath("tag"))
	})),

	// Workers are cluster infrastructure.
	ateapipb.Control_ListWorkers_FullMethodName:                onGlobalOf[*ateapipb.ListWorkersRequest](RoleOwner),
	ateapipb.Control_GetWorker_FullMethodName:                  onGlobalOf[*ateapipb.GetWorkerRequest](RoleOwner),
	ateapipb.Control_CreateWorker_FullMethodName:               onGlobalOf[*ateapipb.CreateWorkerRequest](RoleOwner),
	ateapipb.Control_UpdateWorker_FullMethodName:               onGlobalOf[*ateapipb.UpdateWorkerRequest](RoleOwner),
	ateapipb.Control_DeleteWorker_FullMethodName:               onGlobalOf[*ateapipb.DeleteWorkerRequest](RoleOwner),
	ateapipb.Control_DrainWorker_FullMethodName:                onGlobalOf[*ateapipb.DrainWorkerRequest](RoleOwner),
	ateapipb.Control_ListWorkerActorAssignments_FullMethodName: onGlobalOf[*ateapipb.ListWorkerActorAssignmentsRequest](RoleOwner),

	// atelet authenticates itself by SPIFFE ID in every handler here; none
	// needs a per-atespace or global OpenFGA check as well.
	ateapipb.WorkerService_RegisterWorker_FullMethodName:            handlerAuthorized[*ateapipb.RegisterWorkerRequest](),
	ateapipb.WorkerService_MintAteomActorCertificate_FullMethodName: handlerAuthorized[*ateapipb.MintAteomActorCertificateRequest](),
	ateapipb.WorkerService_RequestActorSuspend_FullMethodName:       handlerAuthorized[*ateapipb.RequestActorSuspendRequest](),
}
