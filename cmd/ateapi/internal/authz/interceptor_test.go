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
	"context"
	"strings"
	"testing"

	"github.com/agent-substrate/substrate/internal/principal"
	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func setupTestAuthorizer(t *testing.T) *Authorizer {
	t.Helper()
	ctx := context.Background()
	pool := startPostgres(t)

	fgaServer, err := NewOpenFGAServer(pool)
	if err != nil {
		t.Fatalf("NewOpenFGAServer failed: %v", err)
	}
	t.Cleanup(fgaServer.Close)

	authorizer, policyManager, err := New(ctx, pool, fgaServer, nil)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	writeTestTuple(t, ctx, pool, policyManager, "alice@example.com", "owner", GlobalRootObject)
	return authorizer
}

func TestUnaryServerInterceptor_QuickRejectionAndDispatch(t *testing.T) {
	authorizer := setupTestAuthorizer(t)

	allowedCtx := principal.InjectContext(context.Background(), principal.PrincipalInfo{
		ID:   "alice@example.com",
		Kind: principal.KindJWT,
	})
	deniedCtx := principal.InjectContext(context.Background(), principal.PrincipalInfo{
		ID:   "bob@example.com",
		Kind: principal.KindJWT,
	})

	interceptor := UnaryServerInterceptor(authorizer, true)

	tests := []struct {
		name        string
		fullMethod  string
		req         any
		ctx         context.Context
		wantCode    codes.Code
		wantHandler bool
	}{
		{
			name:        "CreateAtespace denied before handler",
			fullMethod:  ateapipb.Control_CreateAtespace_FullMethodName,
			req:         &ateapipb.CreateAtespaceRequest{Atespace: &ateapipb.Atespace{Metadata: &ateapipb.ResourceMetadata{Name: "team1"}}},
			ctx:         deniedCtx,
			wantCode:    codes.PermissionDenied,
			wantHandler: false,
		},
		{
			name:        "CreateAtespace allowed",
			fullMethod:  ateapipb.Control_CreateAtespace_FullMethodName,
			req:         &ateapipb.CreateAtespaceRequest{Atespace: &ateapipb.Atespace{Metadata: &ateapipb.ResourceMetadata{Name: "team1"}}},
			ctx:         allowedCtx,
			wantCode:    codes.OK,
			wantHandler: true,
		},
		{
			name:        "ListAtespaces denied before handler",
			fullMethod:  ateapipb.Control_ListAtespaces_FullMethodName,
			req:         &ateapipb.ListAtespacesRequest{},
			ctx:         deniedCtx,
			wantCode:    codes.PermissionDenied,
			wantHandler: false,
		},
		{
			name:        "ListAtespaces allowed",
			fullMethod:  ateapipb.Control_ListAtespaces_FullMethodName,
			req:         &ateapipb.ListAtespacesRequest{},
			ctx:         allowedCtx,
			wantCode:    codes.OK,
			wantHandler: true,
		},
		{
			name:        "GetAtespace denied before handler",
			fullMethod:  ateapipb.Control_GetAtespace_FullMethodName,
			req:         &ateapipb.GetAtespaceRequest{Atespace: &ateapipb.ObjectRef{Name: "team1"}},
			ctx:         deniedCtx,
			wantCode:    codes.PermissionDenied,
			wantHandler: false,
		},
		{
			name:        "GetAtespace allowed",
			fullMethod:  ateapipb.Control_GetAtespace_FullMethodName,
			req:         &ateapipb.GetAtespaceRequest{Atespace: &ateapipb.ObjectRef{Name: "team1"}},
			ctx:         allowedCtx,
			wantCode:    codes.OK,
			wantHandler: true,
		},
		{
			name:        "DeleteAtespace denied before handler",
			fullMethod:  ateapipb.Control_DeleteAtespace_FullMethodName,
			req:         &ateapipb.DeleteAtespaceRequest{Atespace: &ateapipb.ObjectRef{Name: "team1"}},
			ctx:         deniedCtx,
			wantCode:    codes.PermissionDenied,
			wantHandler: false,
		},
		{
			name:        "DeleteAtespace allowed",
			fullMethod:  ateapipb.Control_DeleteAtespace_FullMethodName,
			req:         &ateapipb.DeleteAtespaceRequest{Atespace: &ateapipb.ObjectRef{Name: "team1"}},
			ctx:         allowedCtx,
			wantCode:    codes.OK,
			wantHandler: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			handlerCalled := false
			_, err := interceptor(tc.ctx, tc.req, &grpc.UnaryServerInfo{FullMethod: tc.fullMethod}, func(ctx context.Context, req any) (any, error) {
				handlerCalled = true
				return "ok", nil
			})
			if status.Code(err) != tc.wantCode {
				t.Fatalf("status.Code(err) = %v, want %v (err: %v)", status.Code(err), tc.wantCode, err)
			}
			if handlerCalled != tc.wantHandler {
				t.Fatalf("handlerCalled = %v, want %v", handlerCalled, tc.wantHandler)
			}
		})
	}
}

func TestUnaryServerInterceptor_MalformedRequestRequiresPrincipalThenDelegatesValidation(t *testing.T) {
	authorizer := setupTestAuthorizer(t)
	interceptor := UnaryServerInterceptor(authorizer, true)

	// 1. Unauthenticated caller with empty atespace name -> Unauthenticated
	_, err := interceptor(context.Background(), &ateapipb.GetAtespaceRequest{}, &grpc.UnaryServerInfo{
		FullMethod: ateapipb.Control_GetAtespace_FullMethodName,
	}, func(ctx context.Context, req any) (any, error) {
		t.Fatal("handler must not be invoked for unauthenticated request")
		return nil, nil
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated for missing principal, got %v", err)
	}

	// 2. Authenticated caller with empty atespace name -> delegates to handler for InvalidArgument
	authCtx := principal.InjectContext(context.Background(), principal.PrincipalInfo{
		ID:   "alice@example.com",
		Kind: principal.KindJWT,
	})
	handlerCalled := false
	_, err = interceptor(authCtx, &ateapipb.GetAtespaceRequest{}, &grpc.UnaryServerInfo{
		FullMethod: ateapipb.Control_GetAtespace_FullMethodName,
	}, func(ctx context.Context, req any) (any, error) {
		handlerCalled = true
		return nil, status.Error(codes.InvalidArgument, "atespace.name is required")
	})
	if !handlerCalled {
		t.Fatal("expected handler to be invoked to return validation error")
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument from handler, got %v", err)
	}

	// 3. Unexpected request type for a registered RPC -> fails closed with codes.Internal without calling handler
	_, err = interceptor(authCtx, "wrong-type", &grpc.UnaryServerInfo{
		FullMethod: ateapipb.Control_GetAtespace_FullMethodName,
	}, func(ctx context.Context, req any) (any, error) {
		t.Fatal("handler must not be invoked when request type assertion fails")
		return nil, nil
	})
	if status.Code(err) != codes.Internal {
		t.Fatalf("expected Internal for unexpected request type, got %v", err)
	}

}

func TestUnaryServerInterceptor_EnforcementDisabled(t *testing.T) {
	authorizer := setupTestAuthorizer(t)
	interceptor := UnaryServerInterceptor(authorizer, false)
	bobCtx := principal.InjectContext(context.Background(), principal.PrincipalInfo{
		ID:   "bob@example.com",
		Kind: principal.KindJWT,
	})
	aliceCtx := principal.InjectContext(context.Background(), principal.PrincipalInfo{
		ID:   "alice@example.com",
		Kind: principal.KindJWT,
	})

	tests := []struct {
		name       string
		ctx        context.Context
		fullMethod string
		req        any
		wantCode   codes.Code
	}{
		{
			name:       "regular RPC skips the check",
			ctx:        bobCtx,
			fullMethod: ateapipb.Control_CreateAtespace_FullMethodName,
			req:        &ateapipb.CreateAtespaceRequest{Atespace: &ateapipb.Atespace{Metadata: &ateapipb.ResourceMetadata{Name: "team1"}}},
			wantCode:   codes.OK,
		},
		{
			name:       "governance RPC is still denied",
			ctx:        bobCtx,
			fullMethod: ateapipb.Control_UpdateGlobalAccessPolicy_FullMethodName,
			req:        &ateapipb.UpdateGlobalAccessPolicyRequest{},
			wantCode:   codes.PermissionDenied,
		},
		{
			name:       "governance RPC is still allowed for an owner",
			ctx:        aliceCtx,
			fullMethod: ateapipb.Control_UpdateGlobalAccessPolicy_FullMethodName,
			req:        &ateapipb.UpdateGlobalAccessPolicyRequest{},
			wantCode:   codes.OK,
		},
		{
			name:       "governance RPC still requires a principal",
			ctx:        context.Background(),
			fullMethod: ateapipb.Control_GetAtespaceAccessPolicy_FullMethodName,
			req:        &ateapipb.GetAtespaceAccessPolicyRequest{},
			wantCode:   codes.Unauthenticated,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			handlerCalled := false
			_, err := interceptor(tc.ctx, tc.req, &grpc.UnaryServerInfo{FullMethod: tc.fullMethod}, func(ctx context.Context, req any) (any, error) {
				handlerCalled = true
				return "ok", nil
			})
			if status.Code(err) != tc.wantCode {
				t.Fatalf("status.Code(err) = %v, want %v (err: %v)", status.Code(err), tc.wantCode, err)
			}
			if wantHandler := tc.wantCode == codes.OK; handlerCalled != wantHandler {
				t.Fatalf("handlerCalled = %v, want %v", handlerCalled, wantHandler)
			}
		})
	}
}

// TestAccessPolicyRPCsAlwaysEnforced guards against an AccessPolicy RPC being
// added without a governance rule, which would leave it unchecked while
// enforcement is disabled.
func TestAccessPolicyRPCsAlwaysEnforced(t *testing.T) {
	desc := ateapipb.Control_ServiceDesc
	found := 0
	for _, m := range desc.Methods {
		if !strings.Contains(m.MethodName, "AccessPolicy") {
			continue
		}
		found++
		fullMethod := "/" + desc.ServiceName + "/" + m.MethodName
		rule, ok := defaultRPCPermissions[fullMethod]
		if !ok {
			t.Errorf("%s has no permission rule", fullMethod)
			continue
		}
		if !rule.alwaysEnforce {
			t.Errorf("%s is not marked alwaysEnforce", fullMethod)
		}
	}
	if found == 0 {
		t.Fatal("found no AccessPolicy RPCs in Control_ServiceDesc")
	}
}

// TestCreateAtespaceInterceptor_CreatorBecomesOwner exercises the
// CreateAtespace/DeleteAtespace lifecycle hook through the real
// UnaryServerInterceptor: a principal who holds only the global
// atespace_creator relation (BasicBlock's global.atespaceCreators config,
// bound as "atespace_creator" on global:root; see Config.tuples) is not an
// owner of anything yet, but creating an atespace must still make it theirs,
// the same way an atespace creator ("dev-<name>") must be able to create
// actors in what it just created. Another principal must not inherit any of
// that, and recording the same creator twice (a retried CreateAtespace, or a
// second replica's interceptor racing the first) must stay consistent rather
// than erroring or duplicating state.
func TestCreateAtespaceInterceptor_CreatorBecomesOwner(t *testing.T) {
	ctx := context.Background()
	pool := startPostgres(t)

	fgaServer, err := NewOpenFGAServer(pool)
	if err != nil {
		t.Fatalf("NewOpenFGAServer failed: %v", err)
	}
	t.Cleanup(fgaServer.Close)

	authorizer, policyManager, err := New(ctx, pool, fgaServer, nil)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	// dave holds only atespace_creator on global:root -- not owner, and no
	// per-atespace binding of any kind.
	writeTestTuple(t, ctx, pool, policyManager, "dave@example.com", "atespace_creator", GlobalRootObject)

	daveCtx := principal.InjectContext(ctx, principal.PrincipalInfo{ID: "dave@example.com", Kind: principal.KindJWT})
	erinCtx := principal.InjectContext(ctx, principal.PrincipalInfo{ID: "erin@example.com", Kind: principal.KindJWT})

	interceptor := UnaryServerInterceptor(authorizer, true)
	createReq := &ateapipb.CreateAtespaceRequest{Atespace: &ateapipb.Atespace{Metadata: &ateapipb.ResourceMetadata{Name: "dev-dave"}}}
	handlerCalls := 0
	handler := func(ctx context.Context, req any) (any, error) {
		handlerCalls++
		return "ok", nil
	}

	if _, err := interceptor(daveCtx, createReq, &grpc.UnaryServerInfo{FullMethod: ateapipb.Control_CreateAtespace_FullMethodName}, handler); err != nil {
		t.Fatalf("dave (atespace_creator only) should be allowed to create dev-dave: %v", err)
	}
	if handlerCalls != 1 {
		t.Fatalf("handler calls = %d, want 1", handlerCalls)
	}

	// dave is now dev-dave's owner via the recorded creator tuple, and so can
	// create an actor in it.
	if err := authorizer.Check(daveCtx, RoleOwner, AtespaceObject("dev-dave")); err != nil {
		t.Errorf("dave (creator) should be owner of dev-dave: %v", err)
	}
	if err := authorizer.Check(daveCtx, RelationCanCreateActor, AtespaceObject("dev-dave")); err != nil {
		t.Errorf("dave (creator) should be allowed can_create_actor on dev-dave: %v", err)
	}

	// erin has no binding and is not dev-dave's creator: denied both ways.
	if err := authorizer.Check(erinCtx, RoleOwner, AtespaceObject("dev-dave")); status.Code(err) != codes.PermissionDenied {
		t.Errorf("erin should be denied owner on dev-dave, got %v", err)
	}
	if err := authorizer.Check(erinCtx, RelationCanCreateActor, AtespaceObject("dev-dave")); status.Code(err) != codes.PermissionDenied {
		t.Errorf("erin should be denied can_create_actor on dev-dave, got %v", err)
	}

	// A repeated create (e.g. a client retry) records the same creator tuple
	// again without error, and leaves dave's ownership exactly as it was.
	if _, err := interceptor(daveCtx, createReq, &grpc.UnaryServerInfo{FullMethod: ateapipb.Control_CreateAtespace_FullMethodName}, handler); err != nil {
		t.Fatalf("repeated create should stay consistent, got %v", err)
	}
	if err := authorizer.Check(daveCtx, RoleOwner, AtespaceObject("dev-dave")); err != nil {
		t.Errorf("dave should still be owner of dev-dave after the repeated create: %v", err)
	}

	// DeleteAtespace forgets dave's creator record, so a later atespace of the
	// same name would not inherit it.
	deleteReq := &ateapipb.DeleteAtespaceRequest{Atespace: &ateapipb.ObjectRef{Name: "dev-dave"}}
	if _, err := interceptor(daveCtx, deleteReq, &grpc.UnaryServerInfo{FullMethod: ateapipb.Control_DeleteAtespace_FullMethodName}, handler); err != nil {
		t.Fatalf("dave (owner via creator) should be allowed to delete dev-dave: %v", err)
	}
	if err := authorizer.Check(daveCtx, RoleOwner, AtespaceObject("dev-dave")); status.Code(err) != codes.PermissionDenied {
		t.Errorf("dave should have lost dev-dave ownership once delete forgot his creator record, got %v", err)
	}
}
