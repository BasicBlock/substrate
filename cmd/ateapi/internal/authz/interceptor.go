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
	"log/slog"

	"github.com/agent-substrate/substrate/internal/principal"
	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// UnaryServerInterceptor returns a gRPC unary interceptor that enforces per-RPC
// permissions registered in defaultRPCPermissions using authorizer. When
// enforce is false, only rules marked alwaysEnforce are checked. Creating an
// atespace makes the caller its creator; deleting one forgets its creators
// (see recordAtespaceLifecycle).
func UnaryServerInterceptor(authorizer *Authorizer, enforce bool) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if IsBypassed(ctx) {
			return handler(ctx, req)
		}
		rule, registered := defaultRPCPermissions[info.FullMethod]
		if !registered || (!enforce && !rule.alwaysEnforce) {
			return handler(ctx, req)
		}

		checks, err := rule.extract(req)
		if err != nil {
			return nil, err
		}
		if len(checks) == 0 {
			p, hasPrincipal := principal.FromContext(ctx)
			if !hasPrincipal || p.ID == "" {
				return nil, status.Error(codes.Unauthenticated, "unauthenticated: missing principal in context")
			}
			return handler(ctx, req)
		}
		for _, c := range checks {
			if err := authorizer.Check(ctx, c.relation, c.object); err != nil {
				return nil, err
			}
		}

		resp, err := handler(ctx, req)
		if err != nil {
			return resp, err
		}
		if err := recordAtespaceLifecycle(ctx, authorizer, info.FullMethod, req); err != nil {
			return nil, err
		}
		return resp, nil
	}
}

// UnaryServerInterceptorForMode returns the interceptor --authorization-config
// selects. ModeEnforce behaves exactly like UnaryServerInterceptor(authorizer,
// true). ModeAudit evaluates every rule (so a would-be denial is logged, and
// an atespace creator is still recorded) but only blocks a rule marked
// alwaysEnforce, logging what it would otherwise have denied and letting the
// call through.
func UnaryServerInterceptorForMode(authorizer *Authorizer, mode Mode) grpc.UnaryServerInterceptor {
	enforced := UnaryServerInterceptor(authorizer, true)
	if mode == ModeEnforce {
		return enforced
	}
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if rule, registered := defaultRPCPermissions[info.FullMethod]; registered && rule.alwaysEnforce {
			return enforced(ctx, req, info, handler)
		}
		resp, err := enforced(ctx, req, info, handler)
		if status.Code(err) != codes.PermissionDenied {
			return resp, err
		}
		slog.WarnContext(ctx, "Authorization would deny call (audit mode)", slog.String("method", info.FullMethod), slog.Any("err", err))
		resp, err = handler(ctx, req)
		if err != nil {
			return resp, err
		}
		if err := recordAtespaceLifecycle(ctx, authorizer, info.FullMethod, req); err != nil {
			return nil, err
		}
		return resp, nil
	}
}

// recordAtespaceLifecycle makes the caller the creator of an atespace it just
// created, and forgets the creators of one it just deleted. A failure here is
// reported as a server error: the handler already committed the create or
// delete, so the caller must be told the follow-up step failed rather than
// seeing a false success.
func recordAtespaceLifecycle(ctx context.Context, authorizer *Authorizer, method string, req any) error {
	switch method {
	case ateapipb.Control_CreateAtespace_FullMethodName:
		r, ok := req.(*ateapipb.CreateAtespaceRequest)
		if !ok {
			return nil
		}
		name := r.GetAtespace().GetMetadata().GetName()
		p, hasPrincipal := principal.FromContext(ctx)
		if name == "" || !hasPrincipal {
			return nil
		}
		if err := authorizer.RecordCreator(ctx, p, name); err != nil {
			slog.ErrorContext(ctx, "Created atespace, but could not record its creator", slog.String("atespace", name), slog.Any("err", err))
			return status.Errorf(codes.Internal, "atespace %q was created, but its owner could not be recorded; a global owner must delete or bind it", name)
		}
	case ateapipb.Control_DeleteAtespace_FullMethodName:
		r, ok := req.(*ateapipb.DeleteAtespaceRequest)
		if !ok {
			return nil
		}
		name := r.GetAtespace().GetName()
		if name == "" {
			return nil
		}
		if err := authorizer.ForgetCreators(ctx, name); err != nil {
			// A stale creator would own a later atespace of the same name.
			slog.ErrorContext(ctx, "Deleted atespace, but could not remove its creator", slog.String("atespace", name), slog.Any("err", err))
			return status.Errorf(codes.Internal, "atespace %q was deleted, but its creator could not be removed", name)
		}
	}
	return nil
}
