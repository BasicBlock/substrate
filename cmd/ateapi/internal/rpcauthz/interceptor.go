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
	"log/slog"

	"github.com/agent-substrate/substrate/cmd/ateapi/internal/authz"
	"github.com/agent-substrate/substrate/internal/principal"
	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Authorizer is the part of *authz.Authorizer the interceptors use.
type Authorizer interface {
	Mode() authz.Mode
	Allowed(ctx context.Context, p principal.PrincipalInfo, checks []authz.Check) (bool, *authz.Check, error)
	RecordCreator(ctx context.Context, p principal.PrincipalInfo, atespace string) error
	ForgetCreators(ctx context.Context, atespace string) error
}

// UnaryServerInterceptor authorizes each call after authentication. In audit
// mode a call the bindings would deny is logged and allowed; in enforce mode
// it fails with PermissionDenied, as does a method without a rule. Creating
// an atespace makes the caller its creator; deleting one forgets its creators.
func UnaryServerInterceptor(a Authorizer) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		p, err := authorize(ctx, a, info.FullMethod, req)
		if err != nil {
			return nil, err
		}
		resp, err := handler(ctx, req)
		if err != nil {
			return resp, err
		}
		switch info.FullMethod {
		case ateapipb.Control_CreateAtespace_FullMethodName:
			name := req.(*ateapipb.CreateAtespaceRequest).GetAtespace().GetMetadata().GetName()
			if err := a.RecordCreator(ctx, p, name); err != nil {
				slog.ErrorContext(ctx, "Created atespace, but could not record its creator", slog.String("atespace", name), slog.Any("err", err))
				return nil, status.Errorf(codes.Internal, "atespace %q was created, but its owner could not be recorded; a global owner must delete or bind it", name)
			}
		case ateapipb.Control_DeleteAtespace_FullMethodName:
			name := req.(*ateapipb.DeleteAtespaceRequest).GetAtespace().GetName()
			if err := a.ForgetCreators(ctx, name); err != nil {
				// A stale creator would own a later atespace of the same name.
				slog.ErrorContext(ctx, "Deleted atespace, but could not remove its creator", slog.String("atespace", name), slog.Any("err", err))
				return nil, status.Errorf(codes.Internal, "atespace %q was deleted, but its creator could not be removed", name)
			}
		}
		return resp, nil
	}
}

// StreamServerInterceptor authorizes streaming calls, whose rules need no
// request.
func StreamServerInterceptor(a Authorizer) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if _, err := authorize(ss.Context(), a, info.FullMethod, nil); err != nil {
			return err
		}
		return handler(srv, ss)
	}
}

func authorize(ctx context.Context, a Authorizer, method string, req any) (principal.PrincipalInfo, error) {
	p, ok := principal.FromContext(ctx)
	if !ok {
		return p, status.Error(codes.Unauthenticated, "no authenticated principal")
	}
	attrs := []any{slog.String("method", method), slog.String("provider", p.Provider), slog.String("principal", p.ID)}
	checks, err := checksFor(method, req)
	if err != nil {
		return p, decide(ctx, a.Mode(), append(attrs, slog.Any("err", err)), "unmapped method")
	}
	allowed, denied, err := a.Allowed(ctx, p, checks)
	if err != nil {
		slog.ErrorContext(ctx, "Authorization check failed", append(attrs, slog.Any("err", err))...)
		if a.Mode() == authz.ModeAudit {
			return p, nil
		}
		return p, status.Error(codes.Unavailable, "authorization is unavailable")
	}
	if allowed {
		return p, nil
	}
	return p, decide(ctx, a.Mode(), append(attrs, slog.String("object", denied.Object.ID), slog.String("relation", denied.Relation)), denied.String())
}

// decide logs a denial and returns the error to fail the call with, or nil
// when only auditing.
func decide(ctx context.Context, mode authz.Mode, attrs []any, what string) error {
	if mode == authz.ModeAudit {
		slog.WarnContext(ctx, "Authorization would deny call (audit mode)", attrs...)
		return nil
	}
	slog.InfoContext(ctx, "Authorization denied call", attrs...)
	return status.Errorf(codes.PermissionDenied, "permission denied: %s", what)
}
