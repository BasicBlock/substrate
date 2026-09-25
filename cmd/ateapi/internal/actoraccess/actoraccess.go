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

// Package actoraccess answers CheckActorAccess: whether the bearer of a token
// the ingress gateway received may reach an actor's ports. The token is
// authenticated as it would be on a call to ate-api, and its principal needs
// can_connect on the actor.
package actoraccess

import (
	"context"
	"log/slog"

	"github.com/agent-substrate/substrate/cmd/ateapi/internal/authz"
	"github.com/agent-substrate/substrate/internal/principal"
	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Authenticator authenticates a bearer token (ateapiauth.ServerConfig).
type Authenticator interface {
	Authenticate(ctx context.Context, token string) (principal.PrincipalInfo, error)
}

// Authorizer is the part of *authz.Authorizer the check uses.
type Authorizer interface {
	Allowed(ctx context.Context, p principal.PrincipalInfo, checks []authz.Check) (bool, *authz.Check, error)
}

// Checker answers CheckActorAccess.
type Checker struct {
	authn Authenticator
	authz Authorizer
}

// New returns a Checker. A nil authorizer, when ate-api runs without
// --authorization-config, lets every authenticated principal connect, as it
// may call every RPC.
func New(authn Authenticator, authorizer Authorizer) *Checker {
	return &Checker{authn: authn, authz: authorizer}
}

// Check reports whether req's token may reach req's actor. A token that does
// not authenticate is a denial, not an error; an authorization store that
// cannot answer is Unavailable.
func (c *Checker) Check(ctx context.Context, req *ateapipb.CheckActorAccessRequest) (*ateapipb.CheckActorAccessResponse, error) {
	p, err := c.authn.Authenticate(ctx, req.GetToken())
	if err != nil {
		return &ateapipb.CheckActorAccessResponse{Reason: "token did not authenticate: " + status.Convert(err).Message()}, nil
	}
	who := p.Provider + ":" + p.ID
	if c.authz == nil {
		return &ateapipb.CheckActorAccessResponse{Allowed: true, Principal: who}, nil
	}
	ref := req.GetActor()
	allowed, denied, err := c.authz.Allowed(ctx, p, []authz.Check{{Object: authz.ActorObject(ref.GetAtespace(), ref.GetName()), Relation: "can_connect"}})
	if err != nil {
		slog.ErrorContext(ctx, "Actor access check failed", slog.String("principal", who), slog.Any("err", err))
		return nil, status.Error(codes.Unavailable, "authorization is unavailable")
	}
	if !allowed {
		return &ateapipb.CheckActorAccessResponse{Principal: who, Reason: "permission denied: " + denied.String()}, nil
	}
	return &ateapipb.CheckActorAccessResponse{Allowed: true, Principal: who}, nil
}
