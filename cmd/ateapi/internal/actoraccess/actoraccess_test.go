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

package actoraccess

import (
	"context"
	"errors"
	"testing"

	"github.com/agent-substrate/substrate/internal/authz"
	"github.com/agent-substrate/substrate/internal/principal"
	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type fakeAuthn map[string]principal.PrincipalInfo

func (f fakeAuthn) Authenticate(_ context.Context, token string) (principal.PrincipalInfo, error) {
	if p, ok := f[token]; ok {
		return p, nil
	}
	return principal.PrincipalInfo{}, status.Error(codes.Unauthenticated, "invalid bearer token")
}

type fakeAuthz struct {
	connect map[string]bool // principal ID -> may connect
	err     error
	checks  []authz.Check
}

func (f *fakeAuthz) Allowed(_ context.Context, p principal.PrincipalInfo, checks []authz.Check) (bool, *authz.Check, error) {
	f.checks = append(f.checks, checks...)
	if f.err != nil {
		return false, nil, f.err
	}
	if f.connect[p.ID] {
		return true, nil, nil
	}
	return false, &checks[0], nil
}

func TestCheck(t *testing.T) {
	authn := fakeAuthn{
		"alice-token": {ID: "alice@example.com", Provider: "iap"},
		"bob-token":   {ID: "bob@example.com", Provider: "iap"},
	}
	request := func(token string) *ateapipb.CheckActorAccessRequest {
		return &ateapipb.CheckActorAccessRequest{Actor: &ateapipb.ObjectRef{Atespace: "dev-alice", Name: "box"}, Token: token}
	}
	authorizer := &fakeAuthz{connect: map[string]bool{"alice@example.com": true}}
	checker := New(authn, authorizer)

	got, err := checker.Check(t.Context(), request("alice-token"))
	if err != nil || !got.GetAllowed() || got.GetPrincipal() != "iap:alice@example.com" {
		t.Fatalf("alice: %+v, %v; want allowed as iap:alice@example.com", got, err)
	}
	if want := "can_connect on actor:dev-alice/box"; len(authorizer.checks) != 1 || authorizer.checks[0].String() != want {
		t.Fatalf("checks = %v, want [%s]", authorizer.checks, want)
	}
	got, err = checker.Check(t.Context(), request("bob-token"))
	if err != nil || got.GetAllowed() || got.GetPrincipal() != "iap:bob@example.com" || got.GetReason() == "" {
		t.Fatalf("bob: %+v, %v; want denied with a reason", got, err)
	}
	got, err = checker.Check(t.Context(), request("forged"))
	if err != nil || got.GetAllowed() || got.GetPrincipal() != "" || got.GetReason() == "" {
		t.Fatalf("forged token: %+v, %v; want denied without a principal", got, err)
	}

	authorizer.err = errors.New("store down")
	if _, err := checker.Check(t.Context(), request("alice-token")); status.Code(err) != codes.Unavailable {
		t.Fatalf("store failure err = %v, want Unavailable", err)
	}
}

func TestCheckWithoutAuthorization(t *testing.T) {
	checker := New(fakeAuthn{"token": {ID: "anyone", Provider: "kubernetes"}}, nil)
	request := &ateapipb.CheckActorAccessRequest{Actor: &ateapipb.ObjectRef{Atespace: "a", Name: "b"}, Token: "token"}
	if got, err := checker.Check(t.Context(), request); err != nil || !got.GetAllowed() {
		t.Fatalf("Check() = %+v, %v; want allowed", got, err)
	}
	request.Token = "other"
	if got, err := checker.Check(t.Context(), request); err != nil || got.GetAllowed() {
		t.Fatalf("Check() = %+v, %v; want an unauthenticated token denied", got, err)
	}
}
