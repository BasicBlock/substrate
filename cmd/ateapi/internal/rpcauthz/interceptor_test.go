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
	"errors"
	"testing"

	"github.com/agent-substrate/substrate/internal/authz"
	"github.com/agent-substrate/substrate/internal/principal"
	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fakeAuthorizer allows whatever allow says and records creator changes.
type fakeAuthorizer struct {
	mode      authz.Mode
	allow     bool
	checkErr  error
	recordErr error
	recorded  []string
	forgotten []string
}

func (f *fakeAuthorizer) Mode() authz.Mode { return f.mode }

func (f *fakeAuthorizer) Allowed(_ context.Context, _ principal.PrincipalInfo, checks []authz.Check) (bool, *authz.Check, error) {
	if f.checkErr != nil {
		return false, nil, f.checkErr
	}
	if f.allow || len(checks) == 0 {
		return true, nil, nil
	}
	return false, &checks[0], nil
}

func (f *fakeAuthorizer) RecordCreator(_ context.Context, p principal.PrincipalInfo, atespace string) error {
	f.recorded = append(f.recorded, p.ID+" "+atespace)
	return f.recordErr
}

func (f *fakeAuthorizer) ForgetCreators(_ context.Context, atespace string) error {
	f.forgotten = append(f.forgotten, atespace)
	return nil
}

func invoke(a Authorizer, method string, req any, handlerErr error) error {
	ctx := principal.InjectContext(context.Background(), alice)
	handler := func(context.Context, any) (any, error) { return struct{}{}, handlerErr }
	_, err := UnaryServerInterceptor(a)(ctx, req, &grpc.UnaryServerInfo{FullMethod: method}, handler)
	return err
}

func TestInterceptorModes(t *testing.T) {
	get := &ateapipb.GetActorRequest{Actor: ref("dev-bob", "w")}
	tests := []struct {
		name   string
		a      *fakeAuthorizer
		method string
		want   codes.Code
	}{
		{"enforce allows", &fakeAuthorizer{mode: authz.ModeEnforce, allow: true}, ateapipb.Control_GetActor_FullMethodName, codes.OK},
		{"enforce denies", &fakeAuthorizer{mode: authz.ModeEnforce}, ateapipb.Control_GetActor_FullMethodName, codes.PermissionDenied},
		{"audit allows a denial", &fakeAuthorizer{mode: authz.ModeAudit}, ateapipb.Control_GetActor_FullMethodName, codes.OK},
		{"enforce denies an unmapped method", &fakeAuthorizer{mode: authz.ModeEnforce, allow: true}, "/ateapi.Control/NoSuchMethod", codes.PermissionDenied},
		{"audit allows an unmapped method", &fakeAuthorizer{mode: authz.ModeAudit}, "/ateapi.Control/NoSuchMethod", codes.OK},
		{"enforce fails closed", &fakeAuthorizer{mode: authz.ModeEnforce, checkErr: errors.New("down")}, ateapipb.Control_GetActor_FullMethodName, codes.Unavailable},
		{"audit passes through a failed check", &fakeAuthorizer{mode: authz.ModeAudit, checkErr: errors.New("down")}, ateapipb.Control_GetActor_FullMethodName, codes.OK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := status.Code(invoke(tt.a, tt.method, get, nil)); got != tt.want {
				t.Fatalf("code = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestInterceptorRequiresAPrincipal(t *testing.T) {
	a := &fakeAuthorizer{mode: authz.ModeAudit, allow: true}
	handler := func(context.Context, any) (any, error) { return nil, nil }
	_, err := UnaryServerInterceptor(a)(context.Background(), &ateapipb.GetActorRequest{}, &grpc.UnaryServerInfo{FullMethod: ateapipb.Control_GetActor_FullMethodName}, handler)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("code = %v, want Unauthenticated", status.Code(err))
	}
}

func TestInterceptorRecordsCreators(t *testing.T) {
	a := &fakeAuthorizer{mode: authz.ModeEnforce, allow: true}
	if err := invoke(a, ateapipb.Control_CreateAtespace_FullMethodName, newAtespace("dev-alice"), nil); err != nil {
		t.Fatal(err)
	}
	if err := invoke(a, ateapipb.Control_CreateAtespace_FullMethodName, newAtespace("taken"), status.Error(codes.AlreadyExists, "exists")); status.Code(err) != codes.AlreadyExists {
		t.Fatalf("failed create: %v", err)
	}
	if err := invoke(a, ateapipb.Control_DeleteAtespace_FullMethodName, &ateapipb.DeleteAtespaceRequest{Atespace: ref("", "dev-alice")}, nil); err != nil {
		t.Fatal(err)
	}
	if len(a.recorded) != 1 || a.recorded[0] != "alice@basicblock.io dev-alice" {
		t.Errorf("recorded creators = %q, want only alice for dev-alice", a.recorded)
	}
	if len(a.forgotten) != 1 || a.forgotten[0] != "dev-alice" {
		t.Errorf("forgotten creators = %q, want dev-alice", a.forgotten)
	}

	a.recordErr = errors.New("store down")
	if err := invoke(a, ateapipb.Control_CreateAtespace_FullMethodName, newAtespace("dev-other"), nil); status.Code(err) != codes.Internal {
		t.Fatalf("create with a failed creator record: %v, want Internal", err)
	}
}
