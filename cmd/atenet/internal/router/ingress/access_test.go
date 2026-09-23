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

package ingress

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/grpc"

	"github.com/agent-substrate/substrate/cmd/atenet/internal/router/extproc"
	"github.com/agent-substrate/substrate/internal/atenet"
	"github.com/agent-substrate/substrate/internal/resources"
	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
)

// accessClient answers ResumeActor with a routable actor and CheckActorAccess
// from allow (token -> principal allowed to connect to team-a/*).
type accessClient struct {
	ateapipb.ControlClient
	allow   map[string]string
	deny    map[string]string
	err     error
	checks  atomic.Int32
	resumes atomic.Int32
}

func (c *accessClient) ResumeActor(context.Context, *ateapipb.ResumeActorRequest, ...grpc.CallOption) (*ateapipb.ResumeActorResponse, error) {
	c.resumes.Add(1)
	return &ateapipb.ResumeActorResponse{Actor: &ateapipb.Actor{
		Status: &ateapipb.ActorStatus{WorkerAssignment: &ateapipb.WorkerAssignment{WorkerPodIp: "10.0.0.52"}},
	}}, nil
}

func (c *accessClient) CheckActorAccess(_ context.Context, in *ateapipb.CheckActorAccessRequest, _ ...grpc.CallOption) (*ateapipb.CheckActorAccessResponse, error) {
	c.checks.Add(1)
	if c.err != nil {
		return nil, c.err
	}
	if who, ok := c.allow[in.GetToken()]; ok && in.GetActor().GetAtespace() == "team-a" {
		return &ateapipb.CheckActorAccessResponse{Allowed: true, Principal: who}, nil
	}
	if who, ok := c.deny[in.GetToken()]; ok {
		return &ateapipb.CheckActorAccessResponse{Principal: who, Reason: "permission denied"}, nil
	}
	return &ateapipb.CheckActorAccessResponse{Reason: "token did not authenticate"}, nil
}

func header(key, value string) *corev3.HeaderValue {
	return &corev3.HeaderValue{Key: key, Value: value}
}

func statusOf(t *testing.T, err error) int {
	t.Helper()
	var reqErr *extproc.ReqError
	if !errors.As(err, &reqErr) {
		t.Fatalf("error %v is not a ReqError", err)
	}
	return reqErr.StatusCode
}

func TestAccessEnforce(t *testing.T) {
	client := &accessClient{allow: map[string]string{"alice": "iap:alice"}, deny: map[string]string{"mallory": "iap:mallory"}}
	h := New(client, ParkedRequestConfig{}, nil, WithAccess(AccessConfig{
		Mode:         AccessEnforce,
		TokenHeaders: []string{"x-goog-iap-jwt-assertion", "ate-authorization"},
		StripHeaders: []string{"proxy-authorization"},
	}, client))

	cases := []struct {
		name    string
		actor   string
		headers []*corev3.HeaderValue
		want    int // 0: routed
	}{
		{name: "no token", actor: "team-a", want: int(envoy_type.StatusCode_Unauthorized)},
		{name: "unauthenticated", actor: "team-a", headers: []*corev3.HeaderValue{header("ate-authorization", "Bearer forged")}, want: int(envoy_type.StatusCode_Unauthorized)},
		{name: "denied", actor: "team-a", headers: []*corev3.HeaderValue{header("ate-authorization", "Bearer mallory")}, want: int(envoy_type.StatusCode_Forbidden)},
		{name: "another atespace", actor: "team-b", headers: []*corev3.HeaderValue{header("ate-authorization", "alice")}, want: int(envoy_type.StatusCode_Unauthorized)},
		{name: "allowed bearer", actor: "team-a", headers: []*corev3.HeaderValue{header("ate-authorization", "Bearer alice")}},
		{name: "proxy assertion first", actor: "team-a", headers: []*corev3.HeaderValue{header("x-goog-iap-jwt-assertion", "alice"), header("ate-authorization", "Bearer mallory")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resumes := client.resumes.Load()
			res, err := h.HandleRequestHeaders(context.Background(), requestMetadata("box", tc.actor, tc.headers...))
			if tc.want != 0 {
				if got := statusOf(t, err); got != tc.want {
					t.Fatalf("status = %d, want %d", got, tc.want)
				}
				if client.resumes.Load() != resumes {
					t.Fatal("a denied request resumed its actor")
				}
				return
			}
			if err != nil {
				t.Fatalf("HandleRequestHeaders() = %v", err)
			}
			removed := res.Response.GetResponse().GetHeaderMutation().GetRemoveHeaders()
			for _, h := range []string{"x-goog-iap-jwt-assertion", "ate-authorization", "proxy-authorization"} {
				if !slices.Contains(removed, h) {
					t.Errorf("removed headers %v lack %s", removed, h)
				}
			}
		})
	}
}

func TestAccessAudit(t *testing.T) {
	client := &accessClient{}
	h := New(client, ParkedRequestConfig{}, nil, WithAccess(AccessConfig{Mode: AccessAudit, TokenHeaders: []string{"ate-authorization"}}, client))
	if _, err := h.HandleRequestHeaders(context.Background(), requestMetadata("box", "team-a", header("ate-authorization", "forged"))); err != nil {
		t.Fatalf("audit mode rejected a request: %v", err)
	}
	client.err = errors.New("ate-api down")
	if _, err := h.HandleRequestHeaders(context.Background(), requestMetadata("box", "team-b", header("ate-authorization", "other"))); err != nil {
		t.Fatalf("audit mode rejected a request it could not check: %v", err)
	}
}

func TestAccessUnavailable(t *testing.T) {
	client := &accessClient{err: errors.New("ate-api down")}
	h := New(client, ParkedRequestConfig{}, nil, WithAccess(AccessConfig{Mode: AccessEnforce, TokenHeaders: []string{"ate-authorization"}}, client))
	_, err := h.HandleRequestHeaders(context.Background(), requestMetadata("box", "team-a", header("ate-authorization", "alice")))
	if got := statusOf(t, err); got != int(envoy_type.StatusCode_ServiceUnavailable) {
		t.Fatalf("status = %d, want 503", got)
	}
}

func TestAccessDisabledStripsHeaders(t *testing.T) {
	client := &accessClient{}
	h := New(client, ParkedRequestConfig{}, nil, WithAccess(AccessConfig{StripHeaders: []string{"Proxy-Authorization"}}, client))
	res, err := h.HandleRequestHeaders(context.Background(), requestMetadata("box", "team-a"))
	if err != nil {
		t.Fatal(err)
	}
	if removed := res.Response.GetResponse().GetHeaderMutation().GetRemoveHeaders(); !slices.Equal(removed, []string{"proxy-authorization"}) {
		t.Fatalf("removed headers = %v", removed)
	}
	if client.checks.Load() != 0 {
		t.Fatal("disabled authorization asked ate-api")
	}
}

func jwtExpiring(at time.Time) string {
	payload := base64.RawURLEncoding.EncodeToString(fmt.Appendf(nil, `{"exp":%d}`, at.Unix()))
	return "e30." + payload + ".c2ln"
}

func TestAccessCache(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	short := jwtExpiring(now.Add(10 * time.Second))
	client := &accessClient{allow: map[string]string{"long": "iap:alice", short: "iap:alice"}}
	a := newAccessControl(AccessConfig{Mode: AccessEnforce, TokenHeaders: []string{"ate-authorization"}}, client)
	a.now = func() time.Time { return now }
	authorize := func(token string) error {
		return a.authorize(context.Background(), requestMetadata("box", "team-a", header("ate-authorization", token)), mustRef(t, "team-a/box"))
	}

	for range 3 {
		if err := authorize("long"); err != nil {
			t.Fatal(err)
		}
	}
	if got := client.checks.Load(); got != 1 {
		t.Fatalf("checks = %d, want 1 (cached)", got)
	}
	now = now.Add(DefaultAccessCacheTTL)
	if err := authorize("long"); err != nil {
		t.Fatal(err)
	}
	if got := client.checks.Load(); got != 2 {
		t.Fatalf("checks after the TTL = %d, want 2", got)
	}

	// A token's expiry bounds its cached decision.
	if err := authorize(short); err != nil {
		t.Fatal(err)
	}
	now = now.Add(11 * time.Second)
	if err := authorize(short); err != nil {
		t.Fatal(err)
	}
	if got := client.checks.Load(); got != 4 {
		t.Fatalf("checks after the token expired = %d, want 4", got)
	}

	// Denials are cached briefly.
	client.checks.Store(0)
	for range 2 {
		if err := authorize("forged"); err == nil {
			t.Fatal("forged token allowed")
		}
	}
	if got := client.checks.Load(); got != 1 {
		t.Fatalf("checks for a repeated denial = %d, want 1", got)
	}
}

func TestAccessConfigValidate(t *testing.T) {
	for _, cfg := range []AccessConfig{
		{Mode: "strict"},
		{Mode: AccessEnforce},
		{Mode: AccessAudit, TokenHeaders: []string{"bad header"}},
		{StripHeaders: []string{":authority"}},
		{CacheTTL: -time.Second},
	} {
		if err := cfg.Validate(); err == nil {
			t.Errorf("Validate(%+v) succeeded, want an error", cfg)
		}
	}
	if err := (AccessConfig{Mode: AccessEnforce, TokenHeaders: []string{"ate-authorization"}}).Validate(); err != nil {
		t.Errorf("Validate() = %v", err)
	}
}

func mustRef(t *testing.T, value string) resources.ActorRef {
	t.Helper()
	ref, err := atenet.ParseTargetActor(value)
	if err != nil {
		t.Fatal(err)
	}
	return ref
}
