//  Copyright 2026 Google LLC
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

package ateapiauth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/url"
	"reflect"
	"testing"

	"github.com/agent-substrate/substrate/internal/principal"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

const (
	testGoodToken = "e30.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIn0.Z29vZA"
	testBadToken  = "e30.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIn0.YmFk"
)

func TestValidateServerConfig(t *testing.T) {
	validProvider := JWTProvider{Name: "test", Issuer: "https://issuer.example", Verify: func(context.Context, string) (string, []string, error) { return "", nil, nil }}
	tests := []struct {
		name    string
		cfg     ServerConfig
		wantErr bool
	}{
		{name: "valid", cfg: ServerConfig{JWTProviders: []JWTProvider{validProvider}}},
		{name: "missing verifier", cfg: ServerConfig{}, wantErr: true},
		{name: "duplicate issuer", cfg: ServerConfig{JWTProviders: []JWTProvider{validProvider, validProvider}}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateServerConfig(tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateServerConfig(%+v) err=%v, wantErr=%v", tt.cfg, err, tt.wantErr)
			}
		})
	}
}

func TestChainedServerAuthenticatorPrincipal(t *testing.T) {
	const subject = "system:serviceaccount:ate-system:ate-client"
	const issuer = "https://issuer.example"
	spiffeID := &url.URL{Scheme: "spiffe", Host: "ate.dev", Path: "/ns/default/sa/router"}
	spiffePeer := func(ctx context.Context) context.Context {
		return peer.NewContext(ctx, &peer.Peer{
			AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{{URIs: []*url.URL{spiffeID}}},
			}},
		})
	}
	withBearer := func(ctx context.Context, token string) context.Context {
		return metadata.NewIncomingContext(ctx, metadata.Pairs("authorization", "Bearer "+token))
	}
	verifyGoodToken := func(_ context.Context, bearer string) (string, []string, error) {
		if bearer != testGoodToken {
			return "", nil, fmt.Errorf("bad token")
		}
		return subject, []string{"service-accounts"}, nil
	}

	tests := []struct {
		name string
		ctx  context.Context
		// verify is the bearer token verifier; nil means the test fails if
		// it is called (the certificate identity must take precedence).
		verify   func(context.Context, string) (string, []string, error)
		want     principal.PrincipalInfo
		wantCode codes.Code
	}{
		{
			name:     "no peer and no token",
			ctx:      context.Background(),
			wantCode: codes.Unauthenticated,
		},
		{
			name: "peer without certificates and no token",
			ctx: peer.NewContext(context.Background(), &peer.Peer{
				AuthInfo: credentials.TLSInfo{},
			}),
			wantCode: codes.Unauthenticated,
		},
		{
			name:     "no peer with valid bearer",
			ctx:      withBearer(context.Background(), testGoodToken),
			verify:   verifyGoodToken,
			want:     principal.PrincipalInfo{ID: subject, Kind: principal.KindJWT, Issuer: issuer, Provider: "test", Groups: []string{"authenticated", "test", "test/service-accounts"}},
			wantCode: codes.OK,
		},
		{
			name:     "no peer with invalid bearer",
			ctx:      withBearer(context.Background(), testBadToken),
			verify:   verifyGoodToken,
			wantCode: codes.Unauthenticated,
		},
		{
			name: "certificate without URI SAN with valid bearer",
			ctx: withBearer(peer.NewContext(context.Background(), &peer.Peer{
				AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{
					PeerCertificates: []*x509.Certificate{{}},
				}},
			}), testGoodToken),
			verify:   verifyGoodToken,
			want:     principal.PrincipalInfo{ID: subject, Kind: principal.KindJWT, Issuer: issuer, Provider: "test", Groups: []string{"authenticated", "test", "test/service-accounts"}},
			wantCode: codes.OK,
		},
		{
			name:     "certificate with SPIFFE URI SAN",
			ctx:      spiffePeer(context.Background()),
			want:     principal.PrincipalInfo{ID: spiffeID.String(), Kind: principal.KindMTLS, Provider: principal.ProviderMTLS, Groups: []string{"authenticated", "mtls"}},
			wantCode: codes.OK,
		},
		{
			name:     "certificate takes precedence over bearer",
			ctx:      withBearer(spiffePeer(context.Background()), testGoodToken),
			want:     principal.PrincipalInfo{ID: spiffeID.String(), Kind: principal.KindMTLS, Provider: principal.ProviderMTLS, Groups: []string{"authenticated", "mtls"}},
			wantCode: codes.OK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verify := tt.verify
			if verify == nil {
				verify = func(context.Context, string) (string, []string, error) {
					t.Fatal("bearer token verifier called; certificate identity must take precedence")
					return "", nil, nil
				}
			}
			auth := newChainedAuthenticator(ServerConfig{JWTProviders: []JWTProvider{{Name: "test", Issuer: issuer, Verify: verify}}})
			newCtx, err := auth.authenticate(tt.ctx)
			if code := status.Code(err); code != tt.wantCode {
				t.Fatalf("authenticate: code=%v (err=%v), want %v", code, err, tt.wantCode)
			}
			if tt.wantCode != codes.OK {
				return
			}
			got, ok := principal.FromContext(newCtx)
			if !ok {
				t.Fatal("no principal in context")
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("principal=%+v want %+v", got, tt.want)
			}
		})
	}
}

func TestJWTServerAuthenticatorRequiresBearer(t *testing.T) {
	auth := jwtServerAuthenticator{
		providers: []JWTProvider{{Name: "test", Issuer: "https://issuer.example", Verify: func(context.Context, string) (string, []string, error) {
			return "", nil, fmt.Errorf("bad token")
		}}},
	}

	// Missing header -> Unauthenticated.
	_, err := auth.authenticate(context.Background())
	if code := status.Code(err); code != codes.Unauthenticated {
		t.Fatalf("missing bearer: want Unauthenticated, got %v (err=%v)", code, err)
	}

	// Garbage bearer -> Unauthenticated (JWT parsing will fail).
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer not-a-jwt"))
	_, err = auth.authenticate(ctx)
	if code := status.Code(err); code != codes.Unauthenticated {
		t.Fatalf("bad bearer: want Unauthenticated, got %v (err=%v)", code, err)
	}

	ctx = metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+testBadToken))
	_, err = auth.authenticate(ctx)
	if got := status.Convert(err).Message(); got != "invalid bearer token" {
		t.Fatalf("verification error = %q, want generic error", got)
	}
}

func TestJWTServerAuthenticatorInjectsPrincipal(t *testing.T) {
	const subject = "system:serviceaccount:default:router"
	const issuer = "https://issuer.example"
	auth := jwtServerAuthenticator{
		providers: []JWTProvider{{Name: "test", Issuer: issuer, Verify: func(context.Context, string) (string, []string, error) {
			return subject, nil, nil
		}}},
	}

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+testGoodToken))
	newCtx, err := auth.authenticate(ctx)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	got, ok := principal.FromContext(newCtx)
	if !ok {
		t.Fatal("no principal in context")
	}
	want := principal.PrincipalInfo{ID: subject, Kind: principal.KindJWT, Issuer: issuer, Provider: "test", Groups: []string{"authenticated", "test"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("principal=%+v want %+v", got, want)
	}
}

func TestJWTServerAuthenticatorTriesProviders(t *testing.T) {
	auth := jwtServerAuthenticator{providers: []JWTProvider{
		{Name: "first", Issuer: "https://first.example", Verify: func(context.Context, string) (string, []string, error) {
			return "", nil, fmt.Errorf("wrong issuer")
		}},
		{Name: "second", Issuer: "https://second.example", Verify: func(context.Context, string) (string, []string, error) {
			return "subject", nil, nil
		}},
	}}
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer e30.eyJpc3MiOiJodHRwczovL3NlY29uZC5leGFtcGxlIn0.eA"))
	ctx, err := auth.authenticate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := principal.FromContext(ctx)
	want := principal.PrincipalInfo{ID: "subject", Kind: principal.KindJWT, Issuer: "https://second.example", Provider: "second", Groups: []string{"authenticated", "second"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("principal = %+v, want %+v", got, want)
	}
}

func TestBearerToken(t *testing.T) {
	cases := []struct {
		name  string
		hdr   string
		want  string
		found bool
	}{
		{"missing", "", "", false},
		{"no prefix", "abc", "", false},
		{"prefix", "Bearer abc", "abc", true},
		{"prefix with spaces", "Bearer    abc  ", "abc", true},
		{"empty after prefix", "Bearer ", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			if tc.hdr != "" {
				ctx = metadata.NewIncomingContext(ctx, metadata.Pairs("authorization", tc.hdr))
			}
			got, ok := bearerToken(ctx)
			if ok != tc.found || got != tc.want {
				t.Errorf("bearerToken=(%q,%v) want (%q,%v)", got, ok, tc.want, tc.found)
			}
		})
	}
}

// Build-time check.
var _ grpc.UnaryServerInterceptor = UnaryServerInterceptor(ServerConfig{})
var _ grpc.StreamServerInterceptor = StreamServerInterceptor(ServerConfig{})

func TestJWTServerAuthenticatorTokenHeader(t *testing.T) {
	// iss https://iap.example
	const iapToken = "e30.eyJpc3MiOiJodHRwczovL2lhcC5leGFtcGxlIn0.aWFw"
	auth := jwtServerAuthenticator{providers: []JWTProvider{
		{Name: "google", Issuer: "https://issuer.example", Verify: func(_ context.Context, token string) (string, []string, error) {
			if token != testGoodToken {
				return "", nil, fmt.Errorf("bad token")
			}
			return "bearer@example.com", nil, nil
		}},
		{Name: "iap", Issuer: "https://iap.example", TokenHeader: "x-goog-iap-jwt-assertion", Verify: func(_ context.Context, token string) (string, []string, error) {
			if token != iapToken {
				return "", nil, fmt.Errorf("bad assertion")
			}
			return "asserted@example.com", []string{"staff"}, nil
		}},
	}}
	cases := []struct {
		name    string
		md      metadata.MD
		want    string
		wantErr codes.Code
	}{
		{name: "header wins over bearer", md: metadata.Pairs("x-goog-iap-jwt-assertion", iapToken, "authorization", "Bearer "+testGoodToken), want: "iap:asserted@example.com"},
		{name: "invalid header does not fall back", md: metadata.Pairs("x-goog-iap-jwt-assertion", testBadToken, "authorization", "Bearer "+testGoodToken), wantErr: codes.Unauthenticated},
		{name: "bearer without header", md: metadata.Pairs("authorization", "Bearer "+testGoodToken), want: "google:bearer@example.com"},
		// Either header is client input; what counts is the assertion's signature.
		{name: "header token as a bearer token", md: metadata.Pairs("authorization", "Bearer "+iapToken), want: "iap:asserted@example.com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, err := auth.authenticate(metadata.NewIncomingContext(context.Background(), tc.md))
			if tc.wantErr != codes.OK {
				if status.Code(err) != tc.wantErr {
					t.Fatalf("authenticate err = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got, _ := principal.FromContext(ctx)
			if got.Provider+":"+got.ID != tc.want {
				t.Fatalf("principal = %s:%s, want %s", got.Provider, got.ID, tc.want)
			}
		})
	}
}

func TestServerConfigAuthenticate(t *testing.T) {
	cfg := ServerConfig{JWTProviders: []JWTProvider{{Name: "test", Issuer: "https://issuer.example", Verify: func(_ context.Context, token string) (string, []string, error) {
		if token != testGoodToken {
			return "", nil, fmt.Errorf("bad token")
		}
		return "subject", []string{"rule"}, nil
	}}}}
	got, err := cfg.Authenticate(context.Background(), testGoodToken)
	if err != nil {
		t.Fatal(err)
	}
	want := principal.PrincipalInfo{ID: "subject", Kind: principal.KindJWT, Issuer: "https://issuer.example", Provider: "test", Groups: []string{"authenticated", "test", "test/rule"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("principal = %+v, want %+v", got, want)
	}
	if _, err := cfg.Authenticate(context.Background(), testBadToken); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("bad token err = %v, want Unauthenticated", err)
	}
	if _, err := cfg.Authenticate(context.Background(), "not-a-jwt"); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("malformed token err = %v, want Unauthenticated", err)
	}
}
