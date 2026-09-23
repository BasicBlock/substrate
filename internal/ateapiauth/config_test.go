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

package ateapiauth

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestLoadAuthenticationConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authentication.yaml")
	if err := os.WriteFile(path, []byte(`
actorIdentityJWTProvider: kubernetes
jwtProviders:
- name: kubernetes
  issuer: https://kubernetes.default.svc
  audiences: [api.ate-system.svc]
- name: google
  issuer: https://accounts.google.com
  audiences: [cloud-sdk-client]
`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadAuthenticationConfig(path)
	if err != nil {
		t.Fatalf("LoadAuthenticationConfig() error = %v", err)
	}
	if got := len(cfg.JWTProviders); got != 2 {
		t.Fatalf("len(JWTProviders) = %d, want 2", got)
	}
}

func TestLoadAuthenticationConfigRejectsUnknownField(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authentication.yaml")
	if err := os.WriteFile(path, []byte(`
actorIdentityJWTProvider: kubernetes
jwtProviders:
- name: kubernetes
  issuer: https://kubernetes.default.svc
  audiences: [api.ate-system.svc]
  typo: true
`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadAuthenticationConfig(path)
	if err == nil || !strings.Contains(err.Error(), `unknown field "typo"`) {
		t.Fatalf("LoadAuthenticationConfig() error = %v, want unknown-field error", err)
	}
}

func TestValidateAuthenticationConfig(t *testing.T) {
	valid := func() *AuthenticationConfig {
		return &AuthenticationConfig{
			ActorIdentityJWTProvider: "kubernetes",
			JWTProviders: []JWTProviderConfig{{
				Name:      "kubernetes",
				Issuer:    "https://kubernetes.default.svc",
				Audiences: []string{"api.ate-system.svc"},
			}},
		}
	}

	tests := []struct {
		name   string
		mutate func(*AuthenticationConfig)
	}{
		{name: "no providers", mutate: func(c *AuthenticationConfig) { c.JWTProviders = nil }},
		{name: "unknown actor identity provider", mutate: func(c *AuthenticationConfig) { c.ActorIdentityJWTProvider = "missing" }},
		{name: "insecure issuer", mutate: func(c *AuthenticationConfig) { c.JWTProviders[0].Issuer = "http://issuer.example" }},
		{name: "no audiences", mutate: func(c *AuthenticationConfig) { c.JWTProviders[0].Audiences = nil }},
		{name: "duplicate provider", mutate: func(c *AuthenticationConfig) { c.JWTProviders = append(c.JWTProviders, c.JWTProviders[0]) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := valid()
			tt.mutate(cfg)
			if err := ValidateAuthenticationConfig(cfg); err == nil {
				t.Fatal("ValidateAuthenticationConfig() succeeded, want error")
			}
		})
	}
}

// googleProvider admits basicblock.io users and one project's service
// accounts from the same issuer, as docs/authentication.md describes.
const googleProvider = `
actorIdentityJWTProvider: kubernetes
jwtProviders:
- name: kubernetes
  issuer: https://kubernetes.default.svc
  audiences: [api.ate-system.svc]
- name: google
  issuer: https://accounts.google.com
  audiences: [32555940559.apps.googleusercontent.com]
  principalClaim: email
  claimRules:
  - name: basicblock
    claims: {hd: basicblock.io, email_verified: true}
  - name: service-accounts
    claims: {email_verified: true}
    principalSuffix: "@basicblock-internal.iam.gserviceaccount.com"
`

func loadConfig(t *testing.T, content string) *AuthenticationConfig {
	t.Helper()
	path := filepath.Join(t.TempDir(), "authentication.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadAuthenticationConfig(path)
	if err != nil {
		t.Fatalf("LoadAuthenticationConfig() error = %v", err)
	}
	return cfg
}

func TestPrincipalClaimRules(t *testing.T) {
	cfg := loadConfig(t, googleProvider)
	kubernetes, google := cfg.JWTProviders[0], cfg.JWTProviders[1]

	tests := []struct {
		name      string
		provider  JWTProviderConfig
		claims    map[string]any
		wantID    string
		wantRules []string
		wantErr   bool
	}{
		{
			name:     "kubernetes service account is its subject",
			provider: kubernetes,
			claims:   map[string]any{"sub": "system:serviceaccount:eve:eve-runtime"},
			wantID:   "system:serviceaccount:eve:eve-runtime",
		},
		{
			name:      "domain user",
			provider:  google,
			claims:    map[string]any{"sub": "1234", "email": "dev@basicblock.io", "email_verified": true, "hd": "basicblock.io"},
			wantID:    "dev@basicblock.io",
			wantRules: []string{"basicblock"},
		},
		{
			name:      "project service account without hd",
			provider:  google,
			claims:    map[string]any{"sub": "5678", "email": "eve-runtime@basicblock-internal.iam.gserviceaccount.com", "email_verified": true},
			wantID:    "eve-runtime@basicblock-internal.iam.gserviceaccount.com",
			wantRules: []string{"service-accounts"},
		},
		{
			name:     "service account of another project",
			provider: google,
			claims:   map[string]any{"sub": "9012", "email": "eve-runtime@other-project.iam.gserviceaccount.com", "email_verified": true},
			wantErr:  true,
		},
		{
			name:     "user outside the domain",
			provider: google,
			claims:   map[string]any{"sub": "3456", "email": "someone@gmail.com", "email_verified": true},
			wantErr:  true,
		},
		{
			name:     "user of another hosted domain",
			provider: google,
			claims:   map[string]any{"sub": "3456", "email": "someone@example.com", "email_verified": true, "hd": "example.com"},
			wantErr:  true,
		},
		{
			name:     "unverified email",
			provider: google,
			claims:   map[string]any{"sub": "1234", "email": "dev@basicblock.io", "email_verified": false, "hd": "basicblock.io"},
			wantErr:  true,
		},
		{
			name:     "string true matches a boolean rule",
			provider: google,
			claims:   map[string]any{"sub": "1234", "email": "dev@basicblock.io", "email_verified": "true", "hd": "basicblock.io"},
			wantID:   "dev@basicblock.io", wantRules: []string{"basicblock"},
		},
		{
			name:     "missing principal claim",
			provider: google,
			claims:   map[string]any{"sub": "1234", "email_verified": true, "hd": "basicblock.io"},
			wantErr:  true,
		},
		{
			name:     "non-string principal claim",
			provider: google,
			claims:   map[string]any{"sub": "1234", "email": 42, "email_verified": true, "hd": "basicblock.io"},
			wantErr:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, rules, err := tt.provider.Principal(tt.claims)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Principal() = %q, %v, want error", id, rules)
				}
				return
			}
			if err != nil {
				t.Fatalf("Principal() error = %v", err)
			}
			if id != tt.wantID || !slices.Equal(rules, tt.wantRules) {
				t.Fatalf("Principal() = %q, %v, want %q, %v", id, rules, tt.wantID, tt.wantRules)
			}
		})
	}
}

func TestValidateClaimRules(t *testing.T) {
	cfg := loadConfig(t, googleProvider)
	tests := []struct {
		name   string
		mutate func(*JWTProviderConfig)
	}{
		{name: "empty rule", mutate: func(p *JWTProviderConfig) { p.ClaimRules = append(p.ClaimRules, ClaimRule{Name: "empty"}) }},
		{name: "duplicate rule name", mutate: func(p *JWTProviderConfig) { p.ClaimRules[1].Name = p.ClaimRules[0].Name }},
		{name: "rule name with a slash", mutate: func(p *JWTProviderConfig) { p.ClaimRules[0].Name = "a/b" }},
		{name: "reserved provider name", mutate: func(p *JWTProviderConfig) { p.Name = "authenticated" }},
		{name: "provider name with a colon", mutate: func(p *JWTProviderConfig) { p.Name = "google:users" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bad := loadConfig(t, googleProvider)
			tt.mutate(&bad.JWTProviders[1])
			if err := ValidateAuthenticationConfig(bad); err == nil {
				t.Fatal("ValidateAuthenticationConfig() succeeded, want error")
			}
		})
	}
	if err := ValidateAuthenticationConfig(cfg); err != nil {
		t.Fatalf("ValidateAuthenticationConfig() error = %v", err)
	}
}

func TestClaimValueRejectsObjects(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authentication.yaml")
	if err := os.WriteFile(path, []byte(strings.Replace(googleProvider, "hd: basicblock.io", "hd: {nested: true}", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAuthenticationConfig(path); err == nil {
		t.Fatal("LoadAuthenticationConfig() succeeded with an object claim value")
	}
}
