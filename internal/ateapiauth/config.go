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
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/agent-substrate/substrate/internal/principal"
	"sigs.k8s.io/yaml"
)

// AuthenticationConfig configures JWT authentication for ateapi.
type AuthenticationConfig struct {
	ActorIdentityJWTProvider string              `json:"actorIdentityJWTProvider"`
	JWTProviders             []JWTProviderConfig `json:"jwtProviders"`
}

// JWTProviderConfig configures one trusted OIDC issuer.
type JWTProviderConfig struct {
	Name                     string   `json:"name"`
	Issuer                   string   `json:"issuer"`
	Audiences                []string `json:"audiences"`
	CertificateAuthorityFile string   `json:"certificateAuthorityFile,omitempty"`
	DiscoveryTokenFile       string   `json:"discoveryTokenFile,omitempty"`

	// PrincipalClaim names the string claim that identifies the principal:
	// "sub" when empty, or for example "email" for Google identity tokens,
	// whose subject is an opaque number.
	PrincipalClaim string `json:"principalClaim,omitempty"`

	// ClaimRules, when set, admit a token only if it satisfies at least one
	// rule. They let one issuer serve differently constrained principals, such
	// as a domain's users and one project's service accounts.
	ClaimRules []ClaimRule `json:"claimRules,omitempty"`
}

// ClaimRule is one set of conditions a token can satisfy. A token satisfies a
// rule when every listed claim has exactly the listed value and the principal
// ends with PrincipalSuffix.
type ClaimRule struct {
	// Name, when set, puts every principal the rule admits in the group
	// "<provider>/<name>", which authorization bindings can name.
	Name string `json:"name,omitempty"`

	// Claims maps claim names to the value each must have.
	Claims map[string]ClaimValue `json:"claims,omitempty"`

	// PrincipalSuffix, when set, requires the principal to end with it, for
	// example "@my-project.iam.gserviceaccount.com".
	PrincipalSuffix string `json:"principalSuffix,omitempty"`
}

// ClaimValue is the exact value a claim must have. A boolean or number is
// written as its JSON text: "true" matches both the boolean true and the
// string "true".
type ClaimValue string

// UnmarshalJSON accepts a string, boolean or number.
func (v *ClaimValue) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*v = ClaimValue(s)
		return nil
	}
	var raw any
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	switch raw.(type) {
	case bool, float64:
		*v = ClaimValue(strings.TrimSpace(string(b)))
		return nil
	}
	return fmt.Errorf("claim value must be a string, boolean or number, got %s", b)
}

// Principal returns the principal a verified token's claims identify and the
// names of the claim rules it satisfies. It fails when the principal claim is
// missing or empty, or when claim rules are configured and none admits the
// token.
func (p JWTProviderConfig) Principal(claims map[string]any) (string, []string, error) {
	claim := p.PrincipalClaim
	if claim == "" {
		claim = "sub"
	}
	id, ok := claims[claim].(string)
	if !ok || id == "" {
		return "", nil, fmt.Errorf("token has no %q claim", claim)
	}
	if len(p.ClaimRules) == 0 {
		return id, nil, nil
	}
	var satisfied []string
	admitted := false
	for _, rule := range p.ClaimRules {
		if !rule.admits(id, claims) {
			continue
		}
		admitted = true
		if rule.Name != "" {
			satisfied = append(satisfied, rule.Name)
		}
	}
	if !admitted {
		return "", nil, fmt.Errorf("token satisfies none of the claim rules of JWT provider %q", p.Name)
	}
	return id, satisfied, nil
}

func (r ClaimRule) admits(id string, claims map[string]any) bool {
	if !strings.HasSuffix(id, r.PrincipalSuffix) {
		return false
	}
	for name, want := range r.Claims {
		got, ok := claimText(claims[name])
		if !ok || got != string(want) {
			return false
		}
	}
	return true
}

// claimText renders a scalar claim as the text a ClaimValue is compared with.
func claimText(v any) (string, bool) {
	switch v := v.(type) {
	case string:
		return v, true
	case bool:
		return strconv.FormatBool(v), true
	case json.Number:
		return v.String(), true
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64), true
	}
	return "", false
}

// LoadAuthenticationConfig strictly parses and validates a YAML or JSON file.
func LoadAuthenticationConfig(path string) (*AuthenticationConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read authentication config: %w", err)
	}
	var cfg AuthenticationConfig
	if err := yaml.UnmarshalStrict(b, &cfg); err != nil {
		return nil, fmt.Errorf("parse authentication config: %w", err)
	}
	if err := ValidateAuthenticationConfig(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// ValidateAuthenticationConfig validates fields that do not require I/O.
func ValidateAuthenticationConfig(cfg *AuthenticationConfig) error {
	if cfg == nil {
		return fmt.Errorf("authentication config is required")
	}
	if len(cfg.JWTProviders) == 0 {
		return fmt.Errorf("at least one JWT provider is required")
	}

	names := make(map[string]bool, len(cfg.JWTProviders))
	issuers := make(map[string]bool, len(cfg.JWTProviders))
	for i, p := range cfg.JWTProviders {
		field := fmt.Sprintf("jwtProviders[%d]", i)
		if p.Name == "" {
			return fmt.Errorf("%s.name is required", field)
		}
		if names[p.Name] {
			return fmt.Errorf("duplicate JWT provider name %q", p.Name)
		}
		// Authorization names principals "<provider>:<id>" and groups
		// "<provider>/<rule>"; "mtls" and "authenticated" are reserved.
		if strings.ContainsAny(p.Name, ":/#% ") || p.Name == principal.ProviderMTLS || p.Name == principal.GroupAuthenticated {
			return fmt.Errorf("%s.name %q must not contain ':', '/', '#', '%%' or spaces, or be %q or %q", field, p.Name, principal.ProviderMTLS, principal.GroupAuthenticated)
		}
		names[p.Name] = true
		issuerURL, err := url.Parse(p.Issuer)
		if err != nil || issuerURL.Scheme != "https" || issuerURL.Host == "" || issuerURL.RawQuery != "" || issuerURL.Fragment != "" {
			return fmt.Errorf("%s.issuer must be an HTTPS URL without query or fragment", field)
		}
		if issuers[p.Issuer] {
			return fmt.Errorf("duplicate JWT provider issuer %q", p.Issuer)
		}
		issuers[p.Issuer] = true
		if len(p.Audiences) == 0 {
			return fmt.Errorf("%s.audiences must contain at least one audience", field)
		}
		for _, audience := range p.Audiences {
			if audience == "" {
				return fmt.Errorf("%s.audiences must not contain an empty audience", field)
			}
		}
		ruleNames := map[string]bool{}
		for j, rule := range p.ClaimRules {
			ruleField := fmt.Sprintf("%s.claimRules[%d]", field, j)
			if len(rule.Claims) == 0 && rule.PrincipalSuffix == "" {
				return fmt.Errorf("%s must require at least one claim or a principalSuffix", ruleField)
			}
			if rule.Name == "" {
				continue
			}
			if strings.ContainsAny(rule.Name, ":/#% ") {
				return fmt.Errorf("%s.name %q must not contain ':', '/', '#', '%%' or spaces", ruleField, rule.Name)
			}
			if ruleNames[rule.Name] {
				return fmt.Errorf("%s.name %q is not unique", ruleField, rule.Name)
			}
			ruleNames[rule.Name] = true
		}
	}
	if cfg.ActorIdentityJWTProvider == "" {
		return fmt.Errorf("actorIdentityJWTProvider is required")
	}
	if !names[cfg.ActorIdentityJWTProvider] {
		return fmt.Errorf("actorIdentityJWTProvider %q does not name a JWT provider", cfg.ActorIdentityJWTProvider)
	}
	return nil
}
