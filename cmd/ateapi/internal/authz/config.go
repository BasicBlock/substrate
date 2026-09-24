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
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/agent-substrate/substrate/internal/principal"
	"github.com/agent-substrate/substrate/internal/resources"
	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"sigs.k8s.io/yaml"
)

// Mode selects what ate-api does with a call its role bindings do not allow.
type Mode string

const (
	// ModeAudit logs each call the bindings would deny and allows it. Rules
	// marked alwaysEnforce (the AccessPolicy RPCs) are still denied.
	ModeAudit Mode = "audit"
	// ModeEnforce denies it with PermissionDenied.
	ModeEnforce Mode = "enforce"
)

// Config is the file passed to ate-api's --authorization-config. Its role
// bindings are reconciled into OpenFGA at startup by ReconcileConfig: a
// binding removed from the file is removed from the store. An atespace's
// "creator" tuple (RecordCreator, ForgetCreators) is not part of this
// reconciliation and survives it, as do any bindings an AccessPolicy RPC
// wrote through PolicyManager -- the two mechanisms manage the same
// relations, so whichever last reconciled a given (user, relation, object)
// wins until the other reconciles it again.
//
// Bindings name a principal "<provider>:<id>" (the provider a JWT in
// --authentication-config is trusted under, or "mtls" for an mTLS client
// certificate's SPIFFE ID) or a group "group:<name>", where name is
// "authenticated", a provider, or "<provider>/<claim-rule>" (see
// AuthenticationConfig.GroupNames).
type Config struct {
	Mode   Mode           `json:"mode"`
	Global GlobalBindings `json:"global,omitempty"`
	// Atespaces binds roles in named atespaces, which need not exist yet.
	Atespaces map[string]AtespaceBindings `json:"atespaces,omitempty"`
}

// GlobalBindings are the global:root roles.
type GlobalBindings struct {
	// Owners control every atespace and the workers.
	Owners []string `json:"owners,omitempty"`
	// Viewers read every atespace.
	Viewers []string `json:"viewers,omitempty"`
	// AtespaceCreators may create atespaces, each becoming its creator's.
	AtespaceCreators []string `json:"atespaceCreators,omitempty"`
	// Connectors reach can_connect on every actor in every atespace (for
	// example an in-cluster proxy reaching actors across atespaces created on
	// demand) and nothing else: no get/list/create/update/suspend/resume/
	// delete, no templates, tags, egress policies or workers, and no
	// credential minting.
	Connectors []string `json:"connectors,omitempty"`
}

// AtespaceBindings are one atespace's roles.
type AtespaceBindings struct {
	Owners  []string `json:"owners,omitempty"`
	Editors []string `json:"editors,omitempty"`
	Viewers []string `json:"viewers,omitempty"`
}

// LoadConfig strictly parses an authorization config file. Call Validate
// against the authentication providers before using it.
func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read authorization config: %w", err)
	}
	var cfg Config
	if err := yaml.UnmarshalStrict(b, &cfg); err != nil {
		return nil, fmt.Errorf("parse authorization config: %w", err)
	}
	return &cfg, nil
}

// Validate checks the mode, the atespace names, and that every binding is
// well-formed and names a known provider or group. providers and ruleGroups
// are an AuthenticationConfig's GroupNames.
func (c *Config) Validate(providers, ruleGroups []string) error {
	if c.Mode != ModeAudit && c.Mode != ModeEnforce {
		return fmt.Errorf("mode must be %q or %q, got %q", ModeAudit, ModeEnforce, c.Mode)
	}
	knownProvider := func(name string) bool {
		return name == principal.ProviderMTLS || slices.Contains(providers, name)
	}
	knownGroup := func(name string) bool {
		return name == principal.GroupAuthenticated || knownProvider(name) || slices.Contains(ruleGroups, name)
	}
	checkRef := func(field, ref string) error {
		if name, ok := strings.CutPrefix(ref, "group:"); ok {
			if _, err := FormatMember(ref); err != nil {
				return fmt.Errorf("%s: %w", field, err)
			}
			if !knownGroup(name) {
				return fmt.Errorf("%s: binding %q names an unknown group", field, ref)
			}
			return nil
		}
		provider, id, ok := strings.Cut(ref, ":")
		if !ok || id == "" {
			return fmt.Errorf("%s: binding %q must be \"<provider>:<id>\" or \"group:<name>\"", field, ref)
		}
		if !knownProvider(provider) {
			return fmt.Errorf("%s: binding %q names an unknown provider %q", field, ref, provider)
		}
		if _, err := FormatMember("user:" + id); err != nil {
			return fmt.Errorf("%s: %w", field, err)
		}
		return nil
	}
	check := func(field string, refs []string) error {
		for _, ref := range refs {
			if err := checkRef(field, ref); err != nil {
				return err
			}
		}
		return nil
	}
	if err := check("global.owners", c.Global.Owners); err != nil {
		return err
	}
	if err := check("global.viewers", c.Global.Viewers); err != nil {
		return err
	}
	if err := check("global.atespaceCreators", c.Global.AtespaceCreators); err != nil {
		return err
	}
	if err := check("global.connectors", c.Global.Connectors); err != nil {
		return err
	}
	for name, b := range c.Atespaces {
		if !resources.IsValidResourceName(name) {
			return fmt.Errorf("atespaces: %q is not a valid atespace name", name)
		}
		for role, refs := range map[string][]string{"owners": b.Owners, "editors": b.Editors, "viewers": b.Viewers} {
			if err := check(fmt.Sprintf("atespaces.%s.%s", name, role), refs); err != nil {
				return err
			}
		}
	}
	return nil
}

// configMember returns the OpenFGA user a validated binding names. A group
// reference formats exactly as FormatMember already does. A principal
// reference "<provider>:<id>" drops the provider: Check() looks a caller up
// by formatUser(p.ID) alone, with no provider segment (see formatUser), so a
// tuple naming more would never match a live request. BasicBlock's principal
// ID spaces (a Google email, a "system:serviceaccount:<ns>:<sa>" string, a
// SPIFFE URI) do not collide with each other in practice; the provider
// segment in a binding is validated by Validate but does not reach the
// stored tuple.
func configMember(ref string) (string, error) {
	if strings.HasPrefix(ref, "group:") {
		return FormatMember(ref)
	}
	_, id, ok := strings.Cut(ref, ":")
	if !ok || id == "" {
		return "", fmt.Errorf("binding %q must be \"<provider>:<id>\" or \"group:<name>\"", ref)
	}
	return FormatMember("user:" + id)
}

// tuples returns the role-binding tuples cfg asks for. A ref Validate would
// reject is skipped rather than failing here, so a Config that was not
// validated still reconciles its well-formed bindings.
func (c *Config) tuples() []*openfgav1.TupleKey {
	var out []*openfgav1.TupleKey
	add := func(object, relation string, refs []string) {
		for _, ref := range refs {
			user, err := configMember(ref)
			if err != nil {
				continue
			}
			out = append(out, &openfgav1.TupleKey{User: user, Relation: relation, Object: object})
		}
	}
	add(GlobalRootObject, RoleOwner, c.Global.Owners)
	add(GlobalRootObject, RoleViewer, c.Global.Viewers)
	add(GlobalRootObject, "atespace_creator", c.Global.AtespaceCreators)
	add(GlobalRootObject, "connector", c.Global.Connectors)
	for name, b := range c.Atespaces {
		object := AtespaceObject(name)
		add(object, RoleOwner, b.Owners)
		add(object, RoleEditor, b.Editors)
		add(object, RoleViewer, b.Viewers)
	}
	return out
}

// bindingKey is a comparable (user, relation, object) tuple, used to diff the
// stored bindings against a Config's desired set.
type bindingKey struct{ user, relation, object string }

// managed reports whether a stored tuple is a role binding ReconcileConfig
// manages, as opposed to an atespace's "creator" tuple or an unrelated
// relation.
func managed(k bindingKey) bool {
	if k.object == GlobalRootObject {
		return k.relation == RoleOwner || k.relation == RoleViewer || k.relation == "atespace_creator" || k.relation == "connector"
	}
	if strings.HasPrefix(k.object, "atespace:") {
		return k.relation == RoleOwner || k.relation == RoleEditor || k.relation == RoleViewer
	}
	return false
}
