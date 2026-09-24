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
	"sigs.k8s.io/yaml"
)

// Mode selects what ate-api does with a call the bindings do not allow.
type Mode string

const (
	// ModeAudit logs each call the bindings would deny and allows it.
	ModeAudit Mode = "audit"
	// ModeEnforce denies it with PermissionDenied.
	ModeEnforce Mode = "enforce"
)

// Config is the file passed to ate-api's --authorization-config. Its role
// bindings are reconciled into OpenFGA at startup: a binding removed from the
// file is removed from the store. Atespace creators are recorded separately
// and survive reconciliation.
//
// Bindings name a principal as "<provider>:<id>" (see
// docs/authentication.md#principals), or a group as "group:<name>", where the
// name is "authenticated", a provider, or "<provider>/<claim rule>".
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

// LoadConfig strictly parses an authorization config file. Validate it
// against the authentication providers before use.
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

// Validate checks the mode, the atespace names and that every binding names
// a known provider or group. providers are the JWT provider names, groups the
// "<provider>/<rule>" names of their named claim rules.
func (c *Config) Validate(providers, ruleGroups []string) error {
	if c.Mode != ModeAudit && c.Mode != ModeEnforce {
		return fmt.Errorf("mode must be %q or %q, got %q", ModeAudit, ModeEnforce, c.Mode)
	}
	known := func(ref string) error {
		if name, ok := strings.CutPrefix(ref, "group:"); ok {
			if name == principal.GroupAuthenticated || name == principal.ProviderMTLS ||
				slices.Contains(providers, name) || slices.Contains(ruleGroups, name) {
				return nil
			}
			return fmt.Errorf("binding %q names an unknown group", ref)
		}
		provider, id, ok := strings.Cut(ref, ":")
		if !ok || id == "" {
			return fmt.Errorf("binding %q must be <provider>:<id> or group:<name>", ref)
		}
		if provider != principal.ProviderMTLS && !slices.Contains(providers, provider) {
			return fmt.Errorf("binding %q names an unknown provider %q", ref, provider)
		}
		return nil
	}
	check := func(field string, refs []string) error {
		for _, ref := range refs {
			if err := known(ref); err != nil {
				return fmt.Errorf("%s: %w", field, err)
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

// tuples returns the role binding tuples the config asks for.
func (c *Config) tuples() []tuple {
	var out []tuple
	add := func(object, relation string, refs []string) {
		for _, ref := range refs {
			out = append(out, tuple{User: referenceUser(ref), Relation: relation, Object: object})
		}
	}
	add(GlobalObject, "owner", c.Global.Owners)
	add(GlobalObject, "viewer", c.Global.Viewers)
	add(GlobalObject, "atespace_creator", c.Global.AtespaceCreators)
	add(GlobalObject, "connector", c.Global.Connectors)
	for name, b := range c.Atespaces {
		object := AtespaceObject(name).ID
		add(object, "owner", b.Owners)
		add(object, "editor", b.Editors)
		add(object, "viewer", b.Viewers)
	}
	return out
}

// managed reports whether a stored tuple is a role binding the config owns,
// as opposed to a creator record or a structural relation.
func managed(t tuple) bool {
	if t.Object == GlobalObject {
		return t.Relation == "owner" || t.Relation == "viewer" || t.Relation == "atespace_creator" || t.Relation == "connector"
	}
	if strings.HasPrefix(t.Object, "atespace:") {
		return t.Relation == "owner" || t.Relation == "editor" || t.Relation == "viewer"
	}
	return false
}
