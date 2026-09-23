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
	"strings"
	"unicode"

	"github.com/agent-substrate/substrate/internal/principal"
)

// GlobalObject is the singleton global scope.
const GlobalObject = "global:root"

// tuple is a relationship tuple in OpenFGA's string form.
type tuple struct {
	User     string
	Relation string
	Object   string
}

// Object is an OpenFGA object together with the structural tuples that place
// it: an actor or template in its atespace, an atespace under global:root.
// They are derived from the resource name and sent with each check rather
// than stored, so they cannot drift from the resources.
type Object struct {
	ID         string
	structural []tuple
}

// Global returns the global scope.
func Global() Object { return Object{ID: GlobalObject} }

// AtespaceObject returns an atespace.
func AtespaceObject(name string) Object {
	id := "atespace:" + name
	return Object{ID: id, structural: []tuple{{User: GlobalObject, Relation: "parent_global", Object: id}}}
}

// ActorObject returns an actor in its atespace.
func ActorObject(atespace, name string) Object {
	return child("actor", atespace, name)
}

// ActorTemplateObject returns an actor template in its atespace.
func ActorTemplateObject(atespace, name string) Object {
	return child("actor_template", atespace, name)
}

func child(kind, atespace, name string) Object {
	parent := AtespaceObject(atespace)
	id := kind + ":" + atespace + "/" + name
	return Object{ID: id, structural: append([]tuple{{User: parent.ID, Relation: "parent_atespace", Object: id}}, parent.structural...)}
}

// Check is one relation a caller must have on an object.
type Check struct {
	Object   Object
	Relation string
}

func (c Check) String() string { return c.Relation + " on " + c.Object.ID }

// PrincipalUser returns the OpenFGA user for an authenticated principal.
func PrincipalUser(p principal.PrincipalInfo) (string, error) {
	if p.Provider == "" || p.ID == "" {
		return "", fmt.Errorf("principal has no provider or ID")
	}
	return "user:" + escape(p.Provider) + "/" + escape(p.ID), nil
}

// memberships returns the contextual tuples placing p in its groups.
func memberships(user string, p principal.PrincipalInfo) []tuple {
	out := make([]tuple, 0, len(p.Groups))
	for _, g := range p.Groups {
		out = append(out, tuple{User: user, Relation: "member", Object: "group:" + escape(g)})
	}
	return out
}

// referenceUser returns the OpenFGA user a validated config binding names:
// "group:<name>" or "<provider>:<id>".
func referenceUser(ref string) string {
	if name, ok := strings.CutPrefix(ref, "group:"); ok {
		return "group:" + escape(name) + "#member"
	}
	provider, id, _ := strings.Cut(ref, ":")
	return "user:" + escape(provider) + "/" + escape(id)
}

// escape percent-encodes the characters OpenFGA IDs cannot hold (':', '#',
// whitespace and control characters) and '%' itself, so every principal ID
// (for example "system:serviceaccount:ns:name" or a SPIFFE URI) has one
// reversible OpenFGA form.
func escape(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r == '%' || r == ':' || r == '#' || unicode.IsSpace(r) || unicode.IsControl(r) {
			for _, c := range []byte(string(r)) {
				fmt.Fprintf(&b, "%%%02X", c)
			}
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
