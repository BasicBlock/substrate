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

// Package atepg is an ate storage backend built on PostgreSQL.
//
// Each table holds native SQL columns for fields SQL must operate on
// (primary keys, versions, pagination, update/delete preconditions) plus
// the complete protobuf message, binary-encoded, in a BYTEA column.
// TLS is configured entirely through the connection string passed
// to Connect (standard libpq sslmode/sslrootcert/sslcert/sslkey parameters)
package atepg

import (
	"github.com/agent-substrate/substrate/cmd/ateapi/internal/store"
	"github.com/agent-substrate/substrate/internal/resources"
	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
	"testing"
)

func TestUnmarshalStoredLegacySandboxClass(t *testing.T) {
	for _, tc := range []struct {
		legacy uint64
		want   string
	}{{1, "gvisor"}, {2, "microvm"}} {
		config := protowire.AppendTag(nil, 1, protowire.VarintType)
		config = protowire.AppendVarint(config, tc.legacy)
		config = protowire.AppendString(protowire.AppendTag(config, 2, protowire.BytesType), "gvisor-default")
		data := protowire.AppendBytes(protowire.AppendTag(nil, 6, protowire.BytesType), config)
		var template ateapipb.ActorTemplate
		if err := unmarshalStored(data, &template); err != nil {
			t.Fatal(err)
		}
		if got := template.GetSandboxConfig().GetSandboxClass(); got != tc.want {
			t.Errorf("sandbox class = %q, want %q", got, tc.want)
		}
	}
}

func TestTemplateWritesRemainReadableByPreviousBinary(t *testing.T) {
	s := setupPostgresPersistence(t)
	ctx := t.Context()
	createTestAtespace(t, s, "compat")
	// The previous enum used varints, represented here by int32 on the same wire.
	schema, err := protodesc.NewFile(&descriptorpb.FileDescriptorProto{
		Name: proto.String("legacy-template.proto"), Package: proto.String("legacy"),
		MessageType: []*descriptorpb.DescriptorProto{
			{Name: proto.String("SandboxConfig"), Field: []*descriptorpb.FieldDescriptorProto{{Name: proto.String("sandbox_class"), Number: proto.Int32(1), Type: descriptorpb.FieldDescriptorProto_TYPE_INT32.Enum()}}},
			{Name: proto.String("ActorTemplate"), Field: []*descriptorpb.FieldDescriptorProto{{Name: proto.String("sandbox_config"), Number: proto.Int32(6), Type: descriptorpb.FieldDescriptorProto_TYPE_MESSAGE.Enum(), TypeName: proto.String(".legacy.SandboxConfig")}}},
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		class string
		value int64
	}{{"gvisor", 1}, {"microvm", 2}} {
		template, err := s.CreateActorTemplate(ctx, &ateapipb.ActorTemplate{
			Metadata:      &ateapipb.ResourceMetadata{Atespace: "compat", Name: tc.class},
			SandboxConfig: &ateapipb.SandboxConfig{SandboxClass: tc.class, ConfigName: tc.class + "-default"},
		})
		if err != nil {
			t.Fatal(err)
		}
		for _, operation := range []string{"create", "update"} {
			if operation == "update" {
				template, err = s.UpdateActorTemplate(ctx, resources.ActorTemplateRef{Atespace: "compat", Name: tc.class}, store.PreconditionFrom(template), func(updated *ateapipb.ActorTemplate) error {
					updated.WorkerSelector = &ateapipb.Selector{MatchLabels: map[string]string{"workload": "compat"}}
					return nil
				})
				if err != nil {
					t.Fatal(err)
				}
			}
			var data []byte
			if err := s.pool.QueryRow(ctx, "SELECT proto FROM actor_templates WHERE atespace = $1 AND name = $2", "compat", tc.class).Scan(&data); err != nil {
				t.Fatal(err)
			}
			old := dynamicpb.NewMessage(schema.Messages().ByName("ActorTemplate"))
			if err := (proto.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(data, old); err != nil {
				t.Fatal(err)
			}
			config := old.Get(old.Descriptor().Fields().ByNumber(6)).Message()
			if got := config.Get(config.Descriptor().Fields().ByNumber(1)).Int(); got != tc.value {
				t.Errorf("%s %s: previous binary reads %d, want %d", operation, tc.class, got, tc.value)
			}
			var current ateapipb.ActorTemplate
			if err := unmarshalStored(data, &current); err != nil {
				t.Fatal(err)
			}
			if current.GetSandboxConfig().GetSandboxClass() != tc.class {
				t.Errorf("current binary reads %q", current.GetSandboxConfig().GetSandboxClass())
			}
		}
	}
}
