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
	"fmt"
	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

// legacySandboxClass reads the enum stored before SandboxConfig.sandbox_class
// became a string. Only ActorTemplate field 6 contains that config. All other
// fields keep their current decoder and normal unknown-field handling.
func legacySandboxClass(data []byte) (string, error) {
	for len(data) > 0 {
		number, kind, n := protowire.ConsumeTag(data)
		if n < 0 {
			return "", protowire.ParseError(n)
		}
		data = data[n:]
		if number == 6 && kind == protowire.BytesType {
			config, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return "", protowire.ParseError(n)
			}
			for len(config) > 0 {
				field, wire, n := protowire.ConsumeTag(config)
				if n < 0 {
					return "", protowire.ParseError(n)
				}
				config = config[n:]
				if field == 1 && wire == protowire.VarintType {
					value, n := protowire.ConsumeVarint(config)
					if n < 0 {
						return "", protowire.ParseError(n)
					}
					switch value {
					case 1:
						return "gvisor", nil
					case 2:
						return "microvm", nil
					default:
						return "", fmt.Errorf("unsupported legacy sandbox class %d", value)
					}
				}
				n = protowire.ConsumeFieldValue(field, wire, config)
				if n < 0 {
					return "", protowire.ParseError(n)
				}
				config = config[n:]
			}
		}
		n = protowire.ConsumeFieldValue(number, kind, data)
		if n < 0 {
			return "", protowire.ParseError(n)
		}
		data = data[n:]
	}
	return "", nil
}

// marshalStoredTemplate keeps the previous enum alongside the current string
// through the rolling-upgrade and rollback window. Each decoder ignores the
// other wire type. Old writers retain the enum; unmarshalStored reads those.
func marshalStoredTemplate(template *ateapipb.ActorTemplate) ([]byte, error) {
	copy := proto.CloneOf(template)
	var legacy uint64
	switch copy.GetSandboxConfig().GetSandboxClass() {
	case "gvisor":
		legacy = 1
	case "microvm":
		legacy = 2
	}
	if legacy != 0 {
		config := copy.SandboxConfig.ProtoReflect()
		config.SetUnknown(protowire.AppendVarint(protowire.AppendTag(config.GetUnknown(), 1, protowire.VarintType), legacy))
	}
	return proto.Marshal(copy)
}
