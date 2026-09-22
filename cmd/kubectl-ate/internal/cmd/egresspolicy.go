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

package cmd

import (
	"fmt"

	"github.com/agent-substrate/substrate/cmd/kubectl-ate/internal/printer"
	"github.com/agent-substrate/substrate/internal/ateclient"
	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"
	"sigs.k8s.io/yaml"
)

// An actor has at most one egress policy, always named "default".
const egressPolicyName = "default"

var (
	egressPolicyAtespaceFlag string
	egressPolicyFilenameFlag string
)

var getEgressPolicyCmd = &cobra.Command{
	Use:   "egress-policy <actor-name>",
	Short: "Get an actor's egress policy",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		c, err := ateclient.NewClient(ctx, kubeconfig, k8sContext, endpoint, tokenFile, traceEnabled)
		if err != nil {
			return fmt.Errorf("failed to connect to ate-api-server: %w", err)
		}
		defer c.Close()

		policy, err := c.GetActorEgressPolicy(ctx, &ateapipb.GetActorEgressPolicyRequest{
			Actor: &ateapipb.ObjectRef{Atespace: egressPolicyAtespaceFlag, Name: args[0]},
		})
		if err != nil {
			return fmt.Errorf("failed to get egress policy: %w", err)
		}
		return printer.PrintEgressPolicyTo(cmd.OutOrStdout(), args[0], policy, outputFmt)
	},
}

var createEgressPolicyCmd = &cobra.Command{
	Use:   "egress-policy <actor-name> -f <manifest>",
	Short: "Create an actor's egress policy from a manifest",
	Long: `Create an actor's egress policy from a manifest file.

The manifest is a single YAML (or JSON) document holding one ateapipb.EgressPolicy
message in its protojson form. Its metadata may be omitted: the policy is always
named "default" in the actor's atespace. An actor without a policy has no egress.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		data, err := readFileOrStdin(cmd.InOrStdin(), egressPolicyFilenameFlag)
		if err != nil {
			return err
		}
		policy, err := egressPolicyFromManifest(data, egressPolicyAtespaceFlag)
		if err != nil {
			return fmt.Errorf("failed to parse egress policy manifest %q: %w", egressPolicyFilenameFlag, err)
		}

		ctx := cmd.Context()
		c, err := ateclient.NewClient(ctx, kubeconfig, k8sContext, endpoint, tokenFile, traceEnabled)
		if err != nil {
			return fmt.Errorf("failed to connect to ate-api-server: %w", err)
		}
		defer c.Close()

		created, err := c.CreateActorEgressPolicy(ctx, &ateapipb.CreateActorEgressPolicyRequest{
			Actor:        &ateapipb.ObjectRef{Atespace: egressPolicyAtespaceFlag, Name: args[0]},
			EgressPolicy: policy,
		})
		if err != nil {
			return fmt.Errorf("failed to create egress policy: %w", err)
		}
		return printer.PrintEgressPolicyTo(cmd.OutOrStdout(), args[0], created, outputFmt)
	},
}

var deleteEgressPolicyCmd = &cobra.Command{
	Use:   "egress-policy <actor-name>",
	Short: "Delete an actor's egress policy, removing all its egress",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		c, err := ateclient.NewClient(ctx, kubeconfig, k8sContext, endpoint, tokenFile, traceEnabled)
		if err != nil {
			return fmt.Errorf("failed to connect to ate-api-server: %w", err)
		}
		defer c.Close()

		if _, err := c.DeleteActorEgressPolicy(ctx, &ateapipb.DeleteActorEgressPolicyRequest{
			Actor: &ateapipb.ObjectRef{Atespace: egressPolicyAtespaceFlag, Name: args[0]},
		}); err != nil {
			return fmt.Errorf("failed to delete egress policy: %w", err)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "egress policy of actor %q deleted\n", args[0])
		return nil
	},
}

// egressPolicyFromManifest parses a single protojson-shaped YAML or JSON
// document into an EgressPolicy, strictly, and fills in its fixed metadata.
func egressPolicyFromManifest(data []byte, atespace string) (*ateapipb.EgressPolicy, error) {
	jsonData, err := yaml.YAMLToJSON(data)
	if err != nil {
		return nil, fmt.Errorf("invalid YAML: %w", err)
	}
	if string(jsonData) == "null" {
		return nil, fmt.Errorf("manifest is empty")
	}
	policy := &ateapipb.EgressPolicy{}
	if err := protojson.Unmarshal(jsonData, policy); err != nil {
		return nil, err
	}
	if policy.Metadata == nil {
		policy.Metadata = &ateapipb.ResourceMetadata{}
	}
	if policy.Metadata.Atespace == "" {
		policy.Metadata.Atespace = atespace
	}
	if policy.Metadata.Name == "" {
		policy.Metadata.Name = egressPolicyName
	}
	return policy, nil
}

func init() {
	for _, c := range []*cobra.Command{getEgressPolicyCmd, createEgressPolicyCmd, deleteEgressPolicyCmd} {
		c.Flags().StringVarP(&egressPolicyAtespaceFlag, "atespace", "a", "", "Atespace the actor lives in")
		_ = c.MarkFlagRequired("atespace")
	}
	createEgressPolicyCmd.Flags().StringVarP(&egressPolicyFilenameFlag, "filename", "f", "", "Manifest file holding a single protojson-shaped EgressPolicy document; use - for stdin (required)")
	_ = createEgressPolicyCmd.MarkFlagRequired("filename")
	getCmd.AddCommand(getEgressPolicyCmd)
	createCmd.AddCommand(createEgressPolicyCmd)
	deleteCmd.AddCommand(deleteEgressPolicyCmd)
}
