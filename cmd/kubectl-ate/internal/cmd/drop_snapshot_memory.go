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
	"github.com/agent-substrate/substrate/internal/resources"
	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	"github.com/spf13/cobra"
)

var dropSnapshotMemoryAtespaceFlag string

var dropSnapshotMemoryCmd = &cobra.Command{
	Use:   "snapshot-memory <actor-name>",
	Short: "Drop the process memory from a suspended actor's stored snapshot",
	Long: `Downgrade a SUSPENDED actor's stored MEMORY snapshot to ROOTFS in place: the
actor's next resume cold-boots its containers from the snapshot's root
filesystem image and durable data instead of restoring guest memory. The memory
objects are emptied in snapshot storage; the root filesystem image and durable
data are kept.

Idempotent; refuses an actor that is not SUSPENDED or whose snapshot holds no
root filesystem to keep (it predates root filesystem snapshots, or capturing
one failed). Meant for a long-suspended actor, such as a development workspace
idle for days, whose memory image may no longer restore on a changed worker.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		apiClient, err := ateclient.NewClient(ctx, kubeconfig, k8sContext, endpoint, tokenFile, traceEnabled)
		if err != nil {
			return fmt.Errorf("failed to connect to ate-api-server: %w", err)
		}
		defer apiClient.Close()

		actorRef := resources.ActorRef{Atespace: dropSnapshotMemoryAtespaceFlag, Name: args[0]}
		resp, err := apiClient.DropSnapshotMemory(ctx, &ateapipb.DropSnapshotMemoryRequest{
			Actor: actorRef.ToObjectRef(),
		})
		if err != nil {
			return fmt.Errorf("failed to drop snapshot memory: %w", err)
		}

		return printer.PrintActorTo(cmd.OutOrStdout(), resp.GetActor(), outputFmt)
	},
}

func init() {
	dropSnapshotMemoryCmd.Flags().StringVarP(&dropSnapshotMemoryAtespaceFlag, "atespace", "a", "", "Atespace the actor lives in")
	_ = dropSnapshotMemoryCmd.MarkFlagRequired("atespace")
	dropCmd.AddCommand(dropSnapshotMemoryCmd)
}
