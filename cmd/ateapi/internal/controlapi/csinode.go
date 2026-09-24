// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package controlapi

import (
	"context"

	"github.com/agent-substrate/substrate/internal/volume"
	storagev1listers "k8s.io/client-go/listers/storage/v1"
)

// csiNodePlugin gives a CSI controller the node ID its driver registered for a
// node, rather than the Kubernetes node name. Controllers such as GCE PD
// address a node by their own ID (projects/<p>/zones/<z>/instances/<name>),
// which the driver's node plugin records in the node's CSINode object. A driver
// that registers none, such as NFS, keeps the node name.
type csiNodePlugin struct {
	volume.VolumePluginControlPlane
	driver string
	nodes  storagev1listers.CSINodeLister
}

func (p csiNodePlugin) AttachVolume(ctx context.Context, volumeID string, node string) error {
	return p.VolumePluginControlPlane.AttachVolume(ctx, volumeID, p.nodeID(node))
}

func (p csiNodePlugin) DetachVolume(ctx context.Context, volumeID string, node string) error {
	return p.VolumePluginControlPlane.DetachVolume(ctx, volumeID, p.nodeID(node))
}

func (p csiNodePlugin) nodeID(node string) string {
	csiNode, err := p.nodes.Get(node)
	if err != nil {
		return node
	}
	for _, driver := range csiNode.Spec.Drivers {
		if driver.Name == p.driver && driver.NodeID != "" {
			return driver.NodeID
		}
	}
	return node
}

// withCSINodeIDs wraps plugin so its attach and detach use CSI node IDs, when
// the service has CSINode access.
func withCSINodeIDs(plugin volume.VolumePluginControlPlane, driver string, nodes storagev1listers.CSINodeLister) volume.VolumePluginControlPlane {
	if nodes == nil {
		return plugin
	}
	return csiNodePlugin{VolumePluginControlPlane: plugin, driver: driver, nodes: nodes}
}
