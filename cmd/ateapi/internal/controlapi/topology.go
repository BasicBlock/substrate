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
	"fmt"

	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	corev1listers "k8s.io/client-go/listers/core/v1"
	storagev1listers "k8s.io/client-go/listers/storage/v1"
)

// nodeTopology resolves where a node sits for volume placement: its labels,
// and the topology segments a CSI driver's node plugin registered for it. A
// zonal disk (GCE PD) is created in its first worker's zone and attaches only
// to nodes there, so the actor is scheduled only onto such nodes afterwards.
type nodeTopology struct {
	csiNodes storagev1listers.CSINodeLister
	nodes    corev1listers.NodeLister
}

// labels returns node's labels, and false for a node the lister does not know.
func (t *nodeTopology) labels(node string) (map[string]string, bool) {
	n, err := t.nodes.Get(node)
	if err != nil {
		return nil, false
	}
	return n.GetLabels(), true
}

// driverSegments returns the topology driver's node plugin registered for
// node: the node's labels for the topology keys in its CSINode entry, which is
// where kubelet publishes the plugin's segments. Nil when the driver registers
// no topology keys, or none on this node: a volume every node reaches (NFS),
// or a driver with no node plugin here, is created without a requirement.
func (t *nodeTopology) driverSegments(driver, node string) (map[string]string, error) {
	csiNode, err := t.csiNodes.Get(node)
	if err != nil {
		return nil, nil
	}
	var keys []string
	for _, registered := range csiNode.Spec.Drivers {
		if registered.Name == driver {
			keys = registered.TopologyKeys
		}
	}
	if len(keys) == 0 {
		return nil, nil
	}
	n, err := t.nodes.Get(node)
	if err != nil {
		return nil, fmt.Errorf("while reading node %q for CSI driver %q's topology: %w", node, driver, err)
	}
	segments := make(map[string]string, len(keys))
	for _, key := range keys {
		value, ok := n.GetLabels()[key]
		if !ok {
			return nil, fmt.Errorf("node %q has no label %q, a topology key of CSI driver %q", node, key, driver)
		}
		segments[key] = value
	}
	return segments, nil
}

// volumeTopologies returns, for each of volumes accessible only from some
// topologies, the segments of those topologies: the placement constraint the
// scheduler matches node labels against.
func volumeTopologies(volumes []*ateapipb.ExternalVolume) [][]map[string]string {
	var out [][]map[string]string
	for _, vol := range volumes {
		var alternatives []map[string]string
		for _, topology := range vol.GetAccessibleTopology() {
			if len(topology.GetSegments()) > 0 {
				alternatives = append(alternatives, topology.GetSegments())
			}
		}
		if len(alternatives) > 0 {
			out = append(out, alternatives)
		}
	}
	return out
}

// topologiesProto converts the topology a volume plugin reported into the
// actor's record of it.
func topologiesProto(topology []map[string]string) []*ateapipb.Topology {
	var out []*ateapipb.Topology
	for _, segments := range topology {
		if len(segments) > 0 {
			out = append(out, &ateapipb.Topology{Segments: segments})
		}
	}
	return out
}
