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
	"testing"

	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	"github.com/google/go-cmp/cmp"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
)

const pdDriver = "pd.csi.storage.gke.io"

func nodeLister(t *testing.T, nodes ...*corev1.Node) corev1listers.NodeLister {
	t.Helper()
	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	for _, node := range nodes {
		if err := indexer.Add(node); err != nil {
			t.Fatal(err)
		}
	}
	return corev1listers.NewNodeLister(indexer)
}

func testNodeTopology(t *testing.T) *nodeTopology {
	t.Helper()
	return &nodeTopology{
		csiNodes: csiNodes(t,
			&storagev1.CSINode{
				ObjectMeta: metav1.ObjectMeta{Name: "node-a"},
				Spec: storagev1.CSINodeSpec{Drivers: []storagev1.CSINodeDriver{
					{Name: "nfs.csi.k8s.io", NodeID: "node-a"},
					{Name: pdDriver, NodeID: "projects/p/zones/us-central1-a/instances/node-a", TopologyKeys: []string{"topology.gke.io/zone"}},
				}},
			},
			&storagev1.CSINode{
				ObjectMeta: metav1.ObjectMeta{Name: "node-unlabeled"},
				Spec: storagev1.CSINodeSpec{Drivers: []storagev1.CSINodeDriver{
					{Name: pdDriver, TopologyKeys: []string{"topology.gke.io/zone"}},
				}},
			}),
		nodes: nodeLister(t,
			&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-a", Labels: map[string]string{
				"topology.gke.io/zone": "us-central1-a", "kubernetes.io/hostname": "node-a",
			}}},
			&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-unlabeled"}}),
	}
}

func TestNodeTopologyDriverSegments(t *testing.T) {
	topology := testNodeTopology(t)
	for _, tc := range []struct {
		name, driver, node string
		want               map[string]string
		wantErr            bool
	}{
		{"zonal driver", pdDriver, "node-a", map[string]string{"topology.gke.io/zone": "us-central1-a"}, false},
		{"driver without topology keys", "nfs.csi.k8s.io", "node-a", nil, false},
		{"driver not on the node", "other.csi.example.com", "node-a", nil, false},
		{"node without a CSINode", pdDriver, "node-z", nil, false},
		{"node missing the key's label", pdDriver, "node-unlabeled", nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := topology.driverSegments(tc.driver, tc.node)
			if (err != nil) != tc.wantErr {
				t.Fatalf("driverSegments() error = %v, wantErr %v", err, tc.wantErr)
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("driverSegments() mismatch (-want +got):\n%s", diff)
			}
		})
	}
	if _, ok := topology.labels("node-z"); ok {
		t.Error("labels() found a node the lister does not have")
	}
}

func TestVolumeTopologies(t *testing.T) {
	zoneA := map[string]string{"topology.gke.io/zone": "us-central1-a"}
	got := volumeTopologies([]*ateapipb.ExternalVolume{
		{VolumeName: "everywhere"},
		{VolumeName: "zonal", AccessibleTopology: []*ateapipb.Topology{{Segments: zoneA}}},
		{VolumeName: "empty-segments", AccessibleTopology: []*ateapipb.Topology{{}}},
	})
	if diff := cmp.Diff([][]map[string]string{{zoneA}}, got); diff != "" {
		t.Errorf("volumeTopologies() mismatch (-want +got):\n%s", diff)
	}
}
