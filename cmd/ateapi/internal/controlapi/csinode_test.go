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
	"testing"

	"github.com/agent-substrate/substrate/internal/volume"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	storagev1listers "k8s.io/client-go/listers/storage/v1"
	"k8s.io/client-go/tools/cache"
)

type recordingPlugin struct {
	volume.VolumePluginControlPlane
	attached, detached []string
}

func (p *recordingPlugin) AttachVolume(_ context.Context, _ string, node string) error {
	p.attached = append(p.attached, node)
	return nil
}

func (p *recordingPlugin) DetachVolume(_ context.Context, _ string, node string) error {
	p.detached = append(p.detached, node)
	return nil
}

func csiNodes(t *testing.T, nodes ...*storagev1.CSINode) storagev1listers.CSINodeLister {
	t.Helper()
	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	for _, node := range nodes {
		if err := indexer.Add(node); err != nil {
			t.Fatal(err)
		}
	}
	return storagev1listers.NewCSINodeLister(indexer)
}

func TestCSINodePluginUsesTheDriversNodeID(t *testing.T) {
	const pdNode = "projects/project/zones/us-central1-a/instances/gke-node-a"
	nodes := csiNodes(t, &storagev1.CSINode{
		ObjectMeta: metav1.ObjectMeta{Name: "gke-node-a"},
		Spec: storagev1.CSINodeSpec{Drivers: []storagev1.CSINodeDriver{
			{Name: "nfs.csi.k8s.io", NodeID: "gke-node-a"},
			{Name: "pd.csi.storage.gke.io", NodeID: pdNode},
		}},
	})
	inner := &recordingPlugin{}
	plugin := withCSINodeIDs(inner, "pd.csi.storage.gke.io", nodes)

	if err := plugin.AttachVolume(context.Background(), "disk", "gke-node-a"); err != nil {
		t.Fatal(err)
	}
	if err := plugin.DetachVolume(context.Background(), "disk", "gke-node-a"); err != nil {
		t.Fatal(err)
	}
	if len(inner.attached) != 1 || inner.attached[0] != pdNode || len(inner.detached) != 1 || inner.detached[0] != pdNode {
		t.Errorf("attached %v, detached %v; want %q for both", inner.attached, inner.detached, pdNode)
	}
}

func TestCSINodePluginKeepsTheNodeNameWithoutARegistration(t *testing.T) {
	nodes := csiNodes(t, &storagev1.CSINode{
		ObjectMeta: metav1.ObjectMeta{Name: "gke-node-a"},
		Spec: storagev1.CSINodeSpec{Drivers: []storagev1.CSINodeDriver{
			{Name: "pd.csi.storage.gke.io", NodeID: "projects/p/zones/z/instances/gke-node-a"},
		}},
	})
	for _, tc := range []struct{ driver, node string }{
		{"nfs.csi.k8s.io", "gke-node-a"},        // the node has no registration for this driver
		{"pd.csi.storage.gke.io", "gke-node-b"}, // the node has no CSINode object
	} {
		inner := &recordingPlugin{}
		if err := withCSINodeIDs(inner, tc.driver, nodes).AttachVolume(context.Background(), "disk", tc.node); err != nil {
			t.Fatal(err)
		}
		if len(inner.attached) != 1 || inner.attached[0] != tc.node {
			t.Errorf("%s on %s: attached %v, want the node name", tc.driver, tc.node, inner.attached)
		}
	}

	inner := &recordingPlugin{}
	if got := withCSINodeIDs(inner, "pd.csi.storage.gke.io", nil); got != volume.VolumePluginControlPlane(inner) {
		t.Errorf("without CSINode access the plugin must be returned unwrapped")
	}
}
