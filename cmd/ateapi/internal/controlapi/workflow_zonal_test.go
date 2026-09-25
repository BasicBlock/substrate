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
	"time"

	"github.com/agent-substrate/substrate/cmd/ateapi/internal/scheduling"
	"github.com/agent-substrate/substrate/cmd/ateapi/internal/store"
	"github.com/agent-substrate/substrate/cmd/ateapi/internal/store/storetest"
	"github.com/agent-substrate/substrate/cmd/ateapi/internal/workercache"
	"github.com/agent-substrate/substrate/internal/resources"
	"github.com/agent-substrate/substrate/internal/volume"
	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// zonalFixture is two workers in different zones, a PD StorageClass, and a
// workflow that knows both nodes' zones.
func zonalFixture(t *testing.T, ctx context.Context) (*ActorWorkflow, store.Interface, map[string]*ateapipb.Worker) {
	t.Helper()
	persistence := newTestPersistence(t)
	zones := map[string]string{"node-a": "us-central1-a", "node-b": "us-central1-b"}
	var csiNodeObjs []*storagev1.CSINode
	var nodeObjs []*corev1.Node
	workers := map[string]*ateapipb.Worker{}
	for node, zone := range zones {
		pod := "pod-" + node
		worker, err := persistence.CreateWorker(ctx, &ateapipb.Worker{
			Metadata:        &ateapipb.ResourceMetadata{Name: testWorkerUID(pod)},
			WorkerNamespace: "worker-ns",
			WorkerPool:      "pool",
			WorkerPod:       pod,
			WorkerPodUid:    testWorkerUID(pod),
			NodeName:        node,
			SandboxClass:    "gvisor",
			Status:          &ateapipb.WorkerStatus{State: ateapipb.WorkerState_WORKER_STATE_ACTIVE, Capacity: &ateapipb.WorkerResources{Actors: 1}},
		})
		if err != nil {
			t.Fatalf("CreateWorker: %v", err)
		}
		workers[node] = worker
		csiNodeObjs = append(csiNodeObjs, &storagev1.CSINode{
			ObjectMeta: metav1.ObjectMeta{Name: node},
			Spec: storagev1.CSINodeSpec{Drivers: []storagev1.CSINodeDriver{
				{Name: pdDriver, NodeID: node, TopologyKeys: []string{"topology.gke.io/zone"}},
			}},
		})
		nodeObjs = append(nodeObjs, &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: node, Labels: map[string]string{"topology.gke.io/zone": zone}}})
	}

	cacheCtx, cancel := context.WithCancel(ctx)
	t.Cleanup(cancel)
	wc := workercache.New(persistence, time.Minute)
	if err := wc.Start(cacheCtx); err != nil {
		t.Fatalf("workercache.Start: %v", err)
	}
	w := &ActorWorkflow{
		store:       persistence,
		workerCache: wc,
		pluginRegistry: &mockPluginRegistry{plugins: map[string]volume.VolumePluginControlPlane{
			pdDriver: volume.NewMockVolumePlugin(),
		}},
		storageClassLister: &fakeStorageClassLister{storageClasses: map[string]*storagev1.StorageClass{
			"pd": {ObjectMeta: metav1.ObjectMeta{Name: "pd"}, Provisioner: pdDriver},
		}},
	}
	w.scheduler = scheduling.New(wc, scheduling.WithNodeLabels(w.nodeLabels))
	w.topology.Store(&nodeTopology{csiNodes: csiNodes(t, csiNodeObjs...), nodes: nodeLister(t, nodeObjs...)})
	return w, persistence, workers
}

// TestZonalVolumeFollowsItsFirstWorker verifies a first resume creates the
// actor's PD volume in the zone of a worker it can run on and records it, and
// that the claim and every later placement only consider workers there.
func TestZonalVolumeFollowsItsFirstWorker(t *testing.T) {
	ctx := context.Background()
	w, persistence, workers := zonalFixture(t, ctx)
	actorRef := resources.ActorRef{Atespace: "team-a", Name: "id1"}
	tmpl := &ateapipb.ActorTemplate{
		SandboxConfig: &ateapipb.SandboxConfig{SandboxClass: ateapipb.SandboxClass_SANDBOX_CLASS_GVISOR},
		Volumes: []*ateapipb.Volume{{
			Name:                   "data",
			ExternalVolumeTemplate: &ateapipb.ExternalVolumeTemplate{StorageClassName: "pd", Capacity: "10Gi"},
		}},
	}
	actor := storetest.MustCreateActor(t, ctx, persistence, &ateapipb.Actor{
		Metadata: &ateapipb.ResourceMetadata{Atespace: actorRef.Atespace, Name: actorRef.Name},
		Status: &ateapipb.ActorStatus{
			State:        ateapipb.ActorState_ACTOR_STATE_SUSPENDED,
			ActorVolumes: []*ateapipb.ExternalVolume{{VolumeName: "data", VolumeType: pdDriver, Status: ateapipb.ExternalVolume_STATUS_PENDING}},
		},
	})

	created, err := w.ensureVolumesCreated(ctx, actorRef, actor, tmpl)
	if err != nil {
		t.Fatalf("ensureVolumesCreated: %v", err)
	}
	topology := created.GetStatus().GetActorVolumes()[0].GetAccessibleTopology()
	if len(topology) != 1 {
		t.Fatalf("volume topology = %v, want one zone", topology)
	}
	// The claim follows the volume, whichever worker the sample was.
	_, worker, err := w.ensureWorkerAssigned(ctx, actorRef, created, tmpl)
	if err != nil {
		t.Fatalf("ensureWorkerAssigned: %v", err)
	}
	wantZone := map[string]string{"node-a": "us-central1-a", "node-b": "us-central1-b"}[worker.GetNodeName()]
	if got := topology[0].GetSegments()["topology.gke.io/zone"]; got != wantZone {
		t.Fatalf("volume zone = %s, but the actor was placed on %s in %s", got, worker.GetNodeName(), wantZone)
	}

	constraints, err := schedulingConstraints(created, tmpl)
	if err != nil {
		t.Fatalf("schedulingConstraints: %v", err)
	}
	for node, candidate := range workers {
		if got, want := w.scheduler.Applies(candidate, constraints), node == worker.GetNodeName(); got != want {
			t.Errorf("Applies(worker on %s) = %v, want %v", node, got, want)
		}
	}
}

// mountedPDTemplate mounts one PD volume, "data".
func mountedPDTemplate() *ateapipb.ActorTemplate {
	return &ateapipb.ActorTemplate{
		SandboxConfig: &ateapipb.SandboxConfig{SandboxClass: ateapipb.SandboxClass_SANDBOX_CLASS_GVISOR},
		Containers:    []*ateapipb.Container{{Name: "main", VolumeMounts: []*ateapipb.VolumeMount{{Name: "data", MountPath: "/data"}}}},
		Volumes: []*ateapipb.Volume{{
			Name:                   "data",
			ExternalVolumeTemplate: &ateapipb.ExternalVolumeTemplate{StorageClassName: "pd", Capacity: "10Gi"},
		}},
	}
}

// TestAttachDetachesFromTheNodeItWasLeftOn verifies a resume first detaches a
// volume from the node a crash left it attached to, then attaches it to the
// new worker's node and records that node.
func TestAttachDetachesFromTheNodeItWasLeftOn(t *testing.T) {
	ctx := context.Background()
	w, persistence, workers := zonalFixture(t, ctx)
	plugin := &recordingPlugin{}
	w.pluginRegistry = &mockPluginRegistry{plugins: map[string]volume.VolumePluginControlPlane{pdDriver: plugin}}
	actorRef := resources.ActorRef{Atespace: "team-a", Name: "id1"}
	actor := storetest.MustCreateActor(t, ctx, persistence, &ateapipb.Actor{
		Metadata: &ateapipb.ResourceMetadata{Atespace: actorRef.Atespace, Name: actorRef.Name},
		Status: &ateapipb.ActorStatus{
			State: ateapipb.ActorState_ACTOR_STATE_RESUMING,
			ActorVolumes: []*ateapipb.ExternalVolume{{
				VolumeName: "data", VolumeType: pdDriver, Status: ateapipb.ExternalVolume_STATUS_CREATED,
				StorageVolumeId: "disk-1", AttachedNode: "node-b",
			}},
		},
	})

	stored, err := w.ensureVolumesAttached(ctx, actorRef, actor, workers["node-a"], mountedPDTemplate())
	if err != nil {
		t.Fatalf("ensureVolumesAttached: %v", err)
	}
	if len(plugin.detached) != 1 || plugin.detached[0] != "node-b" || len(plugin.attached) != 1 || plugin.attached[0] != "node-a" {
		t.Errorf("detached %v, attached %v; want detached from node-b, then attached to node-a", plugin.detached, plugin.attached)
	}
	if got := stored.GetStatus().GetActorVolumes()[0].GetAttachedNode(); got != "node-a" {
		t.Errorf("AttachedNode = %q, want node-a", got)
	}

	// A re-entered attach to the same node detaches nothing.
	plugin.attached, plugin.detached = nil, nil
	if _, err := w.ensureVolumesAttached(ctx, actorRef, stored, workers["node-a"], mountedPDTemplate()); err != nil {
		t.Fatalf("ensureVolumesAttached again: %v", err)
	}
	if len(plugin.detached) != 0 || len(plugin.attached) != 1 {
		t.Errorf("re-entered attach: detached %v, attached %v; want only the attach", plugin.detached, plugin.attached)
	}
}

// TestDetachUsesTheVolumesNodeWithoutAnAssignment verifies a volume is
// detached from the node it records even after a crash cleared the actor's
// worker assignment, so deleting the actor can delete its disk.
func TestDetachUsesTheVolumesNodeWithoutAnAssignment(t *testing.T) {
	ctx := context.Background()
	persistence := newTestPersistence(t)
	plugin := &recordingPlugin{}
	registry := &mockPluginRegistry{plugins: map[string]volume.VolumePluginControlPlane{pdDriver: plugin}}
	actor := &ateapipb.Actor{
		Metadata: &ateapipb.ResourceMetadata{Atespace: "team-a", Name: "id1"},
		Status: &ateapipb.ActorStatus{
			State: ateapipb.ActorState_ACTOR_STATE_CRASHED,
			ActorVolumes: []*ateapipb.ExternalVolume{
				{VolumeName: "data", VolumeType: pdDriver, Status: ateapipb.ExternalVolume_STATUS_CREATED, StorageVolumeId: "disk-1", AttachedNode: "node-b"},
				{VolumeName: "never-attached", VolumeType: pdDriver, Status: ateapipb.ExternalVolume_STATUS_CREATED, StorageVolumeId: "disk-2"},
			},
		},
	}
	if err := detachActorVolumes(ctx, persistence, registry, actor, nil, "delete"); err != nil {
		t.Fatalf("detachActorVolumes: %v", err)
	}
	if len(plugin.detached) != 1 || plugin.detached[0] != "node-b" {
		t.Errorf("detached %v, want only disk-1 from node-b", plugin.detached)
	}
}
