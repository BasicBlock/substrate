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

package demo

import (
	"context"
	"testing"
	"time"

	"github.com/agent-substrate/substrate/internal/e2e"
	"github.com/agent-substrate/substrate/internal/resources"
	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestGracefulWorkerTermination verifies that a worker eviction suspends its
// actor and releases its assignment, and that a replacement worker restores
// both the actor's memory and filesystem state.
func TestGracefulWorkerTermination(t *testing.T) {
	t.Parallel()
	nsObj := e2e.CreateNamespace(t)

	ctx := context.Background()
	clients := e2e.GetClients()

	at, err := createActorTemplate(ctx, t, clients, nsObj, ateapipb.SnapshotFidelity_SNAPSHOT_FIDELITY_MEMORY)
	if err != nil {
		t.Fatalf("failed to initialize ActorTemplate: %v", err)
	}

	actorID := "graceful-term-" + nsObj.Name
	if _, err := clients.SubstrateAPI.CreateActor(ctx, &ateapipb.CreateActorRequest{
		Actor: &ateapipb.Actor{
			Metadata:      &ateapipb.ResourceMetadata{Atespace: demoAtespace, Name: actorID},
			ActorTemplate: e2e.TemplateRef(at),
		},
	}); err != nil {
		t.Fatalf("failed to create Actor: %v", err)
	}
	defer func() {
		_, _ = clients.SubstrateAPI.DeleteActor(ctx, &ateapipb.DeleteActorRequest{
			Actor: &ateapipb.ObjectRef{Atespace: demoAtespace, Name: actorID},
		})
	}()

	// Bring the actor up on a worker so it is bound to a pod.
	if _, err := e2e.ResumeActorAwaitCapacity(t, ctx, clients, &ateapipb.ResumeActorRequest{
		Actor: &ateapipb.ObjectRef{Atespace: demoAtespace, Name: actorID},
	}); err != nil {
		t.Fatalf("failed to resume Actor: %v", err)
	}
	waitForActorState(ctx, t, clients, actorID, ateapipb.ActorState_ACTOR_STATE_RUNNING)

	// Set the sigterm sleep interval to 15 seconds.
	if _, err := callActorPath(t, resources.ActorRef{Atespace: demoAtespace, Name: actorID}, "GET", "/set-sigterm-sleep?duration=15"); err != nil {
		t.Fatalf("failed to set sigterm sleep: %v", err)
	}

	before, err := callActor(t, resources.ActorRef{Atespace: demoAtespace, Name: actorID})
	if err != nil {
		t.Fatalf("counter before eviction: %v", err)
	}
	validateCounterResponse(t, before, "before eviction", 1, 1)

	running, err := clients.SubstrateAPI.GetActor(ctx, &ateapipb.GetActorRequest{
		Actor: &ateapipb.ObjectRef{Atespace: demoAtespace, Name: actorID},
	})
	if err != nil {
		t.Fatalf("failed to get running Actor: %v", err)
	}
	podNS := running.GetStatus().GetWorkerAssignment().GetWorkerNamespace()
	podName := running.GetStatus().GetWorkerAssignment().GetWorkerPod()
	if podNS == "" || podName == "" {
		t.Fatalf("running actor has no bound worker pod: ns=%q name=%q", podNS, podName)
	}
	t.Logf("Actor %q bound to worker pod %s/%s", actorID, podNS, podName)

	// A terminating worker waits while the controller checkpoints its actor.
	if err := clients.K8s.CoreV1().Pods(podNS).Delete(ctx, podName, metav1.DeleteOptions{}); err != nil {
		t.Fatalf("failed to delete worker pod %s/%s: %v", podNS, podName, err)
	}

	// The worker record must eventually be removed once the pod is gone.
	if err := waitForWorkerRemoved(ctx, t, clients, podName, 60*time.Second); err != nil {
		t.Fatalf("worker %s not removed after pod deletion: %v", podName, err)
	}

	// The actor is safely suspended rather than crashed.
	waitForActorState(ctx, t, clients, actorID, ateapipb.ActorState_ACTOR_STATE_SUSPENDED)

	// Verify the pod assignment was cleared.
	actor, err := clients.SubstrateAPI.GetActor(ctx, &ateapipb.GetActorRequest{
		Actor: &ateapipb.ObjectRef{Atespace: demoAtespace, Name: actorID},
	})
	if err != nil {
		t.Fatalf("failed to get actor: %v", err)
	}
	if pod := actor.GetStatus().GetWorkerAssignment().GetWorkerPod(); pod != "" {
		t.Errorf("actor still bound to worker pod %q, expected empty", pod)
	}
	if _, err := e2e.ResumeActorAwaitCapacity(t, ctx, clients, &ateapipb.ResumeActorRequest{Actor: &ateapipb.ObjectRef{Atespace: demoAtespace, Name: actorID}}); err != nil {
		t.Fatalf("resume after eviction: %v", err)
	}
	after, err := callActor(t, resources.ActorRef{Atespace: demoAtespace, Name: actorID})
	if err != nil {
		t.Fatalf("counter after eviction: %v", err)
	}
	validateCounterResponse(t, after, "after eviction", 2, 2)
	if _, err := clients.SubstrateAPI.SuspendActor(ctx, &ateapipb.SuspendActorRequest{Actor: &ateapipb.ObjectRef{Atespace: demoAtespace, Name: actorID}}); err != nil {
		t.Fatalf("final suspend: %v", err)
	}

}

// waitForWorkerRemoved polls ListWorkers until the named worker is absent.
func waitForWorkerRemoved(ctx context.Context, t *testing.T, clients *e2e.Clients, podName string, timeout time.Duration) error {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		resp, err := clients.SubstrateAPI.ListWorkers(ctx, &ateapipb.ListWorkersRequest{})
		if err == nil {
			found := false
			for _, w := range resp.GetWorkers() {
				if w.GetWorkerPod() == podName {
					found = true
					break
				}
			}
			if !found {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return context.DeadlineExceeded
		}
		time.Sleep(time.Second)
	}
}

// TestGracefulWorkerTerminationSuspend exercises the case where a worker pod is
// deleted (evicted), and while the container is in its SIGTERM shutdown phase,
// we initiate a suspend. Suspend should succeed.
func TestGracefulWorkerTerminationSuspend(t *testing.T) {
	t.Parallel()
	nsObj := e2e.CreateNamespace(t)

	ctx := context.Background()
	clients := e2e.GetClients()

	at, err := createActorTemplate(ctx, t, clients, nsObj, ateapipb.SnapshotFidelity_SNAPSHOT_FIDELITY_MEMORY)
	if err != nil {
		t.Fatalf("failed to initialize ActorTemplate: %v", err)
	}

	actorID := "graceful-term-suspend-" + nsObj.Name
	if _, err := clients.SubstrateAPI.CreateActor(ctx, &ateapipb.CreateActorRequest{
		Actor: &ateapipb.Actor{
			Metadata:      &ateapipb.ResourceMetadata{Atespace: demoAtespace, Name: actorID},
			ActorTemplate: e2e.TemplateRef(at),
		},
	}); err != nil {
		t.Fatalf("failed to create Actor: %v", err)
	}
	defer func() {
		_, _ = clients.SubstrateAPI.DeleteActor(ctx, &ateapipb.DeleteActorRequest{
			Actor: &ateapipb.ObjectRef{Atespace: demoAtespace, Name: actorID},
		})
	}()

	// Bring the actor up on a worker so it is bound to a pod.
	if _, err := e2e.ResumeActorAwaitCapacity(t, ctx, clients, &ateapipb.ResumeActorRequest{
		Actor: &ateapipb.ObjectRef{Atespace: demoAtespace, Name: actorID},
	}); err != nil {
		t.Fatalf("failed to resume Actor: %v", err)
	}
	waitForActorState(ctx, t, clients, actorID, ateapipb.ActorState_ACTOR_STATE_RUNNING)

	// Set the sigterm sleep interval to 30 seconds.
	if _, err := callActorPath(t, resources.ActorRef{Atespace: demoAtespace, Name: actorID}, "GET", "/set-sigterm-sleep?duration=30"); err != nil {
		t.Fatalf("failed to set sigterm sleep: %v", err)
	}

	running, err := clients.SubstrateAPI.GetActor(ctx, &ateapipb.GetActorRequest{
		Actor: &ateapipb.ObjectRef{Atespace: demoAtespace, Name: actorID},
	})
	if err != nil {
		t.Fatalf("failed to get running Actor: %v", err)
	}
	podNS := running.GetStatus().GetWorkerAssignment().GetWorkerNamespace()
	podName := running.GetStatus().GetWorkerAssignment().GetWorkerPod()
	if podNS == "" || podName == "" {
		t.Fatalf("running actor has no bound worker pod: ns=%q name=%q", podNS, podName)
	}
	t.Logf("Actor %q bound to worker pod %s/%s", actorID, podNS, podName)

	// Evict the worker pod, which starts the controller's suspend operation.
	if err := clients.K8s.CoreV1().Pods(podNS).Delete(ctx, podName, metav1.DeleteOptions{}); err != nil {
		t.Fatalf("failed to delete worker pod %s/%s: %v", podNS, podName, err)
	}

	// Let the deletion watch start the controller's suspend operation.
	time.Sleep(2 * time.Second)

	// A caller racing the controller waits for its lease and then succeeds
	// idempotently against the suspended actor.
	deadline := time.Now().Add(time.Minute)
	for {
		_, err := clients.SubstrateAPI.SuspendActor(ctx, &ateapipb.SuspendActorRequest{Actor: &ateapipb.ObjectRef{Atespace: demoAtespace, Name: actorID}})
		if err == nil {
			break
		}
		if status.Code(err) != codes.Aborted || time.Now().After(deadline) {
			t.Fatalf("suspend during eviction: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}

	// The worker record must eventually be removed once the pod is gone.
	if err := waitForWorkerRemoved(ctx, t, clients, podName, 60*time.Second); err != nil {
		t.Fatalf("worker %s not removed after pod deletion: %v", podName, err)
	}

	// Verify the actor lands in ACTOR_STATE_SUSPENDED
	waitForActorState(ctx, t, clients, actorID, ateapipb.ActorState_ACTOR_STATE_SUSPENDED)

	// Verify the pod assignment was cleared.
	actor, err := clients.SubstrateAPI.GetActor(ctx, &ateapipb.GetActorRequest{
		Actor: &ateapipb.ObjectRef{Atespace: demoAtespace, Name: actorID},
	})
	if err != nil {
		t.Fatalf("failed to get actor: %v", err)
	}
	if pod := actor.GetStatus().GetWorkerAssignment().GetWorkerPod(); pod != "" {
		t.Errorf("actor still bound to worker pod %q, expected empty", pod)
	}
}
