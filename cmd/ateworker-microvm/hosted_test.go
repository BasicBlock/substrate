//go:build linux

// Copyright 2026 The Agent Substrate Authors
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

package main

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	"go.ate.dev/substrate/internal/actorlock"
	"go.ate.dev/substrate/internal/apierror"
	"go.ate.dev/substrate/internal/ateworker/suspend"
	"go.ate.dev/substrate/internal/resources"
)

// Re-admitting an actor that is already hosted keeps its slot, so it succeeds
// on a full worker and a retry cannot lose its place to another actor.
func TestAdmitActorKeepsAHostedActorsSlot(t *testing.T) {
	s := &AteWorkerService{actors: map[string]*hostedActor{}, maxActors: 1}
	first, _, err := s.admitActor(resources.ActorAttribution{UID: "actor-a"}, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	again, _, err := s.admitActor(resources.ActorAttribution{UID: "actor-a"}, false, 0)
	if err != nil {
		t.Fatalf("re-admitting a hosted actor on a full worker: %v", err)
	}
	if again == first {
		t.Error("re-admission kept the old record; readers could not tell the incarnations apart")
	}
	// ResourceExhausted, so the control plane treats it as a capacity miss.
	if _, _, err := s.admitActor(resources.ActorAttribution{UID: "actor-b"}, false, 0); apierror.Code(err) != codes.ResourceExhausted {
		t.Errorf("admitting past the ceiling: got %v, want ResourceExhausted", err)
	}
	if got := len(s.hostedActors()); got != 1 {
		t.Errorf("hosting %d actors, want 1", got)
	}
}

type shutdownRequester struct {
	service   *AteWorkerService
	requested chan suspend.Actor
}

func (r *shutdownRequester) RequestSuspend(_ context.Context, actor suspend.Actor) error {
	r.service.actorsMu.Lock()
	delete(r.service.actors, actor.UID)
	r.service.actorsMu.Unlock()
	r.requested <- actor
	return nil
}
func TestWorkerDrainRequestsItsHostedActorBeforeExit(t *testing.T) {
	actor := suspend.Actor{Atespace: "team", Name: "workspace", UID: "drain-actor-uid"}
	service := &AteWorkerService{actors: map[string]*hostedActor{actor.UID: {attribution: resources.ActorAttribution{Ref: resources.ActorRef{Atespace: actor.Atespace, Name: actor.Name}, UID: actor.UID}}}, inFlight: actorlock.NewInFlight()}
	requester := &shutdownRequester{service: service, requested: make(chan suspend.Actor, 1)}
	service.suspendRequester = requester
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() { service.gracefulShutdown(ctx); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("shutdown blocked the checkpoint callback")
	}
	select {
	case got := <-requester.requested:
		if got != actor {
			t.Fatalf("requested %v,want %v", got, actor)
		}
	default:
		t.Fatal("worker exited without asking to save its hosted actor")
	}
}
