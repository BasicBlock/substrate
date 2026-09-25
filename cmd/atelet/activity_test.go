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

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/agent-substrate/substrate/internal/ateompath"
	"github.com/agent-substrate/substrate/internal/proto/ateletpb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fakeAteoms builds an ateoms dir with one entry per pod, each answering
// with its entry in answers.
func fakeAteoms(t *testing.T, answers map[string]func() ([]string, error)) *actorActivity {
	t.Helper()
	dir := t.TempDir()
	for pod := range answers {
		if err := os.MkdirAll(filepath.Join(dir, pod), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return newActorActivityWith(dir, func(_ context.Context, pod string) ([]string, error) {
		return answers[pod]()
	})
}

func TestActorActivityRunning(t *testing.T) {
	a := fakeAteoms(t, map[string]func() ([]string, error){
		"pod-live": func() ([]string, error) { return []string{"actor-a"}, nil },
		"pod-idle": func() ([]string, error) { return nil, nil },
		"pod-gone": func() ([]string, error) { return nil, status.Error(codes.Unavailable, "connection refused") },
	})
	running, err := a.running(context.Background())
	if err != nil {
		t.Fatalf("running: %v", err)
	}
	if len(running) != 1 || !running["actor-a"] {
		t.Errorf("running = %v, want only actor-a (an exited ateom runs nothing)", running)
	}

	stuck := fakeAteoms(t, map[string]func() ([]string, error){
		"pod-stuck": func() ([]string, error) { return nil, status.Error(codes.DeadlineExceeded, "timeout") },
	})
	if _, err := stuck.running(context.Background()); err == nil {
		t.Error("running succeeded although an ateom did not answer; nothing may be assumed idle then")
	}
}

func TestActorActivityClaim(t *testing.T) {
	a := newActorActivityWith(t.TempDir(), nil)
	done := a.hold("actor-a")
	if _, ok := a.claim("actor-a"); ok {
		t.Fatal("claimed an actor with an RPC in flight")
	}
	done()

	release, ok := a.claim("actor-a")
	if !ok {
		t.Fatal("could not claim an idle actor")
	}
	if _, ok := a.claim("actor-a"); ok {
		t.Error("claimed an actor twice")
	}
	held := make(chan struct{})
	go func() {
		defer close(held)
		a.hold("actor-a")()
	}()
	select {
	case <-held:
		t.Fatal("an RPC ran while its actor's directories were being removed")
	case <-time.After(50 * time.Millisecond):
	}
	release()
	select {
	case <-held:
	case <-time.After(5 * time.Second):
		t.Fatal("the RPC stayed held off after the removal finished")
	}
}

// reclaimHerder is an atelet whose node runs the given ateoms, with an actor
// dir holding a pause snapshot and bundles.
func reclaimHerder(t *testing.T, answers map[string]func() ([]string, error)) (*AteomHerder, string) {
	t.Helper()
	useTempNodeDirs(t)
	const uid = "actor-uid-1"
	for _, dir := range []string{
		ateompath.LocalSnapshotDir(uid, "snap-1"),
		filepath.Join(ateompath.ActorPath(uid), "bundles", "app"),
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return &AteomHerder{
		systemInfoVolumes: newSystemInfoVolumeRefresher(nil, nil),
		activity:          fakeAteoms(t, answers),
	}, uid
}

func reclaimRequest(uid string) *ateletpb.ReclaimActorRequest {
	return &ateletpb.ReclaimActorRequest{Atespace: "ate-demo", ActorName: "paused-1", ActorUid: uid}
}

func TestReclaimActorRemovesAPausedActorsNodeState(t *testing.T) {
	s, uid := reclaimHerder(t, map[string]func() ([]string, error){
		"pod-other": func() ([]string, error) { return []string{"someone-else"}, nil },
	})
	for attempt := 1; attempt <= 2; attempt++ {
		if _, err := s.ReclaimActor(context.Background(), reclaimRequest(uid)); err != nil {
			t.Fatalf("ReclaimActor attempt %d: %v", attempt, err)
		}
	}
	if _, err := os.Stat(ateompath.ActorPath(uid)); !os.IsNotExist(err) {
		t.Errorf("actor dir survived ReclaimActor (stat err = %v)", err)
	}
}

func TestReclaimActorRefusesAnActorInUse(t *testing.T) {
	t.Run("running on an ateom", func(t *testing.T) {
		s, uid := reclaimHerder(t, map[string]func() ([]string, error){
			"pod-1": func() ([]string, error) { return []string{"actor-uid-1"}, nil },
		})
		_, err := s.ReclaimActor(context.Background(), reclaimRequest(uid))
		if status.Code(err) != codes.FailedPrecondition {
			t.Errorf("ReclaimActor = %v, want FailedPrecondition", err)
		}
		if _, err := os.Stat(ateompath.LocalSnapshotDir(uid, "snap-1")); err != nil {
			t.Errorf("the running actor's snapshot was removed: %v", err)
		}
	})
	t.Run("RPC in flight", func(t *testing.T) {
		s, uid := reclaimHerder(t, nil)
		defer s.activity.hold(uid)()
		if _, err := s.ReclaimActor(context.Background(), reclaimRequest(uid)); status.Code(err) != codes.FailedPrecondition {
			t.Errorf("ReclaimActor = %v, want FailedPrecondition", err)
		}
	})
	t.Run("ateom not answering", func(t *testing.T) {
		s, uid := reclaimHerder(t, map[string]func() ([]string, error){
			"pod-1": func() ([]string, error) { return nil, errors.New("deadline exceeded") },
		})
		if _, err := s.ReclaimActor(context.Background(), reclaimRequest(uid)); status.Code(err) != codes.Unavailable {
			t.Errorf("ReclaimActor = %v, want Unavailable", err)
		}
	})
}
