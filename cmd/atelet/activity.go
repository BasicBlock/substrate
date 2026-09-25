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
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/agent-substrate/substrate/internal/ateompath"
	"github.com/agent-substrate/substrate/internal/proto/ateletpb"
	"github.com/agent-substrate/substrate/internal/proto/ateompb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// activityProbeTimeout bounds each ateom's answer to what it runs.
const activityProbeTimeout = 10 * time.Second

// actorActivity tells whether an actor may be using its directories on this
// node, for removing them safely: an atelet RPC naming it is in flight, or an
// ateom here runs a workload of it. Removal claims the actor first, which
// holds off any RPC for it until the removal is done.
type actorActivity struct {
	mu   sync.Mutex
	cond *sync.Cond
	// inFlight counts the RPCs running per actor UID; -1 marks an actor being
	// removed.
	inFlight map[string]int

	ateomsDir string
	// probe returns the actor UIDs the ateom of podUID runs.
	probe func(ctx context.Context, podUID string) ([]string, error)
}

func newActorActivity() *actorActivity {
	return newActorActivityWith(ateompath.AteomsDir(), probeAteomActors)
}

func newActorActivityWith(ateomsDir string, probe func(ctx context.Context, podUID string) ([]string, error)) *actorActivity {
	a := &actorActivity{inFlight: map[string]int{}, ateomsDir: ateomsDir, probe: probe}
	a.cond = sync.NewCond(&a.mu)
	return a
}

// hold marks actorUID in use until the returned func runs, waiting out a
// removal of the actor's directories already under way.
func (a *actorActivity) hold(actorUID string) func() {
	a.mu.Lock()
	for a.inFlight[actorUID] < 0 {
		a.cond.Wait()
	}
	a.inFlight[actorUID]++
	a.mu.Unlock()
	return func() {
		a.mu.Lock()
		if a.inFlight[actorUID]--; a.inFlight[actorUID] == 0 {
			delete(a.inFlight, actorUID)
		}
		a.mu.Unlock()
		a.cond.Broadcast()
	}
}

// claim reserves actorUID for removing its directories: it fails while an RPC
// for the actor is in flight, and holds new ones off until released.
func (a *actorActivity) claim(actorUID string) (release func(), ok bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.inFlight[actorUID] != 0 {
		return nil, false
	}
	a.inFlight[actorUID] = -1
	return func() {
		a.mu.Lock()
		delete(a.inFlight, actorUID)
		a.mu.Unlock()
		a.cond.Broadcast()
	}, true
}

// UnaryInterceptor holds the actor a request names for as long as its RPC
// runs. ReclaimActor claims its actor itself, and so is left alone.
func (a *actorActivity) UnaryInterceptor(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	if info.FullMethod == ateletpb.AteomHerder_ReclaimActor_FullMethodName {
		return handler(ctx, req)
	}
	if named, ok := req.(interface{ GetActorUid() string }); ok && named.GetActorUid() != "" {
		defer a.hold(named.GetActorUid())()
	}
	return handler(ctx, req)
}

// running returns the actor UIDs the ateoms on this node run. An ateom whose
// socket refuses connections has exited and runs nothing (its directory
// outlives an ateom that did not exit cleanly). Any other failure to get an
// answer is an error: callers must then assume every actor may be running.
func (a *actorActivity) running(ctx context.Context) (map[string]bool, error) {
	entries, err := os.ReadDir(a.ateomsDir)
	if os.IsNotExist(err) {
		return map[string]bool{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("while listing ateoms: %w", err)
	}
	running := map[string]bool{}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		probeCtx, cancel := context.WithTimeout(ctx, activityProbeTimeout)
		uids, err := a.probe(probeCtx, entry.Name())
		cancel()
		if status.Code(err) == codes.Unavailable {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("while asking ateom %s what it runs: %w", entry.Name(), err)
		}
		for _, uid := range uids {
			running[uid] = true
		}
	}
	return running, nil
}

// probeAteomActors asks the ateom of podUID which actors it runs.
func probeAteomActors(ctx context.Context, podUID string) ([]string, error) {
	conn, closer, err := dialAteomStats(podUID)
	if err != nil {
		return nil, err
	}
	defer closer.Close()
	resp, err := ateompb.NewAteomClient(conn).GetActiveWorkloadStats(ctx, &ateompb.GetActiveWorkloadStatsRequest{})
	if err != nil {
		return nil, err
	}
	var uids []string
	for _, sample := range resp.GetSamples() {
		uids = append(uids, sample.GetActorUid())
	}
	return uids, nil
}
