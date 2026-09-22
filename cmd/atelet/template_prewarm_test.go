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
	"slices"
	"strconv"
	"sync"
	"testing"

	"google.golang.org/grpc"

	"github.com/agent-substrate/substrate/internal/imagecache"
	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
)

// fakePrewarmControl serves Workers and ActorTemplates one per page, so every
// listing exercises the paging.
type fakePrewarmControl struct {
	workers   []*ateapipb.Worker
	templates []*ateapipb.ActorTemplate
	err       error
}

func prewarmPage[T any](items []T, token string) ([]T, string) {
	start, _ := strconv.Atoi(token)
	if start >= len(items) {
		return nil, ""
	}
	next := ""
	if start+1 < len(items) {
		next = strconv.Itoa(start + 1)
	}
	return items[start : start+1], next
}

func (f *fakePrewarmControl) ListWorkers(_ context.Context, in *ateapipb.ListWorkersRequest, _ ...grpc.CallOption) (*ateapipb.ListWorkersResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	items, next := prewarmPage(f.workers, in.GetPageToken())
	return &ateapipb.ListWorkersResponse{Workers: items, NextPageToken: next}, nil
}

func (f *fakePrewarmControl) ListActorTemplates(_ context.Context, in *ateapipb.ListActorTemplatesRequest, _ ...grpc.CallOption) (*ateapipb.ListActorTemplatesResponse, error) {
	if in.GetAtespace() != "" {
		return nil, errors.New("the prewarmer must list templates across all atespaces")
	}
	items, next := prewarmPage(f.templates, in.GetPageToken())
	return &ateapipb.ListActorTemplatesResponse{ActorTemplates: items, NextPageToken: next}, nil
}

// fakePrewarmImages records every EnsureImage and fails the refs in fail.
type fakePrewarmImages struct {
	mu      sync.Mutex
	ensured []string
	fail    map[string]bool
}

func (f *fakePrewarmImages) EnsureImage(_ context.Context, ref string) (*imagecache.Image, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ensured = append(f.ensured, ref)
	if f.fail[ref] {
		return nil, errors.New("registry unavailable")
	}
	return &imagecache.Image{}, nil
}

func prewarmWorker(pool, class string, labels map[string]string) *ateapipb.Worker {
	return &ateapipb.Worker{WorkerNamespace: "ate-workers", WorkerPool: pool, SandboxClass: class, Labels: labels}
}

func prewarmTemplate(class ateapipb.SandboxClass, selector map[string]string, images ...string) *ateapipb.ActorTemplate {
	tmpl := &ateapipb.ActorTemplate{SandboxConfig: &ateapipb.SandboxConfig{SandboxClass: class}}
	if selector != nil {
		tmpl.WorkerSelector = &ateapipb.Selector{MatchLabels: selector}
	}
	for _, image := range images {
		tmpl.Containers = append(tmpl.Containers, &ateapipb.Container{Image: image})
	}
	return tmpl
}

// prewarmPools reports worker pods of the named pools scheduled on this node.
func prewarmPools(names ...string) func(context.Context) map[string]workerPoolRef {
	return func(context.Context) map[string]workerPoolRef {
		pods := map[string]workerPoolRef{}
		for i, name := range names {
			pods["pod-"+strconv.Itoa(i)] = workerPoolRef{namespace: "ate-workers", name: name}
		}
		return pods
	}
}

// TestTemplateImagePrewarmWanted pins which templates a node prewarms: those
// the scheduler could place on a pool with a pod here, matched on sandbox
// class and the template's worker selector against the pool's labels.
func TestTemplateImagePrewarmWanted(t *testing.T) {
	gvisor, microvm := ateapipb.SandboxClass_SANDBOX_CLASS_GVISOR, ateapipb.SandboxClass_SANDBOX_CLASS_MICROVM
	control := &fakePrewarmControl{
		workers: []*ateapipb.Worker{
			prewarmWorker("workspaces", "gvisor", map[string]string{"workload": "workspace"}),
			// Same pool on another node: its traits are the pool's.
			prewarmWorker("workspaces", "gvisor", map[string]string{"workload": "workspace"}),
			prewarmWorker("elsewhere", "gvisor", map[string]string{"workload": "batch"}),
		},
		templates: []*ateapipb.ActorTemplate{
			prewarmTemplate(gvisor, map[string]string{"workload": "workspace"}, "registry/workspace@sha256:1", "registry/sidecar@sha256:2"),
			prewarmTemplate(gvisor, nil, "registry/anywhere@sha256:3", "registry/sidecar@sha256:2"),
			prewarmTemplate(gvisor, map[string]string{"workload": "batch"}, "registry/batch@sha256:4"),
			prewarmTemplate(microvm, map[string]string{"workload": "workspace"}, "registry/vm@sha256:5"),
		},
	}
	p := &templateImagePrewarmer{control: control, images: &fakePrewarmImages{}, pools: prewarmPools("workspaces"), pulled: map[string]bool{}}
	got, err := p.wanted(context.Background())
	if err != nil {
		t.Fatalf("wanted: %v", err)
	}
	want := []string{"registry/anywhere@sha256:3", "registry/sidecar@sha256:2", "registry/workspace@sha256:1"}
	if !slices.Equal(got, want) {
		t.Errorf("wanted = %v, want %v", got, want)
	}

	t.Run("no worker pods on the node", func(t *testing.T) {
		p := &templateImagePrewarmer{control: control, pools: prewarmPools()}
		if got, err := p.wanted(context.Background()); err != nil || got != nil {
			t.Errorf("wanted = %v, %v; want nothing", got, err)
		}
	})
	t.Run("pool with no registered worker yet", func(t *testing.T) {
		p := &templateImagePrewarmer{control: control, pools: prewarmPools("brand-new")}
		if got, err := p.wanted(context.Background()); err != nil || got != nil {
			t.Errorf("wanted = %v, %v; want nothing", got, err)
		}
	})
	t.Run("listing fails", func(t *testing.T) {
		p := &templateImagePrewarmer{control: &fakePrewarmControl{err: errors.New("unavailable")}, pools: prewarmPools("workspaces")}
		if _, err := p.wanted(context.Background()); err == nil {
			t.Error("wanted with a failing list: want an error")
		}
	})
}

// TestTemplateImagePrewarmPass verifies that a pass pulls each wanted image
// once, and that a failed pull is retried by the next pass while a pulled one
// is not pulled again.
func TestTemplateImagePrewarmPass(t *testing.T) {
	gvisor := ateapipb.SandboxClass_SANDBOX_CLASS_GVISOR
	control := &fakePrewarmControl{
		workers:   []*ateapipb.Worker{prewarmWorker("workspaces", "gvisor", nil)},
		templates: []*ateapipb.ActorTemplate{prewarmTemplate(gvisor, nil, "registry/a@sha256:1", "registry/b@sha256:2")},
	}
	images := &fakePrewarmImages{fail: map[string]bool{"registry/b@sha256:2": true}}
	p := &templateImagePrewarmer{control: control, images: images, pools: prewarmPools("workspaces"), pulled: map[string]bool{}}

	p.pass(context.Background())
	images.fail = nil
	p.pass(context.Background())
	p.pass(context.Background())

	want := []string{"registry/a@sha256:1", "registry/b@sha256:2", "registry/b@sha256:2"}
	if !slices.Equal(images.ensured, want) {
		t.Errorf("ensured = %v, want %v", images.ensured, want)
	}
}
