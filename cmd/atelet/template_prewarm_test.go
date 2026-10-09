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
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"math"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"google.golang.org/grpc"

	"github.com/agent-substrate/substrate/internal/imagecache"
	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
)

// fakePrewarmControl serves Actors, Workers and ActorTemplates one per page, so every
// listing exercises the paging.
type fakePrewarmControl struct {
	actors    []*ateapipb.Actor
	workers   []*ateapipb.Worker
	templates []*ateapipb.ActorTemplate
	err       error
	actorsErr error
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

func (f *fakePrewarmControl) ListActors(_ context.Context, in *ateapipb.ListActorsRequest, _ ...grpc.CallOption) (*ateapipb.ListActorsResponse, error) {
	if in.GetAtespace() != "" {
		return nil, errors.New("the prewarmer must list actors across all atespaces")
	}
	if f.actorsErr != nil {
		return nil, f.actorsErr
	}
	items, next := prewarmPage(f.actors, in.GetPageToken())
	return &ateapipb.ListActorsResponse{Actors: items, NextPageToken: next}, nil
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
	p := &templateImagePrewarmer{control: control, images: &fakePrewarmImages{}, pools: prewarmPools("workspaces")}
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
// each pass, so cache eviction and failed pulls are retried.
func TestTemplateImagePrewarmPass(t *testing.T) {
	gvisor := ateapipb.SandboxClass_SANDBOX_CLASS_GVISOR
	control := &fakePrewarmControl{
		workers:   []*ateapipb.Worker{prewarmWorker("workspaces", "gvisor", nil)},
		templates: []*ateapipb.ActorTemplate{prewarmTemplate(gvisor, nil, "registry/a@sha256:1", "registry/b@sha256:2")},
	}
	images := &fakePrewarmImages{fail: map[string]bool{"registry/b@sha256:2": true}}
	p := &templateImagePrewarmer{control: control, images: images, pools: prewarmPools("workspaces")}

	p.pass(context.Background())
	images.fail = nil
	p.pass(context.Background())
	p.pass(context.Background())

	want := []string{"registry/a@sha256:1", "registry/b@sha256:2", "registry/a@sha256:1", "registry/b@sha256:2", "registry/a@sha256:1", "registry/b@sha256:2"}
	if !slices.Equal(images.ensured, want) {
		t.Errorf("ensured = %v, want %v", images.ensured, want)
	}
}

func TestTemplateImagePrewarmRewarmsAfterEviction(t *testing.T) {
	ctx := context.Background()
	server := httptest.NewServer(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	t.Cleanup(server.Close)
	tag, err := name.NewTag(strings.TrimPrefix(server.URL, "http://")+"/workspace:test", name.Insecure)
	if err != nil {
		t.Fatal(err)
	}
	var archive bytes.Buffer
	tw := tar.NewWriter(&archive)
	if err := tw.WriteHeader(&tar.Header{Name: "file", Mode: 0o644, Size: 4}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("data")); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(archive.Bytes())), nil })
	if err != nil {
		t.Fatal(err)
	}
	img, err := mutate.AppendLayers(empty.Image, layer)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(tag, img); err != nil {
		t.Fatal(err)
	}
	digest, err := img.Digest()
	if err != nil {
		t.Fatal(err)
	}
	ref := tag.Context().Name() + "@" + digest.String()
	store, err := imagecache.New(t.TempDir(), imagecache.WithMinAge(0))
	if err != nil {
		t.Fatal(err)
	}
	control := &fakePrewarmControl{
		workers:   []*ateapipb.Worker{prewarmWorker("workspaces", "gvisor", nil)},
		templates: []*ateapipb.ActorTemplate{prewarmTemplate(ateapipb.SandboxClass_SANDBOX_CLASS_GVISOR, nil, ref)},
	}
	p := &templateImagePrewarmer{control: control, images: store, pools: prewarmPools("workspaces")}
	p.pass(ctx)
	if size, err := store.CacheSize(); err != nil || size == 0 {
		t.Fatalf("initial prewarm cache size = %d, %v", size, err)
	}
	stats, err := store.EvictUnused(ctx, math.MaxInt64, false)
	if err != nil {
		t.Fatal(err)
	}
	if stats.EvictedImages != 1 || stats.EvictedLayers != 1 {
		t.Fatalf("eviction = %+v, want one image and layer", stats)
	}
	p.pass(ctx)
	if size, err := store.CacheSize(); err != nil || size == 0 {
		t.Fatalf("selected image remains missing after eviction and another prewarm pass: cache size = %d, %v", size, err)
	}
}

func TestTemplateImagePrewarmPrioritizesDemand(t *testing.T) {
	template := func(name, image string, created int64) *ateapipb.ActorTemplate {
		tmpl := prewarmTemplate(ateapipb.SandboxClass_SANDBOX_CLASS_GVISOR, nil, image)
		tmpl.Metadata = &ateapipb.ResourceMetadata{Atespace: "dev", Name: name, CreateTime: timestamppb.New(time.Unix(created, 0))}
		return tmpl
	}
	actor := func(name, pod string, updated int64) *ateapipb.Actor {
		return &ateapipb.Actor{
			Metadata:      &ateapipb.ResourceMetadata{UpdateTime: timestamppb.New(time.Unix(updated, 0))},
			ActorTemplate: &ateapipb.ObjectRef{Atespace: "dev", Name: name},
			Status:        &ateapipb.ActorStatus{State: ateapipb.ActorState_ACTOR_STATE_RUNNING, WorkerAssignment: &ateapipb.WorkerAssignment{WorkerPodUid: pod}},
		}
	}
	control := &fakePrewarmControl{
		workers: []*ateapipb.Worker{prewarmWorker("workspaces", "gvisor", nil)},
		templates: []*ateapipb.ActorTemplate{
			template("old-local", "registry/z-local@sha256:1", 1),
			template("recent-actor", "registry/y-recent@sha256:2", 2),
			template("older-actor", "registry/x-older@sha256:3", 3),
			template("newest-unused", "registry/w-newest@sha256:4", 100),
			template("old-unused", "registry/a-unused@sha256:5", 4),
			template("older-unused", "registry/b-unused@sha256:6", 5),
		},
		actors: []*ateapipb.Actor{actor("older-actor", "elsewhere", 10), actor("recent-actor", "elsewhere", 20), actor("old-local", "pod-0", 5)},
	}
	// A deleting actor must not pull an unused old image ahead of actual demand.
	deleting := actor("old-unused", "pod-0", 200)
	deleting.Status.State = ateapipb.ActorState_ACTOR_STATE_DELETING
	control.actors = append(control.actors, deleting)
	p := &templateImagePrewarmer{control: control, pools: prewarmPools("workspaces")}
	got, err := p.wanted(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"registry/z-local@sha256:1", "registry/y-recent@sha256:2", "registry/x-older@sha256:3", "registry/w-newest@sha256:4"}
	if !slices.Equal(got, want) {
		t.Errorf("wanted = %v, want four priority images %v", got, want)
	}
}

func TestTemplateImagePrewarmLimit(t *testing.T) {
	original := *templateImagePrewarmMaxImages
	t.Cleanup(func() { *templateImagePrewarmMaxImages = original })
	control := &fakePrewarmControl{
		workers:   []*ateapipb.Worker{prewarmWorker("workspaces", "gvisor", nil)},
		templates: []*ateapipb.ActorTemplate{prewarmTemplate(ateapipb.SandboxClass_SANDBOX_CLASS_GVISOR, nil, "registry/c@sha256:3", "registry/a@sha256:1", "registry/a@sha256:1", "registry/b@sha256:2")},
	}
	p := &templateImagePrewarmer{control: control, pools: prewarmPools("workspaces")}
	*templateImagePrewarmMaxImages = 2
	got, err := p.wanted(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"registry/a@sha256:1", "registry/b@sha256:2"}; !slices.Equal(got, want) {
		t.Errorf("wanted = %v, want %v", got, want)
	}
	*templateImagePrewarmMaxImages = 0
	// Disabled prewarming must not make any control-plane calls.
	p.control = nil
	if got, err := p.wanted(context.Background()); err != nil || len(got) != 0 {
		t.Errorf("disabled wanted = %v, %v", got, err)
	}
}

func TestTemplateImagePrewarmActorListFailure(t *testing.T) {
	control := &fakePrewarmControl{
		workers:   []*ateapipb.Worker{prewarmWorker("workspaces", "gvisor", nil)},
		actorsErr: errors.New("actor listing unavailable"),
	}
	p := &templateImagePrewarmer{control: control, pools: prewarmPools("workspaces")}
	if _, err := p.wanted(context.Background()); !errors.Is(err, control.actorsErr) {
		t.Errorf("wanted error = %v, want actor listing error", err)
	}
}

func TestTemplateImagePrewarmScopesDemand(t *testing.T) {
	gvisor := ateapipb.SandboxClass_SANDBOX_CLASS_GVISOR
	used := prewarmTemplate(gvisor, nil, "registry/z-used@sha256:1")
	used.Metadata = &ateapipb.ResourceMetadata{Atespace: "used", Name: "same-name"}
	unused := prewarmTemplate(gvisor, nil, "registry/a-unused@sha256:2")
	unused.Metadata = &ateapipb.ResourceMetadata{Atespace: "unused", Name: "same-name"}
	control := &fakePrewarmControl{
		workers:   []*ateapipb.Worker{prewarmWorker("workspaces", "gvisor", nil)},
		templates: []*ateapipb.ActorTemplate{unused, used},
		actors:    []*ateapipb.Actor{{ActorTemplate: &ateapipb.ObjectRef{Atespace: "used", Name: "same-name"}}},
	}
	p := &templateImagePrewarmer{control: control, pools: prewarmPools("workspaces")}
	got, err := p.wanted(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"registry/z-used@sha256:1", "registry/a-unused@sha256:2"}; !slices.Equal(got, want) {
		t.Errorf("wanted = %v, want %v", got, want)
	}
}
