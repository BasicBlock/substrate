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
	"cmp"
	"context"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/spf13/pflag"
	"google.golang.org/grpc"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/agent-substrate/substrate/internal/imagecache"
	"github.com/agent-substrate/substrate/pkg/api/v1alpha1"
	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
)

var (
	templateImagePrewarmInterval = pflag.Duration("template-image-prewarm-interval", time.Minute,
		"How often to refresh the priority images for this node's workers in the image cache. 0 disables.")
	templateImagePrewarmMaxImages = pflag.Int("template-image-prewarm-max-images", 4,
		"Maximum number of images to keep warm, prioritizing actors on this node, recent actor activity, then recently created templates. 0 disables.")
)

// templateImagePrewarmTimeout bounds pulling one image. Workspace-sized images
// run to gigabytes; a timed-out pull is retried on the next pass. A var so
// tests can shorten it.
var templateImagePrewarmTimeout = 30 * time.Minute

// templatePrewarmControl is the slice of the Control API the prewarmer reads.
type templatePrewarmControl interface {
	ListActors(ctx context.Context, in *ateapipb.ListActorsRequest, opts ...grpc.CallOption) (*ateapipb.ListActorsResponse, error)
	ListWorkers(ctx context.Context, in *ateapipb.ListWorkersRequest, opts ...grpc.CallOption) (*ateapipb.ListWorkersResponse, error)
	ListActorTemplates(ctx context.Context, in *ateapipb.ListActorTemplatesRequest, opts ...grpc.CallOption) (*ateapipb.ListActorTemplatesResponse, error)
}

// imageEnsurer is the image cache operation the prewarmer uses: the same pull,
// dedup and layout as an actor start, so the two can never diverge.
type imageEnsurer interface {
	EnsureImage(ctx context.Context, ref string) (*imagecache.Image, error)
}

// templateImagePrewarmer keeps a bounded working set of images warm before an
// actor needs them. Local actors take priority, followed by recent actor
// activity and recent compatible templates. Historical templates outside this
// set cannot churn the cache or compete with foreground restores for I/O.
//
// Like the SandboxConfig prewarm it is purely a latency optimization: every
// failure is logged and left to the pull inside an actor start, which remains
// the correctness path.
type templateImagePrewarmer struct {
	control templatePrewarmControl
	images  imageEnsurer
	// pools reports the WorkerPools of the worker pods scheduled on this node,
	// keyed by pod UID (newWorkerPoolFetcher). Scheduled pods count before
	// they run, so a new node starts pulling while its workers start.
	pools func(ctx context.Context) map[string]workerPoolRef
}

func startTemplateImagePrewarm(ctx context.Context, interval time.Duration, control templatePrewarmControl, images imageEnsurer, pools func(context.Context) map[string]workerPoolRef) {
	if interval <= 0 || *templateImagePrewarmMaxImages <= 0 {
		slog.InfoContext(ctx, "Template image prewarm disabled")
		return
	}
	if pools == nil {
		slog.WarnContext(ctx, "NODE_NAME not set; template image prewarm disabled")
		return
	}
	p := &templateImagePrewarmer{control: control, images: images, pools: pools}
	go func() {
		for {
			p.pass(ctx)
			select {
			case <-ctx.Done():
				return
			case <-time.After(interval):
			}
		}
	}()
	slog.InfoContext(ctx, "Template image prewarm started", slog.Duration("interval", interval))
}

// pass refreshes the bounded working set one image at a time. EnsureImage
// touches cache-hit recency and re-pulls missing layers after eviction, so
// selected images stay warm while unselected images can age out.
func (p *templateImagePrewarmer) pass(ctx context.Context) {
	refs, err := p.wanted(ctx)
	if err != nil {
		slog.WarnContext(ctx, "Template image prewarm could not list what to pull; retrying next pass", slog.Any("err", err))
		return
	}
	for _, ref := range refs {
		if ctx.Err() != nil {
			continue
		}
		start := time.Now()
		pullCtx, cancel := context.WithTimeout(ctx, templateImagePrewarmTimeout)
		_, err := p.images.EnsureImage(pullCtx, ref)
		cancel()
		if err != nil {
			slog.WarnContext(ctx, "Template image prewarm failed; retrying next pass", slog.String("image", ref), slog.Any("err", err))
			continue
		}
		slog.InfoContext(ctx, "Template image prewarmed", slog.String("image", ref), slog.Duration("duration", time.Since(start)))
	}
}

// poolTraits are what the scheduler matches a template against: a Worker
// carries its pool's sandbox class and labels.
type poolTraits struct {
	sandboxClass string
	labels       labels.Set
}

// wanted ranks distinct images of compatible templates by demand, then
// limits prewarming to the hottest refs. Pool traits come from any registered
// Worker in the pool, so a new node can prewarm before its workers register.
func (p *templateImagePrewarmer) wanted(ctx context.Context) ([]string, error) {
	if *templateImagePrewarmMaxImages <= 0 {
		return nil, nil
	}
	pods := p.pools(ctx)
	local := map[workerPoolRef]bool{}
	for _, pool := range pods {
		local[pool] = true
	}
	if len(local) == 0 {
		return nil, nil
	}

	traits := map[workerPoolRef]poolTraits{}
	workersReq := &ateapipb.ListWorkersRequest{}
	for {
		resp, err := p.control.ListWorkers(ctx, workersReq)
		if err != nil {
			return nil, fmt.Errorf("while listing workers: %w", err)
		}
		for _, w := range resp.GetWorkers() {
			pool := workerPoolRef{namespace: w.GetWorkerNamespace(), name: w.GetWorkerPool()}
			if local[pool] {
				traits[pool] = poolTraits{sandboxClass: w.GetSandboxClass(), labels: labels.Set(w.GetLabels())}
			}
		}
		if resp.GetNextPageToken() == "" {
			break
		}
		workersReq.PageToken = resp.GetNextPageToken()
	}
	if len(traits) == 0 {
		return nil, nil
	}

	// Template refs include their atespace: names need not be globally unique.
	type templateRef struct{ atespace, name string }
	type rank struct {
		priority int
		lastUsed time.Time
	}
	compare := func(a, b rank) int {
		if c := cmp.Compare(a.priority, b.priority); c != 0 {
			return c
		}
		return a.lastUsed.Compare(b.lastUsed)
	}
	demand := map[templateRef]rank{}
	actorsReq := &ateapipb.ListActorsRequest{}
	for {
		resp, err := p.control.ListActors(ctx, actorsReq)
		if err != nil {
			return nil, fmt.Errorf("while listing actors: %w", err)
		}
		for _, actor := range resp.GetActors() {
			if actor.GetStatus().GetState() == ateapipb.ActorState_ACTOR_STATE_DELETING {
				continue
			}
			ref := actor.GetActorTemplate()
			key := templateRef{ref.GetAtespace(), ref.GetName()}
			r := rank{priority: 1, lastUsed: actor.GetMetadata().GetUpdateTime().AsTime()}
			if _, local := pods[actor.GetStatus().GetWorkerAssignment().GetWorkerPodUid()]; local {
				r.priority = 2
			}
			if prev, ok := demand[key]; !ok || compare(r, prev) > 0 {
				demand[key] = r
			}
		}
		if resp.GetNextPageToken() == "" {
			break
		}
		actorsReq.PageToken = resp.GetNextPageToken()
	}
	ranked := map[string]rank{}
	templatesReq := &ateapipb.ListActorTemplatesRequest{}
	for {
		resp, err := p.control.ListActorTemplates(ctx, templatesReq)
		if err != nil {
			return nil, fmt.Errorf("while listing actor templates: %w", err)
		}
		for _, tmpl := range resp.GetActorTemplates() {
			if !placeable(tmpl, traits) {
				continue
			}
			md := tmpl.GetMetadata()
			r, used := demand[templateRef{md.GetAtespace(), md.GetName()}]
			if !used {
				r.lastUsed = md.GetCreateTime().AsTime()
			}
			for _, c := range tmpl.GetContainers() {
				ref := c.GetImage()
				if ref == "" {
					continue
				}
				if prev, ok := ranked[ref]; !ok || compare(r, prev) > 0 {
					ranked[ref] = r
				}
			}
		}
		if resp.GetNextPageToken() == "" {
			break
		}
		templatesReq.PageToken = resp.GetNextPageToken()
	}
	refs := make([]string, 0, len(ranked))
	for ref := range ranked {
		refs = append(refs, ref)
	}
	slices.SortFunc(refs, func(a, b string) int {
		if c := compare(ranked[b], ranked[a]); c != 0 {
			return c
		}
		return cmp.Compare(a, b)
	})
	if len(refs) > *templateImagePrewarmMaxImages {
		refs = refs[:*templateImagePrewarmMaxImages]
	}
	return refs, nil
}

// placeable reports whether any of the pools can host the template's actors,
// by the template-level half of the scheduler's constraints. An actor's own
// selector can narrow placement further, but only narrow it.
func placeable(tmpl *ateapipb.ActorTemplate, pools map[workerPoolRef]poolTraits) bool {
	class := templateSandboxClass(tmpl.GetSandboxConfig().GetSandboxClass())
	selector := labels.SelectorFromSet(labels.Set(tmpl.GetWorkerSelector().GetMatchLabels()))
	for _, pool := range pools {
		if pool.sandboxClass == class && selector.Matches(pool.labels) {
			return true
		}
	}
	return false
}

// templateSandboxClass renders a template's sandbox class in the WorkerPool
// vocabulary a Worker's sandbox_class carries, as the scheduler compares them.
func templateSandboxClass(class ateapipb.SandboxClass) string {
	switch class {
	case ateapipb.SandboxClass_SANDBOX_CLASS_GVISOR:
		return string(v1alpha1.SandboxClassGvisor)
	case ateapipb.SandboxClass_SANDBOX_CLASS_MICROVM:
		return string(v1alpha1.SandboxClassMicroVM)
	default:
		return ""
	}
}
