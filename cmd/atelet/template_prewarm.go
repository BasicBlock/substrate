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

var templateImagePrewarmInterval = pflag.Duration("template-image-prewarm-interval", time.Minute,
	"How often to pull the container images of ActorTemplates that can run on this node's workers into the image cache, so an actor's first start on the node does not wait for its image. 0 disables.")

// templateImagePrewarmTimeout bounds pulling one image. Workspace-sized images
// run to gigabytes; a timed-out pull is retried on the next pass. A var so
// tests can shorten it.
var templateImagePrewarmTimeout = 30 * time.Minute

// templatePrewarmControl is the slice of the Control API the prewarmer reads.
type templatePrewarmControl interface {
	ListWorkers(ctx context.Context, in *ateapipb.ListWorkersRequest, opts ...grpc.CallOption) (*ateapipb.ListWorkersResponse, error)
	ListActorTemplates(ctx context.Context, in *ateapipb.ListActorTemplatesRequest, opts ...grpc.CallOption) (*ateapipb.ListActorTemplatesResponse, error)
}

// imageEnsurer is the image cache operation the prewarmer uses: the same pull,
// dedup and layout as an actor start, so the two can never diverge.
type imageEnsurer interface {
	EnsureImage(ctx context.Context, ref string) (*imagecache.Image, error)
}

// templateImagePrewarmer pulls the images of the ActorTemplates the scheduler
// could place on this node's workers before an actor needs them. Pulls are
// full, so without it the first actor of a template on a new node (one the
// cluster autoscaler just added, say) waits minutes for a large image.
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
	// pulled holds the refs this process has already ensured. They are not
	// ensured again: the cache keeps them until eviction, and a repeated
	// ensure would refresh their recency and shield them from it.
	pulled map[string]bool
}

func startTemplateImagePrewarm(ctx context.Context, interval time.Duration, control templatePrewarmControl, images imageEnsurer, pools func(context.Context) map[string]workerPoolRef) {
	if interval <= 0 {
		slog.InfoContext(ctx, "Template image prewarm disabled")
		return
	}
	if pools == nil {
		slog.WarnContext(ctx, "NODE_NAME not set; template image prewarm disabled")
		return
	}
	p := &templateImagePrewarmer{control: control, images: images, pools: pools, pulled: map[string]bool{}}
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

// pass pulls, one at a time so prewarming never competes with itself for node
// bandwidth, each wanted image this process has not pulled yet.
func (p *templateImagePrewarmer) pass(ctx context.Context) {
	refs, err := p.wanted(ctx)
	if err != nil {
		slog.WarnContext(ctx, "Template image prewarm could not list what to pull; retrying next pass", slog.Any("err", err))
		return
	}
	for _, ref := range refs {
		if p.pulled[ref] || ctx.Err() != nil {
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
		p.pulled[ref] = true
		slog.InfoContext(ctx, "Template image prewarmed", slog.String("image", ref), slog.Duration("duration", time.Since(start)))
	}
}

// poolTraits are what the scheduler matches a template against: a Worker
// carries its pool's sandbox class and labels.
type poolTraits struct {
	sandboxClass string
	labels       labels.Set
}

// wanted returns the container images, sorted and deduplicated, of every
// ActorTemplate whose sandbox class and worker selector a WorkerPool with a
// pod on this node satisfies: the templates whose actors the scheduler could
// place here. A pool's traits come from any of its registered Workers, on any
// node, so they are known before this node's own workers register.
func (p *templateImagePrewarmer) wanted(ctx context.Context) ([]string, error) {
	local := map[workerPoolRef]bool{}
	for _, pool := range p.pools(ctx) {
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

	var refs []string
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
			for _, c := range tmpl.GetContainers() {
				if c.GetImage() != "" {
					refs = append(refs, c.GetImage())
				}
			}
		}
		if resp.GetNextPageToken() == "" {
			break
		}
		templatesReq.PageToken = resp.GetNextPageToken()
	}
	slices.Sort(refs)
	return slices.Compact(refs), nil
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
