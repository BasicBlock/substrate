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

package ocispec

import (
	"slices"
	"strings"

	"github.com/agent-substrate/substrate/internal/sizing"
	"github.com/opencontainers/runtime-spec/specs-go"
)

// PauseContainer is the name of the sandbox root container. The underscore
// keeps it outside the k8s-short-name an ActorTemplate container
// name is drawn from, so no actor container can collide with it.
const PauseContainer = "_pause"

// resolvConf is the sandbox resolver path and default bind source.
const resolvConf = "/etc/resolv.conf"

// etcHosts is the worker's kubelet-managed hosts file bound into the sandbox,
// as runc and containerd provide one: it carries the localhost entries.
const etcHosts = "/etc/hosts"

// devShm is the POSIX shared-memory mount. gVisor's synthetic /dev creates it
// as a root-owned 0755 directory, which non-root workloads cannot write.
const devShm = "/dev/shm"

// cpuFeaturesAnnotation is runsc's OCI annotation that levels the sandbox's
// guest CPUID to the intersection of the host's CPU features and a declared
// allow-list, so a checkpoint records that levelled set instead of the raw
// host CPU (google/gvisor#11498). See
// https://github.com/agent-substrate/substrate/issues/1657.
const cpuFeaturesAnnotation = "dev.gvisor.internal.cpufeatures"

// GVisorOptions describes the gVisor-specific context of one actor container.
type GVisorOptions struct {
	ActorUID      string
	ContainerName string
	// DurableVolumes are declared on the sandbox (pause) spec only.
	DurableVolumes []string
	// ResolvConf is the bind source for /etc/resolv.conf; empty uses the pod's file.
	ResolvConf string
	// Size sizes the container's cgroup leaf. Only gVisor applies it; a micro-VM
	// container's limits come from its own declared resources (see sizing).
	Size sizing.SandboxSize
	// CPUFeatures, when non-empty, is set as the cpuFeaturesAnnotation so runsc
	// levels the guest CPUID to host-features ∩ CPUFeatures. Empty leaves the
	// annotation unset, so runsc exposes the raw host feature set (today's
	// behavior). Only meaningful for a sandbox created fresh: gVisor consults
	// the annotation at sandbox boot, before any checkpoint is loaded, and a
	// restore's compatibility is decided entirely by the feature set already
	// recorded in the checkpoint image.
	CPUFeatures []string
}

// GVisorCgroupLeaf names an actor container's cgroup relative to the pod scope.
func GVisorCgroupLeaf(actorUID, containerName string) string {
	return actorUID + "-" + containerName
}

// ShapeGVisor adds runsc CRI annotations, durable-dir mount hints, /dev/shm,
// host resolv.conf and hosts, and per-container cgroups to the spec. It is idempotent.
func ShapeGVisor(spec *specs.Spec, o GVisorOptions) {
	if spec.Annotations == nil {
		spec.Annotations = make(map[string]string)
	}
	spec.Annotations["io.kubernetes.cri.container-name"] = o.ContainerName
	if o.ContainerName == PauseContainer {
		spec.Annotations["io.kubernetes.cri.container-type"] = "sandbox"
	} else {
		spec.Annotations["io.kubernetes.cri.container-type"] = "container"
		spec.Annotations["io.kubernetes.cri.sandbox-id"] = PauseContainer
	}
	if len(o.CPUFeatures) > 0 {
		spec.Annotations[cpuFeaturesAnnotation] = strings.Join(o.CPUFeatures, ",")
	}

	// Match runc, containerd and the micro-VM guest: a world-writable sticky
	// tmpfs, inserted before volume binds so a volume can still shadow it.
	if !slices.ContainsFunc(spec.Mounts, func(m specs.Mount) bool { return m.Destination == devShm }) {
		i := slices.IndexFunc(spec.Mounts, func(m specs.Mount) bool { return m.Type == "bind" })
		if i < 0 {
			i = len(spec.Mounts)
		}
		spec.Mounts = slices.Insert(spec.Mounts, i, specs.Mount{
			Destination: devShm,
			Type:        "tmpfs",
			Source:      "shm",
			Options:     []string{"nosuid", "noexec", "nodev", "mode=1777", "size=65536k"},
		})
	}

	// Insert resolv.conf and hosts before any volume bind mounts.
	for _, file := range []string{resolvConf, etcHosts} {
		if slices.ContainsFunc(spec.Mounts, func(m specs.Mount) bool { return m.Destination == file }) {
			continue
		}
		i := slices.IndexFunc(spec.Mounts, func(m specs.Mount) bool { return m.Type == "bind" })
		if i < 0 {
			i = len(spec.Mounts)
		}
		// resolv.conf may come from the sandbox's own network (o.ResolvConf);
		// hosts is always the worker's.
		source := file
		if file == resolvConf && o.ResolvConf != "" {
			source = o.ResolvConf
		}
		spec.Mounts = slices.Insert(spec.Mounts, i, specs.Mount{
			Destination: file,
			Type:        "bind",
			Source:      source,
			Options:     []string{"ro"},
		})
	}

	if spec.Linux == nil {
		spec.Linux = &specs.Linux{}
	}
	// Set a colon-free default cgroupsPath relative to the pod scope.
	if spec.Linux.CgroupsPath == "" {
		spec.Linux.CgroupsPath = "/" + GVisorCgroupLeaf(o.ActorUID, o.ContainerName)
	}
	o.Size.ApplyToOCISpec(spec)
}
