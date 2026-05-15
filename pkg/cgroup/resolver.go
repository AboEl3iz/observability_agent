// Package cgroup resolves cgroup_id → container metadata.
//
// M0: Cgroup Scoping Foundation
//
// Strategy:
//   We walk /sys/fs/cgroup (cgroup v2 unified hierarchy) and collect
//   per-directory inode numbers. The inode number of a cgroup directory
//   equals the cgroup_id returned by bpf_get_current_cgroup_id().
//
//   Refresh is triggered on demand if the cache is stale (> 5 seconds).
//   A background goroutine also refreshes every 10 seconds.
package cgroup

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	cgroupRoot    = "/sys/fs/cgroup"
	refreshPeriod = 10 * time.Second
	staleness     = 100 * time.Millisecond
)

// ContainerInfo holds the resolved metadata for a cgroup.
type ContainerInfo struct {
	// CgroupID is the numeric id as returned by bpf_get_current_cgroup_id().
	CgroupID uint64
	// Name is a human friendly label derived from the cgroup path.
	// For Docker containers it will contain the short container ID.
	// For bare processes it will reflect their cgroup slice/unit name.
	Name string
	// CgroupPath is the relative path under /sys/fs/cgroup.
	CgroupPath string
}

// Resolver maps cgroup_id → ContainerInfo.
// The zero value is safe to use as a no-op resolver (all Lookups return false).
type Resolver struct {
	mu          sync.RWMutex
	cache       map[uint64]ContainerInfo
	lastRefresh time.Time
}

// NewResolver creates a Resolver and performs the initial scan.
func NewResolver() (*Resolver, error) {
	r := &Resolver{
		cache: make(map[uint64]ContainerInfo),
	}
	if err := r.refresh(); err != nil {
		return nil, fmt.Errorf("initial cgroup scan failed: %w", err)
	}
	go r.backgroundRefresh()
	return r, nil
}

// Lookup returns the ContainerInfo for a given cgroup_id.
// Returns a not-found result if the resolver is empty or the id is unknown.
func (r *Resolver) Lookup(cgroupID uint64) (ContainerInfo, bool) {
	r.mu.RLock()
	if r.cache == nil {
		r.mu.RUnlock()
		return ContainerInfo{}, false
	}
	info, ok := r.cache[cgroupID]
	stale := time.Since(r.lastRefresh) > staleness
	r.mu.RUnlock()

	if !ok && stale {
		// Trigger a refresh and retry once
		_ = r.refresh()
		r.mu.RLock()
		info, ok = r.cache[cgroupID]
		r.mu.RUnlock()
	}
	return info, ok
}

// All returns a snapshot of all known cgroup mappings.
func (r *Resolver) All() map[uint64]ContainerInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[uint64]ContainerInfo, len(r.cache))
	for k, v := range r.cache {
		out[k] = v
	}
	return out
}

// refresh walks the cgroup v2 hierarchy and updates the cache.
func (r *Resolver) refresh() error {
	fresh := make(map[uint64]ContainerInfo)

	err := filepath.WalkDir(cgroupRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			// Skip unreadable subtrees
			return filepath.SkipDir
		}
		if !d.IsDir() {
			return nil
		}

		var stat syscall.Stat_t
		if err := syscall.Stat(path, &stat); err != nil {
			return nil
		}

		cgroupID := stat.Ino
		rel, _ := filepath.Rel(cgroupRoot, path)
		name := labelFromPath(rel)

		fresh[cgroupID] = ContainerInfo{
			CgroupID:   cgroupID,
			Name:       name,
			CgroupPath: rel,
		}
		return nil
	})
	if err != nil {
		return err
	}

	r.mu.Lock()
	r.cache = fresh
	r.lastRefresh = time.Now()
	r.mu.Unlock()
	return nil
}

func (r *Resolver) backgroundRefresh() {
	ticker := time.NewTicker(refreshPeriod)
	defer ticker.Stop()
	for range ticker.C {
		_ = r.refresh()
	}
}

// BootTimeOffset computes the nanosecond offset to convert bpf_ktime_get_ns()
// values (nanoseconds since boot) to wall-clock UTC nanoseconds.
//
// Formula: wall_ns = ktime_ns + BootTimeOffset()
//
// Implementation: reads the "btime" field from /proc/stat which contains the
// Unix epoch time (seconds) of the system boot. This is the most reliable
// method — it matches exactly how the kernel computes monotonic-to-wall offsets.
//
// Called once at agent startup and the result passed to all security collectors.
// Never call per-event — the offset is stable for the lifetime of the agent.
func BootTimeOffset() (int64, error) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, fmt.Errorf("reading /proc/stat: %w", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "btime ") {
			continue
		}
		var bootSec int64
		if _, err := fmt.Sscanf(line, "btime %d", &bootSec); err != nil {
			return 0, fmt.Errorf("parsing btime from /proc/stat: %w", err)
		}
		// bootTimeNs is the wall-clock Unix time at boot in nanoseconds.
		// offset = boot_epoch_ns - 0 (ktime at boot is 0)
		// For any ktime_ns: wall_ns = boot_epoch_ns + ktime_ns
		return bootSec * int64(time.Second), nil
	}
	return 0, fmt.Errorf("btime not found in /proc/stat")
}

// labelFromPath derives a human-readable label from the cgroup relative path.
//
// Docker uses paths like:
//
//	system.slice/docker-<64-char-id>.scope
//	docker/<64-char-id>
//
// We extract a short 12-char container ID when one is present, otherwise we
// return the last two path components as a readable label.
func labelFromPath(rel string) string {
	if rel == "." || rel == "" {
		return "host"
	}

	parts := strings.Split(rel, "/")
	last := parts[len(parts)-1]

	// Docker scope: "docker-<id>.scope"
	if strings.HasPrefix(last, "docker-") && strings.HasSuffix(last, ".scope") {
		id := strings.TrimPrefix(last, "docker-")
		id = strings.TrimSuffix(id, ".scope")
		if name := fetchDockerName(id); name != "" {
			return "docker:" + name
		}
		if len(id) >= 12 {
			return "docker:" + id[:12]
		}
		return "docker:" + id
	}

	// containerd/k8s: "cri-containerd-<id>.scope"
	if strings.HasPrefix(last, "cri-containerd-") && strings.HasSuffix(last, ".scope") {
		id := strings.TrimPrefix(last, "cri-containerd-")
		id = strings.TrimSuffix(id, ".scope")
		if len(id) >= 12 {
			return "cri:" + id[:12]
		}
		return "cri:" + id
	}

	// Plain docker path: parent dir is "docker", last is full id
	if len(parts) >= 2 && parts[len(parts)-2] == "docker" {
		if len(last) >= 12 {
			return "docker:" + last[:12]
		}
		return "docker:" + last
	}

	// Fall back: join last two components
	if len(parts) >= 2 {
		return parts[len(parts)-2] + "/" + last
	}
	return last
}

func fetchDockerName(id string) string {
	client := http.Client{
		Timeout: 200 * time.Millisecond,
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", "/var/run/docker.sock")
			},
		},
	}
	resp, err := client.Get("http://localhost/containers/" + id + "/json")
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	var result struct {
		Name string `json:"Name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return ""
	}
	return strings.TrimPrefix(result.Name, "/")
}
