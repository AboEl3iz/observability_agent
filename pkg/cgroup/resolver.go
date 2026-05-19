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
	"bufio"
	"context"
	"crypto/tls"
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
	// For K8s containers it will contain namespace/pod/container.
	// For bare processes it will reflect their cgroup slice/unit name.
	Name string
	// CgroupPath is the relative path under /sys/fs/cgroup.
	CgroupPath string

	// Kubernetes-specific metadata
	Namespace string
	Pod       string
	Container string
}

type kubeletPodList struct {
	Items []struct {
		Metadata struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
			UID       string `json:"uid"`
		} `json:"metadata"`
		Status struct {
			ContainerStatuses []struct {
				Name        string `json:"name"`
				ContainerID string `json:"containerID"`
			} `json:"containerStatuses"`
			InitContainerStatuses []struct {
				Name        string `json:"name"`
				ContainerID string `json:"containerID"`
			} `json:"initContainerStatuses"`
			EphemeralContainerStatuses []struct {
				Name        string `json:"name"`
				ContainerID string `json:"containerID"`
			} `json:"ephemeralContainerStatuses"`
		} `json:"status"`
	} `json:"items"`
}

type K8sInfo struct {
	Namespace string
	Pod       string
	Container string
}

// Resolver maps cgroup_id → ContainerInfo.
// The zero value is safe to use as a no-op resolver (all Lookups return false).
type Resolver struct {
	mu          sync.RWMutex
	cache       map[uint64]ContainerInfo
	history     map[uint64]ContainerInfo // historical cache of recently deleted cgroup IDs
	deletedAt   map[uint64]time.Time     // tracks when a cgroup ID was moved to history
	lastRefresh time.Time
	k8sCache    map[string]K8sInfo

	// k8sMode accelerates refresh rate and enables kubelet enrichment logging.
	k8sMode       bool
	refreshPeriodD time.Duration // dynamic refresh period (set by SetK8sMode)
}

// NewResolver creates a Resolver and performs the initial scan.
func NewResolver() (*Resolver, error) {
	r := &Resolver{
		cache:          make(map[uint64]ContainerInfo),
		history:        make(map[uint64]ContainerInfo),
		deletedAt:      make(map[uint64]time.Time),
		k8sCache:       make(map[string]K8sInfo),
		refreshPeriodD: refreshPeriod,
	}
	if err := r.refresh(); err != nil {
		return nil, fmt.Errorf("initial cgroup scan failed: %w", err)
	}
	go r.backgroundRefresh()
	go r.backgroundEviction()
	return r, nil
}

// SetK8sMode enables Kubernetes-optimised behaviour:
//   - Refresh rate drops from 10s → 2s to handle fast pod churn
//   - Kubelet enrichment failures are logged as warnings (instead of silently ignored)
func (r *Resolver) SetK8sMode(enabled bool) {
	r.mu.Lock()
	r.k8sMode = enabled
	if enabled {
		r.refreshPeriodD = 2 * time.Second
	} else {
		r.refreshPeriodD = refreshPeriod
	}
	r.mu.Unlock()
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
	if !ok && r.history != nil {
		info, ok = r.history[cgroupID]
	}
	stale := time.Since(r.lastRefresh) > staleness
	r.mu.RUnlock()

	if !ok && stale {
		// Trigger a refresh and retry once
		_ = r.refresh()
		r.mu.RLock()
		info, ok = r.cache[cgroupID]
		if !ok && r.history != nil {
			info, ok = r.history[cgroupID]
		}
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
	freshK8s := make(map[string]K8sInfo)
	if podList, err := fetchKubeletPods(); err == nil {
		for _, pod := range podList.Items {
			ns := pod.Metadata.Namespace
			podName := pod.Metadata.Name

			// Process standard containers, init containers, and ephemeral containers
			for _, c := range pod.Status.ContainerStatuses {
				cID := cleanContainerID(c.ContainerID)
				if cID != "" {
					freshK8s[cID] = K8sInfo{Namespace: ns, Pod: podName, Container: c.Name}
					if len(cID) > 12 {
						freshK8s[cID[:12]] = K8sInfo{Namespace: ns, Pod: podName, Container: c.Name}
					}
				}
			}
			for _, c := range pod.Status.InitContainerStatuses {
				cID := cleanContainerID(c.ContainerID)
				if cID != "" {
					freshK8s[cID] = K8sInfo{Namespace: ns, Pod: podName, Container: c.Name}
					if len(cID) > 12 {
						freshK8s[cID[:12]] = K8sInfo{Namespace: ns, Pod: podName, Container: c.Name}
					}
				}
			}
			for _, c := range pod.Status.EphemeralContainerStatuses {
				cID := cleanContainerID(c.ContainerID)
				if cID != "" {
					freshK8s[cID] = K8sInfo{Namespace: ns, Pod: podName, Container: c.Name}
					if len(cID) > 12 {
						freshK8s[cID[:12]] = K8sInfo{Namespace: ns, Pod: podName, Container: c.Name}
					}
				}
			}
		}
	}

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

		info := ContainerInfo{
			CgroupID:   cgroupID,
			Name:       name,
			CgroupPath: rel,
		}

		// Try to enrich using K8s metadata
		cID := extractContainerID(rel)
		if cID != "" {
			if k, ok := freshK8s[cID]; ok {
				info.Name = fmt.Sprintf("%s/%s/%s", k.Namespace, k.Pod, k.Container)
				info.Namespace = k.Namespace
				info.Pod = k.Pod
				info.Container = k.Container
			} else if len(cID) > 12 {
				if k, ok := freshK8s[cID[:12]]; ok {
					info.Name = fmt.Sprintf("%s/%s/%s", k.Namespace, k.Pod, k.Container)
					info.Namespace = k.Namespace
					info.Pod = k.Pod
					info.Container = k.Container
				}
			}
		}

		fresh[cgroupID] = info
		return nil
	})
	if err != nil {
		return err
	}

	r.mu.Lock()
	if r.history == nil {
		r.history = make(map[uint64]ContainerInfo)
	}
	if r.deletedAt == nil {
		r.deletedAt = make(map[uint64]time.Time)
	}
	// Move newly deleted/unlisted cgroups from active cache into history
	for id, info := range r.cache {
		if _, exists := fresh[id]; !exists {
			r.history[id] = info
			r.deletedAt[id] = time.Now()
		}
	}
	// Clean up deletedAt if an ID was resurrected
	for id := range fresh {
		delete(r.deletedAt, id)
	}
	// Limit historical cache size to prevent memory growth
	if len(r.history) > 1000 {
		for id := range r.history {
			delete(r.history, id)
			delete(r.deletedAt, id)
			if len(r.history) <= 1000 {
				break
			}
		}
	}
	r.cache = fresh
	r.k8sCache = freshK8s
	r.lastRefresh = time.Now()
	r.mu.Unlock()
	return nil
}

func (r *Resolver) backgroundRefresh() {
	// Use a short initial period; re-evaluate after each tick based on k8sMode.
	ticker := time.NewTicker(refreshPeriod)
	defer ticker.Stop()
	for range ticker.C {
		r.mu.RLock()
		period := r.refreshPeriodD
		r.mu.RUnlock()
		ticker.Reset(period)
		_ = r.refresh()
	}
}

func (r *Resolver) backgroundEviction() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		r.evictStaleEntries()
	}
}

func (r *Resolver) evictStaleEntries() {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	ttl := 2 * refreshPeriod // 2 cycles = 20 seconds

	for id, deletedTime := range r.deletedAt {
		if now.Sub(deletedTime) >= ttl {
			delete(r.history, id)
			delete(r.deletedAt, id)
		}
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
			return "k8s:" + id[:12]
		}
		return "k8s:" + id
	}

	// crio/k8s: "crio-<id>.scope"
	if strings.HasPrefix(last, "crio-") && strings.HasSuffix(last, ".scope") {
		id := strings.TrimPrefix(last, "crio-")
		id = strings.TrimSuffix(id, ".scope")
		if len(id) >= 12 {
			return "k8s:" + id[:12]
		}
		return "k8s:" + id
	}

	// K8s pod directories (e.g. kubepods.slice/kubepods-pod<id>.slice/docker-<id>.scope or cri-containerd)
	// Some systems use purely <id> inside pod scopes. We can check if it's inside a kubepods slice.
	isK8s := false
	for _, part := range parts {
		if strings.HasPrefix(part, "kubepods") {
			isK8s = true
			break
		}
	}

	// Plain docker path: parent dir is "docker", last is full id
	if len(parts) >= 2 && parts[len(parts)-2] == "docker" {
		prefix := "docker:"
		if isK8s {
			prefix = "k8s:"
		}
		if len(last) >= 12 {
			return prefix + last[:12]
		}
		return prefix + last
	}

	// CRI-O plain path (sometimes just ID inside pod folder)
	if isK8s && len(last) == 64 {
		return "k8s:" + last[:12]
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

func getKubeletClient() (*http.Client, string) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Timeout: 500 * time.Millisecond, Transport: tr}

	// 1. Try ServiceAccount Token (in-cluster pod deployment)
	tokenFile := "/var/run/secrets/kubernetes.io/serviceaccount/token"
	if token, err := os.ReadFile(tokenFile); err == nil {
		return client, "Bearer " + strings.TrimSpace(string(token))
	}

	// 2. Try Host-level Kubelet Client PEM (Systemd native on EKS / Kubeadm nodes)
	pemPath := "/var/lib/kubelet/pki/kubelet-client-current.pem"
	if _, err := os.Stat(pemPath); err == nil {
		if cert, err := tls.LoadX509KeyPair(pemPath, pemPath); err == nil {
			tr.TLSClientConfig.Certificates = []tls.Certificate{cert}
			return client, ""
		}
	}

	// 3. Try parsing host-level kubelet kubeconfig for token (bootstrapped nodes)
	kubeconfigPaths := []string{
		"/var/lib/kubelet/kubeconfig",
		"/etc/kubernetes/kubelet/kubeconfig",
	}
	for _, kPath := range kubeconfigPaths {
		if data, err := os.ReadFile(kPath); err == nil {
			scanner := bufio.NewScanner(strings.NewReader(string(data)))
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if strings.HasPrefix(line, "token:") {
					token := strings.TrimSpace(strings.TrimPrefix(line, "token:"))
					token = strings.Trim(token, `"'`)
					if token != "" {
						return client, "Bearer " + token
					}
				}
			}
		}
	}

	return client, ""
}

func fetchKubeletPods() (*kubeletPodList, error) {
	// 1. Try local containerd task configs (OCI specs) first — fast, secure, offline
	if list, err := fetchKubeletPodsFromTaskConfig(); err == nil && len(list.Items) > 0 {
		return list, nil
	}

	// Fallback to Kubelet API
	nodeIP := os.Getenv("NODE_IP")
	if nodeIP == "" {
		nodeIP = "127.0.0.1"
	}

	// Try HTTP first (read-only port)
	client := &http.Client{Timeout: 500 * time.Millisecond}
	resp, err := client.Get(fmt.Sprintf("http://%s:10255/pods", nodeIP))
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			var list kubeletPodList
			if err := json.NewDecoder(resp.Body).Decode(&list); err == nil {
				return &list, nil
			}
		}
	}

	// Try HTTPS with dynamically resolved authentication client (token / client certs)
	clientSec, authHeader := getKubeletClient()
	req, err := http.NewRequest("GET", fmt.Sprintf("https://%s:10250/pods", nodeIP), nil)
	if err != nil {
		return nil, err
	}
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}

	respSec, err := clientSec.Do(req)
	if err == nil {
		defer respSec.Body.Close()
		if respSec.StatusCode == http.StatusOK {
			var list kubeletPodList
			if err := json.NewDecoder(respSec.Body).Decode(&list); err == nil {
				return &list, nil
			}
		}
	}

	return nil, fmt.Errorf("could not reach kubelet /pods API at %s", nodeIP)
}

func fetchKubeletPodsFromTaskConfig() (*kubeletPodList, error) {
	taskPath := "/run/containerd/io.containerd.runtime.v2.task/k8s.io"
	entries, err := os.ReadDir(taskPath)
	if err != nil {
		return nil, err
	}

	type podGroup struct {
		Name       string
		Namespace  string
		UID        string
		Containers []struct {
			Name string
			ID   string
		}
	}
	podMap := make(map[string]*podGroup)

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		cID := entry.Name()
		configPath := filepath.Join(taskPath, cID, "config.json")
		data, err := os.ReadFile(configPath)
		if err != nil {
			continue
		}

		var spec struct {
			Annotations map[string]string `json:"annotations"`
		}
		if err := json.Unmarshal(data, &spec); err != nil {
			continue
		}

		if spec.Annotations == nil {
			continue
		}

		podName := spec.Annotations["io.kubernetes.cri.sandbox-name"]
		podNS := spec.Annotations["io.kubernetes.cri.sandbox-namespace"]
		podUID := spec.Annotations["io.kubernetes.cri.sandbox-uid"]
		containerName := spec.Annotations["io.kubernetes.cri.container-name"]

		if podName == "" {
			podName = spec.Annotations["io.kubernetes.pod.name"]
		}
		if podNS == "" {
			podNS = spec.Annotations["io.kubernetes.pod.namespace"]
		}
		if podUID == "" {
			podUID = spec.Annotations["io.kubernetes.pod.uid"]
		}
		containerType := spec.Annotations["io.kubernetes.cri.container-type"]
		if containerName == "" {
			if containerType == "sandbox" {
				containerName = "sandbox"
			} else {
				containerName = spec.Annotations["io.kubernetes.container.name"]
			}
		}

		if podName != "" && podNS != "" {
			podKey := podNS + "/" + podName
			p, exists := podMap[podKey]
			if !exists {
				p = &podGroup{
					Name:      podName,
					Namespace: podNS,
					UID:       podUID,
				}
				podMap[podKey] = p
			}
			p.Containers = append(p.Containers, struct {
				Name string
				ID   string
			}{
				Name: containerName,
				ID:   "containerd://" + cID,
			})
		}
	}

	var list kubeletPodList
	for _, p := range podMap {
		var item struct {
			Metadata struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
				UID       string `json:"uid"`
			} `json:"metadata"`
			Status struct {
				ContainerStatuses []struct {
					Name        string `json:"name"`
					ContainerID string `json:"containerID"`
				} `json:"containerStatuses"`
				InitContainerStatuses []struct {
					Name        string `json:"name"`
					ContainerID string `json:"containerID"`
				} `json:"initContainerStatuses"`
				EphemeralContainerStatuses []struct {
					Name        string `json:"name"`
					ContainerID string `json:"containerID"`
				} `json:"ephemeralContainerStatuses"`
			} `json:"status"`
		}
		item.Metadata.Name = p.Name
		item.Metadata.Namespace = p.Namespace
		item.Metadata.UID = p.UID

		for _, c := range p.Containers {
			item.Status.ContainerStatuses = append(item.Status.ContainerStatuses, struct {
				Name        string `json:"name"`
				ContainerID string `json:"containerID"`
			}{
				Name:        c.Name,
				ContainerID: c.ID,
			})
		}
		list.Items = append(list.Items, item)
	}

	return &list, nil
}

func extractContainerID(rel string) string {
	parts := strings.Split(rel, "/")
	if len(parts) == 0 {
		return ""
	}
	last := parts[len(parts)-1]

	// Strip prefixes and suffixes
	// cri-containerd-<id>.scope
	if strings.HasPrefix(last, "cri-containerd-") && strings.HasSuffix(last, ".scope") {
		id := strings.TrimPrefix(last, "cri-containerd-")
		return strings.TrimSuffix(id, ".scope")
	}
	// crio-<id>.scope
	if strings.HasPrefix(last, "crio-") && strings.HasSuffix(last, ".scope") {
		id := strings.TrimPrefix(last, "crio-")
		return strings.TrimSuffix(id, ".scope")
	}
	// docker-<id>.scope
	if strings.HasPrefix(last, "docker-") && strings.HasSuffix(last, ".scope") {
		id := strings.TrimPrefix(last, "docker-")
		return strings.TrimSuffix(id, ".scope")
	}
	// plain 64-char hex
	if len(last) == 64 {
		return last
	}
	return ""
}

func cleanContainerID(id string) string {
	if idx := strings.Index(id, "://"); idx != -1 {
		id = id[idx+3:]
	}
	return id
}
