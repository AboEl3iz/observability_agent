package cgroup

import (
	"testing"
	"time"
)

func TestLabelFromPath(t *testing.T) {
	tests := []struct {
		rel  string
		want string
	}{
		{".", "host"},
		{"", "host"},
		{"system.slice/docker-abcdef123456789012345678901234567890123456789012345678901234.scope", "docker:abcdef123456"},
		{"system.slice/cri-containerd-abcdef123456789012345678901234567890.scope", "k8s:abcdef123456"},
		{"docker/abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890", "docker:abcdef123456"},
		{"system.slice/kubepods.slice", "system.slice/kubepods.slice"},
		{"user.slice", "user.slice"},
	}

	for _, tc := range tests {
		got := labelFromPath(tc.rel)
		if got != tc.want {
			t.Errorf("labelFromPath(%q) = %q, want %q", tc.rel, got, tc.want)
		}
	}
}

func TestResolverRefreshDoesNotPanic(t *testing.T) {
	// The resolver must not panic even without Docker running.
	// It should succeed if /sys/fs/cgroup exists (requires Linux with cgroup v2).
	r := &Resolver{cache: make(map[uint64]ContainerInfo)}
	err := r.refresh()
	if err != nil {
		t.Logf("refresh error (expected in restricted CI): %v", err)
	}
}

func TestResolverEviction(t *testing.T) {
	r := &Resolver{
		cache:     make(map[uint64]ContainerInfo),
		history:   make(map[uint64]ContainerInfo),
		deletedAt: make(map[uint64]time.Time),
	}

	// 1. Put some dummy data in history and deletedAt
	id1 := uint64(100)
	id2 := uint64(200)

	r.history[id1] = ContainerInfo{CgroupID: id1, Name: "container-1"}
	r.deletedAt[id1] = time.Now().Add(-30 * time.Second) // older than 2 cycles (20s)

	r.history[id2] = ContainerInfo{CgroupID: id2, Name: "container-2"}
	r.deletedAt[id2] = time.Now() // fresh

	// 2. Run eviction
	r.evictStaleEntries()

	// 3. Verify container-1 is evicted and container-2 is kept
	if _, ok := r.history[id1]; ok {
		t.Errorf("expected container-1 to be evicted from history")
	}
	if _, ok := r.deletedAt[id1]; ok {
		t.Errorf("expected container-1 to be evicted from deletedAt")
	}

	if _, ok := r.history[id2]; !ok {
		t.Errorf("expected container-2 to be preserved in history")
	}
	if _, ok := r.deletedAt[id2]; !ok {
		t.Errorf("expected container-2 to be preserved in deletedAt")
	}
}
