package cgroup

import "testing"

func TestLabelFromPath(t *testing.T) {
	tests := []struct {
		rel  string
		want string
	}{
		{".", "host"},
		{"", "host"},
		{"system.slice/docker-abcdef123456789012345678901234567890123456789012345678901234.scope", "docker:abcdef123456"},
		{"system.slice/cri-containerd-abcdef123456789012345678901234567890.scope", "cri:abcdef123456"},
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
