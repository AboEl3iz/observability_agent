package timeseries

import (
	"sync"
)

// Buffer is a generic thread-safe fixed-size circular buffer for time-series data.
type Buffer[T any] struct {
	mu   sync.RWMutex
	data []T
	head int
	size int
	cap  int
}

// NewBuffer creates a new circular buffer with the given capacity.
func NewBuffer[T any](capacity int) *Buffer[T] {
	return &Buffer[T]{
		data: make([]T, capacity),
		cap:  capacity,
	}
}

// Push adds a new item to the buffer, overwriting the oldest if at capacity.
func (b *Buffer[T]) Push(item T) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.data[b.head] = item
	b.head = (b.head + 1) % b.cap
	if b.size < b.cap {
		b.size++
	}
}

// Snapshot returns a copy of the buffer in oldest-to-newest order.
// This provides a lock-free snapshot for rendering or querying.
func (b *Buffer[T]) Snapshot() []T {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.size == 0 {
		return nil
	}

	out := make([]T, b.size)
	start := (b.head - b.size + b.cap) % b.cap
	for i := 0; i < b.size; i++ {
		out[i] = b.data[(start+i)%b.cap]
	}
	return out
}

// Clear empties the buffer.
func (b *Buffer[T]) Clear() {
	b.mu.Lock()
	defer b.mu.Unlock()
	
	b.head = 0
	b.size = 0
	// We do not reallocate the slice to avoid GC overhead.
}
