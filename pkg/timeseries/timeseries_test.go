package timeseries

import (
	"reflect"
	"sync"
	"testing"
)

func TestBuffer_PushAndSnapshot(t *testing.T) {
	buf := NewBuffer[int](3)

	// Test pushing up to capacity
	buf.Push(1)
	buf.Push(2)
	buf.Push(3)

	snap1 := buf.Snapshot()
	expected1 := []int{1, 2, 3}
	if !reflect.DeepEqual(snap1, expected1) {
		t.Errorf("Expected %v, got %v", expected1, snap1)
	}

	// Test overwriting oldest (wrap-around)
	buf.Push(4)
	buf.Push(5)

	snap2 := buf.Snapshot()
	expected2 := []int{3, 4, 5} // 1 and 2 should be overwritten
	if !reflect.DeepEqual(snap2, expected2) {
		t.Errorf("Expected %v, got %v", expected2, snap2)
	}
}

func TestBuffer_Empty(t *testing.T) {
	buf := NewBuffer[string](5)
	if len(buf.Snapshot()) != 0 {
		t.Errorf("Expected empty snapshot for new buffer")
	}
}

func TestBuffer_Race(t *testing.T) {
	buf := NewBuffer[int](100)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			buf.Push(i)
		}
	}()

	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			_ = buf.Snapshot()
		}
	}()

	wg.Wait()
}
