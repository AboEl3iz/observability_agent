// Package app — focus ring implementation.
package app

// Focusable is the interface that widgets / views implement to participate in
// the focus ring.
type Focusable interface {
	Focus()
	Blur()
}

// FocusRing cycles focus across a fixed list of Focusable items.
type FocusRing struct {
	items   []Focusable
	current int
}

// NewFocusRing creates a ring over the given items.  The first item starts
// focused.
func NewFocusRing(items ...Focusable) *FocusRing {
	f := &FocusRing{items: items}
	if len(items) > 0 {
		items[0].Focus()
	}
	return f
}

// Next moves focus to the next item (wrapping) and returns it.
func (f *FocusRing) Next() Focusable {
	if len(f.items) == 0 {
		return nil
	}
	f.items[f.current].Blur()
	f.current = (f.current + 1) % len(f.items)
	f.items[f.current].Focus()
	return f.items[f.current]
}

// Prev moves focus to the previous item (wrapping) and returns it.
func (f *FocusRing) Prev() Focusable {
	if len(f.items) == 0 {
		return nil
	}
	f.items[f.current].Blur()
	f.current = (f.current - 1 + len(f.items)) % len(f.items)
	f.items[f.current].Focus()
	return f.items[f.current]
}

// FocusAt moves focus to the item at index i.
func (f *FocusRing) FocusAt(i int) Focusable {
	if i < 0 || i >= len(f.items) {
		return nil
	}
	f.items[f.current].Blur()
	f.current = i
	f.items[f.current].Focus()
	return f.items[f.current]
}

// Current returns the currently focused item without changing focus.
func (f *FocusRing) Current() Focusable {
	if len(f.items) == 0 {
		return nil
	}
	return f.items[f.current]
}

// Index returns the index of the currently focused item.
func (f *FocusRing) Index() int { return f.current }
