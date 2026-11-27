package ptyrec

import (
	"sync"
	"sync/atomic"

	"github.com/bonjoski/tinmind/pkg/trace"
)

// DefaultRingCapacityBytes caps the in-memory non-blocking PTY ring buffer at 16 MiB.
const DefaultRingCapacityBytes = 16 * 1024 * 1024

type ringNode struct {
	ev   trace.Event
	size int
}

// RingBuffer is a bounded, non-blocking circular buffer that decouples PTY forwarding
// from pre-disk secret redaction and zstd compression. If disk I/O stalls, Push drops
// the oldest queued chunk and increments DroppedChunks without ever blocking the child PTY.
type RingBuffer struct {
	mu       sync.Mutex
	cond     *sync.Cond
	items    []ringNode
	head     int
	count    int
	maxBytes int
	curBytes int
	closed   bool

	dropped atomic.Uint64
	written atomic.Uint64
}

// NewRingBuffer creates a circular ring buffer with the given byte budget (default 16 MiB).
func NewRingBuffer(maxBytes int) *RingBuffer {
	if maxBytes <= 0 {
		maxBytes = DefaultRingCapacityBytes
	}
	rb := &RingBuffer{
		items:    make([]ringNode, 256),
		maxBytes: maxBytes,
	}
	rb.cond = sync.NewCond(&rb.mu)
	return rb
}

// Push enqueues ev without blocking. If the byte cap would be exceeded, the oldest
// unread chunks are evicted and DroppedChunks is incremented.
func (r *RingBuffer) Push(ev trace.Event) bool {
	sz := estimateEventSize(ev)

	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return false
	}

	// Single event larger than entire ring budget: drop rather than stall.
	if sz > r.maxBytes {
		r.mu.Unlock()
		r.dropped.Add(1)
		return false
	}

	// Evict oldest items until there is byte headroom.
	for r.count > 0 && r.curBytes+sz > r.maxBytes {
		old := r.items[r.head]
		r.items[r.head] = ringNode{}
		r.head = (r.head + 1) % len(r.items)
		r.count--
		r.curBytes -= old.size
		r.dropped.Add(1)
	}

	if r.count == len(r.items) {
		r.growLocked()
	}

	tail := (r.head + r.count) % len(r.items)
	r.items[tail] = ringNode{ev: ev, size: sz}
	r.count++
	r.curBytes += sz
	r.mu.Unlock()

	r.cond.Signal()
	return true
}

func (r *RingBuffer) growLocked() {
	newCap := len(r.items) * 2
	if newCap > 65536 {
		// Cap slot growth; evict oldest to stay bounded.
		old := r.items[r.head]
		r.items[r.head] = ringNode{}
		r.head = (r.head + 1) % len(r.items)
		r.count--
		r.curBytes -= old.size
		r.dropped.Add(1)
		return
	}
	next := make([]ringNode, newCap)
	for i := 0; i < r.count; i++ {
		next[i] = r.items[(r.head+i)%len(r.items)]
	}
	r.items = next
	r.head = 0
}

// Pop blocks until an event is available or the ring is closed and drained.
func (r *RingBuffer) Pop() (trace.Event, bool) {
	r.mu.Lock()
	for r.count == 0 && !r.closed {
		r.cond.Wait()
	}
	if r.count == 0 {
		r.mu.Unlock()
		return trace.Event{}, false
	}
	node := r.items[r.head]
	r.items[r.head] = ringNode{}
	r.head = (r.head + 1) % len(r.items)
	r.count--
	r.curBytes -= node.size
	r.mu.Unlock()
	r.written.Add(1)
	return node.ev, true
}

// Close marks the ring closed and wakes the consumer so remaining events drain cleanly.
func (r *RingBuffer) Close() {
	r.mu.Lock()
	r.closed = true
	r.mu.Unlock()
	r.cond.Broadcast()
}

// DroppedChunks returns the total number of chunks evicted due to backpressure.
func (r *RingBuffer) DroppedChunks() uint64 { return r.dropped.Load() }

// WrittenChunks returns the total number of chunks popped by the consumer.
func (r *RingBuffer) WrittenChunks() uint64 { return r.written.Load() }

func estimateEventSize(ev trace.Event) int {
	return 128 + len(ev.Data) + len(ev.Command) + len(ev.Stdout) + len(ev.Stderr) + len(ev.Cwd)
}
