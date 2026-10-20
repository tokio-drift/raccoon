package intel

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tokio-drift/raccoon/internal/model"
)

type mockVTClient struct {
	mu     sync.Mutex
	calls  map[string]int
	lookup func(ctx context.Context, sha string) (model.Verdict, error)
}

func newMockVTClient(fn func(ctx context.Context, sha string) (model.Verdict, error)) *mockVTClient {
	return &mockVTClient{
		calls:  make(map[string]int),
		lookup: fn,
	}
}

func (m *mockVTClient) Lookup(ctx context.Context, sha string) (model.Verdict, error) {
	m.mu.Lock()
	m.calls[sha]++
	m.mu.Unlock()
	return m.lookup(ctx, sha)
}

func (m *mockVTClient) callCount(sha string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls[sha]
}

func TestTokenBucket(t *testing.T) {
	// Rate of 6000/min = 100/sec, burst 1
	tb := NewTokenBucket(6000, 1)

	ctx := context.Background()
	// First token should be immediately available.
	if err := tb.Wait(ctx); err != nil {
		t.Fatalf("Wait 1: %v", err)
	}

	// Second token should succeed quickly given 100/sec rate.
	start := time.Now()
	if err := tb.Wait(ctx); err != nil {
		t.Fatalf("Wait 2: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Errorf("Wait 2 took too long: %v", elapsed)
	}

	// Cancelled context should abort immediately.
	cancelCtx, cancel := context.WithCancel(ctx)
	cancel()
	if err := tb.Wait(cancelCtx); !errors.Is(err, context.Canceled) {
		t.Errorf("Wait on canceled context: got %v, want context.Canceled", err)
	}
}

func TestQueueEnqueueDeduplication(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	q := NewQueue(ctx, QueueConfig{
		RatePerMinute: 6000,
	})
	defer q.Stop()

	sha := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if !q.Enqueue(sha) {
		t.Fatal("first enqueue should return true")
	}
	if q.Enqueue(sha) {
		t.Fatal("second enqueue of same hash should return false (duplicate)")
	}
	// Case-insensitive deduplication
	shaUpper := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if q.Enqueue(shaUpper) {
		t.Fatal("uppercase version of same hash should return false (duplicate)")
	}

	if !q.IsEnqueued(sha) {
		t.Fatal("IsEnqueued should be true")
	}

	// Empty string should be rejected
	if q.Enqueue("") {
		t.Fatal("empty hash should return false")
	}
}

func TestQueueSuccessfulLookup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sha := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	mock := newMockVTClient(func(ctx context.Context, s string) (model.Verdict, error) {
		return model.Verdict{
			SHA256:    s,
			Source:    "virustotal",
			Status:    "malicious",
			Score:     4,
			Total:     70,
			CheckedAt: time.Now().UnixNano(),
		}, nil
	})

	cache := NewCache(nil, time.Hour)
	var gotVerdict model.Verdict
	done := make(chan struct{})

	q := NewQueue(ctx, QueueConfig{
		Client:        mock,
		Cache:         cache,
		RatePerMinute: 60000, // fast for testing
		OnVerdict: func(v model.Verdict) {
			gotVerdict = v
			close(done)
		},
	})
	defer q.Stop()

	if !q.Enqueue(sha) {
		t.Fatal("enqueue failed")
	}

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for verdict")
	}

	if gotVerdict.Status != "malicious" || gotVerdict.SHA256 != sha {
		t.Errorf("unexpected verdict: %+v", gotVerdict)
	}

	// Verify cached
	cached, ok, err := cache.Get(sha, "virustotal")
	if err != nil || !ok || cached.Status != "malicious" {
		t.Errorf("verdict was not properly cached: ok=%v, err=%v, cached=%+v", ok, err, cached)
	}
}

func TestQueueCachedBypass(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sha := "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	cache := NewCache(nil, time.Hour)
	_ = cache.Put(model.Verdict{
		SHA256:    sha,
		Source:    "virustotal",
		Status:    "no_detections",
		CheckedAt: time.Now().UnixNano(),
	})

	mock := newMockVTClient(func(ctx context.Context, s string) (model.Verdict, error) {
		t.Error("client.Lookup should not be called when verdict is cached")
		return model.Verdict{}, nil
	})

	done := make(chan struct{})
	var gotVerdict model.Verdict

	q := NewQueue(ctx, QueueConfig{
		Client:        mock,
		Cache:         cache,
		RatePerMinute: 60000,
		OnVerdict: func(v model.Verdict) {
			gotVerdict = v
			close(done)
		},
	})
	defer q.Stop()

	q.Enqueue(sha)

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for cached verdict callback")
	}

	if gotVerdict.Status != "no_detections" {
		t.Errorf("got status %q, want \"no_detections\"", gotVerdict.Status)
	}
	if mock.callCount(sha) != 0 {
		t.Errorf("expected 0 client calls, got %d", mock.callCount(sha))
	}
}

func TestQueueNotFoundTerminal(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sha := "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	mock := newMockVTClient(func(ctx context.Context, s string) (model.Verdict, error) {
		return model.Verdict{
			SHA256:    s,
			Source:    "virustotal",
			Status:    "unknown",
			CheckedAt: time.Now().UnixNano(),
		}, ErrVTNotFound
	})

	done := make(chan struct{})
	var gotVerdict model.Verdict

	q := NewQueue(ctx, QueueConfig{
		Client:        mock,
		RatePerMinute: 60000,
		OnVerdict: func(v model.Verdict) {
			gotVerdict = v
			close(done)
		},
	})
	defer q.Stop()

	q.Enqueue(sha)

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for 404 verdict callback")
	}

	if gotVerdict.Status != "unknown" {
		t.Errorf("expected status \"unknown\", got %q", gotVerdict.Status)
	}
	if mock.callCount(sha) != 1 {
		t.Errorf("expected exactly 1 call (no retries for 404), got %d", mock.callCount(sha))
	}
}

func TestQueueRetryWithBackoff(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sha := "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	var attempts int32
	mock := newMockVTClient(func(ctx context.Context, s string) (model.Verdict, error) {
		att := atomic.AddInt32(&attempts, 1)
		if att < 3 {
			return model.Verdict{}, ErrVTRetryable
		}
		return model.Verdict{
			SHA256:    s,
			Source:    "virustotal",
			Status:    "suspicious",
			CheckedAt: time.Now().UnixNano(),
		}, nil
	})

	done := make(chan struct{})
	var gotVerdict model.Verdict

	q := NewQueue(ctx, QueueConfig{
		Client:         mock,
		RatePerMinute:  60000,
		InitialBackoff: 10 * time.Millisecond,
		MaxBackoff:     50 * time.Millisecond,
		MaxRetries:     5,
		OnVerdict: func(v model.Verdict) {
			gotVerdict = v
			close(done)
		},
	})
	defer q.Stop()

	q.Enqueue(sha)

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for retry success")
	}

	if gotVerdict.Status != "suspicious" {
		t.Errorf("expected status \"suspicious\", got %q", gotVerdict.Status)
	}
	if mock.callCount(sha) != 3 {
		t.Errorf("expected 3 calls (2 retries + 1 success), got %d", mock.callCount(sha))
	}
}

func TestQueueExhaustRetries(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sha := "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	mock := newMockVTClient(func(ctx context.Context, s string) (model.Verdict, error) {
		return model.Verdict{}, ErrVTRetryable
	})

	done := make(chan struct{})
	var gotErr error

	q := NewQueue(ctx, QueueConfig{
		Client:         mock,
		RatePerMinute:  60000,
		InitialBackoff: 5 * time.Millisecond,
		MaxBackoff:     10 * time.Millisecond,
		MaxRetries:     2,
		OnError: func(s string, err error) {
			gotErr = err
			close(done)
		},
	})
	defer q.Stop()

	q.Enqueue(sha)

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for error callback")
	}

	if !errors.Is(gotErr, ErrVTRetryable) {
		t.Errorf("expected ErrVTRetryable, got: %v", gotErr)
	}
	// Initial call + 2 retries = 3 calls
	if mock.callCount(sha) != 3 {
		t.Errorf("expected 3 calls, got %d", mock.callCount(sha))
	}
}

func TestQueueContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	q := NewQueue(ctx, QueueConfig{
		RatePerMinute: 6000,
	})

	// Cancel context immediately
	cancel()

	// Stop should complete without hanging
	stopped := make(chan struct{})
	go func() {
		q.Stop()
		close(stopped)
	}()

	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("q.Stop() hung after context cancellation")
	}
}

func TestQueueCloseDrains(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var count int32
	mock := newMockVTClient(func(ctx context.Context, s string) (model.Verdict, error) {
		atomic.AddInt32(&count, 1)
		return model.Verdict{
			SHA256:    s,
			Source:    "virustotal",
			Status:    "no_detections",
			CheckedAt: time.Now().UnixNano(),
		}, nil
	})

	q := NewQueue(ctx, QueueConfig{
		Client:        mock,
		RatePerMinute: 60000,
	})

	q.Enqueue("1111111111111111111111111111111111111111111111111111111111111111")
	q.Enqueue("2222222222222222222222222222222222222222222222222222222222222222")

	// Close should drain the two items
	q.Close()

	if atomic.LoadInt32(&count) != 2 {
		t.Errorf("expected 2 items processed on Close(), got %d", count)
	}
}
