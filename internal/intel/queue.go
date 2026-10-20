package intel

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/tokio-drift/raccoon/internal/limits"
	"github.com/tokio-drift/raccoon/internal/model"
)

// ErrQueueClosed is returned when an operation cannot be completed because
// the queue is closed.
var ErrQueueClosed = errors.New("intel: queue closed")

// ErrNoClient is returned when a lookup is attempted without a configured VTClient.
var ErrNoClient = errors.New("intel: virustotal client is nil")

// TokenBucket implements a token bucket rate limiter for pacing API requests.
type TokenBucket struct {
	mu       sync.Mutex
	capacity float64
	tokens   float64
	rate     float64 // tokens per second
	last     time.Time
}

// NewTokenBucket creates a TokenBucket with the given rate in requests per minute
// and maximum burst capacity. If ratePerMinute <= 0, limits.VTRatePerMinute (4) is used.
// If burst <= 0, burst defaults to 1.
func NewTokenBucket(ratePerMinute, burst int) *TokenBucket {
	if ratePerMinute <= 0 {
		ratePerMinute = limits.VTRatePerMinute
	}
	if burst <= 0 {
		burst = 1
	}
	rate := float64(ratePerMinute) / 60.0
	return &TokenBucket{
		capacity: float64(burst),
		tokens:   float64(burst),
		rate:     rate,
		last:     time.Now(),
	}
}

// Wait blocks until one token is available or until ctx is cancelled.
func (tb *TokenBucket) Wait(ctx context.Context) error {
	for {
		tb.mu.Lock()
		now := time.Now()
		elapsed := now.Sub(tb.last).Seconds()
		tb.tokens += elapsed * tb.rate
		if tb.tokens > tb.capacity {
			tb.tokens = tb.capacity
		}
		tb.last = now

		if tb.tokens >= 1.0 {
			tb.tokens -= 1.0
			tb.mu.Unlock()
			return nil
		}

		needed := 1.0 - tb.tokens
		sleepSec := needed / tb.rate
		sleepDur := time.Duration(sleepSec * float64(time.Second))
		tb.mu.Unlock()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(sleepDur):
		}
	}
}

// VTClient describes the lookup capability required by Queue.
// *Client satisfies this interface.
type VTClient interface {
	Lookup(ctx context.Context, sha256 string) (model.Verdict, error)
}

// QueueConfig specifies configuration parameters for constructing a Queue.
type QueueConfig struct {
	Client         VTClient
	Cache          *Cache
	RatePerMinute  int           // default: limits.VTRatePerMinute (4)
	Burst          int           // default: 1
	InitialBackoff time.Duration // default: 1s
	MaxBackoff     time.Duration // default: 30s
	MaxRetries     int           // default: 3
	OnVerdict      func(v model.Verdict)
	OnError        func(sha256 string, err error)
}

// Queue manages rate-limited, deduplicated lookups against VirusTotal using a
// single background worker goroutine.
type Queue struct {
	mu      sync.Mutex
	cond    *sync.Cond
	items   []string
	seen    map[string]struct{}
	closed  bool
	stopped bool

	client         VTClient
	cache          *Cache
	limiter        *TokenBucket
	initialBackoff time.Duration
	maxBackoff     time.Duration
	maxRetries     int
	onVerdict      func(v model.Verdict)
	onError        func(sha256 string, err error)

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewQueue creates and starts a Queue with a single worker goroutine.
// The worker runs until ctx is cancelled, or Stop() / Close() is called.
func NewQueue(ctx context.Context, cfg QueueConfig) *Queue {
	if cfg.RatePerMinute <= 0 {
		cfg.RatePerMinute = limits.VTRatePerMinute
	}
	if cfg.Burst <= 0 {
		cfg.Burst = 1
	}
	if cfg.InitialBackoff <= 0 {
		cfg.InitialBackoff = time.Second
	}
	if cfg.MaxBackoff <= 0 {
		cfg.MaxBackoff = 30 * time.Second
	}
	if cfg.MaxRetries < 0 {
		cfg.MaxRetries = 0
	} else if cfg.MaxRetries == 0 {
		cfg.MaxRetries = 3
	}

	childCtx, cancel := context.WithCancel(ctx)
	q := &Queue{
		items:          make([]string, 0),
		seen:           make(map[string]struct{}),
		client:         cfg.Client,
		cache:          cfg.Cache,
		limiter:        NewTokenBucket(cfg.RatePerMinute, cfg.Burst),
		initialBackoff: cfg.InitialBackoff,
		maxBackoff:     cfg.MaxBackoff,
		maxRetries:     cfg.MaxRetries,
		onVerdict:      cfg.OnVerdict,
		onError:        cfg.OnError,
		ctx:            childCtx,
		cancel:         cancel,
	}
	q.cond = sync.NewCond(&q.mu)

	// Watch context cancellation to unblock q.cond.Wait() immediately.
	go func() {
		<-q.ctx.Done()
		q.mu.Lock()
		q.cond.Broadcast()
		q.mu.Unlock()
	}()

	q.wg.Add(1)
	go q.worker()

	return q
}

// Enqueue adds a SHA-256 to the lookup queue. It returns true if the hash
// was newly enqueued, or false if it was already seen (deduplicated), empty,
// or the queue is closed.
func (q *Queue) Enqueue(sha string) bool {
	sha = strings.ToLower(strings.TrimSpace(sha))
	if sha == "" {
		return false
	}

	q.mu.Lock()
	defer q.mu.Unlock()

	if q.closed || q.ctx.Err() != nil {
		return false
	}

	if _, exists := q.seen[sha]; exists {
		return false // duplicate
	}

	q.seen[sha] = struct{}{}
	q.items = append(q.items, sha)
	q.cond.Signal()
	return true
}

// IsEnqueued reports whether the given SHA-256 has already been enqueued.
func (q *Queue) IsEnqueued(sha string) bool {
	sha = strings.ToLower(strings.TrimSpace(sha))
	q.mu.Lock()
	defer q.mu.Unlock()
	_, exists := q.seen[sha]
	return exists
}

// Len returns the count of items currently pending in the queue.
func (q *Queue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.items)
}

// Close stops accepting new entries and waits for pending items in the queue
// to be processed.
func (q *Queue) Close() {
	q.mu.Lock()
	if q.closed {
		q.mu.Unlock()
		return
	}
	q.closed = true
	q.cond.Broadcast()
	q.mu.Unlock()
	q.wg.Wait()
}

// Stop immediately cancels processing, discards pending items, and waits
// for the background worker to exit.
func (q *Queue) Stop() {
	q.mu.Lock()
	if q.stopped {
		q.mu.Unlock()
		return
	}
	q.stopped = true
	q.closed = true
	q.cancel()
	q.cond.Broadcast()
	q.mu.Unlock()
	q.wg.Wait()
}

func (q *Queue) worker() {
	defer q.wg.Done()

	for {
		q.mu.Lock()
		for len(q.items) == 0 && !q.closed && q.ctx.Err() == nil {
			q.cond.Wait()
		}

		if q.ctx.Err() != nil {
			q.mu.Unlock()
			return
		}
		if q.closed && len(q.items) == 0 {
			q.mu.Unlock()
			return
		}

		item := q.items[0]
		q.items = q.items[1:]
		q.mu.Unlock()

		q.process(item)
	}
}

func (q *Queue) process(sha string) {
	// 1. Check cache first if available.
	if q.cache != nil {
		if v, ok, err := q.cache.Get(sha, "virustotal"); err == nil && ok {
			if q.onVerdict != nil {
				q.onVerdict(v)
			}
			return
		}
	}

	if q.client == nil {
		if q.onError != nil {
			q.onError(sha, ErrNoClient)
		}
		return
	}

	backoff := q.initialBackoff
	var lastErr error

	for attempt := 0; attempt <= q.maxRetries; attempt++ {
		if q.ctx.Err() != nil {
			return
		}

		// Wait for rate limiter token.
		if err := q.limiter.Wait(q.ctx); err != nil {
			return
		}

		v, err := q.client.Lookup(q.ctx, sha)
		if err == nil {
			// Successful lookup.
			if q.cache != nil {
				_ = q.cache.Put(v)
			}
			if q.onVerdict != nil {
				q.onVerdict(v)
			}
			return
		}

		// HTTP 404 (ErrVTNotFound) returns a terminal "unknown" verdict.
		if errors.Is(err, ErrVTNotFound) {
			if q.cache != nil {
				_ = q.cache.Put(v)
			}
			if q.onVerdict != nil {
				q.onVerdict(v)
			}
			return
		}

		// Retryable error (HTTP 429 or 5xx).
		if errors.Is(err, ErrVTRetryable) {
			lastErr = err
			if attempt == q.maxRetries {
				break
			}
			select {
			case <-q.ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff *= 2
			if backoff > q.maxBackoff {
				backoff = q.maxBackoff
			}
			continue
		}

		// Hard non-retryable error (e.g. HTTP 403, network failure).
		lastErr = err
		break
	}

	if q.onError != nil && lastErr != nil {
		q.onError(sha, lastErr)
	}
}
