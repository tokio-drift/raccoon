package limits

import "time"

// Upload and buffer limits.
const (
	// UploadMaxBytes is the maximum size of a PCAP uploaded through the web UI.
	UploadMaxBytes int64 = 500 * 1024 * 1024
	// PendingBufferPerDir caps the out-of-order buffer for one stream direction.
	PendingBufferPerDir int64 = 4 * 1024 * 1024
	// MaxCarveSize is the largest single carved file (flag --max-file-size).
	MaxCarveSize int64 = 200 * 1024 * 1024
	// MaxGzipBody caps a gzip-decoded HTTP body.
	MaxGzipBody int64 = 100 * 1024 * 1024
	// StreamBytesMaxLen caps the number of stream bytes returned by one API request.
	StreamBytesMaxLen = 64 * 1024
)

// Capture-clock timeouts.
const (
	// HoleTimeout is how long a reassembly hole may persist before it is given up on.
	HoleTimeout = 5 * time.Second
	// FlowIdleTimeout is how long a flow may be idle before it is reaped.
	FlowIdleTimeout = 120 * time.Second
)

// Entropy analysis parameters.
const (
	// EntropyBlockSize is the block size used for Shannon entropy scanning.
	EntropyBlockSize = 1024
	// EntropyThreshold is the bits-per-byte threshold for an opaque region.
	EntropyThreshold = 7.2
)

// API pagination.
const (
	// EventsPageSizeDefault is the default number of events returned per page.
	EventsPageSizeDefault = 200
	// EventsPageSizeMax is the maximum number of events returned per page.
	EventsPageSizeMax = 1000
)

// Threat-intelligence parameters.
const (
	// VTRatePerMinute is the default VirusTotal request rate (flag --vt-rate).
	VTRatePerMinute = 4
	// VerdictCacheTTL is how long a cached verdict remains valid.
	VerdictCacheTTL = 7 * 24 * time.Hour
)
