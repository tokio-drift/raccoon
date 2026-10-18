package reassembly

import "github.com/tokio-drift/raccoon/internal/model"

// AnomalyKind identifies a TCP reassembly anomaly.
type AnomalyKind string

const (
	// AnomalyGap marks a hole where captured bytes were never delivered.
	AnomalyGap AnomalyKind = "gap"
	// AnomalyOverlapConflict marks a retransmission whose bytes differ from
	// data already delivered.
	AnomalyOverlapConflict AnomalyKind = "overlap_conflict"
	// AnomalyMidstream marks a stream that started without a SYN.
	AnomalyMidstream AnomalyKind = "midstream"
	// AnomalyParseError marks a stream where packet handling encountered an unexpected error or panic.
	AnomalyParseError AnomalyKind = "parse_error"
)

// Anomaly describes a reassembly anomaly for a TCP_ANOMALY event.
type Anomaly struct {
	Kind   AnomalyKind
	Dir    model.Direction
	Offset int64
	Length int64
}

// AnomalyFunc receives reassembly anomalies.
type AnomalyFunc func(Anomaly)
