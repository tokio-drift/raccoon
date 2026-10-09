package model

// Severity is the triage level of an event or finding.
type Severity string

// Severity levels. Severity can only be escalated, never lowered.
const (
	SevInfo     Severity = "info"
	SevWarning  Severity = "warning"
	SevCritical Severity = "critical"
)

// Direction identifies the direction of bytes within a flow.
type Direction uint8

// Flow directions. C2S is from the flow initiator.
const (
	C2S Direction = 0
	S2C Direction = 1
)

// EventType enumerates the kinds of events placed on the timeline.
type EventType string

// Event types.
const (
	EvStreamOpened EventType = "STREAM_OPENED"
	EvTCPAnomaly   EventType = "TCP_ANOMALY" // gap, overlap conflict, midstream
	EvFTPLoginTry  EventType = "FTP_LOGIN_ATTEMPT"
	EvFTPLoginOK   EventType = "FTP_LOGIN_SUCCESS"
	EvFTPLoginFail EventType = "FTP_LOGIN_FAILED"
	EvFTPCommand   EventType = "FTP_COMMAND"
	EvFTPTransfer  EventType = "FTP_FILE_TRANSFER" // PLUS-A
	EvHTTPTx       EventType = "HTTP_TRANSACTION"
	EvDNSQuery     EventType = "DNS_QUERY"
	EvFileCarved   EventType = "FILE_CARVED"
	EvOpaqueRegion EventType = "OPAQUE_REGION"
	EvVerdict      EventType = "THREAT_VERDICT"
	EvFinding      EventType = "FINDING" // PLUS-C
	EvGroup        EventType = "GROUP"   // PLUS-D (folded burst)
)

// Event is a single entry on the case timeline.
type Event struct {
	ID         int64
	TS         int64 // unix ns
	PacketNo   uint64
	PacketEnd  uint64
	Type       EventType
	Severity   Severity
	Phase      string // "" until PLUS-D; then recon|access|action|exfil|c2
	StreamID   int64  // 0 if none
	Src, Dst   string // "ip:port"
	Proto      string // ftp|ftp-data|http|dns|tcp|udp|unknown
	Title      string
	Details    map[string]any // JSON object
	Explain    string         // PLUS-E
	ParentID   int64          // 0 if none (PLUS-D groups)
	FileID     int64          // 0 if none
	FindingIDs []int64
}

// Stream describes one reassembled network stream.
type Stream struct {
	ID, ParentID            int64
	Proto                   string
	SrcIP, DstIP            string
	SrcPort, DstPort        uint16
	StartTS, EndTS          int64
	BytesC2S, BytesS2C      int64
	Packets                 int64
	FirstPacket, LastPacket uint64
	Midstream, HasGaps      bool
	UDP                     bool
}

// CarvedFile describes a file extracted from a stream.
type CarvedFile struct {
	ID, StreamID     int64
	Dir              Direction
	StartOff, EndOff int64
	Format, Ext      string
	Status           string // complete|truncated|corrupt
	Confidence       string // high|medium|low
	Size             int64
	MD5, SHA256      string
	DisplayName      string // metadata only, sanitized for display
	Path             string // relative to case dir
	MagicHex         string // e.g. "25504446"
}

// Verdict is the result of a reputation check on a carved file.
type Verdict struct {
	SHA256, Source, Status string // Source: yara|virustotal|malwarebazaar
	Score, Total           int
	Detail                 map[string]any
	CheckedAt              int64
}

// Finding is a detector conclusion mapped to an ATT&CK technique (PLUS-C).
type Finding struct {
	ID               int64
	Title, Technique string // technique e.g. "T1110"
	Severity         Severity
	Explanation      string
	EvidenceEventIDs []int64
}
