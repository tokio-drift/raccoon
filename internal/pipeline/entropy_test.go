package pipeline

import (
	"net/netip"
	"testing"

	"github.com/tokio-drift/raccoon/internal/decode"
	"github.com/tokio-drift/raccoon/internal/entropy"
	"github.com/tokio-drift/raccoon/internal/flow"
	"github.com/tokio-drift/raccoon/internal/model"
	"github.com/tokio-drift/raccoon/internal/reassembly"
)

// rampBytes returns n bytes cycling 0..255, so every aligned 1 KB block has
// entropy exactly 8 and the data is not printable.
func rampBytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

// fakeStream builds a ClosedStream whose S2C direction carries s2c and whose
// C2S direction is empty.
func fakeStream(t *testing.T, id int64, s2c []byte) *ClosedStream {
	t.Helper()
	spool, err := reassembly.NewSpool(t.TempDir(), id)
	if err != nil {
		t.Fatalf("NewSpool: %v", err)
	}
	t.Cleanup(func() { spool.Close() })

	st := reassembly.NewStream(reassembly.StreamConfig{ID: id, Proto: "tcp", Spool: spool})
	// 2000 reassembles cleanly, so a gap-free S2C payload is delivered.
	st.AddPacket(model.C2S, 1000, decode.FlagSYN, nil, 0, 1)
	st.AddPacket(model.S2C, 5000, decode.FlagSYN|decode.FlagACK, nil, 0, 2)
	st.AddPacket(model.S2C, 5001, decode.FlagPSH|decode.FlagACK, s2c, 10, 3)
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	init := flow.Endpoint{IP: netip.MustParseAddr("10.0.0.1"), Port: 4444}
	resp := flow.Endpoint{IP: netip.MustParseAddr("10.0.0.2"), Port: 5555}
	f := &flow.Flow{
		ID:        id,
		Key:       flow.Key{A: init, B: resp, Proto: "tcp"},
		Initiator: init,
		Proto:     "tcp",
		StartTS:   10,
		EndTS:     20,
	}
	return &ClosedStream{Flow: f, Stream: st}
}

type spanTest struct {
	name   string
	length int64
	covers []span
	want   []entropy.Range
}

func TestSubtractRanges(t *testing.T) {
	tests := []spanTest{
		{name: "no coverage", length: 100, want: []entropy.Range{{Start: 0, End: 100}}},
		{name: "zero length", length: 0, want: nil},
		{name: "negative length", length: -5, want: nil},
		{
			name:   "single middle span",
			length: 100, covers: []span{{20, 40}},
			want: []entropy.Range{{Start: 0, End: 20}, {Start: 40, End: 100}},
		},
		{
			name:   "span at start",
			length: 100, covers: []span{{0, 30}},
			want: []entropy.Range{{Start: 30, End: 100}},
		},
		{
			name:   "span at end",
			length: 100, covers: []span{{70, 100}},
			want: []entropy.Range{{Start: 0, End: 70}},
		},
		{
			name:   "span covering all",
			length: 100, covers: []span{{0, 100}},
			want: nil,
		},
		{
			name:   "adjacent spans",
			length: 100, covers: []span{{0, 30}, {30, 60}},
			want: []entropy.Range{{Start: 60, End: 100}},
		},
		{
			name:   "overlapping spans",
			length: 100, covers: []span{{0, 40}, {20, 60}},
			want: []entropy.Range{{Start: 60, End: 100}},
		},
		{
			name:   "unsorted spans",
			length: 100, covers: []span{{70, 100}, {0, 30}},
			want: []entropy.Range{{Start: 30, End: 70}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := subtractRanges(tt.length, tt.covers)
			if len(got) != len(tt.want) {
				t.Fatalf("subtractRanges = %+v, want %+v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("subtractRanges = %+v, want %+v", got, tt.want)
				}
			}
		})
	}
}

func TestEntropyIntoEmitsOpaqueRegion(t *testing.T) {
	cs := fakeStream(t, 1, rampBytes(8*1024))
	var events []model.Event
	if err := entropyInto(cs, "tcp", nil, func(e model.Event) { events = append(events, e) }); err != nil {
		t.Fatalf("entropyInto: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1: %+v", len(events), events)
	}
	e := events[0]
	if e.Type != model.EvOpaqueRegion {
		t.Errorf("type = %q, want %q", e.Type, model.EvOpaqueRegion)
	}
	if e.Severity != model.SevWarning {
		t.Errorf("severity = %q, want %q", e.Severity, model.SevWarning)
	}
	if e.StreamID != 1 {
		t.Errorf("stream id = %d, want 1", e.StreamID)
	}
	if e.Proto != "tcp" {
		t.Errorf("proto = %q, want tcp", e.Proto)
	}
	if e.Src != "10.0.0.1:4444" || e.Dst != "10.0.0.2:5555" {
		t.Errorf("endpoints = %q -> %q", e.Src, e.Dst)
	}
	if e.Details["dir"] != "s2c" {
		t.Errorf("dir = %v, want s2c", e.Details["dir"])
	}
	if e.Details["startOff"] != int64(0) || e.Details["endOff"] != int64(8192) {
		t.Errorf("extent = [%v,%v), want [0,8192)", e.Details["startOff"], e.Details["endOff"])
	}
	if h, _ := e.Details["meanH"].(float64); h < 7.2 {
		t.Errorf("meanH = %v, want >= 7.2", e.Details["meanH"])
	}
	if e.PacketNo == 0 {
		t.Error("packet number not set")
	}
}

func TestEntropyIntoSkipsTextPayload(t *testing.T) {
	payload := make([]byte, 8*1024)
	for i := range payload {
		payload[i] = 'A'
	}
	cs := fakeStream(t, 1, payload)
	var events []model.Event
	if err := entropyInto(cs, "tcp", nil, func(e model.Event) { events = append(events, e) }); err != nil {
		t.Fatalf("entropyInto: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("events = %+v, want none for text", events)
	}
}

func TestEntropyIntoSkipsCarvedRanges(t *testing.T) {
	// The whole high-entropy payload is inside a carved file, so nothing is
	// flagged.
	cs := fakeStream(t, 1, rampBytes(8*1024))
	carved := map[model.Direction][]span{
		model.S2C: {{start: 0, end: 8192}},
	}
	var events []model.Event
	if err := entropyInto(cs, "tcp", carved, func(e model.Event) { events = append(events, e) }); err != nil {
		t.Fatalf("entropyInto: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("events = %+v, want none (all carved)", events)
	}

	// Carving the middle leaves opaque runs on either side.
	carved = map[model.Direction][]span{model.S2C: {{start: 4 * 1024, end: 8 * 1024}}}
	events = nil
	if err := entropyInto(cs, "tcp", carved, func(e model.Event) { events = append(events, e) }); err != nil {
		t.Fatalf("entropyInto: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("events = %+v, want 1", events)
	}
	if events[0].Details["endOff"] != int64(4*1024) {
		t.Errorf("endOff = %v, want 4096", events[0].Details["endOff"])
	}
}

func TestEntropyIntoEmptyStream(t *testing.T) {
	cs := fakeStream(t, 1, nil)
	var events []model.Event
	if err := entropyInto(cs, "tcp", nil, func(e model.Event) { events = append(events, e) }); err != nil {
		t.Fatalf("entropyInto: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("events = %+v, want none for an empty stream", events)
	}
	if err := entropyInto(nil, "tcp", nil, func(model.Event) {}); err != nil {
		t.Fatalf("nil stream: %v", err)
	}
}
