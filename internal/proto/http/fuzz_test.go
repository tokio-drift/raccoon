package http

import (
	"testing"

	"github.com/tokio-drift/raccoon/internal/model"
	"github.com/tokio-drift/raccoon/internal/proto"
	"github.com/tokio-drift/raccoon/internal/reassembly"
)

// FuzzHTTP checks that arbitrary request/response bytes never panic or loop.
func FuzzHTTP(f *testing.F) {
	f.Add(
		[]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		[]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"),
	)
	f.Add(
		[]byte("POST /x HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\n\r\n"),
		[]byte("HTTP/1.1 204 No Content\r\n\r\n"),
	)

	f.Fuzz(func(t *testing.T, c2s, s2c []byte) {
		if len(c2s)+len(s2c) > 1<<20 {
			t.Skip()
		}
		src := &memStream{}
		src.data[model.C2S] = c2s
		src.data[model.S2C] = s2c
		if len(c2s) > 0 {
			src.segs[model.C2S] = []reassembly.Segment{{
				StreamOff: 0, Length: uint32(len(c2s)), TS: 1, PacketNo: 1,
			}}
		}
		if len(s2c) > 0 {
			src.segs[model.S2C] = []reassembly.Segment{{
				StreamOff: 0, Length: uint32(len(s2c)), TS: 2, PacketNo: 2,
			}}
		}
		ctx := proto.NewStreamContext(proto.StreamMeta{
			ID: 1, Proto: "http",
			SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 50000, DstPort: 80,
			StartTS: 1, FirstPacket: 1,
		}, src)
		_ = New().Analyze(ctx, func(model.Event) {})
	})
}
