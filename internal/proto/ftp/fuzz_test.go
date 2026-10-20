package ftp

import (
	"testing"

	"github.com/tokio-drift/raccoon/internal/model"
	"github.com/tokio-drift/raccoon/internal/proto"
	"github.com/tokio-drift/raccoon/internal/reassembly"
)

// FuzzFTP checks that arbitrary control-channel bytes never panic or loop.
func FuzzFTP(f *testing.F) {
	f.Add([]byte("USER bob\r\nPASS s3cr3t\r\n"), []byte("220 ready\r\n331 Password required\r\n230 Logged in\r\n"))
	f.Add([]byte("USER a\r\n"), []byte("220 x\r\n530 no\r\n"))

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
			ID: 1, Proto: "ftp",
			SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 50000, DstPort: 21,
			StartTS: 1, FirstPacket: 1,
		}, src)
		_ = New().Analyze(ctx, func(model.Event) {})
	})
}
