package capture

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"

	"github.com/tokio-drift/raccoon/internal/testutil"
)

var validFixtures = []string{
	"tcp_basic.pcap",
	"tcp_ooo.pcap",
	"tcp_retrans.pcap",
	"tcp_overlap_conflict.pcap",
	"tcp_wrap.pcap",
	"tcp_gap.pcap",
	"tcp_midstream.pcap",
	"tcp_portreuse.pcap",
	"ftp_upload_png.pcap",
	"ftp_download_pdf_port31337.pcap",
	"ftp_bruteforce.pcap",
	"http_get_jpeg_chunked.pcap",
	"dns_queries.pcap",
	"carve_nonstandard_port.pcap",
	"pcapng_basic.pcapng",
}

func TestDetectShortInput(t *testing.T) {
	if _, err := Detect(bytes.NewReader([]byte{0x0A, 0x0D})); !errors.Is(err, ErrNotCapture) {
		t.Fatalf("Detect(short) = %v, want ErrNotCapture", err)
	}
}

func TestValidate(t *testing.T) {
	for _, name := range validFixtures {
		t.Run(name, func(t *testing.T) {
			info, err := Validate(testutil.Pcap(t, name))
			if err != nil {
				t.Fatalf("Validate: %v", err)
			}
			want := FormatPCAP
			if strings.HasSuffix(name, ".pcapng") {
				want = FormatPCAPNG
			}
			if info.Format != want {
				t.Fatalf("Format = %v, want %v", info.Format, want)
			}
			if info.Size <= 0 {
				t.Fatalf("Size = %d, want > 0", info.Size)
			}
			if len(info.LinkTypes) == 0 {
				t.Fatalf("LinkTypes empty")
			}
		})
	}

	t.Run("corrupt_header.pcap", func(t *testing.T) {
		if _, err := Validate(testutil.Pcap(t, "corrupt_header.pcap")); !errors.Is(err, ErrNotCapture) {
			t.Fatalf("Validate = %v, want ErrNotCapture", err)
		}
	})
}

// packetReader is the subset of pcapgo readers used for cross-checking.
type packetReader interface {
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
}

func TestReaderMatchesPcapgo(t *testing.T) {
	for _, name := range validFixtures {
		t.Run(name, func(t *testing.T) {
			path := testutil.Pcap(t, name)
			ours, info, err := Open(path)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			defer ours.Close()

			f, err := os.Open(path)
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			defer f.Close()

			var theirs packetReader
			switch info.Format {
			case FormatPCAP:
				r, err := pcapgo.NewReader(f)
				if err != nil {
					t.Fatalf("pcapgo.NewReader: %v", err)
				}
				theirs = r
			case FormatPCAPNG:
				r, err := pcapgo.NewNgReader(f, pcapgo.DefaultNgReaderOptions)
				if err != nil {
					t.Fatalf("pcapgo.NewNgReader: %v", err)
				}
				theirs = r
			default:
				t.Fatalf("unexpected format %v", info.Format)
			}

			for i := 1; ; i++ {
				p, err := ours.Next()
				if errors.Is(err, io.EOF) {
					break
				}
				if err != nil {
					t.Fatalf("packet %d: Next: %v", i, err)
				}
				data, ci, err := theirs.ReadPacketData()
				if err != nil {
					t.Fatalf("packet %d: pcapgo: %v", i, err)
				}
				if p.No != uint64(i) {
					t.Fatalf("packet %d: No = %d", i, p.No)
				}
				if p.TS != ci.Timestamp.UnixNano() {
					t.Fatalf("packet %d: TS = %d, pcapgo = %d", i, p.TS, ci.Timestamp.UnixNano())
				}
				if p.CapLen != uint32(len(data)) {
					t.Fatalf("packet %d: CapLen = %d, pcapgo = %d", i, p.CapLen, len(data))
				}
				if !bytes.Equal(p.Data, data) {
					t.Fatalf("packet %d: data mismatch", i)
				}
				if p.Offset < 0 {
					t.Fatalf("packet %d: Offset = %d", i, p.Offset)
				}
			}
			if _, _, err := theirs.ReadPacketData(); !errors.Is(err, io.EOF) {
				t.Fatalf("pcapgo expected EOF, got %v", err)
			}
		})
	}
}

func TestReaderTruncatedTail(t *testing.T) {
	path := testutil.Pcap(t, "truncated_tail.pcap")
	rd, _, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer rd.Close()

	count := 0
	for {
		_, err := rd.Next()
		if errors.Is(err, ErrTruncatedTail) {
			break
		}
		if err != nil {
			t.Fatalf("packet %d: %v", count+1, err)
		}
		count++
	}
	if count != 15 {
		t.Fatalf("complete packets = %d, want 15", count)
	}
}

func TestIndexRoundTrip(t *testing.T) {
	for _, name := range []string{"tcp_basic.pcap", "pcapng_basic.pcapng"} {
		t.Run(name, func(t *testing.T) {
			path := testutil.Pcap(t, name)
			rd, _, err := Open(path)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			var buf bytes.Buffer
			iw := NewIndexWriter(&buf)
			var packets [][]byte
			for {
				p, err := rd.Next()
				if errors.Is(err, io.EOF) {
					break
				}
				if err != nil {
					t.Fatalf("Next: %v", err)
				}
				if err := iw.Add(IndexRecord{Offset: p.Offset, TS: p.TS, CapLen: p.CapLen}); err != nil {
					t.Fatalf("Add: %v", err)
				}
				packets = append(packets, append([]byte(nil), p.Data...))
			}
			rd.Close()

			ir := NewIndexReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
			if ir.Len() != int64(len(packets)) {
				t.Fatalf("index Len = %d, want %d", ir.Len(), len(packets))
			}
			for i, want := range packets {
				rec, err := ir.At(uint64(i + 1))
				if err != nil {
					t.Fatalf("At(%d): %v", i+1, err)
				}
				got, err := ReadPacketAt(path, rec)
				if err != nil {
					t.Fatalf("ReadPacketAt(%d): %v", i+1, err)
				}
				if !bytes.Equal(got, want) {
					t.Fatalf("packet %d: ReadPacketAt mismatch", i+1)
				}
			}
			if _, err := ir.At(uint64(len(packets) + 1)); !errors.Is(err, io.EOF) {
				t.Fatalf("At(past end) = %v, want io.EOF", err)
			}
		})
	}
}

func FuzzReader(f *testing.F) {
	for _, name := range []string{"tcp_basic.pcap", "pcapng_basic.pcapng", "truncated_tail.pcap"} {
		data, err := os.ReadFile(filepath.Join("..", "..", "testdata", name))
		if err == nil {
			f.Add(data)
		}
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		format, err := Detect(bytes.NewReader(data))
		if err != nil {
			return
		}
		var rd Reader
		switch format {
		case FormatPCAP:
			r, err := newPCAPReader(bytes.NewReader(data))
			if err != nil {
				return
			}
			rd = r
		case FormatPCAPNG:
			r, err := newNgReader(bytes.NewReader(data))
			if err != nil {
				return
			}
			if err := r.scanHeaders(); err != nil && !errors.Is(err, io.EOF) {
				return
			}
			rd = r
		}
		for i := 0; i < 4096; i++ {
			if _, err := rd.Next(); err != nil {
				break
			}
		}
	})
}
