package carve

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

// dummyFormat is a minimal Format implementation for registry and interface
// tests.
type dummyFormat struct {
	name    string
	ext     string
	headers [][]byte
	maxSize int64
}

func (d dummyFormat) Name() string      { return d.name }
func (d dummyFormat) Ext() string       { return d.ext }
func (d dummyFormat) Headers() [][]byte { return d.headers }
func (d dummyFormat) MaxSize() int64    { return d.maxSize }

func (d dummyFormat) Extent(_ io.ReaderAt, _, _ int64) (int64, string, error) {
	return 0, StatusComplete, nil
}

// TestFormatInterface guards the Format method set expected by the scanner.
func TestFormatInterface(t *testing.T) {
	var f Format = dummyFormat{name: "dummy", ext: "dmy", headers: [][]byte{{0x01, 0x02}}}
	if f.Name() != "dummy" || f.Ext() != "dmy" || f.MaxSize() != 0 {
		t.Fatalf("unexpected accessors: %q %q %d", f.Name(), f.Ext(), f.MaxSize())
	}
}

func TestRegistryRegisterAndAll(t *testing.T) {
	r := NewRegistry()
	a := dummyFormat{name: "a", headers: [][]byte{{0x0A}}}
	b := dummyFormat{name: "b", headers: [][]byte{{0x0B}}}
	if err := r.Register(a); err != nil {
		t.Fatalf("register a: %v", err)
	}
	if err := r.Register(b); err != nil {
		t.Fatalf("register b: %v", err)
	}
	all := r.All()
	if len(all) != 2 || all[0].Name() != "a" || all[1].Name() != "b" {
		t.Fatalf("All() = %v, want [a b] in registration order", all)
	}
	all[0] = nil // mutating the returned slice must not affect the registry
	if r.All()[0] == nil {
		t.Fatal("All() exposed internal storage")
	}
}

func TestRegistryRegisterErrors(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(dummyFormat{name: "a", headers: [][]byte{{0x01}}}); err != nil {
		t.Fatalf("register a: %v", err)
	}
	if err := r.Register(dummyFormat{name: "a", headers: [][]byte{{0x02}}}); !errors.Is(err, ErrDuplicateFormat) {
		t.Fatalf("duplicate register: got %v, want ErrDuplicateFormat", err)
	}
	if err := r.Register(nil); !errors.Is(err, ErrInvalidFormat) {
		t.Fatalf("nil register: got %v, want ErrInvalidFormat", err)
	}
	if err := r.Register(dummyFormat{name: "noheaders"}); !errors.Is(err, ErrInvalidFormat) {
		t.Fatalf("headerless register: got %v, want ErrInvalidFormat", err)
	}
	if err := r.Register(dummyFormat{headers: [][]byte{{0x01}}}); !errors.Is(err, ErrInvalidFormat) {
		t.Fatalf("nameless register: got %v, want ErrInvalidFormat", err)
	}
}

func TestRegistryMatchHeaderLongestWins(t *testing.T) {
	r := NewRegistry()
	short := dummyFormat{name: "short", headers: [][]byte{{'P', 'K'}}}
	long := dummyFormat{name: "long", headers: [][]byte{{'P', 'K', 0x03, 0x04}}}
	other := dummyFormat{name: "other", headers: [][]byte{{0xFF, 0xD8, 0xFF}}}
	for _, f := range []Format{short, long, other} {
		if err := r.Register(f); err != nil {
			t.Fatalf("register %s: %v", f.Name(), err)
		}
	}

	tests := []struct {
		name string
		in   []byte
		want string
	}{
		{"longest header wins", []byte("PK\x03\x04rest"), "long"},
		{"shorter header still matches", []byte("PK\x05\x06"), "short"},
		{"unrelated bytes", []byte{0x00, 0x01}, ""},
	}
	for _, tt := range tests {
		got, ok := r.MatchHeader(tt.in)
		if tt.want == "" {
			if ok {
				t.Fatalf("%s: MatchHeader(%x) = %q, want no match", tt.name, tt.in, got.Name())
			}
			continue
		}
		if !ok || got.Name() != tt.want {
			t.Fatalf("%s: MatchHeader(%x) = %v ok=%v, want %q", tt.name, tt.in, got, ok, tt.want)
		}
	}
}

func TestRegistryMaxHeaderLen(t *testing.T) {
	r := NewRegistry()
	if r.MaxHeaderLen() != 0 {
		t.Fatalf("empty registry MaxHeaderLen = %d, want 0", r.MaxHeaderLen())
	}
	if err := r.Register(dummyFormat{name: "a", headers: [][]byte{{0x01}, {0x02, 0x03, 0x04}}}); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := r.Register(dummyFormat{name: "b", headers: [][]byte{{0x05, 0x06}}}); err != nil {
		t.Fatalf("register: %v", err)
	}
	if got := r.MaxHeaderLen(); got != 3 {
		t.Fatalf("MaxHeaderLen = %d, want 3", got)
	}
}

func TestReadFull(t *testing.T) {
	data := []byte("0123456789abcdef")

	tests := []struct {
		name    string
		off     int64
		n       int64
		want    string
		wantErr error
	}{
		{name: "exact read", off: 4, n: 6, want: "456789"},
		{name: "read at start", off: 0, n: 4, want: "0123"},
		{name: "read to the end", off: 12, n: 4, want: "cdef"},
		{name: "zero length", off: 3, n: 0, want: ""},
		{name: "short read", off: 14, n: 4, wantErr: io.EOF},
		{name: "offset past end", off: 100, n: 2, wantErr: io.EOF},
		{name: "negative offset", off: -1, n: 2, wantErr: ErrBounds},
		{name: "negative length", off: 0, n: -2, wantErr: ErrBounds},
		{name: "length above cap", off: 0, n: maxReadBytes + 1, wantErr: ErrBounds},
	}
	for _, tt := range tests {
		got, err := readFull(bytes.NewReader(data), tt.off, tt.n)
		if tt.wantErr != nil {
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("%s: err = %v, want %v", tt.name, err, tt.wantErr)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: %v", tt.name, err)
		}
		if string(got) != tt.want {
			t.Fatalf("%s: got %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestReadFullNilReader(t *testing.T) {
	if _, err := readFull(nil, 0, 4); !errors.Is(err, ErrBounds) {
		t.Fatalf("nil reader: got %v, want ErrBounds", err)
	}
}
