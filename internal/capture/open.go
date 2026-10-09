package capture

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
)

const readBufSize = 1 << 20

// Open opens path, detects its container format and returns a streaming Reader
// together with container-level Info.
func Open(path string) (Reader, Info, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, Info{}, fmt.Errorf("capture: open %s: %w", path, err)
	}
	format, err := Detect(f)
	if err != nil {
		f.Close()
		return nil, Info{}, err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		f.Close()
		return nil, Info{}, fmt.Errorf("capture: seek %s: %w", path, err)
	}
	info := Info{Format: format}
	if st, err := f.Stat(); err == nil {
		info.Size = st.Size()
	}
	br := bufio.NewReaderSize(f, readBufSize)

	switch format {
	case FormatPCAP:
		rd, err := newPCAPReader(br)
		if err != nil {
			f.Close()
			return nil, Info{}, err
		}
		rd.closer = f
		info.LinkTypes = []uint16{rd.linkType}
		return rd, info, nil
	case FormatPCAPNG:
		rd, err := newNgReader(br)
		if err != nil {
			f.Close()
			return nil, Info{}, err
		}
		if err := rd.scanHeaders(); err != nil && !errors.Is(err, io.EOF) {
			f.Close()
			return nil, Info{}, err
		}
		rd.closer = f
		info.LinkTypes = rd.linkTypes()
		return rd, info, nil
	default:
		f.Close()
		return nil, Info{}, ErrNotCapture
	}
}
