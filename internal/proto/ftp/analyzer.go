package ftp

import (
	"bufio"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/tokio-drift/raccoon/internal/model"
	"github.com/tokio-drift/raccoon/internal/proto"
)

// maxLineLen caps a single control line; longer lines are discarded so a
// hostile stream cannot grow the parser without bound.
const maxLineLen = 64 * 1024

// Analyzer parses FTP control connections.
type Analyzer struct{}

// New returns an FTP control analyzer.
func New() *Analyzer { return &Analyzer{} }

// Name returns "ftp".
func (a *Analyzer) Name() string { return "ftp" }

// Match reports whether the first bytes look like an FTP control message.
func (a *Analyzer) Match(first []byte, dir model.Direction, _ proto.PortPair) bool {
	return proto.IsFTP(first, dir)
}

// Analyze parses the control stream and emits login and command events.
func (a *Analyzer) Analyze(ctx *proto.StreamContext, emit func(model.Event)) error {
	c2s, err := readLines(ctx, model.C2S)
	if err != nil {
		return err
	}
	s2c, err := readLines(ctx, model.S2C)
	if err != nil {
		return err
	}
	lines := mergeLines(c2s, s2c)
	st := state{ctx: ctx, emit: emit}
	for _, ln := range lines {
		st.handle(ln)
	}
	return nil
}

type line struct {
	text string
	off  int64
	ts   int64
	pkt  uint64
	dir  model.Direction
}

// readLines splits one direction into CRLF/LF terminated lines, recording the
// stream offset, timestamp and packet of each line's first byte.
func readLines(ctx *proto.StreamContext, dir model.Direction) ([]line, error) {
	total := ctx.Len(dir)
	if total == 0 {
		return nil, nil
	}
	br := bufio.NewReaderSize(io.NewSectionReader(ctx.ReaderAt(dir), 0, total), 32*1024)

	var (
		out      []line
		lineBuf  []byte
		lineOff  int64
		consumed int64
		overlong bool
	)
	for {
		frag, err := br.ReadSlice('\n')
		consumed += int64(len(frag))
		if !overlong {
			if len(lineBuf)+len(frag) <= maxLineLen {
				lineBuf = append(lineBuf, frag...)
			} else {
				// Too long: drop the rest of this line.
				overlong = true
				lineBuf = lineBuf[:0]
			}
		}

		if err == nil {
			if !overlong {
				out = appendLine(out, lineBuf, lineOff, ctx, dir)
			}
			lineBuf = lineBuf[:0]
			lineOff = consumed
			overlong = false
			continue
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		if err == io.EOF {
			if !overlong && len(lineBuf) > 0 {
				out = appendLine(out, lineBuf, lineOff, ctx, dir)
			}
			break
		}
		return out, err
	}
	return out, nil
}

func appendLine(out []line, buf []byte, off int64, ctx *proto.StreamContext, dir model.Direction) []line {
	text := strings.TrimRight(string(buf), "\r\n")
	return append(out, line{
		text: text,
		off:  off,
		ts:   ctx.TimeAtOffset(dir, off),
		pkt:  ctx.PacketAtOffset(dir, off),
		dir:  dir,
	})
}

func mergeLines(c2s, s2c []line) []line {
	all := make([]line, 0, len(c2s)+len(s2c))
	all = append(all, c2s...)
	all = append(all, s2c...)
	sort.SliceStable(all, func(i, j int) bool {
		if all[i].ts != all[j].ts {
			return all[i].ts < all[j].ts
		}
		if all[i].pkt != all[j].pkt {
			return all[i].pkt < all[j].pkt
		}
		return all[i].dir < all[j].dir
	})
	return all
}

type state struct {
	ctx      *proto.StreamContext
	emit     func(model.Event)
	user     string
	password string
	havePass bool
}

func (s *state) handle(ln line) {
	if ln.text == "" {
		return
	}
	if replyCode(ln.text) > 0 {
		s.reply(ln)
		return
	}
	s.command(ln)
}

func (s *state) command(ln line) {
	cmd, arg := splitCommand(ln.text)
	switch cmd {
	case "USER":
		s.user = arg
		s.emit(s.ctx.NewEvent(ln.ts, ln.pkt, model.EvFTPLoginTry, model.SevInfo,
			"FTP login attempt: "+arg, map[string]any{
				"user":    arg,
				"command": cmd,
			}))
	case "PASS":
		s.password = arg
		s.havePass = true
	case "PWD", "CWD", "LIST", "NLST", "RETR", "STOR", "QUIT", "PASV", "EPSV", "PORT", "EPRT":
		details := map[string]any{"command": cmd}
		if arg != "" {
			details["arg"] = arg
		}
		if cmd == "RETR" || cmd == "STOR" {
			details["filename"] = arg
		}
		title := "FTP command: " + cmd
		if arg != "" {
			title += " " + arg
		}
		s.emit(s.ctx.NewEvent(ln.ts, ln.pkt, model.EvFTPCommand, model.SevInfo, title, details))
	}
}

func (s *state) reply(ln line) {
	code := replyCode(ln.text)
	switch code {
	case 230:
		sev := model.SevInfo
		details := map[string]any{
			"user":            s.user,
			"passwordPresent": s.havePass,
			"reply":           ln.text,
		}
		if s.havePass {
			sev = model.SevWarning
			details["password"] = s.password
		}
		s.emit(s.ctx.NewEvent(ln.ts, ln.pkt, model.EvFTPLoginOK, sev,
			"FTP login successful: "+s.user, details))
		s.clearCredentials()
	case 530:
		sev := model.SevInfo
		details := map[string]any{
			"user":            s.user,
			"passwordPresent": s.havePass,
			"reply":           ln.text,
		}
		if s.havePass {
			sev = model.SevWarning
			details["password"] = s.password
		}
		s.emit(s.ctx.NewEvent(ln.ts, ln.pkt, model.EvFTPLoginFail, sev,
			"FTP login failed: "+s.user, details))
		s.clearCredentials()
	}
}

func (s *state) clearCredentials() {
	s.password = ""
	s.havePass = false
}

func splitCommand(text string) (string, string) {
	cmd, arg, _ := strings.Cut(text, " ")
	return strings.ToUpper(cmd), strings.TrimSpace(arg)
}

// replyCode returns the three-digit reply code if text starts with one, or 0.
func replyCode(text string) int {
	if len(text) < 3 {
		return 0
	}
	for i := 0; i < 3; i++ {
		if text[i] < '0' || text[i] > '9' {
			return 0
		}
	}
	if len(text) > 3 && text[3] != ' ' && text[3] != '-' {
		return 0
	}
	code, err := strconv.Atoi(text[:3])
	if err != nil {
		return 0
	}
	return code
}
