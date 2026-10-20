package http

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/url"
	"path"
	"strconv"
	"strings"

	"github.com/tokio-drift/raccoon/internal/limits"
	"github.com/tokio-drift/raccoon/internal/model"
	"github.com/tokio-drift/raccoon/internal/proto"
)

const (
	maxHeaderBytes = 1 << 20
	maxLineBytes   = 64 << 10
	maxBodyBytes   = limits.MaxCarveSize
)

var (
	errMalformed = errors.New("malformed http message")
	errTooLong   = errors.New("http message too long")
)

// Analyzer parses HTTP/1.x conversations.
type Analyzer struct{}

// New returns an HTTP analyzer.
func New() *Analyzer { return &Analyzer{} }

// Name returns "http".
func (a *Analyzer) Name() string { return "http" }

// Match reports whether the first bytes look like an HTTP/1.x message.
func (a *Analyzer) Match(first []byte, dir model.Direction, _ proto.PortPair) bool {
	return proto.IsHTTP(first, dir)
}

// Analyze pairs requests with responses and emits one event per transaction.
func (a *Analyzer) Analyze(ctx *proto.StreamContext, emit func(model.Event)) error {
	reqs := parseRequests(ctx)
	resps := parseResponses(ctx, requestMethods(reqs))

	n := len(reqs)
	if len(resps) < n {
		n = len(resps)
	}
	for i := 0; i < n; i++ {
		a.emitTransaction(ctx, emit, reqs[i], resps[i])
	}
	return nil
}

func (a *Analyzer) emitTransaction(ctx *proto.StreamContext, emit func(model.Event), req, resp message) {
	details := map[string]any{
		"method":      req.method,
		"host":        req.header.get("host"),
		"url":         req.target,
		"status":      resp.status,
		"userAgent":   req.header.get("user-agent"),
		"contentType": resp.header.get("content-type"),
		"bodyLen":     len(resp.body),
	}

	if filename := filenameFrom(resp.header.get("content-disposition")); filename != "" {
		details["filename"] = filename
	}
	sev := model.SevInfo
	if user, pass, ok := basicAuth(req.header.get("authorization")); ok {
		details["authUser"] = user
		details["passwordPresent"] = true
		details["password"] = pass
		sev = model.SevWarning
	}

	title := fmt.Sprintf("HTTP %s %s -> %d", req.method, req.target, resp.status)
	e := ctx.NewEvent(resp.ts, resp.pkt, model.EvHTTPTx, sev, title, details)
	e.PacketEnd = resp.endPkt
	emit(e)

	if len(resp.body) > 0 {
		name := filenameFrom(resp.header.get("content-disposition"))
		if name == "" {
			name = nameFromTarget(req.target)
		}
		ctx.EmitFileSource(proto.FileSource{
			Name:   name,
			Reader: bytes.NewReader(resp.body),
			Len:    int64(len(resp.body)),
			Dir:    model.S2C,
			Origin: "http",
		})
	}
}

type header map[string][]string

func (h header) get(key string) string {
	if v := h[key]; len(v) > 0 {
		return v[0]
	}
	return ""
}

type message struct {
	startLine string
	method    string
	target    string
	status    int
	header    header
	body      []byte

	ts     int64
	pkt    uint64
	endPkt uint64
}

func parseRequests(ctx *proto.StreamContext) []message {
	p := newParser(ctx, model.C2S)
	var out []message
	for {
		start := p.offset()
		startLine, h, err := p.readHead()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
		method, target, ok := parseRequestLine(startLine)
		if !ok {
			break
		}

		var body []byte
		switch {
		case isChunked(h):
			body, err = p.readChunked(false)
		default:
			if n, ok := contentLength(h); ok {
				body, err = p.readBody(n, false)
			}
		}
		if err != nil {
			break
		}

		out = append(out, message{
			startLine: startLine,
			method:    method,
			target:    target,
			header:    h,
			body:      body,
			ts:        ctx.TimeAtOffset(model.C2S, start),
			pkt:       ctx.PacketAtOffset(model.C2S, start),
			endPkt:    ctx.PacketAtOffset(model.C2S, p.offset()-1),
		})
	}
	return out
}

func requestMethods(reqs []message) []string {
	out := make([]string, len(reqs))
	for i, r := range reqs {
		out[i] = r.method
	}
	return out
}

func parseResponses(ctx *proto.StreamContext, methods []string) []message {
	p := newParser(ctx, model.S2C)
	var out []message
	next := 0
	for {
		start := p.offset()
		startLine, h, err := p.readHead()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
		status, ok := parseStatusLine(startLine)
		if !ok {
			break
		}

		informational := status >= 100 && status < 200 && status != 101
		if informational {
			continue
		}
		method := ""
		if next < len(methods) {
			method = methods[next]
			next++
		}

		var body []byte
		if responseHasBody(status, method) {
			switch {
			case isChunked(h):
				body, err = p.readChunked(true)
			default:
				if n, ok := contentLength(h); ok {
					body, err = p.readBody(n, true)
				} else {
					body, err = p.readToEOF(true)
				}
			}
			if err != nil {
				break
			}
			body = decodeContent(body, h.get("content-encoding"))
		}

		out = append(out, message{
			startLine: startLine,
			status:    status,
			header:    h,
			body:      body,
			ts:        ctx.TimeAtOffset(model.S2C, start),
			pkt:       ctx.PacketAtOffset(model.S2C, start),
			endPkt:    ctx.PacketAtOffset(model.S2C, p.offset()-1),
		})
	}
	return out
}

func responseHasBody(status int, method string) bool {
	if method == "HEAD" {
		return false
	}
	if status >= 100 && status < 200 || status == 204 || status == 304 {
		return false
	}
	if method == "CONNECT" && status >= 200 && status < 300 {
		return false
	}
	return true
}

type offsetReader struct {
	r   io.ReaderAt
	off int64
}

func (o *offsetReader) Read(p []byte) (int, error) {
	n, err := o.r.ReadAt(p, o.off)
	o.off += int64(n)
	return n, err
}

type parser struct {
	br    *bufio.Reader
	or    *offsetReader
	total int64
}

func newParser(ctx *proto.StreamContext, dir model.Direction) *parser {
	total := ctx.Len(dir)
	or := &offsetReader{r: ctx.ReaderAt(dir)}
	if total <= 0 {
		or.r = bytes.NewReader(nil)
	}
	return &parser{br: bufio.NewReaderSize(or, 32*1024), or: or, total: total}
}

// offset is the number of bytes logically consumed by the parser, excluding
// bufio's read-ahead.
func (p *parser) offset() int64 { return p.or.off - int64(p.br.Buffered()) }

// remaining bounds allocations by the bytes actually available in the stream.
func (p *parser) remaining() int64 {
	if p.total <= 0 {
		return 0
	}
	n := p.total - p.offset()
	if n < 0 {
		return 0
	}
	return n
}

func (p *parser) readHead() (string, header, error) {
	startLine, err := p.readLine(maxLineBytes)
	if err != nil {
		return "", nil, err
	}
	h := header{}
	total := len(startLine)
	for {
		ln, err := p.readLine(maxLineBytes)
		if err == io.EOF {
			return "", nil, errMalformed
		}
		if err != nil {
			return "", nil, err
		}
		total += len(ln)
		if total > maxHeaderBytes {
			return "", nil, errTooLong
		}
		if ln == "" {
			return startLine, h, nil
		}
		name, value, ok := strings.Cut(ln, ":")
		if !ok {
			return "", nil, errMalformed
		}
		key := strings.ToLower(strings.TrimSpace(name))
		h[key] = append(h[key], strings.TrimSpace(value))
	}
}

func (p *parser) readLine(max int) (string, error) {
	var buf []byte
	overlong := false
	for {
		frag, err := p.br.ReadSlice('\n')
		if !overlong {
			if len(buf)+len(frag) <= max {
				buf = append(buf, frag...)
			} else {
				overlong = true
				buf = buf[:0]
			}
		}
		if err == nil {
			if overlong {
				return "", errTooLong
			}
			return trimEOL(buf), nil
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		if err == io.EOF {
			if len(buf) == 0 {
				return "", io.EOF
			}
			return trimEOL(buf), io.EOF
		}
		return "", err
	}
}

func trimEOL(b []byte) string {
	s := string(b)
	s = strings.TrimSuffix(s, "\n")
	s = strings.TrimSuffix(s, "\r")
	return s
}

func (p *parser) readBody(n int64, keep bool) ([]byte, error) {
	if n <= 0 {
		return nil, nil
	}
	if !keep {
		_, err := io.CopyN(io.Discard, p.br, n)
		return nil, err
	}
	size := n
	if size > maxBodyBytes {
		size = maxBodyBytes
	}
	if rem := p.remaining(); size > rem {
		size = rem
	}
	body := make([]byte, size)
	if _, err := io.ReadFull(p.br, body); err != nil {
		return body, err
	}
	if rest := n - size; rest > 0 {
		if _, err := io.CopyN(io.Discard, p.br, rest); err != nil {
			return body, err
		}
	}
	return body, nil
}

func (p *parser) readChunked(keep bool) ([]byte, error) {
	var out bytes.Buffer
	for {
		ln, err := p.readLine(maxLineBytes)
		if err != nil {
			return out.Bytes(), err
		}
		sizeStr := ln
		if i := strings.IndexByte(sizeStr, ';'); i >= 0 {
			sizeStr = sizeStr[:i]
		}
		size, err := strconv.ParseInt(strings.TrimSpace(sizeStr), 16, 64)
		if err != nil || size < 0 {
			return out.Bytes(), errMalformed
		}
		if size == 0 {
			for {
				trailer, err := p.readLine(maxLineBytes)
				if err != nil {
					return out.Bytes(), err
				}
				if trailer == "" {
					return out.Bytes(), nil
				}
			}
		}
		if keep {
			room := maxBodyBytes - int64(out.Len())
			if room < 0 {
				room = 0
			}
			n := size
			if n > room {
				n = room
			}
			if rem := p.remaining(); n > rem {
				n = rem
			}
			if n > 0 {
				chunk := make([]byte, n)
				if _, err := io.ReadFull(p.br, chunk); err != nil {
					return out.Bytes(), err
				}
				out.Write(chunk)
			}
			if rest := size - n; rest > 0 {
				if _, err := io.CopyN(io.Discard, p.br, rest); err != nil {
					return out.Bytes(), err
				}
			}
		} else if _, err := io.CopyN(io.Discard, p.br, size); err != nil {
			return out.Bytes(), err
		}
		if _, err := p.readLine(maxLineBytes); err != nil {
			return out.Bytes(), err
		}
	}
}

func (p *parser) readToEOF(keep bool) ([]byte, error) {
	if !keep {
		_, err := io.Copy(io.Discard, p.br)
		return nil, err
	}
	body, err := io.ReadAll(io.LimitReader(p.br, maxBodyBytes))
	if err != nil {
		return body, err
	}
	_, err = io.Copy(io.Discard, p.br)
	return body, err
}

func decodeContent(body []byte, contentEncoding string) []byte {
	if len(body) == 0 || !hasToken(contentEncoding, "gzip") {
		return body
	}
	zr, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return body
	}
	defer zr.Close()
	out, err := io.ReadAll(io.LimitReader(zr, limits.MaxGzipBody))
	if err != nil && len(out) == 0 {
		return body
	}
	return out
}

func parseRequestLine(line string) (method, target string, ok bool) {
	fields := strings.Fields(line)
	if len(fields) != 3 || !strings.HasPrefix(fields[2], "HTTP/1.") {
		return "", "", false
	}
	return fields[0], fields[1], true
}

func parseStatusLine(line string) (int, bool) {
	fields := strings.Fields(line)
	if len(fields) < 2 || !strings.HasPrefix(fields[0], "HTTP/1.") {
		return 0, false
	}
	status, err := strconv.Atoi(fields[1])
	if err != nil || status < 100 || status > 999 {
		return 0, false
	}
	return status, true
}

func contentLength(h header) (int64, bool) {
	value := h.get("content-length")
	if value == "" {
		return 0, false
	}
	n, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

func isChunked(h header) bool {
	return hasToken(h.get("transfer-encoding"), "chunked")
}

func hasToken(value, token string) bool {
	for _, part := range strings.Split(value, ",") {
		if strings.EqualFold(strings.TrimSpace(part), token) {
			return true
		}
	}
	return false
}

func basicAuth(value string) (user, pass string, ok bool) {
	if len(value) < 6 || !strings.EqualFold(value[:6], "basic ") {
		return "", "", false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value[6:]))
	if err != nil {
		return "", "", false
	}
	user, pass, ok = strings.Cut(string(raw), ":")
	return user, pass, ok
}

func filenameFrom(disposition string) string {
	if disposition == "" {
		return ""
	}
	_, params, err := mime.ParseMediaType(disposition)
	if err != nil {
		return ""
	}
	name := params["filename"]
	if name == "" {
		return ""
	}
	return safeBase(name)
}

func nameFromTarget(target string) string {
	u, err := url.Parse(target)
	if err != nil {
		return "http-body"
	}
	name := safeBase(u.Path)
	if name == "" {
		return "http-body"
	}
	return name
}

func safeBase(name string) string {
	name = strings.ReplaceAll(name, "\\", "/")
	name = path.Base(name)
	if name == "" || name == "." || name == "/" {
		return ""
	}
	return name
}
