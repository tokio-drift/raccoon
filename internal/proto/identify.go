package proto

import (
	"bytes"
	"encoding/binary"

	"github.com/tokio-drift/raccoon/internal/model"
)

// PortPair is the client and server port of a flow. It is only a hint:
// content sniffing takes precedence so protocols on non-standard ports are
// still recognized.
type PortPair struct {
	Client uint16
	Server uint16
}

const dnsPort = 53

var httpMethods = [...][]byte{
	[]byte("GET"),
	[]byte("POST"),
	[]byte("HEAD"),
	[]byte("PUT"),
	[]byte("DELETE"),
	[]byte("OPTIONS"),
	[]byte("PATCH"),
	[]byte("TRACE"),
	[]byte("CONNECT"),
}

// Identify names the application protocol of a flow from the first bytes seen
// in each direction. It returns "ftp", "http", "dns", or "unknown".
func Identify(firstC2S, firstS2C []byte, ports PortPair, udp bool) string {
	if IsFTP(firstC2S, model.C2S) || IsFTP(firstS2C, model.S2C) {
		return "ftp"
	}
	if IsHTTP(firstC2S, model.C2S) || IsHTTP(firstS2C, model.S2C) {
		return "http"
	}
	if IsDNS(firstC2S, model.C2S, ports, udp) || IsDNS(firstS2C, model.S2C, ports, udp) {
		return "dns"
	}
	return "unknown"
}

// IsFTP reports whether b begins like an FTP control message in direction dir:
// a server greeting ("220 ...") or a client authentication command.
func IsFTP(b []byte, dir model.Direction) bool {
	if dir == model.S2C {
		return bytes.HasPrefix(b, []byte("220 "))
	}
	for _, cmd := range [...][]byte{
		[]byte("USER "),
		[]byte("PASS "),
		[]byte("AUTH "),
	} {
		if hasCommandPrefix(b, cmd) {
			return true
		}
	}
	return false
}

// IsHTTP reports whether b begins like an HTTP/1.x message in direction dir.
func IsHTTP(b []byte, dir model.Direction) bool {
	if len(b) == 0 {
		return false
	}
	if dir == model.S2C {
		return bytes.HasPrefix(b, []byte("HTTP/1."))
	}
	line := firstLine(b)
	for _, method := range httpMethods {
		if len(line) <= len(method) || !bytes.HasPrefix(line, method) || line[len(method)] != ' ' {
			continue
		}
		return bytes.Contains(line, []byte(" HTTP/1."))
	}
	return false
}

// IsDNS reports whether b begins like a DNS message on port 53. For UDP the
// payload is a bare DNS message; for TCP it is prefixed with a 2-byte length.
func IsDNS(b []byte, _ model.Direction, ports PortPair, udp bool) bool {
	if ports.Client != dnsPort && ports.Server != dnsPort {
		return false
	}
	if udp {
		return IsDNSPayload(b)
	}
	return IsDNSStream(b)
}

// IsDNSPayload reports whether b looks like a bare DNS message: at least a
// 12-byte header, opcode 0 and at least one question.
func IsDNSPayload(b []byte) bool {
	return dnsHeaderSane(b)
}

// IsDNSStream reports whether b starts with a 2-byte length prefix followed by
// a DNS message that passes the header sanity check.
func IsDNSStream(b []byte) bool {
	if len(b) < 2 {
		return false
	}
	n := int(binary.BigEndian.Uint16(b[:2]))
	if n < 12 || 2+n > len(b) {
		return false
	}
	return dnsHeaderSane(b[2 : 2+n])
}

func dnsHeaderSane(b []byte) bool {
	if len(b) < 12 {
		return false
	}
	flags := binary.BigEndian.Uint16(b[2:4])
	if (flags>>11)&0xf != 0 {
		return false
	}
	return binary.BigEndian.Uint16(b[4:6]) >= 1
}

func hasCommandPrefix(b, cmd []byte) bool {
	if len(b) < len(cmd) {
		return false
	}
	return bytes.EqualFold(b[:len(cmd)], cmd)
}

func firstLine(b []byte) []byte {
	if i := bytes.IndexByte(b, '\n'); i >= 0 {
		b = b[:i]
	}
	return bytes.TrimSuffix(b, []byte("\r"))
}
