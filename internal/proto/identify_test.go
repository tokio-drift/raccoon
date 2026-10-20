package proto

import (
	"encoding/binary"
	"testing"

	"github.com/tokio-drift/raccoon/internal/model"
)

func dnsHeader(flags, questions uint16) []byte {
	b := make([]byte, 12)
	binary.BigEndian.PutUint16(b[0:2], 0x1234)
	binary.BigEndian.PutUint16(b[2:4], flags)
	binary.BigEndian.PutUint16(b[4:6], questions)
	return b
}

func dnsTCP(payload []byte) []byte {
	b := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(b[:2], uint16(len(payload)))
	copy(b[2:], payload)
	return b
}

func TestIdentify(t *testing.T) {
	tests := []struct {
		name  string
		c2s   string
		s2c   string
		ports PortPair
		udp   bool
		want  string
	}{
		{
			name:  "ftp server greeting on non-standard port",
			s2c:   "220 raccoon FTP ready\r\n",
			ports: PortPair{Client: 50000, Server: 2121},
			want:  "ftp",
		},
		{
			name:  "ftp client command on non-standard port",
			c2s:   "USER bob\r\n",
			ports: PortPair{Client: 50000, Server: 2121},
			want:  "ftp",
		},
		{
			name:  "ftp auth command is case-insensitive",
			c2s:   "auth TLS\r\n",
			ports: PortPair{Client: 50000, Server: 21},
			want:  "ftp",
		},
		{
			name:  "ftp server greeting on port 8081",
			s2c:   "220 hello\r\n",
			ports: PortPair{Client: 50000, Server: 8081},
			want:  "ftp",
		},
		{
			name:  "http request on non-standard port",
			c2s:   "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n",
			ports: PortPair{Client: 50000, Server: 8081},
			want:  "http",
		},
		{
			name:  "http response on non-standard port",
			s2c:   "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
			ports: PortPair{Client: 50000, Server: 8081},
			want:  "http",
		},
		{
			name:  "http request without version is not http",
			c2s:   "GET /just-a-line\r\n",
			ports: PortPair{Client: 50000, Server: 80},
			want:  "unknown",
		},
		{
			name:  "http-like prefix is not http",
			c2s:   "GETTING coffee HTTP/1.1\r\n",
			ports: PortPair{Client: 50000, Server: 80},
			want:  "unknown",
		},
		{
			name:  "http content wins over FTP port",
			c2s:   "POST /upload HTTP/1.0\r\n\r\n",
			ports: PortPair{Client: 50000, Server: 21},
			want:  "http",
		},
		{
			name:  "dns udp",
			c2s:   string(dnsHeader(0x0100, 1)),
			ports: PortPair{Client: 53000, Server: 53},
			udp:   true,
			want:  "dns",
		},
		{
			name:  "dns udp response",
			s2c:   string(dnsHeader(0x8180, 1)),
			ports: PortPair{Client: 53000, Server: 53},
			udp:   true,
			want:  "dns",
		},
		{
			name:  "dns tcp",
			c2s:   string(dnsTCP(dnsHeader(0x0100, 1))),
			ports: PortPair{Client: 53000, Server: 53},
			want:  "dns",
		},
		{
			name:  "dns on non-standard port",
			c2s:   string(dnsHeader(0x0100, 1)),
			ports: PortPair{Client: 53000, Server: 5353},
			udp:   true,
			want:  "unknown",
		},
		{
			name:  "dns with zero questions",
			c2s:   string(dnsHeader(0x0100, 0)),
			ports: PortPair{Client: 53000, Server: 53},
			udp:   true,
			want:  "unknown",
		},
		{
			name:  "dns with non-query opcode",
			c2s:   string(dnsHeader(0x2800, 1)),
			ports: PortPair{Client: 53000, Server: 53},
			udp:   true,
			want:  "unknown",
		},
		{
			name:  "dns tcp with short length prefix",
			c2s:   string(dnsTCP(dnsHeader(0x0100, 1)[:8])),
			ports: PortPair{Client: 53000, Server: 53},
			want:  "unknown",
		},
		{
			name:  "opaque protocol",
			c2s:   "SSH-2.0-OpenSSH_9.6\r\n",
			ports: PortPair{Client: 50000, Server: 22},
			want:  "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Identify([]byte(tt.c2s), []byte(tt.s2c), tt.ports, tt.udp)
			if got != tt.want {
				t.Fatalf("Identify() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestIsFTP(t *testing.T) {
	for _, tc := range []struct {
		in   string
		dir  model.Direction
		want bool
	}{
		{"220 ready\r\n", model.S2C, true},
		{"220ready\r\n", model.S2C, false},
		{"USER bob\r\n", model.C2S, true},
		{"PASS secret\r\n", model.C2S, true},
		{"user bob\r\n", model.C2S, true},
		{"RETR file\r\n", model.C2S, false},
	} {
		if got := IsFTP([]byte(tc.in), tc.dir); got != tc.want {
			t.Errorf("IsFTP(%q, %v) = %v, want %v", tc.in, tc.dir, got, tc.want)
		}
	}
}
