// Command gen generates the deterministic PCAP fixtures and their expected
// results used by the RACCOON test suite. It uses gopacket only for building
// and writing captures, never for reading them.
package main

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

const (
	flagFIN uint8 = 1 << 0
	flagSYN uint8 = 1 << 1
	flagRST uint8 = 1 << 2
	flagPSH uint8 = 1 << 3
	flagACK uint8 = 1 << 4
)

var (
	clientMAC = net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	serverMAC = net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}
	dnsMAC    = net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x03}

	ipClient = net.IPv4(10, 0, 0, 1)
	ipServer = net.IPv4(10, 0, 0, 2)
	ipDNS    = net.IPv4(10, 0, 0, 5)
	ipDNSsrv = net.IPv4(10, 0, 0, 6)
	ipHTTPc  = net.IPv4(10, 0, 0, 3)
	ipHTTPs  = net.IPv4(10, 0, 0, 4)
)

// clock produces strictly increasing capture timestamps.
type clock struct {
	t  time.Time
	dt time.Duration
}

func newClock() *clock {
	return &clock{t: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC), dt: time.Millisecond}
}

func (c *clock) next() time.Time {
	t := c.t
	c.t = c.t.Add(c.dt)
	return t
}

// recorder accumulates serialized packets.
type recorder struct {
	pkts []recPkt
}

type recPkt struct {
	ts   time.Time
	data []byte
}

func (r *recorder) add(ts time.Time, data []byte) {
	r.pkts = append(r.pkts, recPkt{ts: ts, data: data})
}

func (r *recorder) writePCAP(w *bytes.Buffer, lt layers.LinkType) error {
	pw := pcapgo.NewWriter(w)
	if err := pw.WriteFileHeader(65536, lt); err != nil {
		return err
	}
	for _, p := range r.pkts {
		ci := gopacket.CaptureInfo{Timestamp: p.ts, CaptureLength: len(p.data), Length: len(p.data)}
		if err := pw.WritePacket(ci, p.data); err != nil {
			return err
		}
	}
	return nil
}

func (r *recorder) writePCAPNG(w *bytes.Buffer, lt layers.LinkType) error {
	nw, err := pcapgo.NewNgWriter(w, lt)
	if err != nil {
		return err
	}
	for _, p := range r.pkts {
		ci := gopacket.CaptureInfo{Timestamp: p.ts, CaptureLength: len(p.data), Length: len(p.data)}
		if err := nw.WritePacket(ci, p.data); err != nil {
			return err
		}
	}
	return nw.Flush()
}

// conn models a TCP conversation between an initiator ("client") and a
// responder ("server").
type conn struct {
	r            *recorder
	clk          *clock
	cMAC, sMAC   net.HardwareAddr
	cIP, sIP     net.IP
	cPort, sPort uint16
	cNext, sNext uint32
}

func newConn(r *recorder, clk *clock, cMAC, sMAC net.HardwareAddr, cIP, sIP net.IP, cPort, sPort uint16, cISN, sISN uint32) *conn {
	return &conn{
		r: r, clk: clk,
		cMAC: cMAC, sMAC: sMAC,
		cIP: cIP, sIP: sIP,
		cPort: cPort, sPort: sPort,
		cNext: cISN, sNext: sISN,
	}
}

func (c *conn) raw(fromClient bool, flags uint8, seq, ack uint32, payload []byte) {
	var data []byte
	var err error
	if fromClient {
		data, err = tcpPacket(c.cMAC, c.sMAC, c.cIP, c.sIP, c.cPort, c.sPort, seq, ack, flags, payload)
	} else {
		data, err = tcpPacket(c.sMAC, c.cMAC, c.sIP, c.cIP, c.sPort, c.cPort, seq, ack, flags, payload)
	}
	if err != nil {
		panic(err)
	}
	c.r.add(c.clk.next(), data)
}

func (c *conn) advance(side uint32, flags uint8, n int) uint32 {
	side += uint32(n)
	if flags&flagSYN != 0 {
		side++
	}
	if flags&flagFIN != 0 {
		side++
	}
	return side
}

func (c *conn) cSend(flags uint8, payload []byte) {
	c.raw(true, flags, c.cNext, c.sNext, payload)
	c.cNext = c.advance(c.cNext, flags, len(payload))
}

func (c *conn) sSend(flags uint8, payload []byte) {
	c.raw(false, flags, c.sNext, c.cNext, payload)
	c.sNext = c.advance(c.sNext, flags, len(payload))
}

func (c *conn) handshake() {
	c.raw(true, flagSYN, c.cNext, 0, nil)
	c.cNext++
	c.raw(false, flagSYN|flagACK, c.sNext, c.cNext, nil)
	c.sNext++
	c.raw(true, flagACK, c.cNext, c.sNext, nil)
}

func (c *conn) close() {
	c.raw(true, flagFIN|flagACK, c.cNext, c.sNext, nil)
	c.cNext++
	c.raw(false, flagACK, c.sNext, c.cNext, nil)
	c.raw(false, flagFIN|flagACK, c.sNext, c.cNext, nil)
	c.sNext++
	c.raw(true, flagACK, c.cNext, c.sNext, nil)
}

func tcpPacket(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, srcPort, dstPort uint16, seq, ack uint32, flags uint8, payload []byte) ([]byte, error) {
	eth := &layers.Ethernet{SrcMAC: srcMAC, DstMAC: dstMAC, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: srcIP, DstIP: dstIP}
	tcp := &layers.TCP{
		SrcPort:    layers.TCPPort(srcPort),
		DstPort:    layers.TCPPort(dstPort),
		Seq:        seq,
		Ack:        ack,
		Window:     65535,
		DataOffset: 5,
		SYN:        flags&flagSYN != 0,
		ACK:        flags&flagACK != 0,
		FIN:        flags&flagFIN != 0,
		RST:        flags&flagRST != 0,
		PSH:        flags&flagPSH != 0,
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		return nil, err
	}
	sls := []gopacket.SerializableLayer{eth, ip, tcp}
	if len(payload) > 0 {
		sls = append(sls, gopacket.Payload(payload))
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, sls...); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func dnsPacket(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, srcPort, dstPort uint16, dns *layers.DNS) ([]byte, error) {
	eth := &layers.Ethernet{SrcMAC: srcMAC, DstMAC: dstMAC, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: srcIP, DstIP: dstIP}
	udp := &layers.UDP{SrcPort: layers.UDPPort(srcPort), DstPort: layers.UDPPort(dstPort)}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		return nil, err
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, udp, dns); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ---- expected-result model ------------------------------------------------

// Expect is the golden description of a fixture.
type Expect struct {
	Name    string         `json:"name"`
	Packets int            `json:"packets"`
	Streams []StreamExp    `json:"streams,omitempty"`
	Files   []FileExp      `json:"files,omitempty"`
	Events  map[string]int `json:"events,omitempty"`
}

// StreamExp describes one expected stream.
type StreamExp struct {
	Proto     string `json:"proto,omitempty"`
	SrcIP     string `json:"srcIp"`
	SrcPort   uint16 `json:"srcPort"`
	DstIP     string `json:"dstIp"`
	DstPort   uint16 `json:"dstPort"`
	C2SBytes  int    `json:"c2sBytes"`
	S2CBytes  int    `json:"s2cBytes"`
	C2SSHA256 string `json:"c2sSha256,omitempty"`
	S2CSHA256 string `json:"s2cSha256,omitempty"`
	Midstream bool   `json:"midstream,omitempty"`
	HasGaps   bool   `json:"hasGaps,omitempty"`
}

// FileExp describes one expected carved file.
type FileExp struct {
	SHA256 string `json:"sha256"`
	Ext    string `json:"ext"`
	Name   string `json:"name,omitempty"`
	Status string `json:"status,omitempty"`
}

func sha256hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func streamExp(proto, srcIP string, srcPort uint16, dstIP string, dstPort uint16, c2s, s2c []byte) StreamExp {
	return StreamExp{
		Proto: proto,
		SrcIP: srcIP, SrcPort: srcPort,
		DstIP: dstIP, DstPort: dstPort,
		C2SBytes: len(c2s), S2CBytes: len(s2c),
		C2SSHA256: sha256hex(c2s), S2CSHA256: sha256hex(s2c),
	}
}

// ---- file payloads --------------------------------------------------------

func makePNG() []byte {
	img := image.NewRGBA(image.Rect(0, 0, 16, 16))
	for y := 0; y < 16; y++ {
		for x := 0; x < 16; x++ {
			img.Set(x, y, color.RGBA{R: uint8(x * 16), G: uint8(y * 16), B: 128, A: 255})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func makeJPEG() []byte {
	img := image.NewRGBA(image.Rect(0, 0, 24, 24))
	for y := 0; y < 24; y++ {
		for x := 0; x < 24; x++ {
			img.Set(x, y, color.RGBA{R: uint8(y * 8), G: 64, B: uint8(x * 8), A: 255})
		}
	}
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 80}); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func makePDF() []byte {
	var buf bytes.Buffer
	buf.WriteString("%PDF-1.4\n")
	offsets := make(map[int]int)
	offsets[1] = buf.Len()
	buf.WriteString("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")
	offsets[2] = buf.Len()
	buf.WriteString("2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n")
	offsets[3] = buf.Len()
	buf.WriteString("3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>\nendobj\n")
	xref := buf.Len()
	buf.WriteString("xref\n0 4\n")
	buf.WriteString("0000000000 65535 f \n")
	for i := 1; i <= 3; i++ {
		fmt.Fprintf(&buf, "%010d 00000 n \n", offsets[i])
	}
	buf.WriteString("trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n")
	fmt.Fprintf(&buf, "%d\n", xref)
	buf.WriteString("%%EOF\n")
	return buf.Bytes()
}

func makeZIP() []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	hdr := &zip.FileHeader{
		Name:     "hello.txt",
		Method:   zip.Store,
		Modified: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	w, err := zw.CreateHeader(hdr)
	if err != nil {
		panic(err)
	}
	if _, err := w.Write([]byte("hello from raccoon\n")); err != nil {
		panic(err)
	}
	if err := zw.Close(); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func gzipBytes(data []byte) []byte {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(data); err != nil {
		panic(err)
	}
	if err := zw.Close(); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func chunkedBody(data []byte, chunkSize int) []byte {
	var buf bytes.Buffer
	for len(data) > 0 {
		n := chunkSize
		if n > len(data) {
			n = len(data)
		}
		fmt.Fprintf(&buf, "%x\r\n", n)
		buf.Write(data[:n])
		buf.WriteString("\r\n")
		data = data[n:]
	}
	buf.WriteString("0\r\n\r\n")
	return buf.Bytes()
}

func pattern(seed byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = seed + byte(i)
	}
	return b
}

// ---- fixtures -------------------------------------------------------------

func emit(outDir, name string, r *recorder, exp Expect, asPCAPNG bool) error {
	exp.Name = name
	exp.Packets = len(r.pkts)
	var buf bytes.Buffer
	var err error
	if asPCAPNG {
		err = r.writePCAPNG(&buf, layers.LinkTypeEthernet)
	} else {
		err = r.writePCAP(&buf, layers.LinkTypeEthernet)
	}
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(outDir, name), buf.Bytes(), 0o644); err != nil {
		return err
	}
	return writeExpected(outDir, name, exp)
}

func writeExpected(outDir, name string, exp Expect) error {
	exp.Name = name
	base := strings.TrimSuffix(name, filepath.Ext(name)) + ".json"
	data, err := json.MarshalIndent(exp, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(filepath.Join(outDir, "expected", base), data, 0o644)
}

func newRec() (*recorder, *clock) { return &recorder{}, newClock() }

func tcpBasic() (*recorder, *clock) {
	r, clk := newRec()
	c := newConn(r, clk, clientMAC, serverMAC, ipClient, ipServer, 50000, 80, 1000, 2000)
	c.handshake()
	for _, s := range []string{"AAA", "BBB", "CCC"} {
		c.cSend(flagPSH|flagACK, []byte(s))
	}
	c.sSend(flagACK, nil)
	for _, s := range []string{"111", "222", "333"} {
		c.sSend(flagPSH|flagACK, []byte(s))
	}
	c.cSend(flagACK, nil)
	c.close()
	return r, clk
}

func tcpOOO() (*recorder, *clock) {
	r, clk := newRec()
	c := newConn(r, clk, clientMAC, serverMAC, ipClient, ipServer, 50000, 80, 1000, 2000)
	c.handshake()
	for _, s := range []string{"AAA", "BBB", "CCC"} {
		c.cSend(flagPSH|flagACK, []byte(s))
	}
	c.sSend(flagACK, nil)
	sBase := c.sNext
	c.raw(false, flagPSH|flagACK, sBase+6, c.cNext, []byte("333"))
	c.raw(false, flagPSH|flagACK, sBase, c.cNext, []byte("111"))
	c.raw(false, flagPSH|flagACK, sBase+3, c.cNext, []byte("222"))
	c.sNext = sBase + 9
	c.cSend(flagACK, nil)
	c.close()
	return r, clk
}

func tcpRetrans() (*recorder, *clock) {
	r, clk := newRec()
	c := newConn(r, clk, clientMAC, serverMAC, ipClient, ipServer, 50000, 80, 1000, 2000)
	c.handshake()
	for _, s := range []string{"AAA", "BBB", "CCC"} {
		c.cSend(flagPSH|flagACK, []byte(s))
	}
	c.sSend(flagACK, nil)
	sBase := c.sNext
	c.raw(false, flagPSH|flagACK, sBase, c.cNext, []byte("111"))
	c.raw(false, flagPSH|flagACK, sBase, c.cNext, []byte("111"))
	c.raw(false, flagPSH|flagACK, sBase+3, c.cNext, []byte("222"))
	c.raw(false, flagPSH|flagACK, sBase+6, c.cNext, []byte("333"))
	c.sNext = sBase + 9
	c.cSend(flagACK, nil)
	c.close()
	return r, clk
}

func tcpOverlapConflict() (*recorder, *clock) {
	r, clk := newRec()
	c := newConn(r, clk, clientMAC, serverMAC, ipClient, ipServer, 50000, 80, 1000, 2000)
	c.handshake()
	for _, s := range []string{"AAA", "BBB", "CCC"} {
		c.cSend(flagPSH|flagACK, []byte(s))
	}
	c.sSend(flagACK, nil)
	sBase := c.sNext
	c.raw(false, flagPSH|flagACK, sBase, c.cNext, []byte("AAAA"))
	c.raw(false, flagPSH|flagACK, sBase, c.cNext, []byte("BBBB"))
	c.raw(false, flagPSH|flagACK, sBase+4, c.cNext, []byte("CCCC"))
	c.sNext = sBase + 8
	c.cSend(flagACK, nil)
	c.close()
	return r, clk
}

func tcpWrap() (*recorder, *clock) {
	r, clk := newRec()
	c := newConn(r, clk, clientMAC, serverMAC, ipClient, ipServer, 50000, 80, 1000, 0xFFFFFF00)
	c.handshake()
	for _, s := range []string{"AAA", "BBB", "CCC"} {
		c.cSend(flagPSH|flagACK, []byte(s))
	}
	c.sSend(flagACK, nil)
	p1 := pattern(0x10, 64)
	p2 := pattern(0x50, 64)
	p3 := pattern(0x90, 64)
	c.sSend(flagPSH|flagACK, p1)
	c.sSend(flagPSH|flagACK, p2)
	c.sSend(flagPSH|flagACK, p3)
	c.cSend(flagACK, nil)
	c.close()
	return r, clk
}

func tcpGap() (*recorder, *clock) {
	r, clk := newRec()
	c := newConn(r, clk, clientMAC, serverMAC, ipClient, ipServer, 50000, 80, 1000, 2000)
	c.handshake()
	for _, s := range []string{"AAA", "BBB", "CCC"} {
		c.cSend(flagPSH|flagACK, []byte(s))
	}
	c.sSend(flagACK, nil)
	sBase := c.sNext
	c.raw(false, flagPSH|flagACK, sBase, c.cNext, []byte("111"))
	c.raw(false, flagPSH|flagACK, sBase+6, c.cNext, []byte("333"))
	c.sNext = sBase + 9
	c.cSend(flagACK, nil)
	c.close()
	return r, clk
}

func tcpMidstream() (*recorder, *clock) {
	r, clk := newRec()
	c := newConn(r, clk, clientMAC, serverMAC, ipClient, ipServer, 50000, 80, 5000, 9000)
	c.cSend(flagPSH|flagACK, []byte("hello"))
	c.sSend(flagPSH|flagACK, []byte("world"))
	c.close()
	return r, clk
}

func tcpPortReuse() (*recorder, *clock) {
	r, clk := newRec()
	c1 := newConn(r, clk, clientMAC, serverMAC, ipClient, ipServer, 50000, 80, 1000, 2000)
	c1.handshake()
	c1.cSend(flagPSH|flagACK, []byte("first"))
	c1.sSend(flagPSH|flagACK, []byte("one"))
	c1.close()
	c2 := newConn(r, clk, clientMAC, serverMAC, ipClient, ipServer, 50000, 80, 7000, 8000)
	c2.handshake()
	c2.cSend(flagPSH|flagACK, []byte("second"))
	c2.sSend(flagPSH|flagACK, []byte("two"))
	c2.close()
	return r, clk
}

func ftpUploadPNG(pngBytes []byte) (*recorder, *clock) {
	r, clk := newRec()
	c := newConn(r, clk, clientMAC, serverMAC, ipClient, ipServer, 50000, 21, 1000, 2000)
	c.handshake()
	c.sSend(flagPSH|flagACK, []byte("220 raccoon FTP ready\r\n"))
	c.cSend(flagPSH|flagACK, []byte("USER bob\r\n"))
	c.sSend(flagPSH|flagACK, []byte("331 Password required\r\n"))
	c.cSend(flagPSH|flagACK, []byte("PASS s3cr3t\r\n"))
	c.sSend(flagPSH|flagACK, []byte("230 Logged in\r\n"))
	c.cSend(flagPSH|flagACK, []byte("PASV\r\n"))
	c.sSend(flagPSH|flagACK, []byte("227 Entering Passive Mode (10,0,0,2,117,48)\r\n"))
	c.cSend(flagPSH|flagACK, []byte("STOR secret.png\r\n"))
	c.sSend(flagPSH|flagACK, []byte("150 Ok to send data\r\n"))

	d := newConn(r, clk, clientMAC, serverMAC, ipClient, ipServer, 50001, 30000, 3000, 4000)
	d.handshake()
	d.cSend(flagPSH|flagACK, pngBytes)
	d.cSend(flagFIN|flagACK, nil)
	d.sSend(flagACK, nil)
	d.sSend(flagFIN|flagACK, nil)
	d.cSend(flagACK, nil)

	c.sSend(flagPSH|flagACK, []byte("226 Transfer complete\r\n"))
	c.cSend(flagPSH|flagACK, []byte("QUIT\r\n"))
	c.sSend(flagPSH|flagACK, []byte("221 Bye\r\n"))
	c.close()
	return r, clk
}

func ftpDownloadPDF(pdfBytes []byte) (*recorder, *clock) {
	r, clk := newRec()
	c := newConn(r, clk, clientMAC, serverMAC, ipClient, ipServer, 50000, 21, 1000, 2000)
	c.handshake()
	c.sSend(flagPSH|flagACK, []byte("220 raccoon FTP ready\r\n"))
	c.cSend(flagPSH|flagACK, []byte("USER bob\r\n"))
	c.sSend(flagPSH|flagACK, []byte("331 Password required\r\n"))
	c.cSend(flagPSH|flagACK, []byte("PASS s3cr3t\r\n"))
	c.sSend(flagPSH|flagACK, []byte("230 Logged in\r\n"))
	c.cSend(flagPSH|flagACK, []byte("PORT 10,0,0,1,122,137\r\n"))
	c.sSend(flagPSH|flagACK, []byte("200 PORT command successful\r\n"))
	c.cSend(flagPSH|flagACK, []byte("RETR plans.pdf\r\n"))
	c.sSend(flagPSH|flagACK, []byte("150 Opening data connection\r\n"))

	d := newConn(r, clk, serverMAC, clientMAC, ipServer, ipClient, 20, 31337, 3000, 4000)
	d.handshake()
	d.cSend(flagPSH|flagACK, pdfBytes)
	d.cSend(flagFIN|flagACK, nil)
	d.sSend(flagACK, nil)
	d.sSend(flagFIN|flagACK, nil)
	d.cSend(flagACK, nil)

	c.sSend(flagPSH|flagACK, []byte("226 Transfer complete\r\n"))
	c.cSend(flagPSH|flagACK, []byte("QUIT\r\n"))
	c.sSend(flagPSH|flagACK, []byte("221 Bye\r\n"))
	c.close()
	return r, clk
}

func ftpBruteforce() (*recorder, *clock) {
	r, clk := newRec()
	c := newConn(r, clk, clientMAC, serverMAC, ipClient, ipServer, 50000, 21, 1000, 2000)
	c.handshake()
	c.sSend(flagPSH|flagACK, []byte("220 raccoon FTP ready\r\n"))
	for i := 0; i < 40; i++ {
		c.cSend(flagPSH|flagACK, []byte(fmt.Sprintf("USER user%02d\r\n", i)))
		c.sSend(flagPSH|flagACK, []byte("331 Password required\r\n"))
		c.cSend(flagPSH|flagACK, []byte("PASS wrong\r\n"))
		c.sSend(flagPSH|flagACK, []byte("530 Login incorrect\r\n"))
	}
	c.cSend(flagPSH|flagACK, []byte("USER bob\r\n"))
	c.sSend(flagPSH|flagACK, []byte("331 Password required\r\n"))
	c.cSend(flagPSH|flagACK, []byte("PASS s3cr3t\r\n"))
	c.sSend(flagPSH|flagACK, []byte("230 Logged in\r\n"))
	c.close()
	return r, clk
}

func httpGetJPEGChunked(jpegBytes []byte) (*recorder, *clock) {
	r, clk := newRec()
	c := newConn(r, clk, clientMAC, serverMAC, ipHTTPc, ipHTTPs, 41000, 8080, 1000, 2000)
	c.handshake()
	c.cSend(flagPSH|flagACK, []byte("GET /img.jpg HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n"))
	body := chunkedBody(gzipBytes(jpegBytes), 64)
	header := "HTTP/1.1 200 OK\r\nContent-Type: image/jpeg\r\nContent-Encoding: gzip\r\n" +
		"Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
	c.sSend(flagPSH|flagACK, append([]byte(header), body...))
	c.close()
	return r, clk
}

func dnsQueries() (*recorder, *clock) {
	r, clk := newRec()
	qnames := []string{"example.com", "www.example.com", "mail.example.com", "cdn.example.com"}
	for i, q := range qnames {
		var qdns layers.DNS
		qdns.ID = uint16(0x1000 + i)
		qdns.OpCode = layers.DNSOpCodeQuery
		qdns.RD = true
		qdns.Questions = []layers.DNSQuestion{{Name: []byte(q), Type: layers.DNSTypeA, Class: layers.DNSClassIN}}
		data, err := dnsPacket(dnsMAC, serverMAC, ipDNS, ipDNSsrv, 53000, 53, &qdns)
		if err != nil {
			panic(err)
		}
		r.add(clk.next(), data)

		var adns layers.DNS
		adns.ID = uint16(0x1000 + i)
		adns.QR = true
		adns.RA = true
		adns.Questions = []layers.DNSQuestion{{Name: []byte(q), Type: layers.DNSTypeA, Class: layers.DNSClassIN}}
		adns.Answers = []layers.DNSResourceRecord{{
			Name:  []byte(q),
			Type:  layers.DNSTypeA,
			Class: layers.DNSClassIN,
			TTL:   300,
			IP:    net.IPv4(93, 184, 216, 34),
		}}
		data, err = dnsPacket(serverMAC, dnsMAC, ipDNSsrv, ipDNS, 53, 53000, &adns)
		if err != nil {
			panic(err)
		}
		r.add(clk.next(), data)
	}
	return r, clk
}

func carveNonstandardPort(zipBytes []byte) (*recorder, *clock) {
	r, clk := newRec()
	c := newConn(r, clk, clientMAC, serverMAC, ipClient, ipServer, 50000, 4444, 1000, 2000)
	c.handshake()
	c.cSend(flagPSH|flagACK, zipBytes)
	c.sSend(flagACK, nil)
	c.close()
	return r, clk
}

func corruptHeader() []byte {
	return []byte("RACCOON corrupt header fixture, definitely not a PCAP\n0123456789abcdef\n")
}

func main() {
	outDir := flag.String("out", "testdata", "output directory for generated fixtures")
	flag.Parse()

	if err := generate(*outDir); err != nil {
		log.Fatalf("gen: %v", err)
	}
}

func generate(outDir string) error {
	if err := os.MkdirAll(filepath.Join(outDir, "expected"), 0o755); err != nil {
		return err
	}

	pngBytes := makePNG()
	jpegBytes := makeJPEG()
	pdfBytes := makePDF()
	zipBytes := makeZIP()

	type fixture struct {
		name   string
		r      *recorder
		exp    Expect
		pcapng bool
	}
	fixtures := []fixture{
		{"tcp_basic.pcap", nil, Expect{Streams: []StreamExp{
			streamExp("tcp", ipClient.String(), 50000, ipServer.String(), 80, []byte("AAABBBCCC"), []byte("111222333")),
		}}, false},
		{"tcp_ooo.pcap", nil, Expect{Streams: []StreamExp{
			streamExp("tcp", ipClient.String(), 50000, ipServer.String(), 80, []byte("AAABBBCCC"), []byte("111222333")),
		}}, false},
		{"tcp_retrans.pcap", nil, Expect{Streams: []StreamExp{
			streamExp("tcp", ipClient.String(), 50000, ipServer.String(), 80, []byte("AAABBBCCC"), []byte("111222333")),
		}}, false},
		{"tcp_overlap_conflict.pcap", nil, Expect{Streams: []StreamExp{
			streamExp("tcp", ipClient.String(), 50000, ipServer.String(), 80, []byte("AAABBBCCC"), []byte("AAAACCCC")),
		}}, false},
		{"tcp_wrap.pcap", nil, Expect{Streams: []StreamExp{
			streamExp("tcp", ipClient.String(), 50000, ipServer.String(), 80, []byte("AAABBBCCC"),
				append(append(pattern(0x10, 64), pattern(0x50, 64)...), pattern(0x90, 64)...)),
		}}, false},
		{"tcp_gap.pcap", nil, Expect{Streams: []StreamExp{
			func() StreamExp {
				e := streamExp("tcp", ipClient.String(), 50000, ipServer.String(), 80, []byte("AAABBBCCC"), []byte("111333"))
				e.HasGaps = true
				return e
			}(),
		}}, false},
		{"tcp_midstream.pcap", nil, Expect{Streams: []StreamExp{
			func() StreamExp {
				e := streamExp("tcp", ipClient.String(), 50000, ipServer.String(), 80, []byte("hello"), []byte("world"))
				e.Midstream = true
				return e
			}(),
		}}, false},
		{"tcp_portreuse.pcap", nil, Expect{Streams: []StreamExp{
			streamExp("tcp", ipClient.String(), 50000, ipServer.String(), 80, []byte("first"), []byte("one")),
			streamExp("tcp", ipClient.String(), 50000, ipServer.String(), 80, []byte("second"), []byte("two")),
		}}, false},
		{"ftp_upload_png.pcap", nil, Expect{
			Streams: []StreamExp{
				streamExp("ftp", ipClient.String(), 50000, ipServer.String(), 21, nil, nil),
				streamExp("ftp-data", ipClient.String(), 50001, ipServer.String(), 30000, pngBytes, nil),
			},
			Files:  []FileExp{{SHA256: sha256hex(pngBytes), Ext: "png", Name: "secret.png", Status: "complete"}},
			Events: map[string]int{"FTP_LOGIN_SUCCESS": 1},
		}, false},
		{"ftp_download_pdf_port31337.pcap", nil, Expect{
			Streams: []StreamExp{
				streamExp("ftp", ipClient.String(), 50000, ipServer.String(), 21, nil, nil),
				streamExp("ftp-data", ipServer.String(), 20, ipClient.String(), 31337, pdfBytes, nil),
			},
			Files:  []FileExp{{SHA256: sha256hex(pdfBytes), Ext: "pdf", Name: "plans.pdf", Status: "complete"}},
			Events: map[string]int{"FTP_LOGIN_SUCCESS": 1},
		}, false},
		{"ftp_bruteforce.pcap", nil, Expect{
			Streams: []StreamExp{
				streamExp("ftp", ipClient.String(), 50000, ipServer.String(), 21, nil, nil),
			},
			Events: map[string]int{"FTP_LOGIN_FAILED": 40, "FTP_LOGIN_SUCCESS": 1},
		}, false},
		{"http_get_jpeg_chunked.pcap", nil, Expect{
			Streams: []StreamExp{
				streamExp("http", ipHTTPc.String(), 41000, ipHTTPs.String(), 8080, nil, nil),
			},
			Files: []FileExp{{SHA256: sha256hex(jpegBytes), Ext: "jpg", Status: "complete"}},
		}, false},
		{"dns_queries.pcap", nil, Expect{
			Streams: []StreamExp{
				streamExp("dns", ipDNS.String(), 53000, ipDNSsrv.String(), 53, nil, nil),
			},
		}, false},
		{"carve_nonstandard_port.pcap", nil, Expect{
			Streams: []StreamExp{
				streamExp("unknown", ipClient.String(), 50000, ipServer.String(), 4444, zipBytes, nil),
			},
			Files: []FileExp{{SHA256: sha256hex(zipBytes), Ext: "zip", Status: "complete"}},
		}, false},
	}

	builders := map[string]func() (*recorder, *clock){
		"tcp_basic.pcap":                  tcpBasic,
		"tcp_ooo.pcap":                    tcpOOO,
		"tcp_retrans.pcap":                tcpRetrans,
		"tcp_overlap_conflict.pcap":       tcpOverlapConflict,
		"tcp_wrap.pcap":                   tcpWrap,
		"tcp_gap.pcap":                    tcpGap,
		"tcp_midstream.pcap":              tcpMidstream,
		"tcp_portreuse.pcap":              tcpPortReuse,
		"ftp_upload_png.pcap":             func() (*recorder, *clock) { return ftpUploadPNG(pngBytes) },
		"ftp_download_pdf_port31337.pcap": func() (*recorder, *clock) { return ftpDownloadPDF(pdfBytes) },
		"ftp_bruteforce.pcap":             ftpBruteforce,
		"http_get_jpeg_chunked.pcap":      func() (*recorder, *clock) { return httpGetJPEGChunked(jpegBytes) },
		"dns_queries.pcap":                dnsQueries,
		"carve_nonstandard_port.pcap":     func() (*recorder, *clock) { return carveNonstandardPort(zipBytes) },
	}

	for i := range fixtures {
		f := &fixtures[i]
		r, _ := builders[f.name]()
		if err := emit(outDir, f.name, r, f.exp, false); err != nil {
			return err
		}
	}

	// pcapng_basic: same bytes as tcp_basic, written as pcapng.
	r, _ := tcpBasic()
	if err := emit(outDir, "pcapng_basic.pcapng", r, Expect{Streams: []StreamExp{
		streamExp("tcp", ipClient.String(), 50000, ipServer.String(), 80, []byte("AAABBBCCC"), []byte("111222333")),
	}}, true); err != nil {
		return err
	}

	// corrupt_header: not a capture at all.
	if err := os.WriteFile(filepath.Join(outDir, "corrupt_header.pcap"), corruptHeader(), 0o644); err != nil {
		return err
	}
	if err := writeExpected(outDir, "corrupt_header.pcap", Expect{}); err != nil {
		return err
	}

	// truncated_tail: tcp_basic with a final partial record.
	base, _ := tcpBasic()
	var buf bytes.Buffer
	if err := base.writePCAP(&buf, layers.LinkTypeEthernet); err != nil {
		return err
	}
	var hdr [16]byte
	binary.LittleEndian.PutUint32(hdr[8:12], 200)  // incl_len
	binary.LittleEndian.PutUint32(hdr[12:16], 200) // orig_len
	buf.Write(hdr[:])
	buf.Write(pattern(0x00, 100)) // only half of the declared 200 bytes
	if err := os.WriteFile(filepath.Join(outDir, "truncated_tail.pcap"), buf.Bytes(), 0o644); err != nil {
		return err
	}
	if err := writeExpected(outDir, "truncated_tail.pcap", Expect{
		Streams: []StreamExp{
			streamExp("tcp", ipClient.String(), 50000, ipServer.String(), 80, []byte("AAABBBCCC"), []byte("111222333")),
		},
	}); err != nil {
		return err
	}

	return nil
}
