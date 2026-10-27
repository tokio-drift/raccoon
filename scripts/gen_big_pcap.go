// Command gen_big_pcap generates synthetic 100 MB and 500 MB PCAPs with
// thousands of flows, mixed FTP/HTTP/DNS protocols, embedded files (PNG, PDF,
// ZIP, JPEG) with known hashes, and retransmitted/out-of-order packets.
//
// Usage:
//
//	go run ./scripts/gen_big_pcap.go [-out testdata/big] [-sizes 100,500]
package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"log"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"strconv"
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
	macClient = net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	macServer = net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}
	macDNS    = net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x03}
)

type pcapWriter struct {
	f     *os.File
	bw    *bufio.Writer
	pw    *pcapgo.Writer
	bytes int64
	pkts  int64
	clk   time.Time
}

func newPCAPWriter(path string) (*pcapWriter, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	bw := bufio.NewWriterSize(f, 2*1024*1024)
	pw := pcapgo.NewWriter(bw)
	if err := pw.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
		f.Close()
		return nil, err
	}
	return &pcapWriter{
		f:     f,
		bw:    bw,
		pw:    pw,
		bytes: 24, // PCAP header
		clk:   time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC),
	}, nil
}

func (w *pcapWriter) nextTime() time.Time {
	w.clk = w.clk.Add(50 * time.Microsecond)
	return w.clk
}

func (w *pcapWriter) writePacket(data []byte) error {
	ts := w.nextTime()
	ci := gopacket.CaptureInfo{
		Timestamp:     ts,
		CaptureLength: len(data),
		Length:        len(data),
	}
	if err := w.pw.WritePacket(ci, data); err != nil {
		return err
	}
	w.bytes += int64(16 + len(data))
	w.pkts++
	return nil
}

func (w *pcapWriter) close() error {
	if err := w.bw.Flush(); err != nil {
		w.f.Close()
		return err
	}
	return w.f.Close()
}

type packetBuilder struct {
	eth      layers.Ethernet
	ip       layers.IPv4
	tcpLayer layers.TCP
	udpLayer layers.UDP
	buf      gopacket.SerializeBuffer
}

func newPacketBuilder() *packetBuilder {
	pb := &packetBuilder{
		buf: gopacket.NewSerializeBuffer(),
	}
	pb.eth.EthernetType = layers.EthernetTypeIPv4
	pb.ip.Version = 4
	pb.ip.IHL = 5
	pb.ip.TTL = 64
	return pb
}

func (pb *packetBuilder) tcp(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, srcPort, dstPort uint16, seq, ack uint32, flags uint8, payload []byte) ([]byte, error) {
	pb.eth.SrcMAC = srcMAC
	pb.eth.DstMAC = dstMAC
	pb.ip.SrcIP = srcIP
	pb.ip.DstIP = dstIP
	pb.ip.Protocol = layers.IPProtocolTCP

	pb.tcpLayer.SrcPort = layers.TCPPort(srcPort)
	pb.tcpLayer.DstPort = layers.TCPPort(dstPort)
	pb.tcpLayer.Seq = seq
	pb.tcpLayer.Ack = ack
	pb.tcpLayer.Window = 65535
	pb.tcpLayer.DataOffset = 5
	pb.tcpLayer.SYN = flags&flagSYN != 0
	pb.tcpLayer.ACK = flags&flagACK != 0
	pb.tcpLayer.FIN = flags&flagFIN != 0
	pb.tcpLayer.RST = flags&flagRST != 0
	pb.tcpLayer.PSH = flags&flagPSH != 0

	if err := pb.tcpLayer.SetNetworkLayerForChecksum(&pb.ip); err != nil {
		return nil, err
	}

	pb.buf.Clear()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	var err error
	if len(payload) > 0 {
		err = gopacket.SerializeLayers(pb.buf, opts, &pb.eth, &pb.ip, &pb.tcpLayer, gopacket.Payload(payload))
	} else {
		err = gopacket.SerializeLayers(pb.buf, opts, &pb.eth, &pb.ip, &pb.tcpLayer)
	}
	if err != nil {
		return nil, err
	}
	return pb.buf.Bytes(), nil
}

func (pb *packetBuilder) udp(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, srcPort, dstPort uint16, payload gopacket.SerializableLayer) ([]byte, error) {
	pb.eth.SrcMAC = srcMAC
	pb.eth.DstMAC = dstMAC
	pb.ip.SrcIP = srcIP
	pb.ip.DstIP = dstIP
	pb.ip.Protocol = layers.IPProtocolUDP

	pb.udpLayer.SrcPort = layers.UDPPort(srcPort)
	pb.udpLayer.DstPort = layers.UDPPort(dstPort)

	if err := pb.udpLayer.SetNetworkLayerForChecksum(&pb.ip); err != nil {
		return nil, err
	}

	pb.buf.Clear()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(pb.buf, opts, &pb.eth, &pb.ip, &pb.udpLayer, payload); err != nil {
		return nil, err
	}
	return pb.buf.Bytes(), nil
}

// Embedded files with identical generator logic to testdata/gen/main.go.
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
	buf.WriteString("%%EOF")
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

type fileArtifact struct {
	Name   string `json:"name"`
	Format string `json:"format"`
	Size   int    `json:"size"`
	SHA256 string `json:"sha256"`
	Bytes  []byte `json:"-"`
}

func getArtifacts() []fileArtifact {
	pngBytes := makePNG()
	jpegBytes := makeJPEG()
	pdfBytes := makePDF()
	zipBytes := makeZIP()

	hPNG := sha256.Sum256(pngBytes)
	hJPEG := sha256.Sum256(jpegBytes)
	hPDF := sha256.Sum256(pdfBytes)
	hZIP := sha256.Sum256(zipBytes)

	return []fileArtifact{
		{Name: "secret.png", Format: "png", Size: len(pngBytes), SHA256: hex.EncodeToString(hPNG[:]), Bytes: pngBytes},
		{Name: "photo.jpg", Format: "jpeg", Size: len(jpegBytes), SHA256: hex.EncodeToString(hJPEG[:]), Bytes: jpegBytes},
		{Name: "document.pdf", Format: "pdf", Size: len(pdfBytes), SHA256: hex.EncodeToString(hPDF[:]), Bytes: pdfBytes},
		{Name: "archive.zip", Format: "zip", Size: len(zipBytes), SHA256: hex.EncodeToString(hZIP[:]), Bytes: zipBytes},
	}
}

func writeTCPFlow(w *pcapWriter, pb *packetBuilder, cIP, sIP net.IP, cPort, sPort uint16, reqPayload, respPayload []byte, retransmit bool, outOfOrder bool) error {
	cSeq := uint32(1000 + rand.Intn(10000))
	sSeq := uint32(5000 + rand.Intn(10000))

	// 1. SYN
	pkt, err := pb.tcp(macClient, macServer, cIP, sIP, cPort, sPort, cSeq, 0, flagSYN, nil)
	if err != nil {
		return err
	}
	if err := w.writePacket(pkt); err != nil {
		return err
	}
	cSeq++

	// 2. SYN-ACK
	pkt, err = pb.tcp(macServer, macClient, sIP, cIP, sPort, cPort, sSeq, cSeq, flagSYN|flagACK, nil)
	if err != nil {
		return err
	}
	if err := w.writePacket(pkt); err != nil {
		return err
	}
	sSeq++

	// 3. ACK
	pkt, err = pb.tcp(macClient, macServer, cIP, sIP, cPort, sPort, cSeq, sSeq, flagACK, nil)
	if err != nil {
		return err
	}
	if err := w.writePacket(pkt); err != nil {
		return err
	}

	// 4. Request
	if len(reqPayload) > 0 {
		pkt, err = pb.tcp(macClient, macServer, cIP, sIP, cPort, sPort, cSeq, sSeq, flagPSH|flagACK, reqPayload)
		if err != nil {
			return err
		}
		if err := w.writePacket(pkt); err != nil {
			return err
		}
		cSeq += uint32(len(reqPayload))

		// Server ACK
		pkt, err = pb.tcp(macServer, macClient, sIP, cIP, sPort, cPort, sSeq, cSeq, flagACK, nil)
		if err != nil {
			return err
		}
		if err := w.writePacket(pkt); err != nil {
			return err
		}
	}

	// 5. Response (chunked into ~1300 byte segments)
	if len(respPayload) > 0 {
		chunkSize := 1300
		type seg struct {
			seq     uint32
			payload []byte
		}
		var segs []seg
		for off := 0; off < len(respPayload); off += chunkSize {
			end := off + chunkSize
			if end > len(respPayload) {
				end = len(respPayload)
			}
			segs = append(segs, seg{seq: sSeq + uint32(off), payload: respPayload[off:end]})
		}
		sSeq += uint32(len(respPayload))

		if outOfOrder && len(segs) >= 2 {
			// Swap seg 0 and seg 1
			segs[0], segs[1] = segs[1], segs[0]
		}

		for _, s := range segs {
			flags := flagACK
			if s.seq+uint32(len(s.payload)) == sSeq {
				flags |= flagPSH
			}
			pkt, err = pb.tcp(macServer, macClient, sIP, cIP, sPort, cPort, s.seq, cSeq, uint8(flags), s.payload)
			if err != nil {
				return err
			}
			if err := w.writePacket(pkt); err != nil {
				return err
			}

			if retransmit {
				// Re-send the same packet (retransmission)
				if err := w.writePacket(pkt); err != nil {
					return err
				}
				retransmit = false
			}
		}

		// Client ACK
		pkt, err = pb.tcp(macClient, macServer, cIP, sIP, cPort, sPort, cSeq, sSeq, flagACK, nil)
		if err != nil {
			return err
		}
		if err := w.writePacket(pkt); err != nil {
			return err
		}
	}

	// 6. FIN-ACK from client
	pkt, err = pb.tcp(macClient, macServer, cIP, sIP, cPort, sPort, cSeq, sSeq, flagFIN|flagACK, nil)
	if err != nil {
		return err
	}
	if err := w.writePacket(pkt); err != nil {
		return err
	}
	cSeq++

	// 7. ACK from server
	pkt, err = pb.tcp(macServer, macClient, sIP, cIP, sPort, cPort, sSeq, cSeq, flagACK, nil)
	if err != nil {
		return err
	}
	if err := w.writePacket(pkt); err != nil {
		return err
	}

	// 8. FIN-ACK from server
	pkt, err = pb.tcp(macServer, macClient, sIP, cIP, sPort, cPort, sSeq, cSeq, flagFIN|flagACK, nil)
	if err != nil {
		return err
	}
	if err := w.writePacket(pkt); err != nil {
		return err
	}
	sSeq++

	// 9. Final ACK from client
	pkt, err = pb.tcp(macClient, macServer, cIP, sIP, cPort, sPort, cSeq, sSeq, flagACK, nil)
	if err != nil {
		return err
	}
	return w.writePacket(pkt)
}

func writeDNS(w *pcapWriter, pb *packetBuilder, cIP, sIP net.IP, cPort, sPort uint16, qname string) error {
	txID := uint16(rand.Intn(65535))

	// DNS Query
	q := &layers.DNS{
		ID:     txID,
		QR:     false,
		OpCode: layers.DNSOpCodeQuery,
		RD:     true,
		Questions: []layers.DNSQuestion{
			{
				Name:  []byte(qname),
				Type:  layers.DNSTypeA,
				Class: layers.DNSClassIN,
			},
		},
	}
	pkt, err := pb.udp(macClient, macDNS, cIP, sIP, cPort, sPort, q)
	if err != nil {
		return err
	}
	if err := w.writePacket(pkt); err != nil {
		return err
	}

	// DNS Response
	resp := &layers.DNS{
		ID:           txID,
		QR:           true,
		OpCode:       layers.DNSOpCodeQuery,
		ResponseCode: layers.DNSResponseCodeNoErr,
		AA:           true,
		RD:           true,
		RA:           true,
		Questions: []layers.DNSQuestion{
			{
				Name:  []byte(qname),
				Type:  layers.DNSTypeA,
				Class: layers.DNSClassIN,
			},
		},
		Answers: []layers.DNSResourceRecord{
			{
				Name:  []byte(qname),
				Type:  layers.DNSTypeA,
				Class: layers.DNSClassIN,
				TTL:   300,
				IP:    net.IPv4(93, 184, 216, byte(rand.Intn(250)+1)),
			},
		},
	}
	pkt, err = pb.udp(macDNS, macClient, sIP, cIP, sPort, cPort, resp)
	if err != nil {
		return err
	}
	return w.writePacket(pkt)
}

func generateBigPCAP(path string, targetBytes int64, artifacts []fileArtifact) (int64, int, error) {
	w, err := newPCAPWriter(path)
	if err != nil {
		return 0, 0, err
	}
	defer w.close()

	pb := newPacketBuilder()
	flowCount := 0

	// 1. First embed each known file in separate flows (both HTTP and FTP)
	for i, art := range artifacts {
		clientIP := net.IPv4(10, 0, 1, byte(i+10))
		serverIP := net.IPv4(192, 168, 1, byte(i+20))
		cPort := uint16(40000 + i)

		// A: HTTP GET with the artifact as body
		req := []byte(fmt.Sprintf("GET /files/%s HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n", art.Name))
		var respBuf bytes.Buffer
		contentType := "application/octet-stream"
		switch art.Format {
		case "png":
			contentType = "image/png"
		case "jpeg":
			contentType = "image/jpeg"
		case "pdf":
			contentType = "application/pdf"
		case "zip":
			contentType = "application/zip"
		}
		fmt.Fprintf(&respBuf, "HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", contentType, len(art.Bytes))
		respBuf.Write(art.Bytes)

		if err := writeTCPFlow(w, pb, clientIP, serverIP, cPort, 80, req, respBuf.Bytes(), i%2 == 0, i%3 == 0); err != nil {
			return 0, 0, err
		}
		flowCount++

		// B: FTP raw transfer with the artifact
		cPortData := uint16(45000 + i)
		if err := writeTCPFlow(w, pb, clientIP, serverIP, cPortData, 20, nil, art.Bytes, false, false); err != nil {
			return 0, 0, err
		}
		flowCount++
	}

	// 2. Fill the rest of the target size with thousands of varied flows
	domains := []string{"api.example.com", "cdn.raccoon.local", "auth.cloud.net", "repo.mirror.org", "updates.patch.io"}
	fillerPayload := make([]byte, 10240) // 10 KB per response
	for i := range fillerPayload {
		fillerPayload[i] = byte((i*31 + 17) % 256)
	}

	for w.bytes < targetBytes {
		flowType := flowCount % 10
		cPort := uint16(1024 + (flowCount % 60000))
		clientIP := net.IPv4(10, byte((flowCount>>8)%250+1), byte(flowCount%250+1), byte((flowCount*7)%250+1))
		serverIP := net.IPv4(192, 168, byte((flowCount>>4)%250+1), byte((flowCount*3)%250+1))

		switch {
		case flowType < 2:
			// DNS flow (UDP)
			d := domains[flowCount%len(domains)]
			if err := writeDNS(w, pb, clientIP, serverIP, cPort, 53, d); err != nil {
				return 0, 0, err
			}
			flowCount++

		case flowType < 6:
			// HTTP GET flow
			req := []byte(fmt.Sprintf("GET /api/v1/resource/%d HTTP/1.1\r\nHost: api.example.com\r\nAccept: */*\r\n\r\n", flowCount))
			resp := []byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n", len(fillerPayload)))
			resp = append(resp, fillerPayload...)
			retrans := (flowCount % 7) == 0
			ooo := (flowCount % 11) == 0
			if err := writeTCPFlow(w, pb, clientIP, serverIP, cPort, 80, req, resp, retrans, ooo); err != nil {
				return 0, 0, err
			}
			flowCount++

		default:
			// Generic TCP / FTP stream
			req := []byte(fmt.Sprintf("USER client%d\r\nPASS p%d\r\n", flowCount, flowCount))
			resp := []byte("220 Welcome\r\n331 Password required\r\n230 Logged in\r\n")
			retrans := (flowCount % 5) == 0
			ooo := (flowCount % 13) == 0
			if err := writeTCPFlow(w, pb, clientIP, serverIP, cPort, 21, req, resp, retrans, ooo); err != nil {
				return 0, 0, err
			}
			flowCount++
		}
	}

	return w.bytes, flowCount, nil
}

func main() {
	outDir := flag.String("out", "testdata/big", "output directory for big PCAP files")
	sizesFlag := flag.String("sizes", "100,500", "comma-separated sizes in MB to generate")
	flag.Parse()

	artifacts := getArtifacts()

	sizeStrs := strings.Split(*sizesFlag, ",")
	results := make(map[string]any)

	for _, sStr := range sizeStrs {
		sStr = strings.TrimSpace(sStr)
		if sStr == "" {
			continue
		}
		mb, err := strconv.ParseInt(sStr, 10, 64)
		if err != nil {
			log.Fatalf("invalid size: %s: %v", sStr, err)
		}

		target := mb * 1024 * 1024
		filename := fmt.Sprintf("big_%dmb.pcap", mb)
		path := filepath.Join(*outDir, filename)

		start := time.Now()
		fmt.Printf("Generating %s (target %d MB)...\n", path, mb)
		writtenBytes, flows, err := generateBigPCAP(path, target, artifacts)
		if err != nil {
			log.Fatalf("generate %s: %v", path, err)
		}
		duration := time.Since(start)

		fmt.Printf("Done: %s\n  Bytes: %d (%.2f MB)\n  Flows: %d\n  Duration: %s\n",
			path, writtenBytes, float64(writtenBytes)/(1024*1024), flows, duration)

		results[filename] = map[string]any{
			"filename":  filename,
			"path":      path,
			"bytes":     writtenBytes,
			"flows":     flows,
			"artifacts": artifacts,
		}
	}

	expPath := filepath.Join(*outDir, "expected.json")
	expBytes, err := json.MarshalIndent(results, "", "  ")
	if err == nil {
		_ = os.WriteFile(expPath, expBytes, 0o644)
	}
	fmt.Printf("\nGenerated all requested PCAPs in %s. Metadata in %s\n", *outDir, expPath)
}
