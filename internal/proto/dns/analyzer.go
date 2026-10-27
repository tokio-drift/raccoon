package dns

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/tokio-drift/raccoon/internal/model"
	"github.com/tokio-drift/raccoon/internal/proto"
)

// responseWindow is how long a query may wait for its response, matched by
// transaction id.
const responseWindow = 5 * time.Second

// Analyzer parses DNS queries and responses.
type Analyzer struct{}

// New returns a DNS analyzer.
func New() *Analyzer { return &Analyzer{} }

// Name returns "dns".
func (a *Analyzer) Name() string { return "dns" }

// Match reports whether the first bytes look like DNS on port 53, either a
// bare UDP payload or a TCP message with a 2-byte length prefix.
func (a *Analyzer) Match(first []byte, _ model.Direction, ports proto.PortPair) bool {
	if ports.Client != 53 && ports.Server != 53 {
		return false
	}
	return proto.IsDNSPayload(first) || proto.IsDNSStream(first)
}

type dnsMsg struct {
	d   *layers.DNS
	ts  int64
	pkt uint64
}

type query struct {
	d       *layers.DNS
	ts      int64
	pkt     uint64
	resp    *layers.DNS
	respPkt uint64
}

// Analyze correlates queries with responses and emits one event per query.
func (a *Analyzer) Analyze(ctx *proto.StreamContext, emit func(model.Event)) error {
	var msgs []dnsMsg
	if datagrams := ctx.Datagrams(); len(datagrams) > 0 {
		msgs = parseDatagrams(datagrams)
	} else {
		msgs = parseStreams(ctx)
	}

	queries := correlate(msgs)
	for _, q := range queries {
		emit(queryEvent(ctx, q))
	}
	return nil
}

func parseDatagrams(datagrams []proto.Datagram) []dnsMsg {
	out := make([]dnsMsg, 0, len(datagrams))
	for _, dg := range datagrams {
		d, ok := decode(dg.Payload)
		if !ok {
			continue
		}
		out = append(out, dnsMsg{d: d, ts: dg.TS, pkt: dg.PacketNo})
	}
	return out
}

func parseStreams(ctx *proto.StreamContext) []dnsMsg {
	c2s := parseStream(ctx, model.C2S)
	s2c := parseStream(ctx, model.S2C)
	all := make([]dnsMsg, 0, len(c2s)+len(s2c))
	all = append(all, c2s...)
	all = append(all, s2c...)
	sort.SliceStable(all, func(i, j int) bool {
		if all[i].ts != all[j].ts {
			return all[i].ts < all[j].ts
		}
		return all[i].pkt < all[j].pkt
	})
	return all
}

func parseStream(ctx *proto.StreamContext, dir model.Direction) []dnsMsg {
	total := ctx.Len(dir)
	if total <= 0 {
		return nil
	}
	br := bufio.NewReaderSize(io.NewSectionReader(ctx.ReaderAt(dir), 0, total), 16*1024)
	var (
		out []dnsMsg
		off int64
	)
	for {
		var prefix [2]byte
		if _, err := io.ReadFull(br, prefix[:]); err != nil {
			break
		}
		start := off
		off += 2
		n := int64(binary.BigEndian.Uint16(prefix[:]))
		payload := make([]byte, n)
		if _, err := io.ReadFull(br, payload); err != nil {
			break
		}
		off += n
		if n < 12 {
			continue
		}
		d, ok := decode(payload)
		if !ok {
			continue
		}
		out = append(out, dnsMsg{
			d:   d,
			ts:  ctx.TimeAtOffset(dir, start),
			pkt: ctx.PacketAtOffset(dir, start),
		})
	}
	return out
}

func decode(payload []byte) (d *layers.DNS, ok bool) {
	defer func() {
		if r := recover(); r != nil {
			d = nil
			ok = false
		}
	}()
	var dns layers.DNS
	if err := dns.DecodeFromBytes(payload, gopacket.NilDecodeFeedback); err != nil {
		return nil, false
	}
	return &dns, true
}

func correlate(msgs []dnsMsg) []*query {
	var queries []*query
	pending := map[uint16][]*query{}
	for i := range msgs {
		m := &msgs[i]
		if m.d.QR {
			qs := pending[m.d.ID]
			for len(qs) > 0 {
				q := qs[0]
				qs = qs[1:]
				if m.ts-q.ts >= 0 && m.ts-q.ts <= responseWindow.Nanoseconds() {
					q.resp = m.d
					q.respPkt = m.pkt
					break
				}
			}
			pending[m.d.ID] = qs
			continue
		}
		if len(m.d.Questions) == 0 {
			continue
		}
		q := &query{d: m.d, ts: m.ts, pkt: m.pkt}
		queries = append(queries, q)
		pending[m.d.ID] = append(pending[m.d.ID], q)
	}
	return queries
}

func queryEvent(ctx *proto.StreamContext, q *query) model.Event {
	question := q.d.Questions[0]
	name := string(question.Name)
	qtype := question.Type.String()

	details := map[string]any{
		"qname": name,
		"qtype": qtype,
	}
	if q.resp != nil {
		details["rcode"] = q.resp.ResponseCode.String()
		answers, minTTL := answerDetails(q.resp.Answers)
		details["answers"] = answers
		if len(answers) > 0 {
			details["ttl"] = minTTL
		}
	}

	title := fmt.Sprintf("DNS query: %s (%s)", name, qtype)
	e := ctx.NewEvent(q.ts, q.pkt, model.EvDNSQuery, model.SevInfo, title, details)
	if q.respPkt != 0 {
		e.PacketEnd = q.respPkt
	}
	return e
}

func answerDetails(rrs []layers.DNSResourceRecord) ([]map[string]any, uint32) {
	out := make([]map[string]any, 0, len(rrs))
	var minTTL uint32
	for i := range rrs {
		rr := &rrs[i]
		a := map[string]any{
			"name": string(rr.Name),
			"type": rr.Type.String(),
			"ttl":  rr.TTL,
		}
		if data := rdata(rr); data != "" {
			a["data"] = data
		}
		out = append(out, a)
		if i == 0 || rr.TTL < minTTL {
			minTTL = rr.TTL
		}
	}
	return out, minTTL
}

func rdata(rr *layers.DNSResourceRecord) string {
	switch {
	case len(rr.IP) > 0:
		return net.IP(rr.IP).String()
	case len(rr.CNAME) > 0:
		return string(rr.CNAME)
	case len(rr.NS) > 0:
		return string(rr.NS)
	case len(rr.PTR) > 0:
		return string(rr.PTR)
	case len(rr.TXTs) > 0:
		parts := make([]string, 0, len(rr.TXTs))
		for _, txt := range rr.TXTs {
			parts = append(parts, string(txt))
		}
		return strings.Join(parts, " ")
	case len(rr.SOA.MName) > 0:
		return fmt.Sprintf("%s %s", rr.SOA.MName, rr.SOA.RName)
	case len(rr.SRV.Name) > 0:
		return fmt.Sprintf("%s:%d", rr.SRV.Name, rr.SRV.Port)
	case len(rr.MX.Name) > 0:
		return fmt.Sprintf("%d %s", rr.MX.Preference, rr.MX.Name)
	case len(rr.URI.Target) > 0:
		return string(rr.URI.Target)
	default:
		return ""
	}
}
