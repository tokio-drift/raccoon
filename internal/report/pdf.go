package report

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/go-pdf/fpdf"
	"github.com/tokio-drift/raccoon/internal/model"
)

// RenderPDF produces an A4 PDF case report using fpdf.
func RenderPDF(data *ReportData) ([]byte, error) {
	return renderPDF(data)
}

func sanitizeLatin1(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r > 255 {
			b.WriteByte('?')
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func renderPDF(data *ReportData) ([]byte, error) {
	if data == nil {
		return nil, fmt.Errorf("report: nil report data")
	}

	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(15, 15, 15)
	pdf.SetAutoPageBreak(true, 18)

	// Footer callback on every page
	pdf.SetFooterFunc(func() {
		pdf.SetY(-12)
		pdf.SetFont("Helvetica", "I", 8)
		pdf.SetTextColor(110, 101, 95) // muted ink

		sha := data.Meta["pcap_sha256"]
		if len(sha) > 16 {
			sha = sha[:16] + "..."
		}
		footerText := fmt.Sprintf("RACCOON v%s  |  PCAP SHA-256: %s  |  Page %d/{nb}",
			sanitizeLatin1(data.ToolVersion),
			sanitizeLatin1(sha),
			pdf.PageNo(),
		)
		pdf.CellFormat(0, 8, sanitizeLatin1(footerText), "", 0, "C", false, 0, "")
	})
	pdf.AliasNbPages("{nb}")

	pdf.AddPage()

	// Title banner
	pdf.SetFont("Helvetica", "B", 18)
	pdf.SetTextColor(31, 27, 22) // ink
	pdf.CellFormat(0, 8, "RACCOON Forensic Case Report", "", 1, "L", false, 0, "")

	pdf.SetFont("Helvetica", "", 9)
	pdf.SetTextColor(110, 101, 95) // muted
	sub := fmt.Sprintf("Case ID: %s   |   Generated: %s   |   Tool Version: %s",
		data.CaseID,
		data.GeneratedAt,
		data.ToolVersion,
	)
	pdf.CellFormat(0, 5, sanitizeLatin1(sub), "", 1, "L", false, 0, "")
	pdf.Ln(4)

	// Horizontal rule
	pdf.SetDrawColor(227, 222, 216)
	pdf.SetLineWidth(0.5)
	pdf.Line(15, pdf.GetY(), 195, pdf.GetY())
	pdf.Ln(4)

	// Executive summary header
	pdf.SetFont("Helvetica", "B", 12)
	pdf.SetTextColor(31, 27, 22)
	pdf.CellFormat(0, 6, "1. Executive Summary", "", 1, "L", false, 0, "")
	pdf.Ln(2)

	// Summary KPI boxes (6 cards: Events, Files, Streams, Critical, Warning, Info)
	cardW := 28.5
	cardH := 14.0
	pdf.SetDrawColor(227, 222, 216)
	pdf.SetLineWidth(0.2)

	drawKPI := func(x float64, label string, val int64, r, g, b int) {
		pdf.SetXY(x, pdf.GetY())
		pdf.SetFillColor(251, 249, 246)
		pdf.Rect(x, pdf.GetY(), cardW, cardH, "DF")

		pdf.SetXY(x+1, pdf.GetY()+2)
		pdf.SetFont("Helvetica", "B", 7)
		pdf.SetTextColor(110, 101, 95)
		pdf.CellFormat(cardW-2, 3, sanitizeLatin1(strings.ToUpper(label)), "", 2, "C", false, 0, "")

		pdf.SetFont("Helvetica", "B", 13)
		pdf.SetTextColor(r, g, b)
		pdf.CellFormat(cardW-2, 6, fmt.Sprintf("%d", val), "", 0, "C", false, 0, "")
	}

	startX := 15.0
	startY := pdf.GetY()
	drawKPI(startX+0*(cardW+2), "Events", data.Counts.Events, 31, 27, 22)
	pdf.SetY(startY)
	drawKPI(startX+1*(cardW+2), "Files", data.Counts.Files, 31, 27, 22)
	pdf.SetY(startY)
	drawKPI(startX+2*(cardW+2), "Streams", data.Counts.Streams, 31, 27, 22)
	pdf.SetY(startY)
	drawKPI(startX+3*(cardW+2), "Critical", data.Counts.Critical, 161, 44, 37)
	pdf.SetY(startY)
	drawKPI(startX+4*(cardW+2), "Warning", data.Counts.Warning, 138, 82, 0)
	pdf.SetY(startY)
	drawKPI(startX+5*(cardW+2), "Info", data.Counts.Info, 20, 73, 93)

	pdf.SetXY(startX, startY+cardH+4)

	// Top findings if any
	if len(data.Findings) > 0 {
		pdf.SetFont("Helvetica", "B", 10)
		pdf.SetTextColor(31, 27, 22)
		pdf.CellFormat(0, 5, fmt.Sprintf("Key Findings (%d)", len(data.Findings)), "", 1, "L", false, 0, "")
		pdf.Ln(1)

		for _, f := range data.Findings {
			pdf.SetFillColor(254, 247, 237)
			if f.Severity == model.SevCritical {
				pdf.SetFillColor(253, 242, 241)
				pdf.SetDrawColor(241, 183, 179)
			} else {
				pdf.SetDrawColor(248, 211, 158)
			}

			boxY := pdf.GetY()
			pdf.SetFont("Helvetica", "B", 9)
			if f.Severity == model.SevCritical {
				pdf.SetTextColor(161, 44, 37)
			} else {
				pdf.SetTextColor(138, 82, 0)
			}

			titleLine := fmt.Sprintf("[%s] %s  (%s)", f.Technique, f.Title, f.Severity)
			pdf.CellFormat(180, 5, sanitizeLatin1(titleLine), "LTR", 1, "L", true, 0, "")

			pdf.SetFont("Helvetica", "", 8)
			pdf.SetTextColor(31, 27, 22)
			expl := f.Explanation
			if len(f.EvidenceEventIDs) > 0 {
				var evStrs []string
				for _, id := range f.EvidenceEventIDs {
					evStrs = append(evStrs, fmt.Sprintf("#%d", id))
				}
				expl += " (Evidence: " + strings.Join(evStrs, ", ") + ")"
			}
			pdf.MultiCell(180, 4, sanitizeLatin1(expl), "LBR", "L", true)
			pdf.Ln(2)
			_ = boxY
		}
		pdf.Ln(2)
	}

	// Capture & Case Metadata
	pdf.SetFont("Helvetica", "B", 12)
	pdf.SetTextColor(31, 27, 22)
	pdf.CellFormat(0, 6, "2. Capture & Case Metadata", "", 1, "L", false, 0, "")
	pdf.Ln(1)

	pdf.SetFont("Helvetica", "", 8)
	pdf.SetDrawColor(238, 233, 227)
	for k, v := range data.Meta {
		pdf.SetFont("Helvetica", "B", 8)
		pdf.SetTextColor(110, 101, 95)
		pdf.CellFormat(40, 5, sanitizeLatin1(k), "B", 0, "L", false, 0, "")
		pdf.SetFont("Helvetica", "", 8)
		pdf.SetTextColor(31, 27, 22)
		pdf.CellFormat(140, 5, sanitizeLatin1(v), "B", 1, "L", false, 0, "")
	}
	pdf.Ln(4)

	// Carved Artifacts Table
	pdf.SetFont("Helvetica", "B", 12)
	pdf.SetTextColor(31, 27, 22)
	pdf.CellFormat(0, 6, fmt.Sprintf("3. Carved Artifacts (%d)", len(data.Files)), "", 1, "L", false, 0, "")
	pdf.Ln(1)

	// Table headers
	colWName := 48.0
	colWFmt := 16.0
	colWSize := 20.0
	colWSHA := 56.0
	colWVerd := 40.0

	pdf.SetFillColor(245, 243, 240)
	pdf.SetTextColor(110, 101, 95)
	pdf.SetFont("Helvetica", "B", 8)
	pdf.CellFormat(colWName, 5, "NAME", "B", 0, "L", true, 0, "")
	pdf.CellFormat(colWFmt, 5, "FORMAT", "B", 0, "L", true, 0, "")
	pdf.CellFormat(colWSize, 5, "SIZE", "B", 0, "R", true, 0, "")
	pdf.CellFormat(colWSHA, 5, "SHA-256", "B", 0, "L", true, 0, "")
	pdf.CellFormat(colWVerd, 5, "VERDICT", "B", 1, "L", true, 0, "")

	pdf.SetFont("Helvetica", "", 8)
	pdf.SetTextColor(31, 27, 22)
	if len(data.Files) == 0 {
		pdf.CellFormat(180, 6, "No carved files found.", "B", 1, "C", false, 0, "")
	} else {
		for _, file := range data.Files {
			// Format size
			szStr := fmt.Sprintf("%d B", file.Size)
			if file.Size >= 1024*1024 {
				szStr = fmt.Sprintf("%.1f MB", float64(file.Size)/(1024*1024))
			} else if file.Size >= 1024 {
				szStr = fmt.Sprintf("%.1f KB", float64(file.Size)/1024)
			}

			// Format verdict
			verdStr := "Not checked"
			if len(file.Verdicts) > 0 {
				var parts []string
				for _, v := range file.Verdicts {
					part := v.Status
					if v.Score > 0 || v.Total > 0 {
						part = fmt.Sprintf("%s (%d/%d)", v.Status, v.Score, v.Total)
					}
					parts = append(parts, part)
				}
				verdStr = strings.Join(parts, ", ")
			}

			sha := file.SHA256
			if len(sha) > 28 {
				sha = sha[:28] + "..."
			}

			name := file.DisplayName
			if len(name) > 28 {
				name = name[:25] + "..."
			}

			pdf.CellFormat(colWName, 5, sanitizeLatin1(name), "B", 0, "L", false, 0, "")
			pdf.CellFormat(colWFmt, 5, sanitizeLatin1(file.Format), "B", 0, "L", false, 0, "")
			pdf.CellFormat(colWSize, 5, sanitizeLatin1(szStr), "B", 0, "R", false, 0, "")
			pdf.CellFormat(colWSHA, 5, sanitizeLatin1(sha), "B", 0, "L", false, 0, "")
			pdf.CellFormat(colWVerd, 5, sanitizeLatin1(verdStr), "B", 1, "L", false, 0, "")
		}
	}
	pdf.Ln(4)

	// Timeline Table (Paged)
	pdf.SetFont("Helvetica", "B", 12)
	pdf.SetTextColor(31, 27, 22)
	pdf.CellFormat(0, 6, fmt.Sprintf("4. Timeline Events (%d)", len(data.Events)), "", 1, "L", false, 0, "")
	pdf.Ln(1)

	colWTime := 34.0
	colWPkt := 14.0
	colWSev := 18.0
	colWProto := 16.0
	colWTitle := 98.0

	pdf.SetFillColor(245, 243, 240)
	pdf.SetTextColor(110, 101, 95)
	pdf.SetFont("Helvetica", "B", 8)
	pdf.CellFormat(colWTime, 5, "TIME (UTC)", "B", 0, "L", true, 0, "")
	pdf.CellFormat(colWPkt, 5, "PKT", "B", 0, "R", true, 0, "")
	pdf.CellFormat(colWSev, 5, "SEVERITY", "B", 0, "C", true, 0, "")
	pdf.CellFormat(colWProto, 5, "PROTO", "B", 0, "L", true, 0, "")
	pdf.CellFormat(colWTitle, 5, "EVENT TITLE", "B", 1, "L", true, 0, "")

	if len(data.Events) == 0 {
		pdf.SetFont("Helvetica", "", 8)
		pdf.CellFormat(180, 6, "No timeline events recorded.", "B", 1, "C", false, 0, "")
	} else {
		for _, ev := range data.Events {
			timeStr := ""
			if ev.TS != 0 {
				timeStr = time.Unix(0, ev.TS).UTC().Format("15:04:05.000")
			}
			pktStr := fmt.Sprintf("#%d", ev.PacketNo)

			// Severity styling
			pdf.SetFont("Helvetica", "B", 7)
			switch ev.Severity {
			case model.SevCritical:
				pdf.SetTextColor(161, 44, 37)
			case model.SevWarning:
				pdf.SetTextColor(138, 82, 0)
			default:
				pdf.SetTextColor(20, 73, 93)
			}

			title := ev.Title
			if len(title) > 60 {
				title = title[:57] + "..."
			}

			pdf.SetFont("Helvetica", "", 8)
			pdf.SetTextColor(31, 27, 22)
			pdf.CellFormat(colWTime, 5, sanitizeLatin1(timeStr), "B", 0, "L", false, 0, "")
			pdf.CellFormat(colWPkt, 5, sanitizeLatin1(pktStr), "B", 0, "R", false, 0, "")

			pdf.SetFont("Helvetica", "B", 7)
			switch ev.Severity {
			case model.SevCritical:
				pdf.SetTextColor(161, 44, 37)
			case model.SevWarning:
				pdf.SetTextColor(138, 82, 0)
			default:
				pdf.SetTextColor(20, 73, 93)
			}
			pdf.CellFormat(colWSev, 5, sanitizeLatin1(string(ev.Severity)), "B", 0, "C", false, 0, "")

			pdf.SetFont("Helvetica", "", 8)
			pdf.SetTextColor(31, 27, 22)
			pdf.CellFormat(colWProto, 5, sanitizeLatin1(ev.Proto), "B", 0, "L", false, 0, "")
			pdf.CellFormat(colWTitle, 5, sanitizeLatin1(title), "B", 1, "L", false, 0, "")
		}
	}

	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		return nil, fmt.Errorf("report: render pdf: %w", err)
	}

	return buf.Bytes(), nil
}
