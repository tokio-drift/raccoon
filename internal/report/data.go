package report

import (
	"fmt"
	"time"

	"github.com/tokio-drift/raccoon/internal/casedir"
	"github.com/tokio-drift/raccoon/internal/model"
	"github.com/tokio-drift/raccoon/internal/store"
	"github.com/tokio-drift/raccoon/internal/version"
)

// ReportData is the assembled report model.
type ReportData struct {
	SchemaVersion int               `json:"schemaVersion"`
	GeneratedAt   string            `json:"generatedAt"`
	ToolVersion   string            `json:"toolVersion"`
	CaseID        string            `json:"caseId"`
	CaseDir       string            `json:"caseDir"`
	Meta          map[string]string `json:"meta"`
	Counts        Counts            `json:"counts"`
	Events        []model.Event     `json:"events"`
	Files         []File            `json:"files"`
	Findings      []model.Finding   `json:"findings,omitempty"`
}

// Data is an alias for ReportData for backward compatibility.
type Data = ReportData

// Counts summarises a case, including counts by severity.
type Counts struct {
	Events     int64          `json:"events"`
	Files      int64          `json:"files"`
	Streams    int64          `json:"streams"`
	Critical   int64          `json:"critical"`
	Warning    int64          `json:"warning"`
	Info       int64          `json:"info"`
	Severities SeverityCounts `json:"severities"`
}

// SeverityCounts breaks down event counts by severity.
type SeverityCounts struct {
	Critical int64 `json:"critical"`
	Warning  int64 `json:"warning"`
	Info     int64 `json:"info"`
}

// File pairs a carved file with its reputation verdicts.
type File struct {
	model.CarvedFile
	Verdicts []model.Verdict `json:"verdicts,omitempty"`
}

// Assemble builds a ReportData from a case directory.
func Assemble(c *casedir.Case) (*ReportData, error) {
	return Load(c)
}

// Load reads the report model from a case database.
func Load(c *casedir.Case) (*ReportData, error) {
	if c == nil {
		return nil, fmt.Errorf("report: nil case")
	}
	db, err := store.Open(c.DB())
	if err != nil {
		return nil, fmt.Errorf("report: open case database: %w", err)
	}
	defer db.Close()

	meta, err := db.Meta()
	if err != nil {
		return nil, fmt.Errorf("report: read case metadata: %w", err)
	}
	events, err := loadEvents(db)
	if err != nil {
		return nil, err
	}
	carved, err := db.Files(store.FileFilter{Confidence: store.ConfidenceAll})
	if err != nil {
		return nil, fmt.Errorf("report: read files: %w", err)
	}
	files := make([]File, 0, len(carved))
	for _, f := range carved {
		verdicts, err := db.Verdicts(f.SHA256)
		if err != nil {
			return nil, fmt.Errorf("report: read verdicts: %w", err)
		}
		files = append(files, File{CarvedFile: f, Verdicts: verdicts})
	}
	findings, err := db.Findings()
	if err != nil {
		return nil, fmt.Errorf("report: read findings: %w", err)
	}
	evCount, fileCount, streamCount, err := db.Counts()
	if err != nil {
		return nil, err
	}

	var crit, warn, info int64
	for _, e := range events {
		switch e.Severity {
		case model.SevCritical:
			crit++
		case model.SevWarning:
			warn++
		case model.SevInfo:
			info++
		}
	}

	return &ReportData{
		SchemaVersion: SchemaVersion,
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339Nano),
		ToolVersion:   version.String(),
		CaseID:        c.ID,
		CaseDir:       c.Dir,
		Meta:          meta,
		Counts: Counts{
			Events:   evCount,
			Files:    fileCount,
			Streams:  streamCount,
			Critical: crit,
			Warning:  warn,
			Info:     info,
			Severities: SeverityCounts{
				Critical: crit,
				Warning:  warn,
				Info:     info,
			},
		},
		Events:   events,
		Files:    files,
		Findings: findings,
	}, nil
}

func loadEvents(db *store.DB) ([]model.Event, error) {
	var out []model.Event
	cursor := ""
	for {
		page, next, err := db.Events(store.EventFilter{Limit: 1000, Cursor: cursor, Flat: true})
		if err != nil {
			return nil, fmt.Errorf("report: read events: %w", err)
		}
		out = append(out, page...)
		if next == "" {
			break
		}
		cursor = next
	}
	return out, nil
}
