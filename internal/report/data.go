package report

import (
	"fmt"
	"time"

	"github.com/tokio-drift/raccoon/internal/casedir"
	"github.com/tokio-drift/raccoon/internal/model"
	"github.com/tokio-drift/raccoon/internal/store"
	"github.com/tokio-drift/raccoon/internal/version"
)

// Data is the rendered report model.
type Data struct {
	SchemaVersion int               `json:"schemaVersion"`
	GeneratedAt   string            `json:"generatedAt"`
	ToolVersion   string            `json:"toolVersion"`
	CaseID        string            `json:"caseId"`
	CaseDir       string            `json:"caseDir"`
	Meta          map[string]string `json:"meta"`
	Counts        Counts            `json:"counts"`
	Events        []model.Event     `json:"events"`
	Files         []File            `json:"files"`
}

// Counts summarises a case.
type Counts struct {
	Events  int64 `json:"events"`
	Files   int64 `json:"files"`
	Streams int64 `json:"streams"`
}

// File pairs a carved file with its reputation verdicts.
type File struct {
	model.CarvedFile
	Verdicts []model.Verdict `json:"verdicts,omitempty"`
}

// Load reads the report model from a case database.
func Load(c *casedir.Case) (*Data, error) {
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
	evCount, fileCount, streamCount, err := db.Counts()
	if err != nil {
		return nil, err
	}

	return &Data{
		SchemaVersion: SchemaVersion,
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339Nano),
		ToolVersion:   version.String(),
		CaseID:        c.ID,
		CaseDir:       c.Dir,
		Meta:          meta,
		Counts: Counts{
			Events:  evCount,
			Files:   fileCount,
			Streams: streamCount,
		},
		Events: events,
		Files:  files,
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
