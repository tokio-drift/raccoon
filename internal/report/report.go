// Package report renders case reports as HTML, JSON and PDF.
package report

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/tokio-drift/raccoon/internal/casedir"
)

// SchemaVersion is the version of the JSON report schema.
const SchemaVersion = 1

// ErrUnsupportedFormat is returned for a report format this build cannot write.
var ErrUnsupportedFormat = errors.New("report: unsupported format")

// IsUnsupported reports whether err is an unsupported-format error.
func IsUnsupported(err error) bool { return errors.Is(err, ErrUnsupportedFormat) }

// Format identifies a report output format.
type Format string

// Supported report formats.
const (
	FormatJSON Format = "json"
	FormatHTML Format = "html"
	FormatPDF  Format = "pdf"
)

// ParseFormat validates and normalises a report format.
func ParseFormat(s string) (Format, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "json":
		return FormatJSON, nil
	case "html":
		return FormatHTML, nil
	case "pdf":
		return FormatPDF, nil
	default:
		return "", fmt.Errorf("%w: %q (want html, json or pdf)", ErrUnsupportedFormat, s)
	}
}

// Write builds a report for the case at casePath and writes it to the case
// reports directory. It returns the absolute report path.
func Write(casePath string, format Format) (string, error) {
	c, err := casedir.Open(casePath)
	if err != nil {
		return "", err
	}
	data, err := Load(c)
	if err != nil {
		return "", err
	}

	var (
		name string
		body []byte
	)
	switch format {
	case FormatJSON:
		name = "report.json"
		body, err = renderJSON(data)
	case FormatHTML:
		name = "report.html"
		body, err = renderHTML(data)
	case FormatPDF:
		name = "report.pdf"
		body, err = renderPDF(data)
	default:
		return "", fmt.Errorf("%w: %q", ErrUnsupportedFormat, format)
	}
	if err != nil {
		return "", err
	}

	dir := c.ReportsDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("report: create reports directory: %w", err)
	}
	dst := filepath.Join(dir, name)
	tmp, err := os.CreateTemp(dir, ".report-*")
	if err != nil {
		return "", fmt.Errorf("report: create temporary file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return "", fmt.Errorf("report: set report mode: %w", err)
	}
	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		return "", fmt.Errorf("report: write report: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("report: close report: %w", err)
	}
	if err := os.Rename(tmpName, dst); err != nil {
		return "", fmt.Errorf("report: replace report: %w", err)
	}
	return dst, nil
}
