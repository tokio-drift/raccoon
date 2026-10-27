package report

import (
	"encoding/json"
	"fmt"
)

// RenderJSON produces formatted JSON for ReportData.
func RenderJSON(data *ReportData) ([]byte, error) {
	return renderJSON(data)
}

func renderJSON(data *ReportData) ([]byte, error) {
	if data == nil {
		return nil, fmt.Errorf("report: nil report data")
	}
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("report: render json: %w", err)
	}
	return append(b, '\n'), nil
}
