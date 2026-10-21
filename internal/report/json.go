package report

import (
	"encoding/json"
)

func renderJSON(data *Data) ([]byte, error) {
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}
