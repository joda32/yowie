package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/joda32/yowie/internal/model"
)

// JSON writes the full result, including evidence, as indented JSON.
func JSON(w io.Writer, r *model.Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(r)
}

// JSONL writes one finding per line, which is what log pipelines and SIEM
// ingestion generally want.
func JSONL(w io.Writer, r *model.Result) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	for _, f := range r.Findings {
		row := struct {
			Domain string `json:"domain"`
			model.Finding
		}{Domain: r.Domain, Finding: f}
		if err := enc.Encode(row); err != nil {
			return err
		}
	}
	return nil
}

// CSV writes one row per finding. Evidence is flattened into a single column
// so the file stays a rectangle, which is what spreadsheet users expect.
func CSV(w io.Writer, r *model.Result) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()

	if err := cw.Write([]string{
		"domain", "vendor", "category", "confidence", "methods", "evidence", "signatures", "notes",
	}); err != nil {
		return err
	}

	for _, f := range r.Findings {
		methods := map[model.Method]bool{}
		var evidence []string
		for _, ev := range f.Evidence {
			methods[ev.Method] = true
			evidence = append(evidence, fmt.Sprintf("%s %s -> %s", ev.Method, ev.Query, ev.Value))
		}
		var methodList []string
		for m := range methods {
			methodList = append(methodList, string(m))
		}

		if err := cw.Write([]string{
			r.Domain,
			f.Vendor,
			f.Category,
			string(f.Confidence),
			strings.Join(methodList, " "),
			strings.Join(evidence, " ; "),
			strings.Join(f.Signatures, " "),
			strings.Join(f.Notes, " "),
		}); err != nil {
			return err
		}
	}
	return cw.Error()
}
