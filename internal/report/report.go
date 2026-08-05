// Package report renders a scan result: to a terminal, to structured JSON or
// CSV for pipelines, and to a self-contained HTML report for humans who do not
// live in a terminal.
package report

import (
	_ "embed"
	"strings"

	"github.com/joda32/yowie/internal/model"
)

//go:embed banner.txt
var banner string

// DefaultMaxEvidence is how many supporting records the terminal report shows
// per finding before summarising the rest.
const DefaultMaxEvidence = 6

// Banner returns the startup banner with the scan parameters filled in.
//
// It is preserved verbatim from the original tool, where the source comment
// records it as non-negotiable.
func Banner(domain string, candidates []string) string {
	c := strings.Join(candidates, ", ")
	if c == "" {
		c = "(none)"
	}
	return strings.NewReplacer("?", domain, "@", c).Replace(banner)
}

// countByConfidence tallies findings per confidence level.
func countByConfidence(findings []model.Finding) (high, medium, low int) {
	for _, f := range findings {
		switch f.Confidence {
		case model.ConfidenceHigh:
			high++
		case model.ConfidenceMedium:
			medium++
		default:
			low++
		}
	}
	return
}

// groupByConfidence splits findings into the three confidence buckets,
// preserving the incoming order within each.
func groupByConfidence(findings []model.Finding) map[model.Confidence][]model.Finding {
	out := map[model.Confidence][]model.Finding{}
	for _, f := range findings {
		out[f.Confidence] = append(out[f.Confidence], f)
	}
	return out
}

// confidenceOrder is the order buckets are rendered in, strongest first.
var confidenceOrder = []model.Confidence{
	model.ConfidenceHigh,
	model.ConfidenceMedium,
	model.ConfidenceLow,
}

// confidenceLabel is the human-facing heading for a bucket.
func confidenceLabel(c model.Confidence) string {
	switch c {
	case model.ConfidenceHigh:
		return "Confirmed"
	case model.ConfidenceMedium:
		return "Probable"
	default:
		return "Leads — verify before acting"
	}
}
