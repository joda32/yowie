package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/joda32/yowie/internal/model"
)

func resultWithEvidence(n int) *model.Result {
	evs := make([]model.Evidence, n)
	for i := range evs {
		evs[i] = model.Evidence{Method: model.MethodCT, Query: "host", Value: "target"}
	}
	return &model.Result{
		Domain: "acme.com",
		Findings: []model.Finding{{
			Vendor:     "Azure Cloud Services",
			Category:   "Infrastructure",
			Confidence: model.ConfidenceMedium,
			Evidence:   evs,
		}},
	}
}

func render(t *testing.T, r *model.Result, opts CLIOptions) string {
	t.Helper()
	var buf bytes.Buffer
	if err := CLI(&buf, r, opts); err != nil {
		t.Fatalf("CLI: %v", err)
	}
	return buf.String()
}

func TestCLICapsEvidence(t *testing.T) {
	out := render(t, resultWithEvidence(50), CLIOptions{ShowEvidence: true, MaxEvidence: 6})

	if got := strings.Count(out, "CT      host"); got != 6 {
		t.Errorf("printed %d evidence lines, want 6", got)
	}
	if !strings.Contains(out, "and 44 more") {
		t.Errorf("expected a remainder summary, got:\n%s", out)
	}
}

func TestCLIUncappedEvidence(t *testing.T) {
	// Zero means no limit, matching the flag's documented behaviour.
	out := render(t, resultWithEvidence(50), CLIOptions{ShowEvidence: true, MaxEvidence: 0})

	if got := strings.Count(out, "CT      host"); got != 50 {
		t.Errorf("printed %d evidence lines, want all 50", got)
	}
	if strings.Contains(out, "more (use") {
		t.Error("no remainder summary should appear when uncapped")
	}
}

func TestCLINoRemainderWhenUnderLimit(t *testing.T) {
	out := render(t, resultWithEvidence(3), CLIOptions{ShowEvidence: true, MaxEvidence: 6})
	if strings.Contains(out, "more (use") {
		t.Errorf("unexpected remainder summary:\n%s", out)
	}
}

func TestCLIEmptyResultExplainsItself(t *testing.T) {
	r := &model.Result{Domain: "acme.com", Stats: model.Stats{Signatures: 232, DNSQueries: 500}}
	out := render(t, r, CLIOptions{ShowEvidence: true})

	// An empty report must distinguish "we looked and found nothing" from
	// "the scan did not run".
	if !strings.Contains(out, "No SaaS services identified") || !strings.Contains(out, "232 signatures") {
		t.Errorf("empty result should report the work done, got:\n%s", out)
	}
}

func TestCLICompactMatchesLegacyStyle(t *testing.T) {
	r := &model.Result{
		Domain: "acme.com",
		Findings: []model.Finding{{
			Vendor:     "Atlassian",
			Confidence: model.ConfidenceHigh,
			Evidence:   []model.Evidence{{Method: model.MethodTXT, Query: "acme.com", Value: "token"}},
		}},
	}
	out := render(t, r, CLIOptions{Compact: true})
	want := "Atlassian (from TXT lookup of acme.com)\n"
	if out != want {
		t.Errorf("compact output = %q, want %q", out, want)
	}
}

func TestBannerSubstitutesScanParameters(t *testing.T) {
	out := Banner("acme.com", []string{"acme", "acmecorp"})
	if !strings.Contains(out, "acme.com") || !strings.Contains(out, "acme, acmecorp") {
		t.Error("banner should carry the domain and candidates")
	}
	if strings.Contains(out, "?") || strings.Contains(out, "@") {
		t.Error("banner placeholders should all be replaced")
	}
	if none := Banner("acme.com", nil); !strings.Contains(none, "(none)") {
		t.Error("banner should say (none) when no candidates were given")
	}
}
