package model

import "testing"

func ev(m Method, q, v string) Evidence { return Evidence{Method: m, Query: q, Value: v} }

func TestFindingSetMergesByVendor(t *testing.T) {
	s := NewFindingSet()
	s.Add(Finding{Vendor: "Slack", Confidence: ConfidenceHigh, Signatures: []string{"txt-slack"},
		Evidence: []Evidence{ev(MethodTXT, "acme.com", "slack-domain-verification=1")}})
	s.Add(Finding{Vendor: "slack", Confidence: ConfidenceLow, Signatures: []string{"http-slack"},
		Evidence: []Evidence{ev(MethodHTTP, "https://acme.slack.com", "Slack")}})

	if s.Len() != 1 {
		t.Fatalf("got %d findings, want 1 (vendor match is case-insensitive)", s.Len())
	}
	f := s.Findings()[0]
	if len(f.Evidence) != 2 {
		t.Errorf("got %d evidence items, want 2", len(f.Evidence))
	}
	if len(f.Signatures) != 2 {
		t.Errorf("got %d signature ids, want 2", len(f.Signatures))
	}
	if f.Confidence != ConfidenceHigh {
		t.Errorf("confidence = %q, want the strongest observed (high)", f.Confidence)
	}
}

func TestFindingSetDeduplicatesIdenticalEvidence(t *testing.T) {
	s := NewFindingSet()
	e := ev(MethodTXT, "acme.com", "token")
	s.Add(Finding{Vendor: "Acme", Confidence: ConfidenceHigh, Evidence: []Evidence{e}})
	s.Add(Finding{Vendor: "Acme", Confidence: ConfidenceHigh, Evidence: []Evidence{e}})

	if got := len(s.Findings()[0].Evidence); got != 1 {
		t.Errorf("got %d evidence items, want 1", got)
	}
}

func TestCorroborationPromotesMediumToHigh(t *testing.T) {
	s := NewFindingSet()
	s.Add(Finding{Vendor: "Zendesk", Confidence: ConfidenceMedium,
		Evidence: []Evidence{ev(MethodA, "acme.zendesk.com", "1.2.3.4")}})
	s.Add(Finding{Vendor: "Zendesk", Confidence: ConfidenceMedium,
		Evidence: []Evidence{ev(MethodCT, "support.acme.com", "acme.zendesk.com")}})

	if got := s.Findings()[0].Confidence; got != ConfidenceHigh {
		t.Errorf("confidence = %q, want high: two independent methods corroborate", got)
	}
}

func TestCorroborationRequiresDistinctMethods(t *testing.T) {
	s := NewFindingSet()
	s.Add(Finding{Vendor: "Zendesk", Confidence: ConfidenceMedium,
		Evidence: []Evidence{ev(MethodA, "acme.zendesk.com", "1.2.3.4")}})
	s.Add(Finding{Vendor: "Zendesk", Confidence: ConfidenceMedium,
		Evidence: []Evidence{ev(MethodA, "acmecorp.zendesk.com", "5.6.7.8")}})

	if got := s.Findings()[0].Confidence; got != ConfidenceMedium {
		t.Errorf("confidence = %q, want medium: two hits from the same method are not corroboration", got)
	}
}

func TestFindingsSortedByConfidenceThenName(t *testing.T) {
	s := NewFindingSet()
	s.Add(Finding{Vendor: "Zulip", Confidence: ConfidenceLow})
	s.Add(Finding{Vendor: "Beta", Confidence: ConfidenceHigh})
	s.Add(Finding{Vendor: "Alpha", Confidence: ConfidenceHigh})
	s.Add(Finding{Vendor: "Middle", Confidence: ConfidenceMedium})

	var got []string
	for _, f := range s.Findings() {
		got = append(got, f.Vendor)
	}
	want := []string{"Alpha", "Beta", "Middle", "Zulip"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order = %v, want %v", got, want)
		}
	}
}

func TestTruncateCollapsesWhitespace(t *testing.T) {
	if got := Truncate("  a\n\t b   c  ", 100); got != "a b c" {
		t.Errorf("Truncate = %q, want %q", got, "a b c")
	}
	if got := Truncate("abcdefghij", 4); got != "abcd…" {
		t.Errorf("Truncate = %q, want %q", got, "abcd…")
	}
}
