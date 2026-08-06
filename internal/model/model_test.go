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

// Several tenants named after the same candidate are one assumption repeated,
// not independent corroboration. Without this the corroboration bonus would
// promote a contested finding to high the moment a second vendor matched.
func TestContestedFindingsDoNotCorroborateEachOther(t *testing.T) {
	s := NewFindingSet()
	s.Add(Finding{Vendor: "Salesforce", Confidence: ConfidenceHigh, ContestedNamespace: true,
		Signatures: []string{"vanity-salesforce"},
		Evidence:   []Evidence{ev(MethodA, "abc.my.salesforce.com", "136.146.27.240")}})
	s.Add(Finding{Vendor: "Salesforce", Confidence: ConfidenceMedium, ContestedNamespace: true,
		Signatures: []string{"http-salesforce"},
		Evidence:   []Evidence{ev(MethodHTTP, "https://abc.lightning.force.com", "Salesforce")}})

	f := s.Findings()[0]
	if f.Confidence != ConfidenceMedium {
		t.Errorf("confidence = %q, want medium: two candidate-namespace matches are the same claim twice", f.Confidence)
	}
	if !f.ContestedNamespace {
		t.Error("finding should still be marked contested")
	}
}

// One domain-scoped match settles ownership, and the cap must lift.
func TestDomainScopedEvidenceLiftsTheContestedCap(t *testing.T) {
	s := NewFindingSet()
	s.Add(Finding{Vendor: "Salesforce", Confidence: ConfidenceMedium, ContestedNamespace: true,
		Signatures: []string{"vanity-salesforce"},
		Evidence:   []Evidence{ev(MethodA, "abc.my.salesforce.com", "136.146.27.240")}})
	s.Add(Finding{Vendor: "Salesforce", Confidence: ConfidenceHigh,
		Signatures: []string{"txt-salesforce"},
		Evidence:   []Evidence{ev(MethodTXT, "abc.example", "salesforce-domain-verification=x")}})

	f := s.Findings()[0]
	if f.ContestedNamespace {
		t.Error("a domain-scoped match should clear the contested mark")
	}
	if f.Confidence != ConfidenceHigh {
		t.Errorf("confidence = %q, want high once ownership is proven", f.Confidence)
	}
}

// Order must not matter: the domain-scoped match may arrive first.
func TestContestedCapIsOrderIndependent(t *testing.T) {
	s := NewFindingSet()
	s.Add(Finding{Vendor: "Okta", Confidence: ConfidenceHigh,
		Evidence: []Evidence{ev(MethodTXT, "acme.com", "okta-verification=x")}})
	s.Add(Finding{Vendor: "Okta", Confidence: ConfidenceHigh, ContestedNamespace: true,
		Evidence: []Evidence{ev(MethodCNAME, "acm.okta.com", "ok6-crtrs.tng.okta.com")}})

	if f := s.Findings()[0]; f.Confidence != ConfidenceHigh || f.ContestedNamespace {
		t.Errorf("confidence = %q contested = %v, want high and not contested", f.Confidence, f.ContestedNamespace)
	}
}

// A lone contested match arriving as high is capped on insert, not only on merge.
func TestLoneContestedFindingIsCappedOnInsert(t *testing.T) {
	s := NewFindingSet()
	s.Add(Finding{Vendor: "Zoom", Confidence: ConfidenceHigh, ContestedNamespace: true,
		Evidence: []Evidence{ev(MethodA, "abc.zoom.us", "170.114.52.2")}})

	if f := s.Findings()[0]; f.Confidence != ConfidenceMedium {
		t.Errorf("confidence = %q, want medium", f.Confidence)
	}
}
