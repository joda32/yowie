package signature

import (
	"strings"
	"testing"
	"testing/fstest"

	"github.com/joda32/yowie/internal/model"
)

func pack(body string) fstest.MapFS {
	return fstest.MapFS{"test.yaml": &fstest.MapFile{Data: []byte(body)}}
}

const header = "version: 1\npack: test\nsignatures:\n"

func TestLoadAppliesDefaults(t *testing.T) {
	set, err := LoadFS(pack(`version: 1
pack: test
defaults:
  category: Collaboration
  confidence: low
signatures:
  - id: a
    vendor: Acme
    type: txt
    query: "{domain}"
    match:
      contains: ACME-VERIFY
  - id: b
    vendor: Beta
    category: Storage
    confidence: high
    type: txt
    query: "{domain}"
    match:
      contains: beta
`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if set.Len() != 2 {
		t.Fatalf("got %d signatures, want 2", set.Len())
	}

	a := set.All()[0]
	if a.Category != "Collaboration" || a.Confidence != model.ConfidenceLow {
		t.Errorf("pack defaults not applied: category=%q confidence=%q", a.Category, a.Confidence)
	}
	// DNS needles are lowercased at load so matching does not have to be.
	if a.Match.Contains != "acme-verify" {
		t.Errorf("contains = %q, want lowercased", a.Match.Contains)
	}

	b := set.All()[1]
	if b.Category != "Storage" || b.Confidence != model.ConfidenceHigh {
		t.Errorf("explicit values should override defaults, got %q/%q", b.Category, b.Confidence)
	}
}

func TestLoadRejects(t *testing.T) {
	cases := map[string]struct{ body, want string }{
		"duplicate id": {header + `
  - id: dup
    vendor: A
    type: txt
    query: "{domain}"
    match: {contains: x}
  - id: dup
    vendor: B
    type: txt
    query: "{domain}"
    match: {contains: y}
`, "duplicate signature id"},

		"unknown type": {header + `
  - id: a
    vendor: A
    type: telepathy
    query: "{domain}"
    match: {contains: x}
`, "unknown type"},

		"unknown field": {header + `
  - id: a
    vendor: A
    type: txt
    query: "{domain}"
    confidance: high
    match: {contains: x}
`, "field confidance not found"},

		"http with both markers": {header + `
  - id: a
    vendor: A
    type: http
    query: "https://{candidate}.example.com"
    match: {present: yes, absent: no}
`, "at most one of match.present or match.absent"},

		"http with no match criteria at all": {header + `
  - id: a
    vendor: A
    type: http
    query: "https://{candidate}.example.com"
    match: {}
`, "set match.present, match.absent, or match.status"},

		"vanity without candidate": {header + `
  - id: a
    vendor: A
    type: vanity_a
    query: "fixed.example.com"
`, "must reference {candidate}"},

		"vanity with match block": {header + `
  - id: a
    vendor: A
    type: vanity_a
    query: "{candidate}.example.com"
    match: {contains: x}
`, "no match block"},

		"txt without contains": {header + `
  - id: a
    vendor: A
    type: txt
    query: "{domain}"
`, "match.contains is required"},

		"cname_target with template": {header + `
  - id: a
    vendor: A
    type: cname_target
    query: "{candidate}.example.com"
`, "bare hosting suffix"},

		"wrong schema version": {"version: 99\npack: t\nsignatures:\n  - id: a\n    vendor: A\n    type: txt\n    query: x\n    match: {contains: y}\n",
			"schema version 99 is not supported"},

		"bad url": {header + `
  - id: a
    vendor: A
    type: http
    query: "ftp://example.com"
    match: {present: x}
`, "must be an http(s) URL"},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := LoadFS(pack(tc.body))
			if err == nil {
				t.Fatalf("expected an error mentioning %q, got none", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

// TestStatusOnlyHTTPSignatureIsValid covers vendors whose response body is the
// same single-page-application shell whether the namespace exists or not,
// leaving the status code as the only discriminator. HackerOne is the live
// example.
func TestStatusOnlyHTTPSignatureIsValid(t *testing.T) {
	set, err := LoadFS(pack(header + `
  - id: a
    vendor: A
    type: http
    query: "https://example.com/{candidate}"
    match: {status: [200]}
`))
	if err != nil {
		t.Fatalf("a status-only http signature should be valid: %v", err)
	}
	if got := set.All()[0].Match.Status; len(got) != 1 || got[0] != 200 {
		t.Errorf("status = %v, want [200]", got)
	}
}

func TestDisabledSignaturesAreSkippedButStillValidated(t *testing.T) {
	set, err := LoadFS(pack(header + `
  - id: live
    vendor: A
    type: txt
    query: "{domain}"
    match: {contains: x}
  - id: parked
    vendor: B
    type: txt
    query: "{domain}"
    match: {contains: y}
    disabled: true
`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if set.Len() != 1 || set.All()[0].ID != "live" {
		t.Fatalf("disabled signature was not skipped: %+v", set.All())
	}
}

func TestExpand(t *testing.T) {
	cases := []struct{ query, domain, candidate, want string }{
		{"{domain}", "acme.com", "", "acme.com"},
		{"_dmarc.{domain}", "acme.com", "", "_dmarc.acme.com"},
		{"{candidate}.zendesk.com", "acme.com", "acme", "acme.zendesk.com"},
		{"{candidate}-my.sharepoint.com", "acme.com", "acme", "acme-my.sharepoint.com"},
		{"https://x.com/y?q={candidate}&d={domain}", "acme.com", "acme", "https://x.com/y?q=acme&d=acme.com"},
	}
	for _, tc := range cases {
		if got := Expand(tc.query, tc.domain, tc.candidate); got != tc.want {
			t.Errorf("Expand(%q) = %q, want %q", tc.query, got, tc.want)
		}
	}
}

func TestNeedsCandidate(t *testing.T) {
	if (Signature{Query: "{domain}"}).NeedsCandidate() {
		t.Error("{domain} should not need a candidate")
	}
	if !(Signature{Query: "{candidate}.x.com"}).NeedsCandidate() {
		t.Error("{candidate} should need a candidate")
	}
}

// TestRejectsOverbroadCNAMETarget guards the wildcard against claiming a whole
// TLD, which would attribute every unrelated host to one vendor.
func TestRejectsOverbroadCNAMETarget(t *testing.T) {
	_, err := LoadFS(pack(header + `
  - id: a
    vendor: A
    type: cname_target
    query: "*.com"
`))
	if err == nil || !strings.Contains(err.Error(), "may not start with a bare") {
		t.Fatalf("expected a rejection of *.com, got %v", err)
	}

	// An anchored wildcard is fine.
	if _, err := LoadFS(pack(header + `
  - id: a
    vendor: A
    type: cname_target
    query: "mkto-*.com"
`)); err != nil {
		t.Fatalf("anchored wildcard should be valid: %v", err)
	}
}
