package detect

import (
	"errors"
	"strings"
	"testing"

	"github.com/joda32/yowie/internal/signature"
)

func TestSPFTerms(t *testing.T) {
	terms := spfTerms(`v=spf1 ip4:1.2.3.4 ip6:::1 include:spf.protection.outlook.com ` +
		`-include:_spf.google.com a:mail.acme.com/24 mx:mx.acme.com. exists:%{i}._spf.acme.com ` +
		`ptr:acme.com ~all redirect=_spf.fallback.com`)

	got := map[string]spfTerm{}
	for _, term := range terms {
		got[term.Host] = term
	}

	// ip4/ip6/all carry no host and must not appear.
	if len(terms) != 6 {
		t.Fatalf("got %d terms, want 6: %+v", len(terms), terms)
	}

	for _, want := range []string{
		"spf.protection.outlook.com", "_spf.google.com", "mail.acme.com",
		"mx.acme.com", "ptr:acme.com"[4:], "_spf.fallback.com",
	} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing host %q", want)
		}
	}

	// The dual-CIDR suffix is stripped, and the trailing dot with it.
	if _, ok := got["mail.acme.com"]; !ok {
		t.Error("a: mechanism should have its /24 suffix stripped")
	}
	if _, ok := got["mx.acme.com"]; !ok {
		t.Error("mx: mechanism should have its trailing dot stripped")
	}

	// A macro mechanism is not a usable vendor identifier.
	for _, term := range terms {
		if term.Host == "%{i}._spf.acme.com" {
			t.Error("macro mechanisms should be skipped")
		}
	}

	// Only include: and redirect= recurse.
	if !got["spf.protection.outlook.com"].Recurse {
		t.Error("include: should recurse")
	}
	if !got["_spf.fallback.com"].Recurse {
		t.Error("redirect= should recurse")
	}
	if got["mail.acme.com"].Recurse {
		t.Error("a: should not recurse")
	}

	// The qualifier is stripped for matching but the original term is kept as
	// evidence.
	if got["_spf.google.com"].Term != "-include:_spf.google.com" {
		t.Errorf("Term = %q, want the original text including its qualifier", got["_spf.google.com"].Term)
	}
}

func TestSPFTermsIgnoresBareMechanisms(t *testing.T) {
	// Bare "a", "mx" and "ptr" refer to the current domain and name no host.
	if terms := spfTerms("v=spf1 a mx ptr -all"); len(terms) != 0 {
		t.Errorf("got %+v, want no host-bearing terms", terms)
	}
}

func TestStatusAllowed(t *testing.T) {
	absent := func(status ...int) signature.Match {
		return signature.Match{Absent: "no such tenant", Status: status}
	}
	present := func(status ...int) signature.Match {
		return signature.Match{Present: "live marker", Status: status}
	}

	cases := []struct {
		name   string
		status int
		match  signature.Match
		want   bool
	}{
		// An absent-marker signature defaults to a 2xx/3xx guard, because any
		// unrelated error page also lacks the vendor's not-found text.
		{"absent 200", 200, absent(), true},
		{"absent 302", 302, absent(), true},
		{"absent 404", 404, absent(), false},
		{"absent 500", 500, absent(), false},

		// A present-marker signature is not status-constrained: the marker is
		// the evidence. This is the Auth0 regression — a live tenant answers
		// 400 and was being discarded.
		{"present 400", 400, present(), true},
		{"present 403", 403, present(), true},
		{"present 500", 500, present(), true},

		// An explicit status list always wins, in both directions. This is the
		// S3/GCS case, where a bucket that exists but denies access is a 403.
		{"explicit 403 allowed", 403, absent(200, 403), true},
		{"explicit 404 still blocked", 404, absent(200, 403), false},
		{"explicit narrows present", 500, present(200), false},

		// Status-only signatures are defined entirely by their list.
		{"status-only match", 200, signature.Match{Status: []int{200}}, true},
		{"status-only miss", 404, signature.Match{Status: []int{200}}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := statusAllowed(tc.status, tc.match); got != tc.want {
				t.Errorf("statusAllowed(%d, %+v) = %v, want %v", tc.status, tc.match, got, tc.want)
			}
		})
	}
}

func TestHostMatchesSuffixRespectsLabelBoundary(t *testing.T) {
	cases := []struct {
		host, suffix string
		want         bool
	}{
		{"acme.zendesk.com", "zendesk.com", true},
		{"zendesk.com", "zendesk.com", true},
		{"a.b.zendesk.com", "zendesk.com", true},
		{"notzendesk.com", "zendesk.com", false}, // the whole point of the check
		{"zendesk.com.evil.net", "zendesk.com", false},
		{"acme.zendesk.com.", "zendesk.com", true},
	}
	for _, tc := range cases {
		if got := hostMatchesSuffix(tc.host, tc.suffix); got != tc.want {
			t.Errorf("hostMatchesSuffix(%q, %q) = %v, want %v", tc.host, tc.suffix, got, tc.want)
		}
	}
}

func TestSameOrg(t *testing.T) {
	cases := []struct {
		host, domain string
		want         bool
	}{
		{"acme.com", "acme.com", true},
		{"mail.acme.com", "acme.com", true},
		{"acme.com.au", "acme.com", false},
		{"notacme.com", "acme.com", false},
		{"acme.com.", "acme.com", true},
	}
	for _, tc := range cases {
		if got := sameOrg(tc.host, tc.domain); got != tc.want {
			t.Errorf("sameOrg(%q, %q) = %v, want %v", tc.host, tc.domain, got, tc.want)
		}
	}
}

func TestProviderKey(t *testing.T) {
	cases := map[string]string{
		"acme.zendesk.com":      "zendesk.com",
		"a.b.c.freshdesk.com":   "freshdesk.com",
		"foo.example.com.au":    "example.com.au",
		"example.com":           "example.com",
		"a.b.retailpath.com.au": "retailpath.com.au",
	}
	for host, want := range cases {
		if got := providerKey(host); got != want {
			t.Errorf("providerKey(%q) = %q, want %q", host, got, want)
		}
	}
}

func TestTitle(t *testing.T) {
	cases := map[string]string{
		`<html><head><TITLE>Acme Support</TITLE></head>`: "Acme Support",
		`<title >spaced</title>`:                         "spaced",
		`no title here`:                                  "no title here",
		`<title>unclosed`:                                "unclosed",
	}
	for body, want := range cases {
		if got := title(body); got != want {
			t.Errorf("title(%q) = %q, want %q", body, got, want)
		}
	}
}

func TestURLHosts(t *testing.T) {
	got := urlHosts(`v=BIMI1; l=https://cdn.acme.com/logo.svg; a=https://certs.digicert.com/vmc.pem`)
	if len(got) != 2 || got[0] != "cdn.acme.com" || got[1] != "certs.digicert.com" {
		t.Errorf("urlHosts = %v, want [cdn.acme.com certs.digicert.com]", got)
	}
}

func TestXMLValues(t *testing.T) {
	body := `<Response><Domain>acme.com</Domain><Domain>acme.onmicrosoft.com</Domain></Response>`
	got := xmlValues(body, "Domain")
	if len(got) != 2 || got[0] != "acme.com" || got[1] != "acme.onmicrosoft.com" {
		t.Errorf("xmlValues = %v", got)
	}
	if v := xmlValue(body, "Missing"); v != "" {
		t.Errorf("xmlValue for a missing tag = %q, want empty", v)
	}
}

func TestSnippetIncludesContext(t *testing.T) {
	body := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaMARKERbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	got := snippet(body, "MARKER")
	if !strings.Contains(got, "MARKER") {
		t.Errorf("snippet = %q, want it to contain the marker", got)
	}
	if len(got) > 210 {
		t.Errorf("snippet is %d chars, want it bounded", len(got))
	}
}

func TestParseCrtSh(t *testing.T) {
	// name_value packs SANs into one newline-separated string, and crt.sh
	// returns neighbouring names that must be filtered out.
	body := `[
	  {"name_value":"support.acme.com\n*.acme.com","common_name":"support.acme.com"},
	  {"name_value":"WWW.ACME.COM","common_name":"www.acme.com"},
	  {"name_value":"acme.com.","common_name":"acme.com"},
	  {"name_value":"other.example.net","common_name":"other.example.net"},
	  {"name_value":"notacme.com","common_name":"notacme.com"}
	]`
	got, err := parseCrtSh(body, "acme.com")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := []string{"acme.com", "support.acme.com", "www.acme.com"}
	assertHosts(t, got, want)
}

func TestParseCertSpotter(t *testing.T) {
	body := `[
	  {"dns_names":["support.acme.com","*.acme.com"]},
	  {"dns_names":["api.acme.com","unrelated.example.net"]}
	]`
	got, err := parseCertSpotter(body, "acme.com")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	assertHosts(t, got, []string{"acme.com", "api.acme.com", "support.acme.com"})
}

func TestCTParsersRejectNonJSON(t *testing.T) {
	// Both services return an HTML error page under load; that must surface as
	// an error so the caller falls through to the next source.
	for name, parse := range map[string]func(string, string) ([]string, error){
		"crt.sh":      parseCrtSh,
		"certspotter": parseCertSpotter,
	} {
		if _, err := parse("<html>502 Bad Gateway</html>", "acme.com"); err == nil {
			t.Errorf("%s: expected an error for a non-JSON body", name)
		}
	}
}

func assertHosts(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestHostMatchesSuffixWildcard(t *testing.T) {
	cases := []struct {
		host, suffix string
		want         bool
	}{
		{"d-abc.execute-api.ap-southeast-2.amazonaws.com", "execute-api.*.amazonaws.com", true},
		{"d-abc.execute-api.us-east-1.amazonaws.com", "execute-api.*.amazonaws.com", true},
		{"execute-api.eu-west-1.amazonaws.com", "execute-api.*.amazonaws.com", true},
		// A wildcard matches exactly one label, not several.
		{"x.execute-api.a.b.amazonaws.com", "execute-api.*.amazonaws.com", false},
		// Wrong service under the same parent must not match.
		{"foo.elb.ap-southeast-2.amazonaws.com", "execute-api.*.amazonaws.com", false},
		// Too few labels to satisfy the pattern.
		{"amazonaws.com", "execute-api.*.amazonaws.com", false},
	}
	for _, tc := range cases {
		if got := hostMatchesSuffix(tc.host, tc.suffix); got != tc.want {
			t.Errorf("hostMatchesSuffix(%q, %q) = %v, want %v", tc.host, tc.suffix, got, tc.want)
		}
	}
}

func TestHostMatchesSuffixGlobWithinLabel(t *testing.T) {
	cases := []struct {
		host, suffix string
		want         bool
	}{
		// Marketo mints a per-customer tracking domain, so the registrable
		// domain itself varies.
		{"mkto-sj180011.com", "mkto-*.com", true},
		{"track.mkto-ab99.com", "mkto-*.com", true},
		{"mkto.com", "mkto-*.com", false},
		// The glob must not escape its label and swallow the whole TLD.
		{"evil.com", "mkto-*.com", false},
		{"notmkto-1.com", "mkto-*.com", false},
		// Whole-label wildcards still work.
		{"d-x.execute-api.ap-southeast-2.amazonaws.com", "execute-api.*.amazonaws.com", true},
	}
	for _, tc := range cases {
		if got := hostMatchesSuffix(tc.host, tc.suffix); got != tc.want {
			t.Errorf("hostMatchesSuffix(%q, %q) = %v, want %v", tc.host, tc.suffix, got, tc.want)
		}
	}
}

func TestCTFailureReason(t *testing.T) {
	cases := []struct {
		name, body string
		status     int
		want       string
	}{
		{"server-side timeout", `{"code":"timeout","message":"This query took longer than 15 seconds to complete"}`,
			504, "will not help"},
		{"rate limited", `{"code":"rate_limited","message":"You have exceeded the domain search rate limit"}`,
			429, "wait before retrying"},
		{"other structured error", `{"code":"bad_request","message":"unknown parameter"}`,
			400, "unknown parameter"},
		{"html error page", `<html>502 Bad Gateway</html>`, 502, "HTTP 502"},
		{"empty body", ``, 503, "HTTP 503"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ctFailureReason(tc.status, tc.body)
			if !strings.Contains(got, tc.want) {
				t.Errorf("ctFailureReason(%d, %q) = %q, want it to mention %q", tc.status, tc.body, got, tc.want)
			}
		})
	}

	// A server-side timeout must not tell the reader to raise the client
	// timeout, which is the advice the old message gave.
	if got := ctFailureReason(504, `{"code":"timeout","message":"x"}`); strings.Contains(got, "raise -ct-timeout") {
		t.Errorf("must not suggest raising the client timeout for a server-side timeout: %q", got)
	}
}

// TestHostMatchesSuffixAWSLoadBalancerForms covers both AWS load balancer
// hostname shapes. The region sits on a different side of the "elb" label in
// each, so a signature written for one form silently misses the other.
func TestHostMatchesSuffixAWSLoadBalancerForms(t *testing.T) {
	classic := "my-lb-1234567890.ap-southeast-2.elb.amazonaws.com"
	modern := "hlb-public-main-nlb-89c783465efdc470.elb.ap-southeast-2.amazonaws.com"

	if !hostMatchesSuffix(classic, "elb.amazonaws.com") {
		t.Error("classic form should match the plain elb.amazonaws.com suffix")
	}
	if hostMatchesSuffix(modern, "elb.amazonaws.com") {
		t.Error("modern form must NOT match the plain suffix — this was the gap")
	}
	if !hostMatchesSuffix(modern, "elb.*.amazonaws.com") {
		t.Error("modern form should match the regional wildcard")
	}
	// The wildcard must not swallow unrelated AWS services.
	if hostMatchesSuffix("d-abc.execute-api.ap-southeast-2.amazonaws.com", "elb.*.amazonaws.com") {
		t.Error("regional wildcard must not match API Gateway")
	}
}

func TestMergeCTResults(t *testing.T) {
	// The motivating case: one source returns a strict subset of the other.
	// Stopping at the first answer discarded the difference.
	results := []ctResult{
		{source: "primary", hosts: []string{"c.acme.com", "a.acme.com", "b.acme.com"}},
		{source: "secondary", hosts: []string{"a.acme.com", "d.acme.com"}},
	}
	merged, contributed, failures := mergeCTResults(results)

	want := []string{"a.acme.com", "b.acme.com", "c.acme.com", "d.acme.com"}
	if len(merged) != len(want) {
		t.Fatalf("merged = %v, want %v", merged, want)
	}
	for i := range want {
		if merged[i] != want[i] {
			t.Fatalf("merged = %v, want %v (sorted)", merged, want)
		}
	}
	if len(failures) != 0 {
		t.Errorf("failures = %v, want none", failures)
	}
	// The report must show what each source actually added, so a run where one
	// source contributed nothing new is visible.
	if !strings.Contains(contributed[0], "3, 3 new") {
		t.Errorf("primary contribution = %q, want it to report 3 new", contributed[0])
	}
	if !strings.Contains(contributed[1], "2, 1 new") {
		t.Errorf("secondary contribution = %q, want it to report 1 new", contributed[1])
	}
}

func TestMergeCTResultsPartialFailure(t *testing.T) {
	results := []ctResult{
		{source: "primary", err: errors.New("HTTP 502")},
		{source: "secondary", hosts: []string{"a.acme.com"}},
	}
	merged, contributed, failures := mergeCTResults(results)

	if len(merged) != 1 {
		t.Errorf("a surviving source should still yield its hosts, got %v", merged)
	}
	if len(failures) != 1 || !strings.Contains(failures[0], "primary") {
		t.Errorf("failures = %v, want the failed source named", failures)
	}
	if len(contributed) != 1 || !strings.Contains(contributed[0], "secondary") {
		t.Errorf("contributed = %v, want only the surviving source", contributed)
	}
}

func TestMergeCTResultsTotalFailure(t *testing.T) {
	results := []ctResult{
		{source: "primary", err: errors.New("HTTP 502")},
		{source: "secondary", err: errors.New("HTTP 429")},
	}
	merged, _, failures := mergeCTResults(results)
	if len(merged) != 0 {
		t.Errorf("merged = %v, want empty", merged)
	}
	if len(failures) != 2 {
		t.Errorf("failures = %v, want both recorded", failures)
	}
}

func TestMergeCTResultsDeduplicates(t *testing.T) {
	results := []ctResult{
		{source: "a", hosts: []string{"x.acme.com", "x.acme.com"}},
		{source: "b", hosts: []string{"x.acme.com"}},
	}
	merged, contributed, _ := mergeCTResults(results)
	if len(merged) != 1 {
		t.Errorf("merged = %v, want one entry", merged)
	}
	if !strings.Contains(contributed[1], "1, 0 new") {
		t.Errorf("second source added nothing new; contribution = %q", contributed[1])
	}
}
