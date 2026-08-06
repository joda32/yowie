package detect

import "testing"

func TestContestedByLength(t *testing.T) {
	for _, tc := range []struct {
		candidate string
		want      bool
	}{
		{"abc", true},
		{"xyz", true},
		{"pqr", true},
		{"lmn", true},
		{"efg", true},
		{"widget", false},
		{"example", false},
		{"placeholder", false},
		{" efg ", true},
	} {
		if got := contestedByLength(tc.candidate); got != tc.want {
			t.Errorf("contestedByLength(%q) = %v, want %v", tc.candidate, got, tc.want)
		}
	}
}

// The case this whole file exists for: a three-letter candidate matched a
// tenant belonging to an unrelated organisation, and the vendor's page said so.
func TestConflictingOrgCatchesTheMotivatingCase(t *testing.T) {
	org, ok := conflictingOrg("Atlantic Beverage Holdings · GitHub", "abc", "abc.example", "GitHub")
	if !ok {
		t.Fatal("did not flag a page naming a different organisation")
	}
	if org != "Atlantic Beverage Holdings" {
		t.Errorf("named %q, want %q", org, "Atlantic Beverage Holdings")
	}
}

// An acronym relationship must NOT count as a match. The shared acronym is the
// reason two unrelated organisations wanted the same tenant name, so treating
// it as evidence of ownership would suppress every true collision.
func TestConflictingOrgIgnoresAcronymExpansion(t *testing.T) {
	if _, ok := conflictingOrg("Northern Provincial Banking", "npb", "npb.example", "Okta"); !ok {
		t.Error("acronym expansion was treated as a match; the collision should still be flagged")
	}
}

func TestConflictingOrgDoesNotFireOnOrdinaryTitles(t *testing.T) {
	for _, tc := range []struct{ title, candidate, domain, vendor string }{
		// Vendor name only.
		{"Slack", "acme", "acme.com", "Slack"},
		{"Zoom", "acme", "acme.com", "Zoom"},
		// Auth and error furniture, capitalised but not a name.
		{"Log in with Atlassian account", "acme", "acme.com", "Atlassian"},
		{"Sign In · Your Account", "acme", "acme.com", "Okta"},
		{"Page Not Found", "acme", "acme.com", "Zendesk"},
		{"Access Denied", "acme", "acme.com", "AWS S3"},
		{"Welcome to the Support Portal", "acme", "acme.com", "Freshdesk"},
		// The organisation's own name, in several shapes.
		{"Acme Corporation · Zendesk", "acme", "acme.com", "Zendesk"},
		{"Acme Group Support", "acme", "acme.com", "Zendesk"},
		{"ACME LIMITED", "acme", "acme.com", "Okta"},
		// Related to the domain even though the candidate differs.
		{"Widgetco Group", "wid", "widgetco.example", "Okta"},
		// Nothing to reason about.
		{"", "acme", "acme.com", "Slack"},
		{"   ", "acme", "acme.com", "Slack"},
		// A single capitalised word is not a name.
		{"Dashboard", "acme", "acme.com", "Okta"},
		{"Grafana", "acme", "acme.com", "Grafana"},
		// Scripts without case cannot be reasoned about, so stay silent.
		{"Пример — новости", "abc", "abc.example", "Okta"},
		{"淘宝网", "topshop", "shopfront.market.example", "Okta"},
	} {
		if org, ok := conflictingOrg(tc.title, tc.candidate, tc.domain, tc.vendor); ok {
			t.Errorf("conflictingOrg(%q, %q, %q, %q) flagged %q, want no conflict",
				tc.title, tc.candidate, tc.domain, tc.vendor, org)
		}
	}
}

func TestProperNounPhrases(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want []string
	}{
		{"Atlantic Beverage Holdings", []string{"Atlantic Beverage Holdings"}},
		// "Holdings" is generic, so it does not help prove the phrase is a name,
		// but it is part of the name once proven and stays in the phrase.
		{"Bank of the West Holdings", []string{"Bank of the West Holdings"}},
		{"Sign in", nil},
		{"Please Wait", nil},
		{"Acme Widgets · Okta", []string{"Acme Widgets"}},
		{"of and the", nil},
	} {
		got := properNounPhrases(tc.in)
		if len(got) != len(tc.want) {
			t.Errorf("properNounPhrases(%q) = %v, want %v", tc.in, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("properNounPhrases(%q)[%d] = %q, want %q", tc.in, i, got[i], tc.want[i])
			}
		}
	}
}

func TestNormaliseAndOverlaps(t *testing.T) {
	if got := normalise("Atlantic Beverage Holdings"); got != "atlanticbeverageholdings" {
		t.Errorf("normalise = %q", got)
	}
	if !overlaps("acmecorporation", "acme") {
		t.Error("substring in one direction should overlap")
	}
	if !overlaps("acme", "acmegroup") {
		t.Error("substring in the other direction should overlap")
	}
	if overlaps("atlanticbeverageholdings", "abc") {
		t.Error("acronym must not count as overlap")
	}
	if overlaps("", "acme") {
		t.Error("empty never overlaps")
	}
}

func TestFirstLabel(t *testing.T) {
	for in, want := range map[string]string{
		"abc.example":              "abc",
		"press.com.example":        "press",
		"shopfront.market.example": "shopfront",
		"localhost":                "localhost",
		"acme.com.":                "acme",
	} {
		if got := firstLabel(in); got != want {
			t.Errorf("firstLabel(%q) = %q, want %q", in, got, want)
		}
	}
}

// A response with no <title> has no page name to reason about. Reading its
// markup as prose reported an organisation called "Code><Message>Access Denied<".
func TestTitleTagIsEmptyWithoutATitleElement(t *testing.T) {
	xml := `<?xml version="1.0" encoding="UTF-8"?><Error><Code>AccessDenied</Code>` +
		`<Message>Access Denied</Message></Error>`
	if got := titleTag(xml); got != "" {
		t.Errorf("titleTag on an XML error document = %q, want empty", got)
	}
	if got := title(xml); got == "" {
		t.Error("title should still fall back to the body for display")
	}
	if org, ok := conflictingOrg(titleTag(xml), "abc", "abc.example", "AWS S3"); ok {
		t.Errorf("XML error document flagged %q as an organisation", org)
	}
}

func TestMarkupCannotFormANamePhrase(t *testing.T) {
	if got := properNounPhrases("<Code>AccessDenied</Code><Message>Access Denied</Message>"); len(got) != 0 {
		t.Errorf("properNounPhrases on markup = %v, want none", got)
	}
}
