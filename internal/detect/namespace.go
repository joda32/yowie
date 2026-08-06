package detect

import (
	"strings"
	"unicode"
)

// This file holds the checks that decide whether a tenant named after a
// candidate string really belongs to the organisation being scanned.
//
// Finding acme.zendesk.com proves a Zendesk tenant called "acme" exists. It
// does not prove it is *this* acme. Vendor tenant namespaces are global and
// first-come-first-served, so the two claims come apart whenever a name is
// contested — and they come apart most often for exactly the short, memorable
// candidates an analyst is most likely to supply.

// shortCandidateLen is the length at or below which a candidate is treated as
// contested by default.
//
// Three- and four-character names are heavily oversubscribed in vendor
// namespaces: whoever registered first holds the name globally, across every
// vendor, and it is rarely the organisation under scan. Longer candidates are
// not immune, but the collision rate falls away sharply.
const shortCandidateLen = 4

// contestedByLength reports whether a candidate is short enough that a matching
// tenant shows the tenant exists without showing who owns it.
func contestedByLength(candidate string) bool {
	return len([]rune(strings.TrimSpace(candidate))) <= shortCandidateLen
}

// connectors may appear inside a proper-noun phrase without ending it:
// "Atlantic Beverage Holdings", "Bank of the West", "Banco de Chile".
var connectors = map[string]bool{
	"of": true, "the": true, "and": true, "for": true, "de": true, "del": true,
	"du": true, "da": true, "di": true, "van": true, "von": true, "der": true,
	"den": true, "la": true, "le": true, "el": true, "y": true,
}

// genericTitleWords are capitalised words that carry no organisational
// identity. Page titles are full of them, and counting them as part of a name
// is what would turn "Sign In · Your Account" into a false collision report.
var genericTitleWords = map[string]bool{
	"sign": true, "signin": true, "log": true, "login": true, "logout": true,
	"in": true, "out": true, "to": true, "your": true, "my": true, "our": true,
	"account": true, "accounts": true, "welcome": true, "home": true,
	"homepage": true, "page": true, "not": true, "found": true, "error": true,
	"errors": true, "support": true, "help": true, "helpdesk": true,
	"dashboard": true, "portal": true, "access": true, "denied": true,
	"forbidden": true, "unauthorized": true, "unauthorised": true,
	"redirecting": true, "loading": true, "please": true, "wait": true,
	"secure": true, "auth": true, "authentication": true, "sso": true,
	"single": true, "on": true, "identity": true, "service": true,
	"services": true, "status": true, "online": true, "offline": true,
	"test": true, "demo": true, "app": true, "apps": true, "web": true,
	"site": true, "website": true, "customer": true, "client": true,
	"partner": true, "user": true, "users": true, "admin": true,
	"console": true, "cloud": true, "platform": true, "solutions": true,
	"group": true, "holdings": true, "limited": true, "ltd": true,
	"inc": true, "corp": true, "corporation": true, "company": true,
	"pty": true, "plc": true, "gmbh": true, "existing": true, "new": true,
	"continue": true, "get": true, "started": true,
}

// conflictingOrg looks for an organisation name in a vendor's tenant page that
// is not the organisation being scanned.
//
// The motivating case: a three-letter candidate matched a tenant belonging to
// an unrelated company on the other side of the world, and the vendor's own
// page said whose it was — in its title, inside the evidence string — while the
// finding was still graded as proof. When a tenant page names its owner and
// that name bears no relation to the domain under scan, the namespace belongs
// to someone else.
//
// It is deliberately conservative, because a false alarm downgrades a true
// finding. It fires only on a capitalised multi-word phrase — a name, not prose
// — that survives removal of the vendor's own name and of ordinary page
// furniture, and that bears no textual relation to the candidate or the domain.
//
// Acronym expansion is deliberately *not* treated as a relation. "ABH" and
// "Atlantic Beverage Holdings" look related, and that is precisely the
// collision this exists to catch: the shared acronym is why two unrelated
// organisations both wanted the same tenant name. Treating it as a match
// would suppress the one case the check was written for.
func conflictingOrg(title, candidate, domain, vendor string) (string, bool) {
	title = strings.TrimSpace(title)
	if title == "" {
		return "", false
	}

	// The vendor's own name appears in almost every tenant page title and is
	// never the tenant owner.
	cleaned := title
	for _, form := range vendorForms(vendor) {
		cleaned = removeFold(cleaned, form)
	}

	label := firstLabel(domain)
	for _, phrase := range properNounPhrases(cleaned) {
		n := normalise(phrase)
		if n == "" {
			continue
		}
		if overlaps(n, normalise(candidate)) || overlaps(n, normalise(label)) {
			continue
		}
		return phrase, true
	}
	return "", false
}

// vendorForms returns the spellings of a vendor name worth stripping from a
// title: the whole name, and its individual words. "Salesforce Marketing Cloud"
// has to lose "Salesforce" even when the title says only that.
func vendorForms(vendor string) []string {
	vendor = strings.TrimSpace(vendor)
	if vendor == "" {
		return nil
	}
	forms := []string{vendor}
	for _, w := range strings.Fields(vendor) {
		w = strings.Trim(w, "().,")
		if len([]rune(w)) >= 3 && !genericTitleWords[strings.ToLower(w)] {
			forms = append(forms, w)
		}
	}
	return forms
}

// properNounPhrases extracts runs of capitalised words that look like a name.
//
// A run needs at least two capitalised words that are not ordinary page
// furniture. That threshold is what separates "Atlantic Beverage Holdings" from
// "Sign In" and from a capitalised sentence opener.
func properNounPhrases(s string) []string {
	segments := strings.FieldsFunc(s, func(r rune) bool {
		switch r {
		case '·', '|', '—', '–', '-', ':', '/', '(', ')', ',', '"', '\n', '\t',
			'<', '>', '{', '}', '[', ']', ';', '=':
			return true
		}
		return false
	})

	var out []string
	for _, seg := range segments {
		var run []string
		named := 0

		flush := func() {
			for len(run) > 0 && connectors[strings.ToLower(run[len(run)-1])] {
				run = run[:len(run)-1]
			}
			if named >= 2 && len(run) >= 2 {
				out = append(out, strings.Join(run, " "))
			}
			run, named = nil, 0
		}

		for _, w := range strings.Fields(seg) {
			word := strings.Trim(w, ".,;:!?\"'’")
			if word == "" {
				flush()
				continue
			}
			lower := strings.ToLower(word)
			switch {
			case isCapitalised(word):
				run = append(run, word)
				if !genericTitleWords[lower] {
					named++
				}
			case connectors[lower] && len(run) > 0:
				run = append(run, word)
			default:
				flush()
			}
		}
		flush()
	}
	return out
}

// isCapitalised reports whether a word starts with an upper-case letter. Words
// in scripts without case (Cyrillic has case; Chinese does not) never qualify,
// which keeps the check from firing on titles it cannot reason about.
func isCapitalised(w string) bool {
	for _, r := range w {
		return unicode.IsUpper(r)
	}
	return false
}

// normalise reduces a name to comparable form: lower case, letters and digits
// only. "Atlantic Beverage Holdings" becomes "atlanticbeverageholdings".
func normalise(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// overlaps reports whether either normalised name contains the other. Substring
// containment in both directions covers "acme" against "acmecorporation" and
// "acmegroupsupport" against "acmegroup".
func overlaps(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	return strings.Contains(a, b) || strings.Contains(b, a)
}

// removeFold deletes every case-insensitive occurrence of sub from s.
func removeFold(s, sub string) string {
	if sub == "" {
		return s
	}
	var b strings.Builder
	ls, lsub := strings.ToLower(s), strings.ToLower(sub)
	for {
		i := strings.Index(ls, lsub)
		if i < 0 {
			b.WriteString(s)
			return b.String()
		}
		b.WriteString(s[:i])
		b.WriteString(" ")
		s, ls = s[i+len(sub):], ls[i+len(lsub):]
	}
}

// firstLabel returns the leftmost DNS label, which is the default candidate and
// the closest thing to an organisation name a domain alone provides.
func firstLabel(domain string) string {
	domain = strings.TrimSpace(strings.TrimSuffix(domain, "."))
	if i := strings.Index(domain, "."); i > 0 {
		return domain[:i]
	}
	return domain
}
