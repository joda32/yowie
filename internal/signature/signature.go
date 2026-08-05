// Package signature defines the YAML signature-pack format and loads packs from
// disk or from the binary's embedded defaults.
//
// The whole point of the format is that adding vendor coverage never requires
// touching Go code: drop a new entry into a pack, re-run, done.
package signature

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/joda32/yowie/internal/model"
)

// Type selects which detector evaluates a signature.
type Type string

const (
	// TypeTXT matches a substring against the TXT records of a name. This is
	// the workhorse: most SaaS vendors prove domain ownership with a TXT token.
	TypeTXT Type = "txt"

	// TypeCNAME matches a substring against the CNAME chain of a name.
	TypeCNAME Type = "cname"

	// TypeMX matches a substring against the MX records of the root domain.
	TypeMX Type = "mx"

	// TypeNS matches a substring against the NS records of the root domain.
	TypeNS Type = "ns"

	// TypeVanityA detects a tenant by resolving a candidate-derived hostname
	// and comparing it against a known-nonexistent baseline label. A tenant
	// exists when the two answers differ.
	TypeVanityA Type = "vanity_a"

	// TypeVanityCNAME is TypeVanityA over CNAME records.
	TypeVanityCNAME Type = "vanity_cname"

	// TypeHTTP fetches a URL and matches on the response body or status.
	TypeHTTP Type = "http"

	// TypeSPFInclude matches a host against the fully-resolved SPF include
	// graph of the domain, including nested includes and redirects.
	TypeSPFInclude Type = "spf_include"

	// TypeDMARCRUA matches a host against the destinations in the domain's
	// DMARC rua/ruf tags, which name whoever processes its DMARC reports.
	TypeDMARCRUA Type = "dmarc_rua"

	// TypeCNAMETarget maps a hosting suffix to a vendor. Unlike the other
	// types it is not queried directly: it is applied to hostnames discovered
	// elsewhere — Certificate Transparency logs today — to identify what a
	// custom subdomain is pointed at. Query holds the suffix itself.
	TypeCNAMETarget Type = "cname_target"
)

func (t Type) valid() bool {
	switch t {
	case TypeTXT, TypeCNAME, TypeMX, TypeNS, TypeVanityA, TypeVanityCNAME,
		TypeHTTP, TypeSPFInclude, TypeDMARCRUA, TypeCNAMETarget:
		return true
	}
	return false
}

// UsesCandidates reports whether signatures of this type need candidate strings
// to be useful. Used to skip whole detector classes when no candidates were
// supplied.
func (t Type) UsesCandidates() bool {
	return t == TypeVanityA || t == TypeVanityCNAME
}

// Match describes the condition under which a signature fires.
//
// For DNS types only Contains applies. For HTTP, set at most one of Present or
// Absent, and optionally Status:
//
//   - Present: the marker appears in a live tenant's response. Firing on its
//     presence is the safer construction, and it is not status-constrained by
//     default — a tenant that exists may legitimately answer 400 or 403.
//   - Absent: the marker is the vendor's "no such tenant" page. The signature
//     fires when that marker is missing, which means the namespace resolved to
//     something real. Necessarily noisier, so it defaults to a 2xx/3xx guard;
//     set Status explicitly when the "exists" state is an error code.
//   - Status alone: for vendors whose response body is an identical
//     single-page-application shell either way, leaving the status code as the
//     only discriminator.
type Match struct {
	Contains string `yaml:"contains,omitempty"`
	Present  string `yaml:"present,omitempty"`
	Absent   string `yaml:"absent,omitempty"`
	// Status constrains which HTTP status codes may satisfy the match. When
	// empty the detector applies a default that depends on the match style;
	// see statusAllowed in the detect package.
	Status []int `yaml:"status,omitempty"`
}

// Signature is a single vendor fingerprint.
type Signature struct {
	// ID is a stable, unique, kebab-case identifier. It appears in reports so
	// that a finding can be traced back to the rule that produced it.
	ID string `yaml:"id"`
	// Vendor is the product name shown to the reader.
	Vendor string `yaml:"vendor"`
	// Category groups vendors in reports, e.g. "Identity", "Storage".
	Category string `yaml:"category,omitempty"`
	// Type selects the detector.
	Type Type `yaml:"type"`
	// Query is a template. {domain} expands to the root domain under test and
	// {candidate} to each candidate string. For TypeHTTP it is a URL.
	Query string `yaml:"query"`
	// Match is the firing condition.
	Match Match `yaml:"match"`
	// Confidence defaults to the pack default, or medium.
	Confidence model.Confidence `yaml:"confidence,omitempty"`
	// Notes is analyst guidance carried through to the report — caveats,
	// disambiguation, or what to do about a hit.
	Notes string `yaml:"notes,omitempty"`
	// Disabled parks a signature without deleting it, preserving the research
	// that went into it.
	Disabled bool `yaml:"disabled,omitempty"`

	// pack records the file a signature came from, for error messages.
	pack string
}

// Pack is one YAML file's worth of signatures.
type Pack struct {
	// Version is the schema version. Only 1 exists today; the field is here so
	// that a future breaking change can be detected rather than mis-parsed.
	Version     int    `yaml:"version"`
	Name        string `yaml:"pack"`
	Description string `yaml:"description,omitempty"`
	// Defaults supply values for fields signatures omit, which keeps the
	// per-entry noise down in large packs.
	Defaults struct {
		Category   string           `yaml:"category,omitempty"`
		Confidence model.Confidence `yaml:"confidence,omitempty"`
	} `yaml:"defaults,omitempty"`
	Signatures []Signature `yaml:"signatures"`
}

// Expand substitutes the template placeholders in a query.
func Expand(query, domain, candidate string) string {
	r := strings.NewReplacer("{domain}", domain, "{candidate}", candidate)
	return r.Replace(query)
}

// NeedsCandidate reports whether the signature's query references {candidate}
// and therefore must be expanded once per candidate string.
func (s Signature) NeedsCandidate() bool {
	return strings.Contains(s.Query, "{candidate}")
}

// Pack returns the name of the file the signature was loaded from.
func (s Signature) Pack() string { return s.pack }

// validate checks a single signature, returning a descriptive error naming the
// pack and ID so that a typo in a 200-entry file is easy to find.
func (s *Signature) validate() error {
	where := fmt.Sprintf("%s: signature %q", s.pack, s.ID)
	if s.ID == "" {
		return fmt.Errorf("%s: id is required", s.pack)
	}
	if s.Vendor == "" {
		return fmt.Errorf("%s: vendor is required", where)
	}
	if !s.Type.valid() {
		return fmt.Errorf("%s: unknown type %q", where, s.Type)
	}
	if !s.Confidence.Valid() {
		return fmt.Errorf("%s: invalid confidence %q", where, s.Confidence)
	}
	if s.Query == "" {
		return fmt.Errorf("%s: query is required", where)
	}

	switch s.Type {
	case TypeHTTP:
		u, err := url.Parse(Expand(s.Query, "example.com", "example"))
		if err != nil {
			return fmt.Errorf("%s: query is not a valid URL: %w", where, err)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return fmt.Errorf("%s: query must be an http(s) URL, got scheme %q", where, u.Scheme)
		}
		if s.Match.Present != "" && s.Match.Absent != "" {
			return fmt.Errorf("%s: set at most one of match.present or match.absent", where)
		}
		if s.Match.Present == "" && s.Match.Absent == "" && len(s.Match.Status) == 0 {
			return fmt.Errorf("%s: set match.present, match.absent, or match.status", where)
		}
		if s.Match.Contains != "" {
			return fmt.Errorf("%s: use match.present/match.absent for http, not match.contains", where)
		}
	case TypeVanityA, TypeVanityCNAME:
		if !s.NeedsCandidate() {
			return fmt.Errorf("%s: vanity signatures must reference {candidate}", where)
		}
		if s.Match.Contains != "" || s.Match.Present != "" || s.Match.Absent != "" {
			return fmt.Errorf("%s: vanity signatures match by baseline comparison and take no match block", where)
		}
	case TypeCNAMETarget:
		if s.Match.Contains != "" || s.Match.Present != "" || s.Match.Absent != "" {
			return fmt.Errorf("%s: cname_target matches on query (the hosting suffix) and takes no match block", where)
		}
		// A "*" is allowed and matches exactly one label, for regionalised
		// hostnames such as "execute-api.*.amazonaws.com".
		if strings.ContainsAny(s.Query, "{}/ ") {
			return fmt.Errorf("%s: cname_target query must be a bare hosting suffix, e.g. \"zendesk.com\"", where)
		}
	default: // txt, cname, mx, ns, spf_include, dmarc_rua
		if s.Match.Contains == "" {
			return fmt.Errorf("%s: match.contains is required for type %q", where, s.Type)
		}
		if s.Match.Present != "" || s.Match.Absent != "" {
			return fmt.Errorf("%s: match.present/absent apply only to http signatures", where)
		}
	}
	return nil
}
