// Package model defines the core types shared across Yowie: the findings
// produced by detectors, the evidence that backs them, and the confidence
// scoring used to rank them.
package model

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Confidence expresses how strongly a signature match implies the organisation
// actually subscribes to a service.
//
// High means the token is vendor-issued and domain-scoped — effectively proof.
// Medium means the indicator is strong but could also be explained by shared
// infrastructure or a namespace claimed by someone else. Low means suggestive
// only, and a human should confirm before acting on it.
type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

// Score maps a confidence onto a sortable weight.
func (c Confidence) Score() int {
	switch c {
	case ConfidenceHigh:
		return 3
	case ConfidenceMedium:
		return 2
	case ConfidenceLow:
		return 1
	default:
		return 0
	}
}

// Valid reports whether c is a recognised confidence level.
func (c Confidence) Valid() bool { return c.Score() > 0 }

// Method identifies the channel a piece of evidence came from. These strings
// surface directly in reports, so they are written for a human reader.
type Method string

const (
	MethodTXT        Method = "TXT"
	MethodCNAME      Method = "CNAME"
	MethodMX         Method = "MX"
	MethodA          Method = "A"
	MethodHTTP       Method = "HTTP"
	MethodSPF        Method = "SPF"
	MethodDMARC      Method = "DMARC"
	MethodBIMI       Method = "BIMI"
	MethodMTASTS     Method = "MTA-STS"
	MethodCT         Method = "CT"
	MethodTenant     Method = "Tenant"
	MethodNameserver Method = "NS"
)

// Evidence records exactly why a detector fired. Every finding carries at least
// one. The intent is that a reader can independently re-run Query and see Value
// for themselves — findings in a shadow IT report have to be defensible.
type Evidence struct {
	Method Method `json:"method"`
	// Query is the precise thing that was asked: a DNS name, or a URL.
	Query string `json:"query"`
	// Value is the response that triggered the match, trimmed to something
	// readable.
	Value string `json:"value"`
	// Detail optionally explains the inference drawn from Value.
	Detail string `json:"detail,omitempty"`
}

func (e Evidence) String() string {
	if e.Detail != "" {
		return fmt.Sprintf("%s %s -> %s (%s)", e.Method, e.Query, e.Value, e.Detail)
	}
	return fmt.Sprintf("%s %s -> %s", e.Method, e.Query, e.Value)
}

// Finding is one SaaS vendor believed to be in use, together with everything
// that led Yowie to that belief.
type Finding struct {
	Vendor     string     `json:"vendor"`
	Category   string     `json:"category,omitempty"`
	Confidence Confidence `json:"confidence"`
	// Signatures lists the IDs of every signature that contributed.
	Signatures []string `json:"signatures,omitempty"`
	// Notes carries analyst guidance from the signature pack, e.g. a caveat
	// about false positives.
	Notes []string `json:"notes,omitempty"`
	// ContestedNamespace marks a finding that rests entirely on a tenant named
	// after a candidate string, where the tenant could plausibly belong to a
	// different organisation. Such a finding is capped at medium however much
	// evidence accumulates, because the evidence is all the same claim restated.
	ContestedNamespace bool       `json:"contested_namespace,omitempty"`
	Evidence           []Evidence `json:"evidence"`
	// FirstSeen is set by the engine when the finding is recorded.
	FirstSeen time.Time `json:"first_seen"`
}

// key is the identity used for deduplication. Two matches for the same vendor
// collapse into one finding with the union of their evidence.
func (f *Finding) key() string { return strings.ToLower(f.Vendor) }

// Result is a complete scan of one organisation.
type Result struct {
	Domain     string        `json:"domain"`
	Candidates []string      `json:"candidates"`
	StartedAt  time.Time     `json:"started_at"`
	Duration   time.Duration `json:"duration_ms"`
	Findings   []Finding     `json:"findings"`
	// Errors collects non-fatal problems (timeouts, unreachable endpoints) so
	// that a partial scan is visibly partial rather than silently incomplete.
	Errors []string `json:"errors,omitempty"`
	// Stats records how much work was done, for tuning and for showing the
	// reader that an empty result means "we looked and found nothing".
	Stats Stats `json:"stats"`
}

// Stats summarises the work performed during a scan.
type Stats struct {
	DNSQueries   int `json:"dns_queries"`
	DNSCacheHits int `json:"dns_cache_hits"`
	HTTPRequests int `json:"http_requests"`
	Signatures   int `json:"signatures_evaluated"`
}

// FindingSet accumulates findings, merging duplicates as they arrive. It is not
// safe for concurrent use; the engine owns one and feeds it from a single
// collector goroutine.
type FindingSet struct {
	byVendor map[string]*Finding
	order    []string
}

// NewFindingSet returns an empty set.
func NewFindingSet() *FindingSet {
	return &FindingSet{byVendor: make(map[string]*Finding)}
}

// Add merges f into the set. When a vendor has already been seen, the evidence
// is appended and the confidence is promoted to the strongest observed. Two
// independent medium-confidence hits promote to high: corroboration across
// unrelated channels is exactly the signal we want to reward.
//
// Contested findings are the exception. Several tenants named after the same
// candidate are not independent corroboration — they are one unproven
// assumption about who owns that name, repeated per vendor. Confidence is
// therefore capped at medium for as long as every contributing match is
// contested, and the cap lifts the moment one domain-scoped match arrives.
func (s *FindingSet) Add(f Finding) {
	k := f.key()
	existing, ok := s.byVendor[k]
	if !ok {
		cp := f
		if cp.FirstSeen.IsZero() {
			cp.FirstSeen = time.Now().UTC()
		}
		if cp.ContestedNamespace && cp.Confidence == ConfidenceHigh {
			cp.Confidence = ConfidenceMedium
		}
		s.byVendor[k] = &cp
		s.order = append(s.order, k)
		return
	}

	before := len(existing.Evidence)
	for _, ev := range f.Evidence {
		if !hasEvidence(existing.Evidence, ev) {
			existing.Evidence = append(existing.Evidence, ev)
		}
	}
	for _, id := range f.Signatures {
		if !contains(existing.Signatures, id) {
			existing.Signatures = append(existing.Signatures, id)
		}
	}
	for _, n := range f.Notes {
		if !contains(existing.Notes, n) {
			existing.Notes = append(existing.Notes, n)
		}
	}
	if existing.Category == "" {
		existing.Category = f.Category
	}

	// A finding stays contested only while every contributor is contested. One
	// match that did not come from a candidate namespace settles ownership.
	existing.ContestedNamespace = existing.ContestedNamespace && f.ContestedNamespace

	if f.Confidence.Score() > existing.Confidence.Score() {
		existing.Confidence = f.Confidence
	}
	// Corroboration bonus: distinct evidence from a different method lifts a
	// medium finding to high.
	if existing.Confidence == ConfidenceMedium && len(existing.Evidence) > before &&
		distinctMethods(existing.Evidence) > 1 {
		existing.Confidence = ConfidenceHigh
	}
	// Applied last, so it overrides both the promotion above and any high-
	// confidence contested match that arrived on its own.
	if existing.ContestedNamespace && existing.Confidence == ConfidenceHigh {
		existing.Confidence = ConfidenceMedium
	}
}

// Findings returns the merged findings sorted by confidence (strongest first)
// then vendor name, which is the order every reporter renders them in.
func (s *FindingSet) Findings() []Finding {
	out := make([]Finding, 0, len(s.order))
	for _, k := range s.order {
		out = append(out, *s.byVendor[k])
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Confidence.Score() != out[j].Confidence.Score() {
			return out[i].Confidence.Score() > out[j].Confidence.Score()
		}
		return strings.ToLower(out[i].Vendor) < strings.ToLower(out[j].Vendor)
	})
	return out
}

// Len reports how many distinct vendors are in the set.
func (s *FindingSet) Len() int { return len(s.order) }

func distinctMethods(evs []Evidence) int {
	seen := make(map[Method]struct{}, len(evs))
	for _, e := range evs {
		seen[e.Method] = struct{}{}
	}
	return len(seen)
}

func hasEvidence(list []Evidence, e Evidence) bool {
	for _, x := range list {
		if x.Method == e.Method && x.Query == e.Query && x.Value == e.Value {
			return true
		}
	}
	return false
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// Truncate shortens s for display, appending an ellipsis when it was cut. Used
// to keep HTTP body snippets from flooding reports.
func Truncate(s string, n int) string {
	s = strings.TrimSpace(strings.Join(strings.Fields(s), " "))
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
