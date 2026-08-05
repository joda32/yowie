// Package detect contains the discovery logic: each Detector examines one class
// of externally observable signal and reports the SaaS vendors it implies.
package detect

import (
	"context"
	"fmt"
	"strings"

	"github.com/joda32/yowie/internal/model"
	"github.com/joda32/yowie/internal/resolver"
	"github.com/joda32/yowie/internal/signature"
	"github.com/joda32/yowie/internal/webclient"
)

// Scan carries everything a detector needs for one organisation.
type Scan struct {
	// Domain is the organisation's root domain, e.g. "acme.com.au".
	Domain string
	// Candidates are the short strings a vendor tenant might be named after,
	// e.g. "acme", "acmecorp". Vanity and HTTP detectors iterate over these.
	Candidates []string

	Resolver *resolver.Resolver
	HTTP     *webclient.Client
	Sigs     *signature.Set

	// ReportUnknown controls whether senders and hosts that match no signature
	// are reported as leads. This is the point of the tool for shadow IT work,
	// so it defaults on, but it is the noisiest output.
	ReportUnknown bool

	emit   func(model.Finding)
	warn   func(string)
	status func(string)
}

// NewScan builds a Scan with the given sinks. emit receives findings, warn
// receives non-fatal problems, and status receives progress lines.
func NewScan(domain string, candidates []string, emit func(model.Finding), warn func(string), status func(string)) *Scan {
	return &Scan{
		Domain:     domain,
		Candidates: candidates,
		emit:       emit,
		warn:       warn,
		status:     status,
	}
}

// Emit records a finding.
func (s *Scan) Emit(f model.Finding) {
	if s.emit != nil {
		s.emit(f)
	}
}

// EmitSig records a finding derived from a signature, copying the vendor
// metadata across so detectors do not each repeat it.
func (s *Scan) EmitSig(sig signature.Signature, conf model.Confidence, ev ...model.Evidence) {
	f := model.Finding{
		Vendor:     sig.Vendor,
		Category:   sig.Category,
		Confidence: conf,
		Signatures: []string{sig.ID},
		Evidence:   ev,
	}
	if sig.Notes != "" {
		f.Notes = []string{sig.Notes}
	}
	s.Emit(f)
}

// Warn records a non-fatal problem. Warnings appear in the report so that a
// partial scan is never mistaken for a complete one.
func (s *Scan) Warn(format string, args ...any) {
	if s.warn != nil {
		s.warn(fmt.Sprintf(format, args...))
	}
}

// Status reports progress for the interactive CLI.
func (s *Scan) Status(format string, args ...any) {
	if s.status != nil {
		s.status(fmt.Sprintf(format, args...))
	}
}

// Detector examines one class of signal.
type Detector interface {
	// Name is shown in progress output and in --only/--skip selectors.
	Name() string
	// Run executes the detector. Returning an error aborts only this detector;
	// the rest of the scan continues.
	Run(ctx context.Context, s *Scan) error
}

// All returns every detector in the order they should be started.
func All() []Detector {
	return []Detector{
		&DNSRecords{},
		&Vanity{},
		&HTTPEndpoints{},
		&SPF{},
		&DMARC{},
		&BIMI{},
		&MTASTS{},
		&Tenant{},
		&CertTransparency{},
	}
}

// expandQueries returns the concrete queries a signature produces for this
// scan: one per candidate when the template references {candidate}, otherwise
// a single query.
func (s *Scan) expandQueries(sig signature.Signature) []expansion {
	if !sig.NeedsCandidate() {
		return []expansion{{Query: signature.Expand(sig.Query, s.Domain, "")}}
	}
	out := make([]expansion, 0, len(s.Candidates))
	for _, c := range s.Candidates {
		out = append(out, expansion{
			Query:     signature.Expand(sig.Query, s.Domain, c),
			Candidate: c,
		})
	}
	return out
}

type expansion struct {
	Query     string
	Candidate string
}

// AttributeHost names the vendor behind an arbitrary hostname by testing it
// against the cname_target signatures.
//
// Those signatures map hosting suffixes to vendors, and that mapping is useful
// well beyond the CT detector that motivated it: any detector holding a bare
// hostname can report a product name rather than the raw host.
func (s *Scan) AttributeHost(host string) (signature.Signature, bool) {
	if s.Sigs == nil {
		return signature.Signature{}, false
	}
	for _, sig := range s.Sigs.ByType(signature.TypeCNAMETarget) {
		if hostMatchesSuffix(host, sig.Query) {
			return sig, true
		}
	}
	return signature.Signature{}, false
}

// sameOrg reports whether host belongs to the scanned organisation, used to
// decide whether a mail or report destination is third-party. It is a
// heuristic, not a public-suffix lookup: it asks only whether host is the
// domain or a subdomain of it.
func sameOrg(host, domain string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	return host == domain || strings.HasSuffix(host, "."+domain)
}
