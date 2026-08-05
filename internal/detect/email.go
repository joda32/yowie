package detect

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/joda32/yowie/internal/model"
	"github.com/joda32/yowie/internal/signature"
)

// spfMaxLookups is the RFC 7208 §4.6.4 ceiling on DNS-querying mechanisms.
// Honouring it keeps Yowie from following a malformed or hostile record
// into an unbounded walk, and mirrors what a real receiver would evaluate.
const spfMaxLookups = 10

// SPF walks the domain's SPF include graph and identifies every authorised
// sender.
//
// This is one of the richest shadow IT sources available externally: a team
// that signs up for a mail-sending SaaS almost always has to add an include to
// get delivery working, and unlike a verification token the include stays even
// after the trial ends. The legacy tool only substring-matched the top-level
// TXT bundle, so anything reached through a nested include was invisible.
type SPF struct{}

func (d *SPF) Name() string { return "spf" }

func (d *SPF) Run(ctx context.Context, s *Scan) error {
	s.Status("Walking SPF include graph for %s", s.Domain)

	root, err := spfRecord(ctx, s, s.Domain)
	if err != nil {
		s.Warn("spf: %v", err)
		return nil
	}
	if root == "" {
		return nil
	}

	senders := map[string]string{} // host -> mechanism that introduced it
	visited := map[string]bool{}
	lookups := 0
	d.walk(ctx, s, s.Domain, root, senders, visited, &lookups)

	if lookups > spfMaxLookups {
		s.Warn("spf: %s exceeds the RFC 7208 limit of %d DNS lookups (%d used); "+
			"receivers may reject the record and the walk was truncated",
			s.Domain, spfMaxLookups, lookups)
	}

	sigs := s.Sigs.ByType(signature.TypeSPFInclude)
	matched := map[string]bool{}

	for host, mech := range senders {
		for _, sig := range sigs {
			if !strings.Contains(host, sig.Match.Contains) {
				continue
			}
			matched[host] = true
			s.EmitSig(sig, sig.Confidence, model.Evidence{
				Method: model.MethodSPF,
				Query:  s.Domain,
				Value:  mech,
				Detail: "authorised sender in the SPF include graph",
			})
		}
	}

	if !s.ReportUnknown {
		return nil
	}
	// Anything authorised to send as the organisation but not recognised is
	// precisely what this tool exists to surface. Report it as a lead.
	var unknown []string
	for host := range senders {
		if !matched[host] && !sameOrg(host, s.Domain) {
			unknown = append(unknown, host)
		}
	}
	sort.Strings(unknown)
	for _, host := range unknown {
		s.Emit(model.Finding{
			Vendor:     host,
			Category:   "Unidentified sender",
			Confidence: model.ConfidenceLow,
			Notes: []string{"Authorised to send email as this domain but matches no known vendor signature. " +
				"Identify the owner; if it is a legitimate service, add a signature so future scans name it."},
			Evidence: []model.Evidence{{
				Method: model.MethodSPF,
				Query:  s.Domain,
				Value:  senders[host],
				Detail: "unrecognised sender in the SPF include graph",
			}},
		})
	}
	return nil
}

// walk recursively expands include: and redirect= mechanisms.
func (d *SPF) walk(ctx context.Context, s *Scan, origin, record string, senders map[string]string, visited map[string]bool, lookups *int) {
	if visited[origin] {
		return // include loop
	}
	visited[origin] = true

	for _, t := range spfTerms(record) {
		if *lookups > spfMaxLookups {
			return
		}
		if _, seen := senders[t.Host]; !seen {
			senders[t.Host] = t.Term
		}
		if !t.Recurse {
			continue
		}
		*lookups++
		nested, err := spfRecord(ctx, s, t.Host)
		if err != nil || nested == "" {
			continue
		}
		d.walk(ctx, s, t.Host, nested, senders, visited, lookups)
	}
}

// spfTerm is one host-bearing mechanism extracted from an SPF record.
type spfTerm struct {
	// Host is the normalised hostname the mechanism names.
	Host string
	// Term is the original term, quoted as evidence.
	Term string
	// Recurse marks include:/redirect=, which point at another SPF record.
	Recurse bool
}

// spfTerms extracts the host-bearing mechanisms from an SPF record.
//
// Kept free of I/O so the parsing rules — qualifiers, dual-CIDR suffixes,
// macros — are testable without a resolver.
func spfTerms(record string) []spfTerm {
	var out []spfTerm
	for _, term := range strings.Fields(record) {
		// Strip the optional qualifier (+ - ~ ?) that may prefix a mechanism.
		lower := strings.TrimLeft(strings.ToLower(term), "+-~?")

		var host string
		var recurse bool
		switch {
		case strings.HasPrefix(lower, "include:"):
			host, recurse = strings.TrimPrefix(lower, "include:"), true
		case strings.HasPrefix(lower, "redirect="):
			host, recurse = strings.TrimPrefix(lower, "redirect="), true
		case strings.HasPrefix(lower, "exists:"):
			host = strings.TrimPrefix(lower, "exists:")
		case strings.HasPrefix(lower, "a:"):
			host = strings.TrimPrefix(lower, "a:")
		case strings.HasPrefix(lower, "mx:"):
			host = strings.TrimPrefix(lower, "mx:")
		case strings.HasPrefix(lower, "ptr:"):
			host = strings.TrimPrefix(lower, "ptr:")
		default:
			continue // ip4:, ip6:, a, mx, all, v=spf1, unknown modifiers
		}

		host = strings.Trim(host, "\"'")
		// a: and mx: may carry a dual-CIDR suffix, e.g. "a:mail.example.com/24".
		if i := strings.Index(host, "/"); i >= 0 {
			host = host[:i]
		}
		host = strings.TrimSuffix(host, ".")

		// Macros (%{d} and friends) are not expanded; the literal text is not
		// a stable vendor identifier.
		if host == "" || strings.Contains(host, "%") {
			continue
		}
		out = append(out, spfTerm{Host: host, Term: term, Recurse: recurse})
	}
	return out
}

// spfRecord returns the domain's SPF record, or "" if it publishes none.
func spfRecord(ctx context.Context, s *Scan, domain string) (string, error) {
	txts, err := s.Resolver.TXT(ctx, domain)
	if err != nil {
		return "", err
	}
	for _, t := range txts {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(t)), "v=spf1") {
			return t, nil
		}
	}
	return "", nil
}

// DMARC identifies whoever receives the domain's DMARC aggregate and forensic
// reports. A third-party rua destination is a live subscription to a DMARC
// monitoring platform.
type DMARC struct{}

func (d *DMARC) Name() string { return "dmarc" }

func (d *DMARC) Run(ctx context.Context, s *Scan) error {
	name := "_dmarc." + s.Domain
	s.Status("Resolving DMARC policy for %s", s.Domain)

	txts, err := s.Resolver.TXT(ctx, name)
	if err != nil {
		s.Warn("dmarc: %v", err)
		return nil
	}

	var record string
	for _, t := range txts {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(t)), "v=dmarc1") {
			record = t
			break
		}
	}
	if record == "" {
		return nil
	}

	hosts := map[string]string{} // report host -> the URI it came from
	for _, tag := range strings.Split(record, ";") {
		tag = strings.TrimSpace(tag)
		lower := strings.ToLower(tag)
		if !strings.HasPrefix(lower, "rua=") && !strings.HasPrefix(lower, "ruf=") {
			continue
		}
		for _, uri := range strings.Split(tag[4:], ",") {
			uri = strings.TrimSpace(uri)
			addr := strings.TrimPrefix(strings.ToLower(uri), "mailto:")
			// A destination may carry a size limit suffix, e.g. "!10m".
			if i := strings.Index(addr, "!"); i >= 0 {
				addr = addr[:i]
			}
			at := strings.LastIndex(addr, "@")
			if at < 0 {
				continue
			}
			if host := addr[at+1:]; host != "" {
				hosts[host] = uri
			}
		}
	}

	sigs := s.Sigs.ByType(signature.TypeDMARCRUA)
	for host, uri := range hosts {
		var matched bool
		for _, sig := range sigs {
			if !strings.Contains(host, sig.Match.Contains) {
				continue
			}
			matched = true
			s.EmitSig(sig, sig.Confidence, model.Evidence{
				Method: model.MethodDMARC,
				Query:  name,
				Value:  uri,
				Detail: "receives this domain's DMARC reports",
			})
		}
		if matched || sameOrg(host, s.Domain) || !s.ReportUnknown {
			continue
		}
		s.Emit(model.Finding{
			Vendor:     host,
			Category:   "Unidentified sender",
			Confidence: model.ConfidenceLow,
			Notes:      []string{"Receives DMARC reports for this domain but matches no known vendor signature."},
			Evidence: []model.Evidence{{
				Method: model.MethodDMARC,
				Query:  name,
				Value:  uri,
				Detail: "unrecognised DMARC report destination",
			}},
		})
	}
	return nil
}

// BIMI reports a published BIMI record. The logo and certificate URLs it
// carries are usually hosted by whoever manages the organisation's brand
// indicator, and the presence of a VMC implies a paid certificate.
type BIMI struct{}

func (d *BIMI) Name() string { return "bimi" }

func (d *BIMI) Run(ctx context.Context, s *Scan) error {
	name := "default._bimi." + s.Domain
	txts, err := s.Resolver.TXT(ctx, name)
	if err != nil {
		return nil // absence is the norm; not worth a warning
	}
	for _, t := range txts {
		if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(t)), "v=bimi1") {
			continue
		}
		for _, host := range urlHosts(t) {
			if sameOrg(host, s.Domain) {
				continue
			}
			s.Emit(model.Finding{
				Vendor:     host,
				Category:   "Brand & Certificates",
				Confidence: model.ConfidenceLow,
				Notes:      []string{"Hosts this domain's BIMI logo or Verified Mark Certificate."},
				Evidence: []model.Evidence{{
					Method: model.MethodBIMI,
					Query:  name,
					Value:  model.Truncate(t, 200),
				}},
			})
		}
	}
	return nil
}

// MTASTS reports an MTA-STS policy and the mail hosts it authorises, which name
// the mail platform even when MX records are hidden behind a gateway.
type MTASTS struct{}

func (d *MTASTS) Name() string { return "mta-sts" }

func (d *MTASTS) Run(ctx context.Context, s *Scan) error {
	txts, err := s.Resolver.TXT(ctx, "_mta-sts."+s.Domain)
	if err != nil {
		return nil
	}
	var found bool
	for _, t := range txts {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(t)), "v=stsv1") {
			found = true
			break
		}
	}
	if !found {
		return nil
	}

	policyURL := fmt.Sprintf("https://mta-sts.%s/.well-known/mta-sts.txt", s.Domain)
	s.Status("Fetching MTA-STS policy for %s", s.Domain)

	resp, err := s.HTTP.Get(ctx, policyURL)
	if err != nil || resp.Status != 200 {
		s.Warn("mta-sts: %s advertises a policy that could not be fetched", s.Domain)
		return nil
	}

	// The policy lists the MX patterns the domain accepts mail on. Feed them
	// through the MX signatures so the mail platform is named consistently.
	sigs := s.Sigs.ByType(signature.TypeMX)
	body := strings.ToLower(resp.Body)
	for _, sig := range sigs {
		if !strings.Contains(body, sig.Match.Contains) {
			continue
		}
		s.EmitSig(sig, sig.Confidence, model.Evidence{
			Method: model.MethodMTASTS,
			Query:  policyURL,
			Value:  model.Truncate(matchingLine(resp.Body, sig.Match.Contains), 160),
			Detail: "authorised mail host in the MTA-STS policy",
		})
	}
	return nil
}

// urlHosts extracts the hostnames of any http(s) URLs appearing in s.
func urlHosts(s string) []string {
	var out []string
	seen := map[string]bool{}
	for _, field := range strings.FieldsFunc(s, func(r rune) bool {
		return r == ' ' || r == ';' || r == '\t' || r == '"'
	}) {
		i := strings.Index(field, "https://")
		if i < 0 {
			i = strings.Index(field, "http://")
		}
		if i < 0 {
			continue
		}
		rest := field[i:]
		rest = strings.TrimPrefix(strings.TrimPrefix(rest, "https://"), "http://")
		if j := strings.IndexAny(rest, "/?#"); j >= 0 {
			rest = rest[:j]
		}
		rest = strings.ToLower(strings.TrimSpace(rest))
		if rest != "" && !seen[rest] {
			seen[rest] = true
			out = append(out, rest)
		}
	}
	return out
}

// matchingLine returns the line of body containing needle.
func matchingLine(body, needle string) string {
	for _, line := range strings.Split(body, "\n") {
		if strings.Contains(strings.ToLower(line), needle) {
			return strings.TrimSpace(line)
		}
	}
	return model.Truncate(body, 160)
}
