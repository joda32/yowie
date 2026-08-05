package detect

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/joda32/yowie/internal/model"
	"github.com/joda32/yowie/internal/signature"
	"github.com/joda32/yowie/internal/webclient"
	"github.com/miekg/dns"
	"golang.org/x/sync/errgroup"
)

// DefaultCTLimit caps how many discovered hostnames are resolved. Large
// organisations have thousands of logged certificates and the long tail is
// mostly expired staging hosts.
const DefaultCTLimit = 400

// CertTransparency finds subdomains in public Certificate Transparency logs and
// identifies what they point at.
//
// This is the channel the legacy tool had no equivalent of, and it inverts the
// discovery model. Every other check asks "does this organisation use vendor
// X?" against a fixed list, so it can only find vendors somebody already wrote
// a signature for. CT asks "what has this organisation actually pointed its
// subdomains at?" — which surfaces vendors nobody thought to look for, and that
// is exactly where unsanctioned services hide.
//
// A team that signs up for a SaaS product and wires up support.acme.com gets a
// certificate issued, and that certificate is public and permanent.
type CertTransparency struct {
	// Limit overrides DefaultCTLimit.
	Limit int
	// Timeout overrides ctTimeout for the crt.sh query.
	Timeout time.Duration

	once   sync.Once
	client *webclient.Client
}

// ctTimeout is deliberately far longer than the general HTTP timeout. CT
// aggregators run the query against a very large database and routinely take
// 30 seconds or more; the default 10s budget fails almost every time.
const ctTimeout = 60 * time.Second

func (d *CertTransparency) Name() string { return "ct" }

// httpClient returns a client configured for CT aggregators specifically:
// patient, and limited to one request at a time so a free public service is not
// hammered. It shares the scan's request counter so its traffic still shows up
// in the statistics.
func (d *CertTransparency) httpClient(s *Scan) *webclient.Client {
	d.once.Do(func() {
		timeout := d.Timeout
		if timeout <= 0 {
			timeout = ctTimeout
		}
		// One slot per aggregator, so the sources run in parallel rather than
		// serialising two long timeouts, while still issuing only one request
		// to each free service.
		d.client = s.HTTP.Derive(webclient.Options{Timeout: timeout, Concurrency: len(ctSources)})
	})
	return d.client
}

func (d *CertTransparency) Run(ctx context.Context, s *Scan) error {
	limit := d.Limit
	if limit <= 0 {
		limit = DefaultCTLimit
	}

	hosts, err := d.fetch(ctx, s)
	if err != nil {
		// crt.sh is frequently slow or unavailable. Degrading loudly is better
		// than silently reporting fewer findings.
		s.Warn("ct: %v. Subdomain discovery was skipped, so this scan covers less ground than usual — "+
			"the other detectors only find vendors that already have a signature.", err)
		return nil
	}
	if len(hosts) == 0 {
		return nil
	}

	if total := len(hosts); total > limit {
		hosts = hosts[:limit]
		// The list is sorted, so truncation is not a random sample — it keeps
		// early-alphabet hostnames and drops the rest. Say so, because a
		// silently biased subset looks the same as full coverage in the output.
		s.Warn("ct: %s has %d logged hostnames but -ct-limit is %d, so %d were dropped. "+
			"Selection is alphabetical, not a sample, so the tail of the alphabet was not looked at — "+
			"raise -ct-limit for full coverage",
			s.Domain, total, limit, total-limit)
	}
	s.Status("Resolving %d hostnames from certificate transparency logs", len(hosts))

	sigs := s.Sigs.ByType(signature.TypeCNAMETarget)

	type hit struct {
		host, target string
	}
	var (
		unknown []hit
		mu      sync.Mutex
	)

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(32)

	for _, host := range hosts {
		g.Go(func() error {
			ans, err := s.Resolver.Lookup(gctx, host, dns.TypeCNAME)
			if err != nil || !ans.Exists() || len(ans.CNAME) == 0 {
				return nil
			}
			target := ans.CNAME[len(ans.CNAME)-1]
			if sameOrg(target, s.Domain) {
				return nil // internal alias, not a third party
			}

			var matched bool
			for _, sig := range sigs {
				if !hostMatchesSuffix(target, sig.Query) {
					continue
				}
				matched = true
				s.EmitSig(sig, sig.Confidence, model.Evidence{
					Method: model.MethodCT,
					Query:  host,
					Value:  target,
					Detail: "subdomain found in certificate transparency logs points at this vendor",
				})
			}
			if !matched && s.ReportUnknown {
				mu.Lock()
				unknown = append(unknown, hit{host: host, target: target})
				mu.Unlock()
			}
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return err
	}

	// Group unrecognised targets by their registrable-ish suffix so a vendor
	// hosting twenty subdomains produces one lead, not twenty.
	byProvider := map[string][]hit{}
	for _, h := range unknown {
		byProvider[providerKey(h.target)] = append(byProvider[providerKey(h.target)], h)
	}
	providers := make([]string, 0, len(byProvider))
	for p := range byProvider {
		providers = append(providers, p)
	}
	sort.Strings(providers)

	for _, p := range providers {
		hits := byProvider[p]
		ev := make([]model.Evidence, 0, len(hits))
		for _, h := range hits[:min(len(hits), 5)] {
			ev = append(ev, model.Evidence{
				Method: model.MethodCT,
				Query:  h.host,
				Value:  h.target,
				Detail: "unrecognised third-party host",
			})
		}
		note := fmt.Sprintf("%d subdomain(s) point at %s, which matches no known vendor signature.", len(hits), p)
		s.Emit(model.Finding{
			Vendor:     p,
			Category:   "Unidentified host",
			Confidence: model.ConfidenceLow,
			Notes: []string{note + " Identify the service; if it is legitimate, add a cname_target " +
				"signature so future scans name it."},
			Evidence: ev,
		})
	}
	return nil
}

// ctSource is one Certificate Transparency aggregator.
type ctSource struct {
	name string
	// url builds the query URL for a domain.
	url func(domain string) string
	// parse turns a response body into hostnames under domain.
	parse func(body, domain string) ([]string, error)
}

// ctSources are tried in order. crt.sh is richer but is frequently overloaded
// or returning 502s, so Cert Spotter backs it up; between them the channel is
// usually available, which matters because it is the only detector that finds
// vendors nobody wrote a signature for.
var ctSources = []ctSource{
	{
		name: "crt.sh",
		url: func(d string) string {
			return "https://crt.sh/?q=" + url.QueryEscape("%."+d) + "&output=json&exclude=expired"
		},
		parse: parseCrtSh,
	},
	{
		name: "Cert Spotter",
		url: func(d string) string {
			return "https://api.certspotter.com/v1/issuances?domain=" + url.QueryEscape(d) +
				"&include_subdomains=true&expand=dns_names"
		},
		parse: parseCertSpotter,
	},
}

// ctResult is one aggregator's answer.
type ctResult struct {
	source string
	hosts  []string
	err    error
}

// fetch queries every CT aggregator and returns the union of what they report.
//
// This used to stop at the first source that answered, which silently traded
// away coverage: the aggregators do not hold the same data, and on a measured
// comparison the secondary returned 154 hostnames where the primary returned
// 434 — a strict subset. A scan that fell back therefore searched a third of
// the estate while reporting nothing worse than "fell back", which reads like a
// successful failover rather than the coverage loss it was.
//
// Querying both and merging is strictly better: more hostnames when both
// answer, and the same resilience when one does not.
func (d *CertTransparency) fetch(ctx context.Context, s *Scan) ([]string, error) {
	s.Status("Querying certificate transparency logs for %s", s.Domain)

	results := make([]ctResult, len(ctSources))
	var wg sync.WaitGroup
	for i, src := range ctSources {
		wg.Add(1)
		go func() {
			defer wg.Done()
			hosts, err := d.query(ctx, s, src)
			results[i] = ctResult{source: src.name, hosts: hosts, err: err}
		}()
	}
	wg.Wait()

	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	merged, contributed, failures := mergeCTResults(results)

	if len(merged) == 0 {
		return nil, fmt.Errorf("every source failed (%s)", strings.Join(failures, "; "))
	}
	if len(failures) > 0 {
		// Say what was lost, not merely that something failed.
		s.Warn("ct: %s unavailable (%s); merged %d hostnames from %s alone, so coverage is lower than a healthy run",
			pluralise(len(failures), "source", "sources"), strings.Join(failures, "; "),
			len(merged), strings.Join(contributed, " and "))
	} else {
		s.Status("Merged %d hostnames from %s", len(merged), strings.Join(contributed, " and "))
	}
	return merged, nil
}

// query runs one aggregator and returns the hostnames it reports.
func (d *CertTransparency) query(ctx context.Context, s *Scan, src ctSource) ([]string, error) {
	resp, err := d.httpClient(s).Get(ctx, src.url(s.Domain))
	if err != nil {
		return nil, err
	}
	if resp.Status != 200 {
		return nil, fmt.Errorf("%s", ctFailureReason(resp.Status, resp.Body))
	}
	hosts, err := src.parse(resp.Body, s.Domain)
	if err != nil {
		return nil, err
	}
	if len(hosts) == 0 {
		return nil, fmt.Errorf("no hostnames returned")
	}
	return hosts, nil
}

// mergeCTResults unions the hostnames each source reported, and describes what
// each contributed so a reader can tell a full run from a degraded one.
//
// Kept free of I/O so the merge and its reporting are testable.
func mergeCTResults(results []ctResult) (merged, contributed, failures []string) {
	seen := map[string]bool{}
	for _, r := range results {
		if r.err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", r.source, r.err))
			continue
		}
		added := 0
		for _, h := range r.hosts {
			if !seen[h] {
				seen[h] = true
				merged = append(merged, h)
				added++
			}
		}
		contributed = append(contributed, fmt.Sprintf("%s (%d, %d new)", r.source, len(r.hosts), added))
	}
	sort.Strings(merged)
	return merged, contributed, failures
}

func pluralise(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// ctFailureReason turns a non-200 CT response into something a reader can act
// on.
//
// The aggregators return a JSON error body explaining themselves, and the
// distinction matters: a server-side query timeout is not fixed by raising the
// client timeout, and being rate limited calls for waiting rather than
// retrying. Reporting a bare status code sent people down the wrong path.
func ctFailureReason(status int, body string) string {
	var e struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal([]byte(body), &e); err == nil && e.Code != "" {
		switch e.Code {
		case "timeout":
			return fmt.Sprintf("HTTP %d, the service timed out running the query server-side "+
				"(the domain has too many certificates for its budget) — raising -ct-timeout will not help", status)
		case "rate_limited":
			return fmt.Sprintf("HTTP %d, rate limited — wait before retrying", status)
		}
		return fmt.Sprintf("HTTP %d, %s", status, model.Truncate(e.Message, 120))
	}
	return fmt.Sprintf("HTTP %d", status)
}

// parseCrtSh reads crt.sh's JSON array.
func parseCrtSh(body, domain string) ([]string, error) {
	var entries []struct {
		NameValue  string `json:"name_value"`
		CommonName string `json:"common_name"`
	}
	if err := json.Unmarshal([]byte(body), &entries); err != nil {
		return nil, fmt.Errorf("response was not valid JSON (the service is likely rate limiting): %w", err)
	}

	c := newHostCollector(domain)
	for _, e := range entries {
		// name_value packs a certificate's SANs into one newline-separated
		// string rather than a list.
		for _, n := range strings.Split(e.NameValue, "\n") {
			c.add(n)
		}
		c.add(e.CommonName)
	}
	return c.hosts(), nil
}

// parseCertSpotter reads Cert Spotter's JSON array.
func parseCertSpotter(body, domain string) ([]string, error) {
	var entries []struct {
		DNSNames []string `json:"dns_names"`
	}
	if err := json.Unmarshal([]byte(body), &entries); err != nil {
		return nil, fmt.Errorf("response was not valid JSON (the free tier may be rate limiting): %w", err)
	}

	c := newHostCollector(domain)
	for _, e := range entries {
		for _, n := range e.DNSNames {
			c.add(n)
		}
	}
	return c.hosts(), nil
}

// hostCollector normalises and deduplicates hostnames, keeping only those under
// the scanned domain — both aggregators can return neighbouring names.
type hostCollector struct {
	suffix string
	domain string
	seen   map[string]bool
	out    []string
}

func newHostCollector(domain string) *hostCollector {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	return &hostCollector{
		suffix: "." + domain,
		domain: domain,
		seen:   map[string]bool{},
	}
}

func (c *hostCollector) add(name string) {
	name = strings.ToLower(strings.TrimSpace(name))
	// A wildcard certificate names the parent, which is what we want to probe.
	name = strings.TrimPrefix(name, "*.")
	name = strings.TrimSuffix(name, ".")
	if name == "" || c.seen[name] {
		return
	}
	if name != c.domain && !strings.HasSuffix(name, c.suffix) {
		return
	}
	c.seen[name] = true
	c.out = append(c.out, name)
}

func (c *hostCollector) hosts() []string {
	sort.Strings(c.out)
	return c.out
}

// hostMatchesSuffix reports whether host sits under the given hosting suffix.
//
// Matching is on a label boundary, so "notzendesk.com" never matches
// "zendesk.com". A "*" in the suffix is a glob confined to a single label,
// which covers the two shapes vendors actually use:
//
//   - a whole variable label, as in "execute-api.*.amazonaws.com", which has to
//     match every AWS region without enumerating them;
//   - a generated name within a label, as in "mkto-*.com", where Marketo mints
//     a per-customer tracking domain such as mkto-sj180011.com.
//
// The glob never spans a dot, so a pattern can never widen beyond the label it
// was written for.
func hostMatchesSuffix(host, suffix string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	suffix = strings.ToLower(strings.TrimSuffix(suffix, "."))

	if !strings.Contains(suffix, "*") {
		return host == suffix || strings.HasSuffix(host, "."+suffix)
	}

	hostLabels := strings.Split(host, ".")
	suffixLabels := strings.Split(suffix, ".")
	if len(hostLabels) < len(suffixLabels) {
		return false
	}
	// Compare the suffix against the trailing labels of the host.
	tail := hostLabels[len(hostLabels)-len(suffixLabels):]
	for i, want := range suffixLabels {
		// path.Match treats "*" as matching any run of non-separator bytes, and
		// a DNS label contains no "/", so the glob is naturally label-bound.
		ok, err := path.Match(want, tail[i])
		if err != nil || !ok {
			return false
		}
	}
	return true
}

// providerKey reduces a hostname to the last three labels, or two when the
// third looks like a country-code second-level domain. It groups related hosts
// without shipping a public suffix list.
func providerKey(host string) string {
	parts := strings.Split(strings.ToLower(strings.TrimSuffix(host, ".")), ".")
	if len(parts) <= 2 {
		return host
	}
	// e.g. foo.example.com.au -> example.com.au
	if len(parts) >= 3 && len(parts[len(parts)-1]) == 2 && len(parts[len(parts)-2]) <= 3 {
		if len(parts) >= 3 {
			return strings.Join(parts[len(parts)-3:], ".")
		}
	}
	return strings.Join(parts[len(parts)-2:], ".")
}
