package detect

import (
	"context"
	"fmt"
	"strings"

	"github.com/joda32/yowie/internal/model"
	"github.com/joda32/yowie/internal/resolver"
	"github.com/joda32/yowie/internal/signature"
	"github.com/miekg/dns"
	"golang.org/x/sync/errgroup"
)

// DNSRecords evaluates the substring-matching DNS signature types: TXT, CNAME,
// MX and NS.
//
// Signatures are grouped by the name they resolve so each distinct name is
// looked up exactly once and then tested against every signature that targets
// it. The legacy tool re-resolved the root domain once per non-matching TXT
// signature — roughly sixty redundant queries per scan.
type DNSRecords struct{}

func (d *DNSRecords) Name() string { return "dns" }

// dnsGroup is the set of signatures sharing one (name, record type) lookup.
type dnsGroup struct {
	name  string
	qtype uint16
	sigs  []signature.Signature
}

func (d *DNSRecords) Run(ctx context.Context, s *Scan) error {
	types := map[signature.Type]uint16{
		signature.TypeTXT:   dns.TypeTXT,
		signature.TypeCNAME: dns.TypeCNAME,
		signature.TypeMX:    dns.TypeMX,
		signature.TypeNS:    dns.TypeNS,
	}

	// Key on "qtype|name" so a domain queried for both TXT and MX stays as two
	// groups, while twenty TXT signatures against the root collapse into one.
	index := map[string]*dnsGroup{}
	var order []string

	for sigType, qtype := range types {
		for _, sig := range s.Sigs.ByType(sigType) {
			for _, ex := range s.expandQueries(sig) {
				name := strings.TrimSuffix(strings.ToLower(ex.Query), ".")
				if name == "" {
					continue
				}
				key := fmt.Sprintf("%d|%s", qtype, name)
				g, ok := index[key]
				if !ok {
					g = &dnsGroup{name: name, qtype: qtype}
					index[key] = g
					order = append(order, key)
				}
				g.sigs = append(g.sigs, sig)
			}
		}
	}

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(32)

	for _, key := range order {
		grp := index[key]
		g.Go(func() error {
			s.Status("Resolving %s %s", dns.TypeToString[grp.qtype], grp.name)

			ans, err := s.Resolver.Lookup(gctx, grp.name, grp.qtype)
			if err != nil {
				// A single unresolvable name is expected during a broad sweep
				// and must not abort the scan.
				s.Warn("dns: %v", err)
				return nil
			}
			if !ans.Exists() || ans.Empty() {
				return nil
			}

			method := methodFor(grp.qtype)
			joined := ans.Joined()

			for _, sig := range grp.sigs {
				if !strings.Contains(joined, sig.Match.Contains) {
					continue
				}
				s.EmitSig(sig, sig.Confidence, model.Evidence{
					Method: method,
					Query:  grp.name,
					Value:  model.Truncate(matchingRecord(ans.Values(), sig.Match.Contains), 200),
				})
			}
			return nil
		})
	}
	return g.Wait()
}

func methodFor(qtype uint16) model.Method {
	switch qtype {
	case dns.TypeTXT:
		return model.MethodTXT
	case dns.TypeCNAME:
		return model.MethodCNAME
	case dns.TypeMX:
		return model.MethodMX
	case dns.TypeNS:
		return model.MethodNameserver
	case dns.TypeA:
		return model.MethodA
	}
	return model.Method(dns.TypeToString[qtype])
}

// matchingRecord returns the individual record that contained the needle, so
// evidence quotes the one relevant record rather than every TXT record on a
// busy domain.
func matchingRecord(values []string, needle string) string {
	for _, v := range values {
		if strings.Contains(strings.ToLower(v), needle) {
			return v
		}
	}
	return strings.Join(values, " | ")
}

// baselineFingerprint resolves two random labels under the same parent to learn
// how the vendor answers for a tenant that does not exist.
//
// Two probes rather than one because some vendors answer from geo-distributed
// or round-robin infrastructure. If the two baselines disagree, no
// candidate-versus-baseline comparison can be trusted and the template is
// skipped rather than reported as a false positive.
func baselineFingerprint(ctx context.Context, s *Scan, template string, qtype uint16) (fp string, stable bool) {
	first := signature.Expand(template, s.Domain, resolver.RandomLabel())
	second := signature.Expand(template, s.Domain, resolver.RandomLabel())

	a1, err := s.Resolver.Lookup(ctx, first, qtype)
	if err != nil {
		return "", false
	}
	a2, err := s.Resolver.Lookup(ctx, second, qtype)
	if err != nil {
		return "", false
	}
	if a1.Fingerprint() != a2.Fingerprint() {
		return "", false
	}
	return a1.Fingerprint(), true
}
