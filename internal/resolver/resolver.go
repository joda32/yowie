// Package resolver provides a concurrent, caching DNS client built on
// github.com/miekg/dns.
//
// It exists rather than using net.Resolver because shadow IT detection depends
// on distinctions the stdlib hides: NXDOMAIN versus an empty NOERROR answer,
// the full CNAME chain rather than just the final target, and TXT records
// reassembled correctly from their 255-byte chunks.
package resolver

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"
)

// DefaultServers are public resolvers chosen because they are unlikely to
// return the corporate split-horizon view that would mask externally visible
// records.
var DefaultServers = []string{"1.1.1.1:53", "8.8.8.8:53", "8.8.4.4:53"}

// Answer is a normalised DNS response.
type Answer struct {
	Name  string
	Qtype uint16
	Rcode int

	TXT   []string
	CNAME []string // the chain, in the order returned
	MX    []string
	A     []string
	NS    []string
}

// Exists reports whether the name exists at all. A false result means NXDOMAIN.
func (a *Answer) Exists() bool { return a.Rcode != dns.RcodeNameError }

// Values returns the records relevant to the question that was asked.
func (a *Answer) Values() []string {
	switch a.Qtype {
	case dns.TypeTXT:
		return a.TXT
	case dns.TypeCNAME:
		return a.CNAME
	case dns.TypeMX:
		return a.MX
	case dns.TypeA:
		return a.A
	case dns.TypeNS:
		return a.NS
	}
	return nil
}

// Empty reports whether the name resolved but carried no records of the
// requested type.
func (a *Answer) Empty() bool { return len(a.Values()) == 0 }

// Joined concatenates the answer's records into one lowercase string, which is
// what substring signatures are matched against.
func (a *Answer) Joined() string {
	return strings.ToLower(strings.Join(a.Values(), "|"))
}

// Fingerprint produces a stable identity for the answer, used to compare a
// candidate hostname against a known-nonexistent baseline. Values are sorted so
// that round-robin ordering does not register as a difference.
func (a *Answer) Fingerprint() string {
	if !a.Exists() {
		return "NXDOMAIN"
	}
	vals := append([]string(nil), a.Values()...)
	sort.Strings(vals)
	if len(vals) == 0 {
		return fmt.Sprintf("EMPTY/%d", a.Rcode)
	}
	return strings.ToLower(strings.Join(vals, ","))
}

// Resolver performs cached, rate-limited DNS lookups.
type Resolver struct {
	servers  []string
	attempts int

	udp *dns.Client
	tcp *dns.Client

	cache sync.Map // string -> *Answer
	group singleflight.Group
	sem   chan struct{}

	rr      atomic.Uint64
	queries atomic.Int64
	hits    atomic.Int64
}

// Options configures a Resolver.
type Options struct {
	// Servers is a list of "host:port" upstreams. Empty means DefaultServers.
	Servers []string
	// Timeout bounds a single query. Defaults to 3s.
	Timeout time.Duration
	// Attempts is the number of upstreams tried before giving up. Defaults to
	// the number of servers.
	Attempts int
	// Concurrency caps simultaneous in-flight queries. Defaults to 64.
	Concurrency int
}

// New builds a Resolver from opts.
func New(opts Options) *Resolver {
	servers := opts.Servers
	if len(servers) == 0 {
		servers = DefaultServers
	}
	servers = append([]string(nil), servers...)
	for i, s := range servers {
		if _, _, err := net.SplitHostPort(s); err != nil {
			servers[i] = net.JoinHostPort(s, "53")
		}
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	attempts := opts.Attempts
	if attempts <= 0 {
		attempts = len(servers)
	}
	conc := opts.Concurrency
	if conc <= 0 {
		conc = 64
	}

	return &Resolver{
		servers:  servers,
		attempts: attempts,
		udp:      &dns.Client{Net: "udp", Timeout: timeout},
		tcp:      &dns.Client{Net: "tcp", Timeout: timeout},
		sem:      make(chan struct{}, conc),
	}
}

// Stats reports how many queries were issued and how many were served from
// cache.
func (r *Resolver) Stats() (queries, cacheHits int) {
	return int(r.queries.Load()), int(r.hits.Load())
}

// Lookup resolves name for qtype. Results — including negative ones — are
// cached for the lifetime of the Resolver, which is one scan.
func (r *Resolver) Lookup(ctx context.Context, name string, qtype uint16) (*Answer, error) {
	fqdn := dns.Fqdn(strings.TrimSpace(strings.ToLower(name)))
	key := fmt.Sprintf("%d|%s", qtype, fqdn)

	if v, ok := r.cache.Load(key); ok {
		r.hits.Add(1)
		return v.(*Answer), nil
	}

	v, err, shared := r.group.Do(key, func() (any, error) {
		if v, ok := r.cache.Load(key); ok {
			r.hits.Add(1)
			return v, nil
		}
		ans, err := r.exchange(ctx, fqdn, qtype)
		if err != nil {
			return nil, err
		}
		r.cache.Store(key, ans)
		return ans, nil
	})
	if err != nil {
		return nil, err
	}
	if shared {
		// Detectors run concurrently, so identical lookups frequently collapse
		// into one in-flight query rather than hitting the cache. Those are
		// queries avoided just the same, and counting only cache hits made the
		// statistic read as zero on a healthy scan.
		r.hits.Add(1)
	}
	return v.(*Answer), nil
}

// TXT is a convenience wrapper returning the TXT records of name.
func (r *Resolver) TXT(ctx context.Context, name string) ([]string, error) {
	a, err := r.Lookup(ctx, name, dns.TypeTXT)
	if err != nil {
		return nil, err
	}
	return a.TXT, nil
}

func (r *Resolver) exchange(ctx context.Context, fqdn string, qtype uint16) (*Answer, error) {
	select {
	case r.sem <- struct{}{}:
		defer func() { <-r.sem }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	m := new(dns.Msg)
	m.SetQuestion(fqdn, qtype)
	m.RecursionDesired = true
	// A larger advertised buffer avoids truncation on TXT-heavy zones, which
	// are common on domains with many SaaS verification tokens.
	m.SetEdns0(4096, false)

	var lastErr error
	start := int(r.rr.Add(1))
	for i := 0; i < r.attempts; i++ {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		server := r.servers[(start+i)%len(r.servers)]

		r.queries.Add(1)
		resp, _, err := r.udp.ExchangeContext(ctx, m, server)
		if err == nil && resp != nil && resp.Truncated {
			// Fall back to TCP rather than silently working from a partial
			// record set.
			resp, _, err = r.tcp.ExchangeContext(ctx, m, server)
		}
		if err != nil {
			lastErr = err
			continue
		}
		if resp == nil {
			lastErr = errors.New("nil response")
			continue
		}
		switch resp.Rcode {
		case dns.RcodeSuccess, dns.RcodeNameError:
			return parse(fqdn, qtype, resp), nil
		case dns.RcodeServerFailure, dns.RcodeRefused:
			// Try the next upstream; one resolver failing does not mean the
			// name is unresolvable.
			lastErr = fmt.Errorf("%s: %s", server, dns.RcodeToString[resp.Rcode])
			continue
		default:
			return parse(fqdn, qtype, resp), nil
		}
	}
	return nil, fmt.Errorf("resolving %s %s: %w", strings.TrimSuffix(fqdn, "."), dns.TypeToString[qtype], lastErr)
}

func parse(fqdn string, qtype uint16, resp *dns.Msg) *Answer {
	a := &Answer{
		Name:  strings.TrimSuffix(fqdn, "."),
		Qtype: qtype,
		Rcode: resp.Rcode,
	}
	for _, rr := range resp.Answer {
		switch v := rr.(type) {
		case *dns.TXT:
			// Records over 255 bytes arrive as multiple chunks that must be
			// concatenated with no separator; SPF records in particular are
			// routinely split, and joining them wrongly breaks include parsing.
			a.TXT = append(a.TXT, strings.Join(v.Txt, ""))
		case *dns.CNAME:
			a.CNAME = append(a.CNAME, trimDot(v.Target))
		case *dns.MX:
			a.MX = append(a.MX, trimDot(v.Mx))
		case *dns.A:
			a.A = append(a.A, v.A.String())
		case *dns.AAAA:
			a.A = append(a.A, v.AAAA.String())
		case *dns.NS:
			a.NS = append(a.NS, trimDot(v.Ns))
		}
	}
	return a
}

func trimDot(s string) string { return strings.ToLower(strings.TrimSuffix(s, ".")) }

// RandomLabel returns an unpredictable DNS label used as a known-nonexistent
// baseline when probing for vanity tenants. It must not collide with a real
// tenant name, so it is random rather than a fixed string.
func RandomLabel() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand does not fail in practice; fall back to something that
		// is still very unlikely to be a real tenant.
		return "sq-nonexistent-baseline-x9f2"
	}
	return "sq" + hex.EncodeToString(b)
}
