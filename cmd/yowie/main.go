// Command yowie discovers the SaaS services an organisation subscribes to,
// using only externally observable data.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/joda32/yowie/internal/detect"
	"github.com/joda32/yowie/internal/engine"
	"github.com/joda32/yowie/internal/report"
	"github.com/joda32/yowie/internal/resolver"
	"github.com/joda32/yowie/internal/signature"
	"github.com/joda32/yowie/internal/webclient"
	"github.com/joda32/yowie/signatures"
)

// version is overridden at build time with -ldflags "-X main.version=...".
var version = "dev"

type options struct {
	format      string
	output      string
	sigDir      string
	nameservers string
	only        string
	skip        string
	ctLimit     int
	ctTimeout   time.Duration
	maxEvidence int
	dnsTimeout  time.Duration
	httpTimeout time.Duration
	scanTimeout time.Duration
	dnsConc     int
	httpConc    int
	compact     bool
	noEvidence  bool
	noBanner    bool
	noColour    bool
	noUnknown   bool
	warnings    bool
	insecureTLS bool
	quiet       bool
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "yowie: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var opts options

	fs := flag.NewFlagSet("yowie", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() { usage(fs) }

	fs.StringVar(&opts.format, "format", "cli", "output format: cli, json, jsonl, csv, html")
	fs.StringVar(&opts.output, "o", "", "write output to a file instead of stdout")
	fs.StringVar(&opts.sigDir, "signatures", "", "load signature packs from this directory instead of the embedded set")
	fs.StringVar(&opts.nameservers, "nameservers", "", "comma-separated DNS servers (default 1.1.1.1, 8.8.8.8, 8.8.4.4)")
	fs.StringVar(&opts.only, "only", "", "run only these detectors (comma-separated)")
	fs.StringVar(&opts.skip, "skip", "", "skip these detectors (comma-separated)")
	fs.IntVar(&opts.ctLimit, "ct-limit", detect.DefaultCTLimit, "maximum hostnames to resolve from certificate transparency logs")
	fs.DurationVar(&opts.ctTimeout, "ct-timeout", 60*time.Second, "timeout for the crt.sh query, which is often slow")
	fs.DurationVar(&opts.dnsTimeout, "dns-timeout", 3*time.Second, "per-query DNS timeout")
	fs.DurationVar(&opts.httpTimeout, "http-timeout", 10*time.Second, "per-request HTTP timeout")
	fs.DurationVar(&opts.scanTimeout, "timeout", 5*time.Minute, "overall scan timeout (0 for none)")
	fs.IntVar(&opts.dnsConc, "dns-concurrency", 64, "maximum concurrent DNS queries")
	fs.IntVar(&opts.httpConc, "http-concurrency", 16, "maximum concurrent HTTP requests")
	fs.BoolVar(&opts.compact, "compact", false, "one line per finding, in the original tool's style")
	fs.BoolVar(&opts.noEvidence, "no-evidence", false, "omit supporting records from terminal output")
	fs.IntVar(&opts.maxEvidence, "max-evidence", report.DefaultMaxEvidence, "evidence lines shown per finding in terminal output (0 for all)")
	fs.BoolVar(&opts.noBanner, "no-banner", false, "suppress the banner")
	fs.BoolVar(&opts.noColour, "no-color", false, "disable ANSI colour")
	fs.BoolVar(&opts.noUnknown, "no-unknown", false, "omit unattributed senders and hosts (they are the point, but they are noisy)")
	fs.BoolVar(&opts.warnings, "warnings", false, "show non-fatal warnings")
	fs.BoolVar(&opts.insecureTLS, "insecure", false, "skip TLS certificate verification")
	fs.BoolVar(&opts.quiet, "quiet", false, "suppress progress output")
	showVersion := fs.Bool("version", false, "print version and exit")
	validate := fs.Bool("validate", false, "validate signature packs and exit")

	if err := fs.Parse(os.Args[1:]); err != nil {
		return nil // flag package already printed the problem
	}

	if *showVersion {
		fmt.Printf("yowie %s\n", version)
		return nil
	}

	sigs, err := loadSignatures(opts.sigDir)
	if err != nil {
		return err
	}

	if *validate {
		fmt.Printf("%d signatures across %d packs, covering %d vendors\n",
			sigs.Len(), len(sigs.Packs()), len(sigs.Vendors()))
		for _, p := range sigs.Packs() {
			fmt.Printf("  %s\n", p)
		}
		if parked := sigs.Disabled(); len(parked) > 0 {
			// Parked signatures are validated but never evaluated. Reporting
			// them keeps the verification backlog visible instead of buried in
			// a file nobody opens.
			byPack := map[string][]signature.Signature{}
			var packOrder []string
			for _, sig := range parked {
				if _, seen := byPack[sig.Pack()]; !seen {
					packOrder = append(packOrder, sig.Pack())
				}
				byPack[sig.Pack()] = append(byPack[sig.Pack()], sig)
			}
			sort.Strings(packOrder)

			fmt.Printf("\n%d signature(s) parked behind `disabled: true`, awaiting confirmation against a live tenant:\n", len(parked))
			for _, pack := range packOrder {
				fmt.Printf("\n  %s (%d)\n", pack, len(byPack[pack]))
				for _, sig := range byPack[pack] {
					fmt.Printf("    %-40s %s\n", sig.ID, sig.Vendor)
				}
			}
		}
		return nil
	}

	args := fs.Args()
	if len(args) < 1 {
		usage(fs)
		return fmt.Errorf("a domain is required")
	}
	domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(args[0]), "."))
	candidates := dedupeCandidates(args[1:], domain)

	detectors, err := engine.SelectDetectors(opts.only, opts.skip)
	if err != nil {
		return err
	}
	// Propagate CT tuning into the detector instance.
	for _, d := range detectors {
		if ct, ok := d.(*detect.CertTransparency); ok {
			ct.Limit = opts.ctLimit
			ct.Timeout = opts.ctTimeout
		}
	}

	out, closeOut, err := openOutput(opts.output)
	if err != nil {
		return err
	}
	defer closeOut()

	// Progress goes to stderr so that redirecting stdout to a file still gives
	// a live view, and piped output stays clean.
	interactive := !opts.quiet && opts.format == "cli"
	colour := !opts.noColour && report.ColourSupported(out)

	if opts.format == "cli" && !opts.noBanner {
		fmt.Fprint(out, report.Banner(domain, candidates))
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if opts.scanTimeout > 0 {
		var timeoutCancel context.CancelFunc
		ctx, timeoutCancel = context.WithTimeout(ctx, opts.scanTimeout)
		defer timeoutCancel()
	}

	// Ctrl-C cancels the scan but still reports whatever was found, which
	// matters on a slow sweep of a large organisation.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Fprintln(os.Stderr, "\ninterrupted — reporting partial results")
		cancel()
	}()

	status := func(string) {}
	if interactive {
		status = makeStatusPrinter()
	}

	result, err := engine.Run(ctx, engine.Config{
		Domain:        domain,
		Candidates:    candidates,
		Signatures:    sigs,
		Resolver:      resolver.New(resolver.Options{Servers: splitServers(opts.nameservers), Timeout: opts.dnsTimeout, Concurrency: opts.dnsConc}),
		HTTP:          webclient.New(webclient.Options{Timeout: opts.httpTimeout, Concurrency: opts.httpConc, InsecureTLS: opts.insecureTLS}),
		Detectors:     detectors,
		ReportUnknown: !opts.noUnknown,
		Status:        status,
	})
	if interactive {
		clearStatus()
	}
	if result == nil {
		return err
	}
	if err != nil && ctx.Err() == nil {
		return err
	}

	switch strings.ToLower(opts.format) {
	case "cli", "":
		return report.CLI(out, result, report.CLIOptions{
			Colour:       colour,
			Compact:      opts.compact,
			ShowEvidence: !opts.noEvidence,
			MaxEvidence:  opts.maxEvidence,
			ShowWarnings: opts.warnings,
		})
	case "json":
		return report.JSON(out, result)
	case "jsonl":
		return report.JSONL(out, result)
	case "csv":
		return report.CSV(out, result)
	case "html":
		return report.HTML(out, result)
	default:
		return fmt.Errorf("unknown format %q (want cli, json, jsonl, csv or html)", opts.format)
	}
}

// loadSignatures prefers an explicit directory, then the YOWIE_SIGNATURES
// environment variable, and falls back to the packs embedded in the binary.
func loadSignatures(dir string) (*signature.Set, error) {
	if dir == "" {
		dir = os.Getenv("YOWIE_SIGNATURES")
	}
	if dir != "" {
		return signature.LoadDir(dir)
	}
	sub, err := fs.Sub(signatures.Embedded, ".")
	if err != nil {
		return nil, err
	}
	return signature.LoadFS(sub)
}

// dedupeCandidates cleans the candidate list and derives a sensible default
// from the domain when none were supplied, since the first label of the domain
// is nearly always a valid tenant guess.
func dedupeCandidates(args []string, domain string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(c string) {
		c = strings.ToLower(strings.TrimSpace(c))
		if c == "" || seen[c] {
			return
		}
		seen[c] = true
		out = append(out, c)
	}
	for _, a := range args {
		for _, part := range strings.Split(a, ",") {
			add(part)
		}
	}
	if len(out) == 0 {
		if label, _, ok := strings.Cut(domain, "."); ok && label != "" {
			add(label)
		}
	}
	return out
}

func splitServers(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func openOutput(path string) (io.Writer, func(), error) {
	if path == "" {
		return os.Stdout, func() {}, nil
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, nil, fmt.Errorf("creating %s: %w", path, err)
	}
	return f, func() { f.Close() }, nil
}

// makeStatusPrinter returns a status sink that overwrites a single stderr line,
// matching the original tool's behaviour of showing motion rather than silence.
func makeStatusPrinter() func(string) {
	const width = 78
	return func(s string) {
		if len(s) > width {
			s = s[:width]
		}
		fmt.Fprintf(os.Stderr, "\x1b[2m%-*s\x1b[0m\r", width, s)
	}
}

func clearStatus() {
	fmt.Fprintf(os.Stderr, "%-78s\r", "")
}

func usage(fs *flag.FlagSet) {
	fmt.Fprintf(os.Stderr, `Yowie %s — find the SaaS an organisation actually uses.

Usage:
  yowie [flags] <domain> [candidate ...]

The domain is the organisation's root domain. Candidates are the short strings a
vendor tenant might be named after — trading names, abbreviations, old brands.
Supply as many as you can; each one is another chance to find a tenant. With
none given, the first label of the domain is used.

Examples:
  yowie acme.com.au acme acmecorp acmegroup
  yowie -format html -o report.html acme.com.au acme
  yowie -format json acme.com.au | jq '.findings[] | select(.confidence=="high")'
  yowie -only dns,spf,dmarc -compact acme.com.au
  yowie -signatures ./signatures -validate

Detectors:
  dns      TXT, CNAME, MX and NS record signatures
  vanity   vendor-hosted tenants named after the organisation
  http     application-layer fingerprints
  spf      the full SPF include graph, including nested includes
  dmarc    DMARC report destinations
  bimi     BIMI brand indicator hosting
  mta-sts  MTA-STS policy contents
  tenant   Microsoft tenant, federation and sibling-domain enumeration
  ct       subdomains from certificate transparency logs, resolved and attributed

Flags:
`, version)
	fs.PrintDefaults()

	fmt.Fprintf(os.Stderr, `
All checks use publicly observable data and touch only vendor infrastructure
that any internet user can query. Scan domains you are authorised to assess.
`)
}
