package report

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/joda32/yowie/internal/model"
)

// ANSI escapes, blanked out when colour is disabled.
type palette struct {
	reset, bold, dim, high, medium, low, vendor, method string
}

func newPalette(colour bool) palette {
	if !colour {
		return palette{}
	}
	return palette{
		reset:  "\x1b[0m",
		bold:   "\x1b[1m",
		dim:    "\x1b[2m",
		high:   "\x1b[32m", // green
		medium: "\x1b[33m", // amber
		low:    "\x1b[90m", // grey
		vendor: "\x1b[1;36m",
		method: "\x1b[35m",
	}
}

func (p palette) forConfidence(c model.Confidence) string {
	switch c {
	case model.ConfidenceHigh:
		return p.high
	case model.ConfidenceMedium:
		return p.medium
	default:
		return p.low
	}
}

// CLIOptions controls terminal rendering.
type CLIOptions struct {
	// Colour enables ANSI styling.
	Colour bool
	// Compact prints one line per finding in the original tool's style,
	// for eyeballing a scan or piping into grep.
	Compact bool
	// ShowEvidence prints the supporting records under each finding.
	ShowEvidence bool
	// MaxEvidence caps how many evidence lines are printed per finding, with a
	// count of the remainder. Terminal output is for scanning; a load balancer
	// fronting sixty subdomains should not bury every other finding. Zero or
	// negative means no limit. Structured formats always carry the full set.
	MaxEvidence int
	// ShowWarnings prints the non-fatal problems encountered.
	ShowWarnings bool
}

// ColourSupported reports whether w looks like a terminal that can render ANSI.
func ColourSupported(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// CLI writes a human-readable report to w.
func CLI(w io.Writer, r *model.Result, opts CLIOptions) error {
	p := newPalette(opts.Colour)

	if opts.Compact {
		for _, f := range r.Findings {
			for _, ev := range f.Evidence {
				fmt.Fprintf(w, "%s%s%s %s(from %s lookup of %s)%s\n",
					p.forConfidence(f.Confidence), f.Vendor, p.reset,
					p.dim, ev.Method, ev.Query, p.reset)
			}
		}
		return nil
	}

	if len(r.Findings) == 0 {
		fmt.Fprintf(w, "\n%sNo SaaS services identified for %s.%s\n", p.dim, r.Domain, p.reset)
		fmt.Fprintf(w, "%sThat is a result, not a failure: %d signatures were evaluated across %d DNS queries and %d HTTP requests.%s\n",
			p.dim, r.Stats.Signatures, r.Stats.DNSQueries, r.Stats.HTTPRequests, p.reset)
		writeWarnings(w, r, p, opts)
		return nil
	}

	grouped := groupByConfidence(r.Findings)
	for _, conf := range confidenceOrder {
		findings := grouped[conf]
		if len(findings) == 0 {
			continue
		}

		colour := p.forConfidence(conf)
		heading := fmt.Sprintf("%s (%d)", confidenceLabel(conf), len(findings))
		fmt.Fprintf(w, "\n%s%s%s%s %s%s\n",
			p.bold, colour, heading, p.reset,
			p.dim, strings.Repeat("─", max(0, 66-len(heading))))

		for _, f := range findings {
			category := f.Category
			if category == "" {
				category = "Uncategorised"
			}
			fmt.Fprintf(w, "  %s%s%s  %s%s%s\n",
				p.vendor, f.Vendor, p.reset, p.dim, category, p.reset)

			if opts.ShowEvidence {
				shown := f.Evidence
				if limit := opts.MaxEvidence; limit > 0 && len(shown) > limit {
					shown = shown[:limit]
				}
				for _, ev := range shown {
					fmt.Fprintf(w, "      %s%-7s%s %s %s→%s %s\n",
						p.method, ev.Method, p.reset,
						ev.Query, p.dim, p.reset,
						model.Truncate(ev.Value, 90))
				}
				if rest := len(f.Evidence) - len(shown); rest > 0 {
					fmt.Fprintf(w, "      %s… and %d more (use -max-evidence 0 for all, or -format json)%s\n",
						p.dim, rest, p.reset)
				}
				for _, n := range f.Notes {
					fmt.Fprintf(w, "      %s! %s%s\n", p.dim, model.Truncate(n, 150), p.reset)
				}
			}
		}
	}

	high, medium, low := countByConfidence(r.Findings)
	fmt.Fprintf(w, "\n%s%d services across %d confirmed, %d probable, %d leads%s\n",
		p.bold, len(r.Findings), high, medium, low, p.reset)
	fmt.Fprintf(w, "%s%d DNS queries (%d served from cache), %d HTTP requests, %d signatures, %s%s\n",
		p.dim, r.Stats.DNSQueries, r.Stats.DNSCacheHits, r.Stats.HTTPRequests,
		r.Stats.Signatures, r.Duration.Round(1e6), p.reset)

	writeWarnings(w, r, p, opts)
	return nil
}

func writeWarnings(w io.Writer, r *model.Result, p palette, opts CLIOptions) {
	if len(r.Errors) == 0 {
		return
	}
	if !opts.ShowWarnings {
		fmt.Fprintf(w, "%s%d warnings suppressed; re-run with --warnings to see them%s\n",
			p.dim, len(r.Errors), p.reset)
		return
	}
	fmt.Fprintf(w, "\n%s%sWarnings (%d)%s\n", p.bold, p.low, len(r.Errors), p.reset)
	for _, e := range r.Errors {
		fmt.Fprintf(w, "  %s%s%s\n", p.dim, e, p.reset)
	}
}
