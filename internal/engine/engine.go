// Package engine runs the detectors and assembles their output into a Result.
package engine

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/joda32/yowie/internal/detect"
	"github.com/joda32/yowie/internal/model"
	"github.com/joda32/yowie/internal/resolver"
	"github.com/joda32/yowie/internal/signature"
	"github.com/joda32/yowie/internal/webclient"
)

// Config describes one scan.
type Config struct {
	Domain     string
	Candidates []string

	Signatures *signature.Set
	Resolver   *resolver.Resolver
	HTTP       *webclient.Client

	// Detectors to run. Empty means detect.All().
	Detectors []detect.Detector

	// ReportUnknown surfaces senders and hosts that match no signature.
	ReportUnknown bool

	// Status receives progress lines. Optional.
	Status func(string)
}

// Run executes every configured detector concurrently and returns the merged
// result.
//
// A detector failing is not fatal: its error is recorded as a warning and the
// remaining detectors still run. A partial answer that says which parts are
// missing is more useful than no answer, and far more useful than a complete
// looking answer that quietly dropped a channel.
func Run(ctx context.Context, cfg Config) (*model.Result, error) {
	if cfg.Domain == "" {
		return nil, fmt.Errorf("domain is required")
	}
	if cfg.Signatures == nil {
		return nil, fmt.Errorf("no signatures loaded")
	}
	if cfg.Resolver == nil {
		return nil, fmt.Errorf("no resolver configured")
	}
	if cfg.HTTP == nil {
		return nil, fmt.Errorf("no HTTP client configured")
	}

	detectors := cfg.Detectors
	if len(detectors) == 0 {
		detectors = detect.All()
	}

	started := time.Now()
	result := &model.Result{
		Domain:     strings.ToLower(strings.TrimSuffix(cfg.Domain, ".")),
		Candidates: cfg.Candidates,
		StartedAt:  started.UTC(),
	}

	// Findings and warnings arrive from many goroutines. A single collector
	// owns the FindingSet so no locking is needed around merge logic.
	findings := make(chan model.Finding, 256)
	warnings := make(chan string, 256)

	set := model.NewFindingSet()
	var collector sync.WaitGroup
	collector.Add(2)

	go func() {
		defer collector.Done()
		for f := range findings {
			set.Add(f)
		}
	}()

	var (
		warnMu   sync.Mutex
		warnSeen = map[string]bool{}
	)
	go func() {
		defer collector.Done()
		for w := range warnings {
			warnMu.Lock()
			// Broad sweeps produce the same timeout many times over; collapse
			// duplicates so the warning list stays readable.
			if !warnSeen[w] {
				warnSeen[w] = true
				result.Errors = append(result.Errors, w)
			}
			warnMu.Unlock()
		}
	}()

	status := cfg.Status
	if status == nil {
		status = func(string) {}
	}

	scan := detect.NewScan(
		result.Domain,
		cfg.Candidates,
		func(f model.Finding) { findings <- f },
		func(w string) { warnings <- w },
		status,
	)
	scan.Resolver = cfg.Resolver
	scan.HTTP = cfg.HTTP
	scan.Sigs = cfg.Signatures
	scan.ReportUnknown = cfg.ReportUnknown

	var detectorsWG sync.WaitGroup
	for _, d := range detectors {
		detectorsWG.Add(1)
		go func() {
			defer detectorsWG.Done()
			defer func() {
				// A panic in one detector must not take down a scan that has
				// already gathered findings from the others.
				if r := recover(); r != nil {
					warnings <- fmt.Sprintf("%s: internal error: %v", d.Name(), r)
				}
			}()
			if err := d.Run(ctx, scan); err != nil {
				warnings <- fmt.Sprintf("%s: %v", d.Name(), err)
			}
		}()
	}
	detectorsWG.Wait()

	close(findings)
	close(warnings)
	collector.Wait()

	queries, hits := cfg.Resolver.Stats()
	result.Findings = set.Findings()
	result.Duration = time.Since(started)
	result.Stats = model.Stats{
		DNSQueries:   queries,
		DNSCacheHits: hits,
		HTTPRequests: cfg.HTTP.Requests(),
		Signatures:   cfg.Signatures.Len(),
	}
	sort.Strings(result.Errors)

	return result, ctx.Err()
}

// SelectDetectors filters the full detector list by name. only and skip are
// comma-separated name lists; only wins when both are given.
func SelectDetectors(only, skip string) ([]detect.Detector, error) {
	all := detect.All()
	byName := map[string]detect.Detector{}
	var names []string
	for _, d := range all {
		byName[d.Name()] = d
		names = append(names, d.Name())
	}

	if only != "" {
		var out []detect.Detector
		for _, n := range splitList(only) {
			d, ok := byName[n]
			if !ok {
				return nil, fmt.Errorf("unknown detector %q (available: %s)", n, strings.Join(names, ", "))
			}
			out = append(out, d)
		}
		return out, nil
	}

	if skip != "" {
		skipped := map[string]bool{}
		for _, n := range splitList(skip) {
			if _, ok := byName[n]; !ok {
				return nil, fmt.Errorf("unknown detector %q (available: %s)", n, strings.Join(names, ", "))
			}
			skipped[n] = true
		}
		var out []detect.Detector
		for _, d := range all {
			if !skipped[d.Name()] {
				out = append(out, d)
			}
		}
		return out, nil
	}
	return all, nil
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.ToLower(strings.TrimSpace(p)); p != "" {
			out = append(out, p)
		}
	}
	return out
}
