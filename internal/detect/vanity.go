package detect

import (
	"context"
	"fmt"
	"strings"

	"github.com/joda32/yowie/internal/model"
	"github.com/joda32/yowie/internal/signature"
	"github.com/miekg/dns"
	"golang.org/x/sync/errgroup"
)

// Vanity detects vendor-hosted tenants named after the organisation, e.g.
// acme.zendesk.com.
//
// Detection is by comparison, not by "does it resolve": many vendors wildcard
// their tenant zone so every label resolves. Each template is first probed with
// two random labels to learn the vendor's answer for a tenant that does not
// exist. A candidate is a tenant only when its answer differs from that
// baseline.
type Vanity struct{}

func (v *Vanity) Name() string { return "vanity" }

func (v *Vanity) Run(ctx context.Context, s *Scan) error {
	if len(s.Candidates) == 0 {
		return nil
	}

	sigs := append(
		append([]signature.Signature{}, s.Sigs.ByType(signature.TypeVanityA)...),
		s.Sigs.ByType(signature.TypeVanityCNAME)...,
	)
	if len(sigs) == 0 {
		return nil
	}

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(24)

	for _, sig := range sigs {
		g.Go(func() error {
			qtype := dns.TypeA
			method := model.MethodA
			if sig.Type == signature.TypeVanityCNAME {
				qtype = dns.TypeCNAME
				method = model.MethodCNAME
			}

			s.Status("Probing %s", signature.Expand(sig.Query, s.Domain, "*"))

			baseline, stable := baselineFingerprint(gctx, s, sig.Query, qtype)
			if !stable {
				// Unstable answers make comparison meaningless. Say so rather
				// than emitting a guess.
				s.Warn("vanity: %s answers inconsistently for nonexistent tenants; skipped (signature %s)",
					signature.Expand(sig.Query, s.Domain, "*"), sig.ID)
				return nil
			}
			wildcarded := baseline != "NXDOMAIN"

			for _, candidate := range s.Candidates {
				if gctx.Err() != nil {
					return gctx.Err()
				}
				host := signature.Expand(sig.Query, s.Domain, candidate)

				ans, err := s.Resolver.Lookup(gctx, host, qtype)
				if err != nil {
					s.Warn("vanity: %v", err)
					continue
				}
				if !ans.Exists() || ans.Empty() {
					continue
				}
				fp := ans.Fingerprint()
				if fp == baseline {
					continue
				}

				conf := model.ConfidenceHigh
				detail := "resolves where a random tenant name does not"
				notes := ""
				if wildcarded {
					// The vendor answers for every label, so existence proves
					// nothing; only the differing answer is meaningful.
					conf = sig.Confidence
					detail = "answer differs from the vendor's wildcard response for unknown tenants"
					notes = "Vendor wildcards this zone. The tenant is inferred from a differing answer, " +
						"which is weaker evidence than a plain NXDOMAIN baseline — confirm before reporting."
				}

				// A tenant exists. Whether it is *this* organisation's tenant is
				// a separate question, and a short candidate cannot answer it.
				contested := contestedByLength(candidate)
				if contested {
					if conf == model.ConfidenceHigh {
						conf = model.ConfidenceMedium
					}
					notes = strings.TrimSpace(notes + fmt.Sprintf(
						" Candidate %q is %d characters, short enough that the tenant is likely to "+
							"belong to a different organisation of the same initials — vendor namespaces "+
							"are global and first-come-first-served. Capped at probable: confirm the "+
							"tenant is yours before reporting it.",
						candidate, len([]rune(candidate))))
				}

				f := model.Finding{
					Vendor:             sig.Vendor,
					Category:           sig.Category,
					Confidence:         conf,
					ContestedNamespace: contested,
					Signatures:         []string{sig.ID},
					Evidence: []model.Evidence{{
						Method: method,
						Query:  host,
						Value:  model.Truncate(fmt.Sprint(ans.Values()), 200),
						Detail: detail,
					}},
				}
				if sig.Notes != "" {
					f.Notes = append(f.Notes, sig.Notes)
				}
				if notes != "" {
					f.Notes = append(f.Notes, notes)
				}
				s.Emit(f)
			}
			return nil
		})
	}
	return g.Wait()
}
