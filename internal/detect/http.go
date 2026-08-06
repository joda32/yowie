package detect

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/joda32/yowie/internal/model"
	"github.com/joda32/yowie/internal/signature"
	"golang.org/x/sync/errgroup"
)

// HTTPEndpoints evaluates application-layer signatures against vendor URLs.
type HTTPEndpoints struct{}

func (h *HTTPEndpoints) Name() string { return "http" }

func (h *HTTPEndpoints) Run(ctx context.Context, s *Scan) error {
	sigs := s.Sigs.ByType(signature.TypeHTTP)
	if len(sigs) == 0 {
		return nil
	}

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(16)

	for _, sig := range sigs {
		for _, ex := range s.expandQueries(sig) {
			g.Go(func() error {
				s.Status("Fetching %s", ex.Query)

				resp, err := s.HTTP.Get(gctx, ex.Query)
				if err != nil {
					// Connection failures are routine when probing tenant
					// namespaces that do not exist; record but do not fail.
					s.Warn("http: %v", err)
					return nil
				}
				if !statusAllowed(resp.Status, sig.Match) {
					return nil
				}

				var ev model.Evidence
				switch {
				case sig.Match.Present != "":
					if !strings.Contains(resp.Body, sig.Match.Present) {
						return nil
					}
					ev = model.Evidence{
						Method: model.MethodHTTP,
						Query:  ex.Query,
						Value:  snippet(resp.Body, sig.Match.Present),
						Detail: "response contains the vendor's live-tenant marker",
					}

				case sig.Match.Absent != "":
					if strings.Contains(resp.Body, sig.Match.Absent) {
						return nil
					}
					ev = model.Evidence{
						Method: model.MethodHTTP,
						Query:  ex.Query,
						Value:  model.Truncate(title(resp.Body), 160),
						Detail: "HTTP " + strconv.Itoa(resp.Status) + "; the vendor's no-such-tenant page was not returned",
					}

				default:
					// Status-only signature: some vendors serve a single-page
					// application whose HTML shell is identical whether the
					// namespace exists or not, leaving the status code as the
					// only usable discriminator.
					ev = model.Evidence{
						Method: model.MethodHTTP,
						Query:  ex.Query,
						Value:  model.Truncate(title(resp.Body), 160),
						Detail: "HTTP " + strconv.Itoa(resp.Status) + "; the vendor returns this status only for a namespace that exists",
					}
				}
				// A candidate-derived URL addresses a namespace anyone could
				// have registered, so the match has to survive two ownership
				// questions before it counts as proof.
				conf, contested, notes := sig.Confidence, false, []string{}
				if ex.Candidate != "" {
					if contestedByLength(ex.Candidate) {
						contested = true
						notes = append(notes, fmt.Sprintf(
							"Candidate %q is %d characters, short enough that the namespace is likely to "+
								"belong to a different organisation of the same initials — vendor namespaces "+
								"are global and first-come-first-served. Capped at probable: confirm it is "+
								"yours before reporting it.",
							ex.Candidate, len([]rune(ex.Candidate))))
					}
					if org, ok := conflictingOrg(titleTag(resp.Body), ex.Candidate, s.Domain, sig.Vendor); ok {
						contested = true
						notes = append(notes, fmt.Sprintf(
							"The page names %q, which matches neither the candidate nor the domain. The "+
								"vendor appears to be describing a different organisation's namespace. "+
								"Capped at probable; treat as someone else's tenant until shown otherwise.",
							org))
					}
					if contested && conf == model.ConfidenceHigh {
						conf = model.ConfidenceMedium
					}
				}

				f := model.Finding{
					Vendor:             sig.Vendor,
					Category:           sig.Category,
					Confidence:         conf,
					ContestedNamespace: contested,
					Signatures:         []string{sig.ID},
					Evidence:           []model.Evidence{ev},
				}
				if sig.Notes != "" {
					f.Notes = append(f.Notes, sig.Notes)
				}
				f.Notes = append(f.Notes, notes...)
				s.Emit(f)
				return nil
			})
		}
	}
	return g.Wait()
}

// statusAllowed decides whether a response's status code lets the signature
// fire. The rule differs by match style, because the status code is doing a
// different job in each.
//
//   - An explicit match.status always wins.
//
//   - An absent-marker signature fires on the *absence* of the vendor's
//     no-such-tenant text, which any unrelated error page also satisfies. It
//     needs a sanity guard, so it defaults to success and redirect codes.
//
//   - A present-marker signature fires on the marker itself. That is positive
//     evidence whatever the status, and constraining it caused real misses:
//     Auth0 answers 400 for a tenant that exists, and object stores answer 403
//     for a bucket that exists but denies access. "Exists but access denied" is
//     a normal, informative state.
//
//   - A status-only signature is defined entirely by its status list, which
//     validation requires it to have.
func statusAllowed(status int, m signature.Match) bool {
	if len(m.Status) > 0 {
		for _, a := range m.Status {
			if a == status {
				return true
			}
		}
		return false
	}
	if m.Present != "" {
		return true
	}
	return status >= 200 && status < 400
}

// snippet returns the marker with a little surrounding context, so a reader can
// see where in the page it appeared.
func snippet(body, marker string) string {
	i := strings.Index(body, marker)
	if i < 0 {
		return model.Truncate(marker, 160)
	}
	start := max(0, i-40)
	end := min(len(body), i+len(marker)+40)
	return model.Truncate(body[start:end], 200)
}

// title extracts the page title, which is usually the most informative single
// line to quote when a signature fired on the absence of a marker. It falls
// back to the head of the body so there is always something to show a reader.
func title(body string) string {
	if t := titleTag(body); t != "" {
		return t
	}
	// A truncated response can carry an opening tag with no close. The text
	// after it is still the most title-like thing available, so display keeps
	// using it even though titleTag rejects it.
	if start, ok := titleTextStart(body); ok {
		return model.Truncate(body[start:], 160)
	}
	return model.Truncate(body, 160)
}

// titleTag returns the contents of a <title> element, or "" when the response
// has none.
//
// Unlike title it never falls back to the raw body, and the distinction
// matters: a response with no title element — an XML error document, a JSON
// payload — has no page name to reason about. Feeding its markup to the
// organisation-name check produced a confident report that AWS S3 had named an
// organisation called "Code><Message>Access Denied<".
func titleTag(body string) string {
	start, ok := titleTextStart(body)
	if !ok {
		return ""
	}
	end := strings.Index(strings.ToLower(body[start:]), "</title>")
	if end < 0 {
		return ""
	}
	return strings.TrimSpace(body[start : start+end])
}

// titleTextStart returns the offset just past a <title ...> opening tag.
func titleTextStart(body string) (int, bool) {
	lower := strings.ToLower(body)
	start := strings.Index(lower, "<title")
	if start < 0 {
		return 0, false
	}
	open := strings.Index(lower[start:], ">")
	if open < 0 {
		return 0, false
	}
	return start + open + 1, true
}
