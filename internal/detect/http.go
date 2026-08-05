package detect

import (
	"context"
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
				s.EmitSig(sig, sig.Confidence, ev)
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
// line to quote when a signature fired on the absence of a marker.
func title(body string) string {
	lower := strings.ToLower(body)
	start := strings.Index(lower, "<title")
	if start < 0 {
		return model.Truncate(body, 160)
	}
	open := strings.Index(lower[start:], ">")
	if open < 0 {
		return model.Truncate(body, 160)
	}
	start += open + 1
	end := strings.Index(lower[start:], "</title>")
	if end < 0 {
		return model.Truncate(body[start:], 160)
	}
	return strings.TrimSpace(body[start : start+end])
}
