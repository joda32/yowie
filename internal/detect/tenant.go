package detect

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/joda32/yowie/internal/model"
)

// Tenant interrogates Microsoft's unauthenticated tenant-discovery endpoints.
//
// These are the highest-yield external checks available for a Microsoft-centric
// organisation, and none of them require credentials:
//
//   - the OpenID configuration confirms a tenant exists and yields its GUID;
//   - the user-realm endpoint reveals whether authentication is handled by
//     Entra ID or delegated to a third-party identity provider, naming that
//     provider's sign-in host;
//   - Autodiscover's federation information lists every domain attached to the
//     tenant, which routinely surfaces business units, acquisitions and
//     abandoned brands that nobody thought to mention.
//
// That last one matters most for shadow IT: each additional domain is another
// domain worth scanning.
type Tenant struct{}

func (d *Tenant) Name() string { return "tenant" }

var tenantGUID = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)

func (d *Tenant) Run(ctx context.Context, s *Scan) error {
	tenantID := d.openIDConfiguration(ctx, s)
	d.userRealm(ctx, s)
	d.federatedDomains(ctx, s, tenantID)
	return nil
}

// openIDConfiguration confirms an Entra ID tenant and extracts its GUID.
func (d *Tenant) openIDConfiguration(ctx context.Context, s *Scan) string {
	url := fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0/.well-known/openid-configuration", s.Domain)
	s.Status("Checking Entra ID tenant for %s", s.Domain)

	resp, err := s.HTTP.Get(ctx, url)
	if err != nil {
		s.Warn("tenant: %v", err)
		return ""
	}
	if resp.Status != 200 {
		return ""
	}

	var doc struct {
		Issuer string `json:"issuer"`
	}
	if err := json.Unmarshal([]byte(resp.Body), &doc); err != nil {
		return ""
	}
	id := tenantGUID.FindString(doc.Issuer)
	if id == "" {
		return ""
	}

	s.Emit(model.Finding{
		Vendor:     "Microsoft 365",
		Category:   "Identity & Secrets",
		Confidence: model.ConfidenceHigh,
		Evidence: []model.Evidence{{
			Method: model.MethodTenant,
			Query:  url,
			Value:  "tenant " + id,
			Detail: "domain is attached to an Entra ID tenant",
		}},
	})
	return id
}

// userRealm reports how authentication for the domain is handled. A Federated
// namespace means sign-in is delegated to a third-party identity provider,
// which the AuthURL names.
func (d *Tenant) userRealm(ctx context.Context, s *Scan) {
	url := fmt.Sprintf("https://login.microsoftonline.com/getuserrealm.srf?login=user@%s&xml=1", s.Domain)

	resp, err := s.HTTP.Get(ctx, url)
	if err != nil || resp.Status != 200 {
		return
	}

	nsType := xmlValue(resp.Body, "NameSpaceType")
	if strings.EqualFold(nsType, "Unknown") || nsType == "" {
		return
	}

	brand := xmlValue(resp.Body, "FederationBrandName")
	authURL := xmlValue(resp.Body, "AuthURL")

	if strings.EqualFold(nsType, "Managed") {
		s.Emit(model.Finding{
			Vendor:     "Microsoft 365",
			Category:   "Identity & Secrets",
			Confidence: model.ConfidenceHigh,
			Evidence: []model.Evidence{{
				Method: model.MethodTenant,
				Query:  url,
				Value:  "NameSpaceType=Managed" + brandSuffix(brand),
				Detail: "authentication is handled natively by Entra ID",
			}},
		})
		return
	}

	// Federated: something else owns sign-in.
	hosts := urlHosts(authURL)
	ev := model.Evidence{
		Method: model.MethodTenant,
		Query:  url,
		Value:  model.Truncate(authURL, 200) + brandSuffix(brand),
		Detail: "NameSpaceType=Federated",
	}
	const federationNote = "Microsoft 365 sign-in for this domain is federated to this host. " +
		"If it is not a sanctioned identity provider, it is a significant finding in its own right."

	// Name the provider where a signature knows the host. Without this, an
	// organisation federating to acme.okta.com reports both "Okta" and
	// "acme.okta.com" as separate vendors.
	if len(hosts) > 0 {
		if sig, ok := s.AttributeHost(hosts[0]); ok {
			f := model.Finding{
				Vendor:     sig.Vendor,
				Category:   sig.Category,
				Confidence: model.ConfidenceHigh,
				Signatures: []string{sig.ID},
				Notes:      []string{federationNote},
				Evidence:   []model.Evidence{ev},
			}
			s.Emit(f)
			return
		}
	}

	vendor := "Federated identity provider"
	if len(hosts) > 0 {
		vendor = hosts[0]
	}
	s.Emit(model.Finding{
		Vendor:     vendor,
		Category:   "Identity & Secrets",
		Confidence: model.ConfidenceHigh,
		Notes: []string{federationNote + " The host is a custom sign-in domain that matches no known " +
			"vendor, so it may still front a mainstream identity provider — check the URL path, which " +
			"usually gives the platform away."},
		Evidence: []model.Evidence{ev},
	})
}

// federatedDomains asks Autodiscover which domains belong to the tenant.
func (d *Tenant) federatedDomains(ctx context.Context, s *Scan, tenantID string) {
	const endpoint = "https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc"
	const action = "http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation"

	body := fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:exm="http://schemas.microsoft.com/exchange/services/2006/messages"
               xmlns:ext="http://schemas.microsoft.com/exchange/services/2006/types"
               xmlns:a="http://www.w3.org/2005/08/addressing"
               xmlns:autodiscover="http://schemas.microsoft.com/exchange/2010/Autodiscover"
               xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <a:Action soap:mustUnderstand="1">%s</a:Action>
    <a:To soap:mustUnderstand="1">%s</a:To>
    <a:ReplyTo><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo>
  </soap:Header>
  <soap:Body>
    <autodiscover:GetFederationInformationRequestMessage>
      <autodiscover:Request>
        <autodiscover:Domain>%s</autodiscover:Domain>
      </autodiscover:Request>
    </autodiscover:GetFederationInformationRequestMessage>
  </soap:Body>
</soap:Envelope>`, action, endpoint, s.Domain)

	s.Status("Enumerating tenant domains for %s", s.Domain)

	resp, err := s.HTTP.Post(ctx, endpoint, "text/xml; charset=utf-8", body, map[string]string{
		"SOAPAction": `"` + action + `"`,
	})
	if err != nil || resp.Status != 200 {
		return
	}

	domains := xmlValues(resp.Body, "Domain")
	var others []string
	for _, dom := range domains {
		dom = strings.ToLower(strings.TrimSpace(dom))
		// onmicrosoft.com names are the tenant's own and confirm its short
		// name; other domains are separate properties worth scanning.
		if dom == "" || dom == strings.ToLower(s.Domain) {
			continue
		}
		others = append(others, dom)
	}
	if len(others) == 0 {
		return
	}

	detail := "domains sharing this Microsoft 365 tenant"
	if tenantID != "" {
		detail += " (" + tenantID + ")"
	}
	s.Emit(model.Finding{
		Vendor:     "Microsoft 365",
		Category:   "Identity & Secrets",
		Confidence: model.ConfidenceHigh,
		Notes: []string{fmt.Sprintf("Tenant covers %d further domain(s): %s. "+
			"Each is worth scanning separately — sibling domains are a common home for unsanctioned services.",
			len(others), strings.Join(truncateList(others, 25), ", "))},
		Evidence: []model.Evidence{{
			Method: model.MethodTenant,
			Query:  endpoint,
			Value:  strings.Join(truncateList(others, 10), ", "),
			Detail: detail,
		}},
	})
}

func brandSuffix(brand string) string {
	if brand == "" || strings.EqualFold(brand, "Unknown") {
		return ""
	}
	return " (" + brand + ")"
}

// xmlValue returns the text of the first <tag> element, without pulling in a
// full XML parser for responses whose shape is fixed and known.
func xmlValue(body, tag string) string {
	vals := xmlValues(body, tag)
	if len(vals) == 0 {
		return ""
	}
	return vals[0]
}

func xmlValues(body, tag string) []string {
	var out []string
	open, closing := "<"+tag+">", "</"+tag+">"
	rest := body
	for {
		i := strings.Index(rest, open)
		if i < 0 {
			return out
		}
		rest = rest[i+len(open):]
		j := strings.Index(rest, closing)
		if j < 0 {
			return out
		}
		out = append(out, strings.TrimSpace(rest[:j]))
		rest = rest[j+len(closing):]
	}
}

func truncateList(items []string, n int) []string {
	if len(items) <= n {
		return items
	}
	out := append([]string(nil), items[:n]...)
	return append(out, fmt.Sprintf("and %d more", len(items)-n))
}
