package detect

import "testing"

// A crt.sh-shaped response: two rows for the same certificate (same serial,
// deduped to one) plus a second certificate, a wildcard SAN (kept by parent),
// and a neighbouring-domain SAN (dropped).
const crtShCertFixture = `[
  {"issuer_name":"C=US, O=Let's Encrypt, CN=R3","common_name":"www.acme.com","name_value":"www.acme.com\nacme.com","not_before":"2026-09-02T00:00:00","not_after":"2026-12-01T00:00:00","serial_number":"0abc"},
  {"issuer_name":"C=US, O=Let's Encrypt, CN=R3","common_name":"www.acme.com","name_value":"www.acme.com","not_before":"2026-09-02T00:00:00","not_after":"2026-12-01T00:00:00","serial_number":"0abc"},
  {"issuer_name":"C=US, O=DigiCert Inc, CN=DigiCert TLS","common_name":"*.acme.com","name_value":"*.acme.com\nnot-acme.com","not_before":"2026-08-01T00:00:00","not_after":"2027-08-01T00:00:00","serial_number":"0def"}
]`

func TestParseCrtShCerts(t *testing.T) {
	certs := parseCrtShCerts(crtShCertFixture, "acme.com")

	// Two distinct certs (the duplicate serial collapses).
	if len(certs) != 2 {
		t.Fatalf("certs = %d, want 2: %+v", len(certs), certs)
	}

	bySerial := map[string]int{}
	for i, c := range certs {
		bySerial[c.Serial] = i
	}
	www := certs[bySerial["0abc"]]
	if www.Subject != "www.acme.com" || www.Issuer == "" {
		t.Errorf("cert 0abc = %+v, want subject www.acme.com with an issuer", www)
	}
	// SANs deduped and scoped to the domain.
	if len(www.SANs) != 2 {
		t.Errorf("0abc SANs = %v, want [acme.com www.acme.com]", www.SANs)
	}

	wild := certs[bySerial["0def"]]
	// The wildcard SAN is kept as its parent; the neighbouring domain is dropped.
	for _, s := range wild.SANs {
		if s == "not-acme.com" {
			t.Errorf("0def SANs %v must not include the neighbouring domain", wild.SANs)
		}
	}
	if len(wild.SANs) != 1 || wild.SANs[0] != "acme.com" {
		t.Errorf("0def SANs = %v, want [acme.com] (wildcard -> parent)", wild.SANs)
	}
}

func TestParseCrtShCertsMalformed(t *testing.T) {
	if got := parseCrtShCerts("not json", "acme.com"); got != nil {
		t.Errorf("malformed body should yield nil, got %+v", got)
	}
}
