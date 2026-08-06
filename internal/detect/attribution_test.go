package detect

import (
	"testing"

	"github.com/joda32/yowie/internal/signature"
	"github.com/joda32/yowie/signatures"
)

// Each case is a hostname actually observed on a live estate, paired with the
// vendor its signature was written to name.
//
// This exists because a cname_target signature is only ever exercised when a
// certificate transparency lookup happens to return the host that motivated it.
// When CT is degraded — and one of the two aggregators was returning 404 for the
// whole period these were written — a broken suffix produces an unattributed
// lead rather than a failure, which reads exactly like "the vendor is not
// present". Pinning the observed host makes the signature testable offline.
//
// A case failing means either the suffix was mistyped, or a later broadening
// changed what it captures.
func TestObservedHostsAttributeToTheirVendor(t *testing.T) {
	set, err := signature.LoadFS(signatures.Embedded)
	if err != nil {
		t.Fatalf("load embedded packs: %v", err)
	}
	s := &Scan{Sigs: set}

	cases := []struct{ host, vendor string }{
		{"cname.beehiiv.com", "beehiiv"},
		{"19c819f8.with.contentpass.net", "Contentpass"},
		{"cname.announcekit.app", "AnnounceKit"},
		{"track.omnivery.net", "Omnivery"},
		{"acme.example.com.mta-sts.mailhardener.com", "Mailhardener"},
		{"acme.hasoffers.com", "TUNE"},
		{"ceac5848-la9aykxs.cname.ebis.ne.jp", "AD EBiS"},
		{"homeloantest.example.jp.scutum.jp", "Scutum"},
		{"cl-9463aee7.edgecdn.ru", "EdgeCenter"},
		{"go.pro32connect.ru", "PRO32 Connect"},
		{"cname.short.io", "Short.io"},
		// Akamai publishes several suffixes. Three were carried and three were
		// not, so hosts on the missing ones went out as unattributed leads while
		// the vendor counted as covered.
		{"v5bkduxxffeipb.akamaized.net", "Akamai"},
		{"e1234.x.akamaiedge.net", "Akamai"},
		{"a123.g.akamai.net", "Akamai"},
		{"acme.edgekey.net", "Akamai"},
		{"acme.edgesuite.net", "Akamai"},
	}

	for _, tc := range cases {
		sig, ok := s.AttributeHost(tc.host)
		if !ok {
			t.Errorf("%s: no signature matched; the vendor would be reported as an unattributed lead", tc.host)
			continue
		}
		if sig.Vendor != tc.vendor {
			t.Errorf("%s attributed to %q, want %q", tc.host, sig.Vendor, tc.vendor)
		}
	}
}

// Parked signatures must not attribute anything. An entry sitting in the
// graveyard with a plausible vendor name is a claim the evidence did not
// support; if it fired anyway the disabled flag would be decorative.
func TestParkedSuffixesDoNotAttribute(t *testing.T) {
	set, err := signature.LoadFS(signatures.Embedded)
	if err != nil {
		t.Fatalf("load embedded packs: %v", err)
	}
	s := &Scan{Sigs: set}

	for _, host := range []string{
		"stripe.rs-stripe.com",
		"mobmoto1-relay.iocnt.net",
		"frontend.prod.utiq-aws.net",
		"watashinoyuigon.example.jp.cdnga.net",
		"b2kmsfi6sn42xbis.shadan-kun.jp",
		"acme-elb2.go2cloud.org",
	} {
		if sig, ok := s.AttributeHost(host); ok {
			t.Errorf("%s attributed to %q, but its signature is parked as unconfirmed", host, sig.Vendor)
		}
	}
}
