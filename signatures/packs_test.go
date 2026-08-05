package signatures_test

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/joda32/yowie/internal/signature"
	"github.com/joda32/yowie/signatures"
)

// TestEmbeddedPacksLoad is the guard on the tool's most valuable asset. A typo
// in a signature file is a silent loss of coverage in every scan, so the packs
// are validated on every test run rather than on the next time somebody looks.
func TestEmbeddedPacksLoad(t *testing.T) {
	set, err := signature.LoadFS(signatures.Embedded)
	if err != nil {
		t.Fatalf("embedded signature packs failed to load: %v", err)
	}
	if set.Len() < 150 {
		t.Errorf("only %d signatures loaded; the ported database had ~174, so something was dropped", set.Len())
	}

	byType := map[signature.Type]int{}
	for _, sig := range set.All() {
		byType[sig.Type]++
	}
	// Every detector class needs signatures or it silently does nothing.
	for _, typ := range []signature.Type{
		signature.TypeTXT, signature.TypeCNAME, signature.TypeMX,
		signature.TypeVanityA, signature.TypeVanityCNAME, signature.TypeHTTP,
		signature.TypeSPFInclude, signature.TypeDMARCRUA, signature.TypeCNAMETarget,
	} {
		if byType[typ] == 0 {
			t.Errorf("no signatures of type %q; the matching detector will never fire", typ)
		}
	}
}

func TestEmbeddedPackConventions(t *testing.T) {
	set, err := signature.LoadFS(signatures.Embedded)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	for _, sig := range set.All() {
		if strings.TrimSpace(sig.Vendor) != sig.Vendor {
			t.Errorf("%s: vendor %q has surrounding whitespace", sig.ID, sig.Vendor)
		}
		// The legacy database used a trailing asterisk to mean "unconfirmed".
		// That meaning now lives in confidence and notes, so the marker should
		// not have survived the port.
		if strings.HasSuffix(sig.Vendor, "*") {
			t.Errorf("%s: vendor %q still carries the legacy unconfirmed marker", sig.ID, sig.Vendor)
		}
		if sig.Category == "" {
			t.Errorf("%s (%s): no category, so it will group under Uncategorised in reports", sig.ID, sig.Vendor)
		}
		if sig.ID != strings.ToLower(sig.ID) {
			t.Errorf("%s: ids should be lowercase kebab-case", sig.ID)
		}
	}
}

// TestNoDuplicateVendorSignatures catches the same fingerprint being added
// twice under different ids, which inflates apparent corroboration.
func TestNoDuplicateVendorSignatures(t *testing.T) {
	set, err := signature.LoadFS(signatures.Embedded)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	seen := map[string]string{}
	for _, sig := range set.All() {
		key := string(sig.Type) + "|" + sig.Query + "|" + sig.Match.Contains +
			"|" + sig.Match.Present + "|" + sig.Match.Absent
		if prev, dup := seen[key]; dup {
			t.Errorf("%s duplicates %s: identical type, query and match", sig.ID, prev)
		}
		seen[key] = sig.ID
	}
}

// TestVendorNamesAreConsistent guards against the same product being spelled two
// ways across packs. Findings deduplicate on the vendor string, so "Proofpoint"
// and "Proof Point" would report as two separate products in every scan.
func TestVendorNamesAreConsistent(t *testing.T) {
	set, err := signature.LoadFS(signatures.Embedded)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	// Normalise away case, spaces and punctuation. Names that collide after
	// that are the same product written differently.
	normalise := func(s string) string {
		var b strings.Builder
		for _, r := range strings.ToLower(s) {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
				b.WriteRune(r)
			}
		}
		return b.String()
	}

	variants := map[string]map[string][]string{} // normalised -> vendor -> ids
	for _, sig := range set.All() {
		n := normalise(sig.Vendor)
		if variants[n] == nil {
			variants[n] = map[string][]string{}
		}
		variants[n][sig.Vendor] = append(variants[n][sig.Vendor], sig.ID)
	}

	for _, byName := range variants {
		if len(byName) < 2 {
			continue
		}
		var parts []string
		for name, ids := range byName {
			parts = append(parts, fmt.Sprintf("%q (%s)", name, strings.Join(ids, ", ")))
		}
		sort.Strings(parts)
		t.Errorf("the same product is spelled several ways and will report as separate findings: %s",
			strings.Join(parts, " vs "))
	}
}
