package signature

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/joda32/yowie/internal/model"
	"gopkg.in/yaml.v3"
)

// SchemaVersion is the only pack schema this build understands.
const SchemaVersion = 1

// Set is a validated, deduplicated collection of signatures drawn from one or
// more packs.
type Set struct {
	sigs     []Signature
	packs    []string
	disabled []Signature
}

// All returns every enabled signature.
func (s *Set) All() []Signature { return s.sigs }

// Len reports the number of enabled signatures.
func (s *Set) Len() int { return len(s.sigs) }

// Packs lists the pack names that were loaded.
func (s *Set) Packs() []string { return s.packs }

// Disabled returns the signatures that parsed and validated but are parked
// behind `disabled: true`. They are still checked for correctness so that a
// parked signature does not quietly rot.
func (s *Set) Disabled() []Signature { return s.disabled }

// ByType returns the enabled signatures of a given type.
func (s *Set) ByType(t Type) []Signature {
	var out []Signature
	for _, sig := range s.sigs {
		if sig.Type == t {
			out = append(out, sig)
		}
	}
	return out
}

// Vendors returns the distinct vendor names covered by the set.
func (s *Set) Vendors() []string {
	seen := map[string]struct{}{}
	for _, sig := range s.sigs {
		seen[sig.Vendor] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for v := range seen {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// LoadFS reads and validates every *.yaml and *.yml file at the root of fsys.
func LoadFS(fsys fs.FS) (*Set, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, fmt.Errorf("reading signature directory: %w", err)
	}

	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if ext := strings.ToLower(filepath.Ext(e.Name())); ext == ".yaml" || ext == ".yml" {
			names = append(names, e.Name())
		}
	}
	// Deterministic load order keeps duplicate-ID errors reproducible.
	sort.Strings(names)
	if len(names) == 0 {
		return nil, fmt.Errorf("no signature packs (*.yaml) found")
	}

	set := &Set{}
	seenID := make(map[string]string) // id -> pack that defined it

	for _, name := range names {
		data, err := fs.ReadFile(fsys, name)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", name, err)
		}

		var pack Pack
		dec := yaml.NewDecoder(strings.NewReader(string(data)))
		dec.KnownFields(true) // a typo'd key is an error, not a silent no-op
		if err := dec.Decode(&pack); err != nil {
			return nil, fmt.Errorf("parsing %s: %w", name, err)
		}

		if pack.Version != SchemaVersion {
			return nil, fmt.Errorf("%s: schema version %d is not supported (this build understands version %d)",
				name, pack.Version, SchemaVersion)
		}
		if len(pack.Signatures) == 0 {
			return nil, fmt.Errorf("%s: pack contains no signatures", name)
		}

		set.packs = append(set.packs, name)

		for i := range pack.Signatures {
			sig := pack.Signatures[i]
			sig.pack = name

			// Apply pack-level defaults before validating.
			if sig.Category == "" {
				sig.Category = pack.Defaults.Category
			}
			if sig.Confidence == "" {
				sig.Confidence = pack.Defaults.Confidence
			}
			if sig.Confidence == "" {
				sig.Confidence = model.ConfidenceMedium
			}

			if err := sig.validate(); err != nil {
				return nil, err
			}
			if prev, dup := seenID[sig.ID]; dup {
				return nil, fmt.Errorf("%s: duplicate signature id %q (already defined in %s)", name, sig.ID, prev)
			}
			seenID[sig.ID] = name

			if sig.Disabled {
				set.disabled = append(set.disabled, sig)
				continue
			}

			// DNS comparisons are case-insensitive, so normalise the needle
			// once here rather than on every lookup.
			if sig.Type != TypeHTTP {
				sig.Match.Contains = strings.ToLower(sig.Match.Contains)
			}
			set.sigs = append(set.sigs, sig)
		}
	}

	if len(set.sigs) == 0 {
		return nil, fmt.Errorf("all signatures are disabled")
	}
	return set, nil
}

// LoadDir reads signature packs from a filesystem directory.
func LoadDir(dir string) (*Set, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("signature directory %s: %w", dir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("signature path %s is not a directory", dir)
	}
	set, err := LoadFS(os.DirFS(dir))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", dir, err)
	}
	return set, nil
}
