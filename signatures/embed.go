// Package signatures embeds the default signature packs into the binary so
// that Yowie runs standalone with no data files alongside it.
//
// The embedded copy is a fallback. Point --signatures at a directory to load
// packs from disk instead, which is how you iterate on signatures without
// rebuilding.
package signatures

import "embed"

//go:embed *.yaml
var Embedded embed.FS
