#!/usr/bin/env bash
#
# discover-signatures.sh — batch-scan a list of organisations and surface the
# hosts and senders that matched no known vendor, so they can be triaged into
# new signatures.
#
# This is the repeatable half of the signature-discovery procedure documented in
# docs/signature-discovery.md. Read that first; it explains how to read the
# output and what to do with it.
#
# Usage:
#   scripts/discover-signatures.sh <domains-file> [output-dir]
#
#   <domains-file>  One target per line. Blank lines and lines beginning with #
#                   are ignored. A line may carry candidates after the domain,
#                   exactly as yowie takes them:
#                       acme.example acme acmecorp
#   [output-dir]    Where per-domain JSON and the aggregate report are written.
#                   Defaults to a timestamped directory under ./discovery-runs/.
#
# Safe by construction: every domain is added to .scanned-domains *before* it is
# scanned, which is the ordering CLAUDE.md requires. Nothing here commits,
# pushes or leaves the machine.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$here"

domains_file="${1:-}"
if [[ -z "$domains_file" || ! -f "$domains_file" ]]; then
	echo "usage: scripts/discover-signatures.sh <domains-file> [output-dir]" >&2
	exit 2
fi

out_dir="${2:-discovery-runs/$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$out_dir"

# Locate the binary. Prefer a freshly built one so signatures are current; fall
# back to the checked-in binary if the Go toolchain is not on PATH.
yowie_bin="$here/yowie"
if command -v go >/dev/null 2>&1; then
	echo "building yowie..." >&2
	go build -o "$yowie_bin" ./cmd/yowie
elif [[ ! -x "$yowie_bin" ]]; then
	echo "no go toolchain and no ./yowie binary; cannot continue" >&2
	exit 1
fi

scanned=".scanned-domains"
touch "$scanned"

# Always evaluate against the on-disk signature packs when present, so discovery
# reflects the current signature set rather than whatever the binary embedded at
# build time. Without this a freshly written signature would still show up as an
# "undiscovered" lead.
sig_args=()
if [[ -d "$here/signatures" ]]; then
	sig_args=(-signatures "$here/signatures")
fi

# Normalise a line into its bare domain (first whitespace-separated field).
total=0
while IFS= read -r line || [[ -n "$line" ]]; do
	line="${line%%#*}"
	line="$(echo "$line" | xargs || true)"   # trim
	[[ -z "$line" ]] && continue
	domain="${line%% *}"

	# Guardrail: register the domain before it is scanned.
	if ! grep -qixF "$domain" "$scanned"; then
		printf '%s\n' "$domain" >>"$scanned"
	fi

	total=$((total + 1))
	echo "[$total] scanning $line" >&2
	# shellcheck disable=SC2086
	"$yowie_bin" "${sig_args[@]}" -format json $line >"$out_dir/$domain.json" 2>"$out_dir/$domain.err" || {
		echo "    scan failed for $domain (see $out_dir/$domain.err)" >&2
	}
done <"$domains_file"

echo "scanned $total target(s); aggregating leads..." >&2

# Aggregate across every per-domain JSON. The point of interest is the
# "Unidentified*" bucket: a target host that recurs across unrelated
# organisations is almost certainly a shared SaaS platform that deserves a
# signature.
python3 -I - "$out_dir" >"$out_dir/REPORT.md" <<'PY'
import json, os, sys, glob
from collections import defaultdict

out_dir = sys.argv[1]
leads = defaultdict(lambda: {"orgs": set(), "methods": set(), "samples": [], "category": "", "notes": set()})
per_domain = {}
vendor_hits = defaultdict(set)   # vendor -> set(orgs), for coverage context

for path in sorted(glob.glob(os.path.join(out_dir, "*.json"))):
    try:
        d = json.load(open(path))
    except Exception as e:
        continue
    org = d.get("domain", os.path.basename(path)[:-5])
    conf = prob = lead = 0
    for f in d.get("findings", []):
        cat = f.get("category", "") or ""
        vendor = f.get("vendor", "") or ""
        c = f.get("confidence", "")
        if cat.startswith("Unidentified") or (c == "low" and "matches no known vendor" in " ".join(f.get("notes", []))):
            lead += 1
            key = vendor or cat
            e = leads[key]
            e["orgs"].add(org)
            e["category"] = cat
            for n in f.get("notes", []):
                e["notes"].add(n)
            for ev in f.get("evidence", [])[:3]:
                e["methods"].add(ev.get("method", ""))
                e["samples"].append(f'{org}: {ev.get("query","")} -> {ev.get("value","")}')
        else:
            vendor_hits[vendor].add(org)
            if c == "high":
                conf += 1
            else:
                prob += 1
    per_domain[org] = (conf, prob, lead, len(d.get("errors", []) or []))

def esc(s): return s.replace("|", "\\|")

print("# Signature-discovery run\n")
print(f"Targets scanned: **{len(per_domain)}**  ·  output dir: `{out_dir}`\n")

print("## Per-target summary\n")
print("| Target | Confirmed+Probable | Leads | Errors |")
print("|---|--:|--:|--:|")
for org, (conf, prob, lead, errs) in sorted(per_domain.items()):
    print(f"| {esc(org)} | {conf+prob} | {lead} | {errs} |")

print("\n## Candidate new signatures — unidentified hosts/senders\n")
print("Ranked by how many *distinct organisations* the host served. A host seen")
print("across several unrelated orgs is the strongest signal of a shared SaaS")
print("platform worth a signature.\n")
if not leads:
    print("_No unattributed hosts or senders in this batch._\n")
else:
    ranked = sorted(leads.items(), key=lambda kv: (-len(kv[1]["orgs"]), kv[0]))
    print("| Target host / sender | Orgs | Methods | Category |")
    print("|---|--:|---|---|")
    for key, e in ranked:
        print(f"| {esc(key)} | {len(e['orgs'])} | {esc(','.join(sorted(m for m in e['methods'] if m)))} | {esc(e['category'])} |")
    print("\n### Evidence samples\n")
    for key, e in ranked:
        print(f"**{key}**  (orgs: {', '.join(sorted(e['orgs']))})\n")
        for s in e["samples"][:8]:
            print(f"- `{s}`")
        print()
PY

echo "report written to $out_dir/REPORT.md" >&2
echo "$out_dir/REPORT.md"
