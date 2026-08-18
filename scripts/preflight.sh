#!/usr/bin/env bash
#
# Run before publishing anything: a release, an issue, a push to a new remote.
#
# The git hooks guard commits and pushes. This sweeps the surfaces they cannot
# see — what is already on the remote, and what is about to be written by hand.

set -uo pipefail

cd "$(dirname "$0")/.."
list=".scanned-domains"
fail=0

hr() { printf '\n%s\n' "----------------------------------------------------------------"; }

if [ ! -f "$list" ]; then
  echo "no ${list} — nothing to check against. Create it before scanning anything."
  exit 1
fi

domains=()
while IFS= read -r d; do
  d="${d%%#*}"; d="$(printf '%s' "$d" | tr -d '[:space:]')"
  [ -n "$d" ] && domains+=("$d")
done < "$list"
echo "Checking ${#domains[@]} scanned domain(s) against every published surface."

# Organisation names written in prose, which a domain check cannot see.
#
# Derived from the scanned domains' registrable labels. A label is skipped when
# the signature packs already carry it as a vendor — that is the sanctioned
# exception: a domain may appear because we detect the product, not because the
# organisation was assessed. Short and ordinary-English labels are skipped too,
# or every note mentioning "corporate" or "group" would fire.
#
# Four words joined that set across the eighth and ninth sweeps, and they are
# worth a note because each is core vocabulary here rather than incidental prose:
# how the confidence model describes corroborating detectors, how the status-only
# HTTP signatures describe a single-page-application's HTML, how the engine
# describes collapsing a repeated warning, and how the ct detector reports a
# hostname count against its limit. Every one of them is also somebody's domain
# label, which is the hazard: the larger the scanned list grows, the more
# ordinary English it swallows, and each word added here is a word the prose
# check can no longer see. The literal-domain check still covers all four, so
# this comment does not name them — writing the example out is what tripped the
# guard the last three times, including this one.
orgnames=()
build_orgnames() {
  local vendors lbl
  vendors="$(grep -hoiE '^[[:space:]]+(vendor|query|contains):.*' signatures/*.yaml 2>/dev/null | tr '[:upper:]' '[:lower:]')"
  local stop=" corporate group energy international surgical health global cloud first auto \
systems services holdings limited technologies industries resources digital online \
capital partners financial national general medical dental mobile press \
state history goal book heavy focus orange chess wish genius \
medium booking archive mozilla detail subject \
independent shell times total universal joins \
"
  for d in "${domains[@]}"; do
    # For a subdomain, the first label names the site section, not the
    # organisation: in shop.acme.example the org is acme, while "shop" is the
    # kind of ordinary word that appears in every other line of a codebase.
    # When the parent is also on the list it already contributes the org name,
    # and the child contributes only noise.
    #
    # The first draft of this very comment used a real scanned subdomain as its
    # example and the guard rejected it, which is the second time that has
    # happened while writing a rule about not doing it.
    parent="${d#*.}"
    skip=""
    for other in "${domains[@]}"; do
      [ "$other" = "$parent" ] && { skip=1; break; }
    done
    [ -n "$skip" ] && continue

    lbl="${d%%.*}"
    [ "${#lbl}" -ge 5 ] || continue
    case "$stop" in *" $lbl "*) continue ;; esac
    grep -qiF -- "$lbl" <<<"$vendors" && continue   # carried as a vendor: sanctioned
    orgnames+=("$lbl")
  done
}
build_orgnames

# Artefacts that identify an organisation even after its domain has been removed.
# Each entry is: <regex>|<allowed-placeholder-regex>|<description>.
#
# These exist because an earlier anonymisation pass replaced the domains in a
# worked example but left a live domain-verification token and a fragment of a
# real tenant GUID in place. A verification token is unique to one domain and is
# indexed by DNS-history services, so it identifies the organisation more
# reliably than the name that was carefully removed.
artefacts=(
  'verification=[A-Za-z0-9_/+=-]{16,}|EXAMPLETOKEN|a live domain-verification token'
  '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|00000000-0000-0000-0000-000000000000|a tenant or account GUID'
)

# Self-test. An earlier version of this script piped into `grep -q`, which exits
# on first match and SIGPIPEs the writer; under `set -o pipefail` the pipeline
# then reported failure and the match was silently dropped. It passed on small
# inputs and failed on large ones — a guard that reports "ok" while detecting
# nothing. Every check below is therefore proved against a planted canary, on an
# input large enough to trip that class of bug, before any result is trusted.
selftest() {
  local pad haystack
  pad="$(head -c 400000 /dev/zero | tr '\0' 'x')"

  haystack="${pad}"$'\n'"${domains[0]}"$'\n'
  grep -qiF -- "${domains[0]}" <<<"$haystack" || {
    echo "  ABORT — self-test failed: cannot detect a known domain in a large input." >&2; exit 2; }

  # Assembled at runtime so the canaries never appear as literals in this file —
  # otherwise the self-test would trip the very check it exists to prove, and a
  # realistic-looking canary is itself the thing we are trying to keep out.
  local vpart="verification" vval="Ab3dEf6hIj9lMn2pQr5t"
  haystack="${pad}"$'\n'"google-site-${vpart}=${vval}"$'\n'
  grep -qiE 'verification=[A-Za-z0-9_/+=-]{16,}' <<<"$haystack" || {
    echo "  ABORT — self-test failed: cannot detect a verification token." >&2; exit 2; }

  local g1="aaaaaaaa" g2="bbbb" g3="cccc" g4="dddd" g5="eeeeeeeeeeee"
  haystack="${pad}"$'\n'"tenant ${g1}-${g2}-${g3}-${g4}-${g5}"$'\n'
  grep -qiE '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' <<<"$haystack" || {
    echo "  ABORT — self-test failed: cannot detect a GUID." >&2; exit 2; }

  if [ "${#orgnames[@]}" -gt 0 ]; then
    haystack="${pad}"$'\n'"a note mentioning ${orgnames[0]} in prose"$'\n'
    grep -qiE "(^|[^a-z0-9])${orgnames[0]}([^a-z0-9]|$)" <<<"$haystack" || {
      echo "  ABORT — self-test failed: cannot detect an organisation name." >&2; exit 2; }
  fi

  printf '  self-test ok (domain, token, GUID and org-name detection all verified)\n'
}
selftest

check() { # name, content
  local name="$1" content="$2" hits=""
  for d in "${domains[@]}"; do
    # Here-string, not a pipe. `grep -q` exits on the first match, which sends
    # SIGPIPE to a feeding process; under `set -o pipefail` that makes the whole
    # pipeline report failure and the match is silently lost. It only bites on
    # input large enough that the writer has not finished — so the bug hides on
    # small inputs and appears exactly where it matters.
    if grep -qiF -- "$d" <<<"$content"; then hits="${hits} ${d}"; fi
  done
  if [ -n "$hits" ]; then
    printf '  FAIL  %-26s%s\n' "$name" "$hits"; fail=1
  else
    printf '  ok    %s\n' "$name"
  fi
}

# Organisation names in prose, and scan artefacts that survive de-identification.
# Run only against local content: the remote surfaces are prose written by hand
# and would produce constant false positives on ordinary words.
check_deep() { # name, content
  local name="$1" content="$2" hits="" n found spec re allow desc
  for n in ${orgnames[@]+"${orgnames[@]}"}; do
    if grep -qiE "(^|[^a-z0-9])${n}([^a-z0-9]|$)" <<<"$content"; then hits="${hits} ${n}"; fi
  done
  for spec in "${artefacts[@]}"; do
    re="${spec%%|*}"; allow="${spec#*|}"; desc="${allow#*|}"; allow="${allow%%|*}"
    found="$(grep -oiE "$re" <<<"$content" | grep -viE "$allow" | sort -u | head -3 | tr '\n' ' ')"
    [ -n "$found" ] && hits="${hits} [${desc}: ${found}]"
  done
  if [ -n "$hits" ]; then
    printf '  FAIL  %-26s%s\n' "$name" "$hits"; fail=1
  else
    printf '  ok    %s\n' "$name"
  fi
}

hr; echo "Local repository"
tracked_content="$(git grep -I --no-color -h '' -- . 2>/dev/null || true)"
commit_content="$(git log --all --format='%B' 2>/dev/null || true)"
check "tracked file content" "$tracked_content"
check "commit messages"      "$commit_content"
check "tag messages"         "$(git tag -l --format='%(contents)' 2>/dev/null || true)"
check "branch names"         "$(git for-each-ref --format='%(refname)' 2>/dev/null || true)"

hr; printf 'Deep checks (%d org name(s), %d artefact pattern(s))\n' "${#orgnames[@]}" "${#artefacts[@]}"
check_deep "org names + artefacts in files"   "$tracked_content"
check_deep "org names + artefacts in commits" "$commit_content"

if command -v gh >/dev/null 2>&1 && git remote get-url origin >/dev/null 2>&1; then
  repo="$(gh repo view --json nameWithOwner --jq .nameWithOwner 2>/dev/null || true)"
  if [ -n "$repo" ]; then
    hr; echo "Remote: ${repo}"
    check "repo description"  "$(gh repo view "$repo" --json description --jq '.description // ""' 2>/dev/null || true)"
    check "issue text"        "$(gh api "repos/${repo}/issues?state=all" --jq '.[] | .title + " " + (.body // "")' 2>/dev/null || true)"
    check "pull request text" "$(gh api "repos/${repo}/pulls?state=all" --jq '.[] | .title + " " + (.body // "")' 2>/dev/null || true)"
    check "release notes"     "$(gh api "repos/${repo}/releases" --jq '.[] | .name + " " + (.body // "")' 2>/dev/null || true)"

    vis="$(gh repo view "$repo" --json visibility --jq .visibility 2>/dev/null || echo UNKNOWN)"
    hr; printf 'Visibility: %s\n' "$vis"
    [ "$vis" = "PUBLIC" ] && echo "  Repository is PUBLIC — anything pushed is effectively permanent."
  fi
fi

hr; echo "Test suite"
if go test ./... >/dev/null 2>&1; then echo "  ok    all tests pass"; else echo "  FAIL  tests failing"; fail=1; fi

hr
if [ "$fail" -eq 0 ]; then
  echo "PASS — no scanned domain found on any checked surface."
else
  echo "BLOCKED — resolve the failures above before publishing."
  echo
  echo "Note: a surface already published cannot be fully retracted. Rewriting"
  echo "history leaves the original object reachable by SHA, and push events are"
  echo "archived off-platform. Treat a FAIL here as an incident, not a typo."
fi
exit "$fail"
