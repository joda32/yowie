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

# Self-test. An earlier version of this script piped into `grep -q`, which exits
# on first match and SIGPIPEs the writer; under `set -o pipefail` the pipeline
# then reported failure and the match was silently dropped. It passed on small
# inputs and failed on large ones — a guard that reports "ok" while detecting
# nothing. Prove detection works, on an input large enough to trip that class of
# bug, before trusting any result below.
selftest() {
  local canary="${domains[0]}" haystack
  haystack="$(head -c 400000 /dev/zero | tr '\0' 'x')"$'\n'"${canary}"$'\n'
  if ! grep -qiF -- "$canary" <<<"$haystack"; then
    echo "  ABORT — self-test failed: cannot detect a known domain in a large input." >&2
    echo "  This script is not providing the protection it claims. Fix it before publishing." >&2
    exit 2
  fi
  printf '  self-test ok (detection verified on a %s-byte input)\n' "${#haystack}"
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

hr; echo "Local repository"
check "tracked file content" "$(git grep -I --no-color -h '' -- . 2>/dev/null || true)"
check "commit messages"      "$(git log --all --format='%B' 2>/dev/null || true)"
check "tag messages"         "$(git tag -l --format='%(contents)' 2>/dev/null || true)"
check "branch names"         "$(git for-each-ref --format='%(refname)' 2>/dev/null || true)"

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
