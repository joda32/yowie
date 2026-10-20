# Signature discovery — a repeatable procedure

Yowie can only name a vendor it has a signature for. Everything else lands in the
**Leads** bucket as an unidentified host or sender. This procedure turns that
bucket into new coverage: scan a batch of real organisations, collect the hosts
and senders that matched nothing, and triage the recurring ones into signatures.

Run it on a schedule against fresh batches and the signature set keeps pace with
the SaaS market instead of drifting behind it.

## TL;DR

```
scripts/discover-signatures.sh <domains-file> [output-dir]
```

Writes per-domain JSON plus `REPORT.md` to the output directory (default
`discovery-runs/<timestamp>/`, which is gitignored). Read `REPORT.md`, triage the
candidate table, confirm ownership, then write signatures.

## Why this works

Every other detector asks *"does this org use vendor X?"* against a fixed list,
so it can only confirm what a signature already describes. Discovery inverts it:
it asks *"what has this org pointed its subdomains and mail at that we can't
name?"* — which is the only question that finds a vendor nobody has written yet.

The engine of the procedure is **recurrence across unrelated organisations**. One
council using `merspf.meritec.co.uk` could be anything. Two unrelated councils
both reporting DMARC to the same national mail-check service is a shared
platform, not a coincidence. The aggregator therefore ranks candidates by the number of distinct
organisations a host served — the top of that list is where real SaaS lives.

This only pays off at batch scale. A host that appears once is a lead; a host
that appears across ten orgs writes its own signature.

## Prerequisites

- A built `./yowie`, or the Go toolchain on `PATH` (the runner rebuilds when it
  can, so discovery always reflects the current signature set). The Go toolchain
  installs under `~/.local/go/bin` and is not on `PATH` by default; without it
  the runner falls back to the checked-in binary but still evaluates the on-disk
  `signatures/` packs via `-signatures`.
- The commit-msg and pre-push hooks enabled (`git config core.hooksPath
  scripts/hooks`). The runner registers every target in `.scanned-domains`
  *before* scanning it, so the guard is always in place first — but the hooks are
  what make that registration mean something.

## Selecting targets

Discovery is only as good as its input. Two rules:

1. **Real, active organisations.** Parked domains and spam hosts consume no SaaS
   and waste scans. Government, education, health, and mid-to-large enterprises
   have the richest, most varied footprints — `.gov`, `.edu` and
   national-government domains are consistently productive.
2. **Mind the ordering of any list you sample.** `testdata/testsites.txt` is one
   million domains sorted **alphabetically**, not by popularity — its first
   entries are numeric spam domains, and well-known orgs are scattered by name
   (`google.com` is at line ~401k). Taking its literal "top N" gets you junk.
   Sample real orgs out of it instead, e.g.:

   ```
   grep -E '\.gov$' testdata/testsites.txt | grep -vE '^[0-9]' | shuf -n 20
   grep -E '\.gov\.[a-z]+$' testdata/testsites.txt | shuf -n 20
   ```

The domains file takes one target per line, with optional candidates after the
domain exactly as `yowie` takes them (`acme.example acme acmecorp`). Blank lines
and `#` comments are ignored.

## Reading the report

`REPORT.md` has two parts.

- **Per-target summary** — confirmed+probable counts, lead count, and error count
  per org. Use it to spot targets that under-reported (see CT flakiness below).
- **Candidate new signatures** — every unidentified host/sender, ranked by
  distinct-org count, with evidence samples. This is the triage queue.

## Triage: which candidates become signatures

Not every unidentified host is a SaaS vendor. Sort each candidate into:

| Bucket | What it is | Action |
|---|---|---|
| **SaaS platform** | A third party selling a service, seen under app-named subdomains or as an SPF/DMARC sender (e.g. a billing portal, an HR platform, an election system) | Write a signature |
| **Shared gov/sector infra** | A centralised reporting or hosting service many orgs in one sector share (e.g. a national DMARC aggregation service) | Write a signature if it names a platform; decide first whether a compliance mandate belongs in a shadow-IT report at all |
| **Variant of a covered vendor** | A sovereign-cloud or regional hostname of a vendor already covered (`…portals.us` vs `…portals.com`, `usgov…trafficmanager.net` vs `trafficmanager.net`) | Extend the existing signature with the variant |
| **Self / parent / peer** | The org's own other domains, its parent department, a partner institution hosting a page | Not a signature |
| **Generic CDN/telco** | Edge or load-balancing infrastructure that fronts an unknown app | Low value; add only if you want to name the provider, at `confidence: medium` |

The recurrence rank does most of the sorting for you, but read the evidence: a
host that recurs only because one org wired many subdomains to it (all under that
org's own estate) is self-hosting, not a platform.

## From candidate to signature — evidence-led

**Do not write a signature from a plausible-sounding name.** Confirm ownership
first; see the "Signatures are evidence-led" section of `CLAUDE.md`.

```
dig +short NS <vendor-domain>     # who it is delegated to
dig +short SOA <vendor-domain>    # who administers the zone
```

- Confirmed by DNS or the vendor's own site → write it enabled, record the
  evidence in `notes`.
- Neither DNS nor the vendor confirms ownership → write it `disabled: true` and
  say so in `notes`. A disabled signature that records its uncertainty is worth
  more than an enabled guess that makes a vendor look covered when it is not.

Pick the pack and type by signal:

| Signal in the report | Pack | `type` |
|---|---|---|
| Subdomain → vendor host (CT/CNAME) | `signatures/cname-targets.yaml` | `cname_target` |
| `include:` in SPF | the SPF pack | `spf_include` |
| `mailto:` in DMARC | `signatures/email-dmarc.yaml` | `dmarc_rua` |
| TXT verification token | the DNS-TXT pack | `txt` |

Use placeholder values in any example you add (`acme.example`, `EXAMPLETOKEN…`,
all-zero GUID, `203.0.113.0/24`) — never a value copied from a scan.

## Known limitations

- **CT source availability is the big one.** Subdomain discovery depends on
  external CT logs. The tool queries three and merges them: crt.sh (richest,
  but frequently 502ing — during the government sweep it failed on 90%+ of
  scans), Cert Spotter (rate-limits under batch load), and ctlogs.dev (keyless,
  but its keyless tier returns only the first ~100 hosts per domain). When all
  three fail for a target, CT is skipped and that target only finds vendors that
  already have a signature — i.e. it contributes nothing to discovery. The
  per-target error count flags this. **Re-run CT-failed targets** (a smaller
  batch, spaced out) before trusting a zero-lead result. A spaced re-run does
  not help when crt.sh is in an outage rather than merely throttling — that is
  what the extra sources are for, and why a scan is no longer one 502 away from
  blind.
  - crtlog.com was evaluated as a fourth source and rejected: its index returned
    zero hostnames for well-covered domains and its anonymous tier is capped at
    20 requests a day.
- **Short candidates.** A two- or three-letter candidate matches vendor
  namespaces belonging to other orgs of the same initials; those findings carry a
  caveat and should not be promoted on their own.
- **Images bypass every guard.** If you ever screenshot a run, read it first —
  `REPORT.md` and the JSON contain live tenant hosts and tokens.

## Scaling up

The million-domain file is a source to sample from, not a batch to run whole.
Scale in stages:

1. Batches of a few hundred, not thousands, to stay under CT rate limits.
2. Space batches out, or expect CT to degrade partway through.
3. Let recurrence accumulate **across** batches — keep the per-run `REPORT.md`s
   and watch which unidentified hosts keep reappearing. Those are the signatures
   worth writing first.

## Safety

- The runner commits nothing and sends nothing off the machine; it only scans and
  writes local files.
- Run output contains assessed-org findings, so `discovery-runs/` is gitignored.
  Keep it that way, and never paste a real target host into a commit, issue, or
  anything else that leaves the machine (`CLAUDE.md`).
- Every target is added to `.scanned-domains` before it is scanned.
