# Yowie

Finds the SaaS services an organisation subscribes to, using only externally
observable data. Built for shadow IT discovery: the services worth finding are
the ones nobody told you about.

Named for the Australian bush cryptid, and for the same reason its predecessor
was named after a sasquatch — you are hunting something everyone insists isn't
there.

### Build

```
go build -o yowie ./cmd/yowie
```

Go 1.22 or later. The signature packs are embedded in the binary, so the single
file is all you need to deploy.

### Usage

```
yowie [flags] <domain> [candidate ...]
```

The domain is the organisation's root domain. Candidates are the short strings a
vendor tenant might be named after — trading names, abbreviations, old brands
carried over from acquisitions. Supply as many as you can; each one is another
chance to find a tenant. With none given, the first label of the domain is used.

```
yowie acme.com.au acme acmecorp acmegroup
yowie -format html -o report.html acme.com.au acme
yowie -format json acme.com.au | jq '.findings[] | select(.confidence=="high")'
yowie -only dns,spf,dmarc -compact acme.com.au
yowie -signatures ./signatures -validate
```

### What it looks at

| Detector  | Signal |
|-----------|--------|
| `dns`     | TXT verification tokens, CNAME, MX and NS records |
| `vanity`  | Vendor-hosted tenants named after the organisation (`acme.zendesk.com`) |
| `http`    | Application-layer fingerprints for services with no DNS footprint |
| `spf`     | The full SPF include graph, following nested includes and redirects |
| `dmarc`   | DMARC aggregate/forensic report destinations |
| `bimi`    | BIMI logo and Verified Mark Certificate hosting |
| `mta-sts` | MTA-STS policy contents |
| `tenant`  | Microsoft tenant ID, federated identity provider, and sibling domains |
| `ct`      | Subdomains from Certificate Transparency logs, resolved and attributed |

Select with `-only` or `-skip`, e.g. `-skip ct,http` for a fast DNS-only pass.

The last two deserve a note, because they find things a signature list cannot.

**`tenant`** asks Microsoft's unauthenticated endpoints who the domain belongs
to. Autodiscover's federation information returns *every domain attached to the
same tenant*, which routinely surfaces business units, acquisitions and
abandoned brands. Each one is another domain worth scanning.

**`ct`** inverts the discovery model. Every other check asks "does this
organisation use vendor X?" against a fixed list, so it can only find vendors
somebody already wrote a signature for. CT asks "what has this organisation
actually pointed its subdomains at?" A team that signs up for a product and
wires up `support.acme.com` gets a certificate issued, and that certificate is
public and permanent. Targets matching no signature are reported as leads, which
is how you find the thing you did not know to look for.

### Reading the output

Findings are graded, and the grade is the point:

- **Confirmed** — a vendor-issued, domain-scoped indicator. Treat as in use.
- **Probable** — strong, but could also be shared infrastructure or a namespace
  claimed by someone else. `acme.blogspot.com` might not be your `acme`.
- **Leads** — weak or unattributed, including senders and hosts matching no
  known vendor. The noisiest bucket and the most likely to contain something
  nobody told you about.

Two independent detectors agreeing on a vendor promotes a Probable finding to
Confirmed. Every finding carries the exact record or response that triggered it,
so a report is defensible without re-running the tool.

`-no-unknown` drops the unattributed leads if you want signal only.

### Output formats

`-format cli` (default), `json`, `jsonl`, `csv`, `html`. Use `-o` to write to a
file. The HTML report is self-contained — no external assets — so it survives
being emailed or dropped on a share drive.

Progress goes to stderr and results to stdout, so `yowie -format json acme.com > out.json`
still shows a live progress line.

### Signature packs

Signatures live in `signatures/*.yaml`. The binary embeds them; `-signatures <dir>`
or `YOWIE_SIGNATURES=<dir>` loads from disk instead, which is how you iterate
without rebuilding.

```yaml
version: 1
pack: dns-txt
description: "Domain-ownership verification tokens published as TXT records."
defaults:
  confidence: high

signatures:
  - id: txt-1password
    vendor: "1Password"
    category: "Identity & Secrets"
    type: txt
    query: "{domain}"
    match:
      contains: "1password-site-verification"
```

`{domain}` expands to the root domain, `{candidate}` to each candidate string.
A signature referencing `{candidate}` is evaluated once per candidate.

| Type | Matches | Notes |
|------|---------|-------|
| `txt`, `cname`, `mx`, `ns` | `match.contains` against the records of `query` | Case-insensitive |
| `vanity_a`, `vanity_cname` | Baseline comparison; no `match` block | `query` must contain `{candidate}` |
| `http` | `match.present`, `match.absent`, or `match.status` alone | See status handling below |
| `spf_include` | `match.contains` against the resolved SPF include graph | |
| `dmarc_rua` | `match.contains` against DMARC report destinations | |
| `cname_target` | `query` is a bare hosting suffix | Applied to hosts discovered by `ct`; `*` matches one label |

`disabled: true` parks a signature without losing the research behind it.
`notes:` carries analyst guidance through to the report.

Run `yowie -validate` after editing. Validation is strict — an unknown key is an
error, not a silent no-op — and the packs are also checked by `go test`, so a
typo cannot quietly cost you coverage in every future scan.

#### The packs

| Pack | Contents |
|------|----------|
| `dns-txt`, `dns-cname`, `dns-mx` | Ported from the predecessor tool. Live. |
| `email-spf`, `email-dmarc` | Senders and DMARC processors. Live. |
| `vanity-tenants`, `http-endpoints` | Tenant hostnames and app fingerprints. Live. |
| `cname-targets` | Hosting suffixes for CT-discovered subdomains. Live. |
| `ai-services` | AI and LLM platforms. **Parked.** |
| `file-transfer` | Managed file transfer — MOVEit, GoAnywhere, Egnyte. **Parked.** |
| `finance-procurement` | Finance, expense, payroll, procurement. **Parked.** |
| `security-grc` | Security tooling and compliance automation. **Parked.** |
| `graveyard` | Unverified signatures carried over from the predecessor. **Parked.** |

#### Parked signatures and how to promote one

Four packs ship entirely disabled. They are structurally complete and pass
validation, but their match criteria have never been confirmed against a live
tenant, so they are not evaluated during a scan.

This is deliberate. A signature with a wrong `contains` value never fires and
never errors — it just makes a vendor look covered when it is not. Shipping
those disabled keeps the research in the repo without inflating the numbers.

`-validate` prints the backlog grouped by pack:

```
$ ./yowie -validate
232 signatures across 13 packs, covering 168 vendors
...
71 signature(s) parked behind `disabled: true`, awaiting confirmation against a live tenant:

  ai-services.yaml (24)
    txt-grammarly                            Grammarly
    ...
```

To promote one:

1. Find a domain you know uses the product.
2. Confirm the mechanism by hand:
   ```bash
   dig +short TXT known-customer.com | grep -i <vendor>          # token signatures
   dig +short A acme.egnyte.com                                  # vanity signatures
   dig +short A $(openssl rand -hex 6).egnyte.com                # ...and its baseline
   ```
   A vanity tenant must answer differently from the random label.
3. Replace the guessed value with what you actually observed, delete
   `disabled: true`, and set an honest confidence.
4. Rewrite `notes:` to say what you confirmed.
5. `./yowie -signatures ./signatures -validate`

If a mechanism turns out not to work, **leave it disabled and record the
negative result in `notes:`**. That is as valuable as a working signature — it
stops the next person spending an afternoon rediscovering it. `security-grc`
already carries several of these, explaining why CrowdStrike, Wiz and Tenable
have no vanity signature: they put every customer on a shared console, so there
is nothing per-customer to detect.

#### Finding your own signature candidates

The tool generates its own backlog. Unattributed senders and hosts are exactly
the vendors worth writing signatures for, and across many scans they rank
themselves by frequency:

```bash
for d in $(cat domains.txt); do ./yowie -format json -quiet "$d"; done \
  | jq -r '.findings[] | select(.category|startswith("Unidentified")) | .vendor' \
  | sort | uniq -c | sort -rn | head -40
```

Anything recurring across unrelated organisations is real. This also yields
confirmed live samples for free — the SPF and DMARC evidence contains the actual
sender hostnames, which is precisely what the parked entries need.

#### How vanity detection avoids false positives

Many vendors wildcard their tenant zone, so "it resolves" proves nothing. Each
template is first probed with two random labels to learn how the vendor answers
for a tenant that does not exist. A candidate counts only if its answer differs
from that baseline. If the two baselines disagree with each other — geo-DNS,
round-robin — the comparison is meaningless and the signature is skipped with a
warning rather than guessed at.

A NXDOMAIN baseline yields a Confirmed finding. A wildcard baseline with a
differing answer yields the signature's own confidence and a note explaining why
it is weaker.

### Flags worth knowing

| Flag | Purpose |
|------|---------|
| `-only` / `-skip` | Select detectors |
| `-compact` | One line per finding |
| `-max-evidence` | Evidence lines shown per finding in the terminal, default 6 (`0` for all) |
| `-no-unknown` | Drop unattributed senders and hosts |
| `-warnings` | Show non-fatal problems; a scan with warnings is a partial scan |
| `-ct-limit` | Cap hostnames resolved from CT logs (default 400) |
| `-ct-timeout` | CT aggregators are slow (default 60s) |
| `-nameservers` | Override the public resolvers |
| `-timeout` | Overall scan budget (default 5m) |
| `-dns-concurrency` / `-http-concurrency` | Tune throughput |

Ctrl-C reports whatever was found rather than discarding it.

### Notes on accuracy

- The CT detector depends on crt.sh, falling back to Cert Spotter. crt.sh is
  frequently overloaded; if both fail you get a warning, not a silent gap.
- HTTP status handling depends on the match style, because the status code is
  doing a different job in each. An **absent** marker fires on the *absence* of
  the vendor's no-such-tenant text, which any unrelated error page also
  satisfies, so it defaults to a 2xx/3xx guard. A **present** marker is positive
  evidence whatever the status and is not constrained — that matters because
  "exists but access denied" is a normal state: Auth0 answers 400 for a live
  tenant, S3 and Cloud Storage answer 403 for a private bucket, and Firebase
  answers 401 for a correctly locked database. Set `match.status` explicitly
  when the "exists" state is an error code. A signature with only
  `match.status` matches on the code alone, for vendors serving an identical
  single-page-application shell either way.
- SPF walking honours the RFC 7208 ten-lookup limit and warns when a domain
  exceeds it, since receivers may then reject the record outright.
- Nothing here authenticates to anything. All checks use publicly observable
  data and touch only vendor infrastructure any internet user can query. Scan
  domains you are authorised to assess.

### Illustrative output

Anonymised — the shape of a real report, not a real organisation.

```
$ yowie acme.com.au acme acmecorp

  Yowie  ·  tracking down the SaaS nobody told you about

  Domain      acme.com.au
  Candidates  acme, acmecorp

Confirmed (18) ────────────────────────────────────────────────────
  Atlassian  Collaboration
      TXT     acme.com.au → atlassian-domain-verification=59rFzyTBLE5bPlEP…
      HTTP    https://acme.atlassian.net/ → Log in with Atlassian account
  Microsoft 365  Identity & Secrets
      MX      acme.com.au → acme-com-au.mail.protection.outlook.com
      Tenant  https://login.microsoftonline.com/…/openid-configuration → tenant d7a0631f-…
  Salesforce  Business Applications
      A       acme.lightning.force.com → [141.163.193.226 141.163.193.227]
  …

Probable (8) ──────────────────────────────────────────────────────
  Okta  Identity & Secrets
      CNAME   acme.okta.com → [ok8-crtrs.tng.okta.com]
      ! Vendor wildcards this zone. The tenant is inferred from a differing answer…

Leads — verify before acting (7) ────────────────────────────────
  service-now.com  Unidentified host
      CT      engage.acme.com.au → acme.service-now.com
      ! 9 subdomain(s) point at service-now.com, which matches no known vendor signature.

33 services across 18 confirmed, 8 probable, 7 leads
176 DNS queries (12 served from cache), 73 HTTP requests, 232 signatures, 10.0s
```

### Licence

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).

### History

Yowie is a Go rewrite of an earlier internal Python tool. The signature database
was ported mechanically, so coverage is a superset of its predecessor's.

Behavioural differences worth knowing:

- Detectors run concurrently. A scan that took minutes takes seconds.
- Findings are graded and deduplicated by vendor, rather than one line per hit.
  Use `-compact` for output closer to the old style.
- The old tool's trailing `*` on a vendor name (meaning "never confirmed against
  a live sample") is now expressed as a medium confidence plus an explanatory
  note.
- SPF entries that were substring matches against the root TXT bundle are now
  walked properly, so nested includes are caught.
- The module entry point (`run()`) is replaced by importing `internal/engine`,
  which returns a structured `model.Result` instead of accumulating into a
  package global. The old `run()` never reset its results list, so a second call
  in the same process returned the first call's findings too; that class of bug
  is gone.
