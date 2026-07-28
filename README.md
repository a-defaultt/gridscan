# gridscan

Self-hosted attack-surface scanner. Point it at a scope you own — a domain, an
IP, a CIDR, a URL, or a file of any of those — and it runs the same flow a
hosted ASM platform runs against you:

```
discover ──► probe ──► scan ──► deduped findings with lifecycle ──► report + JSON
subfinder    httpx     nuclei    (SQLite: first_seen / last_seen /
dnsx                             resolved / reappeared)
naabu
```

It only **orchestrates** the ProjectDiscovery OSS tools and manages state. The
detection engine is Nuclei with the public template library plus any private
templates you add. Nothing leaves your infrastructure.

## Install

```bash
./install.sh                      # installs subfinder/dnsx/naabu/httpx/nuclei (needs Go)
export PATH="$PATH:$(go env GOPATH)/bin"
```

gridscan itself is pure stdlib Python 3 — no pip deps. It degrades gracefully if
a tool is missing (e.g. no naabu → httpx probes default web ports), but Nuclei
is required for actual detection.

## Use

```bash
# a domain (does subdomain discovery)
python3 gridscan.py example.com

# multiple IPs / a CIDR (does port discovery)
python3 gridscan.py 203.0.113.10 198.51.100.0/24

# a file of mixed targets, custom scope name + notifications
python3 gridscan.py -f targets.txt -s prod --notify https://hooks.slack.com/...

# reproduce the NocoDB open-registration finding (intrusive template)
python3 gridscan.py noco.example.com --intrusive --tags misconfig
```

Outputs land in `./out/<scope>.report.md` (human) and
`./out/<scope>.findings.json` (machine / Grid ingest). State persists in
`gridscan.db`.

### Key flags

| flag | meaning |
|------|---------|
| `--intrusive` | allow `intrusive` templates (create accounts, etc.). **Off by default.** Required to catch things like the NocoDB open-signup finding. Only ever point at infra you own. |
| `--severity` | which severities to include (default `low,medium,high,critical`) |
| `--tags` | restrict to template tags, e.g. `misconfig,cve,exposure` |
| `--rate` | Nuclei rate limit, req/s (default 150) |
| `--db` | SQLite state file (swap per environment) |
| `--workdir` | keep intermediate files for debugging instead of a temp dir |

## Scheduling (the "continuous scanning" part of PDCP)

A cron entry or systemd timer is all the "continuous" you need for one org:

```cron
0 3 * * *  cd /opt/gridscan && /usr/bin/python3 gridscan.py -f scope.txt -s prod \
             --notify "$SLACK_WEBHOOK" >> /var/log/gridscan.log 2>&1
```

## What this replaces vs PDCP — and the honest gaps

| PDCP capability | gridscan |
|---|---|
| Discovery + Nuclei detection | ✅ same OSS tools |
| Asset inventory, first/last-seen | ✅ `assets` table |
| Finding dedup + lifecycle (their `vuln_hash`) | ✅ stable `finding_key = sha1(template_id\|matched_at\|matcher_name)` |
| Continuous scanning | ✅ cron / systemd timer |
| Notifications | ✅ webhook (`--notify`) |
| Internal-network reach | ✅ you're already inside it |
| Massively parallel engine (35–50× faster) | ⚠️ single-box; irrelevant at one-org scale. Shard the target list across workers if scans get slow. |
| Autonomous exploit validation (Neo) | ⚠️ partial: new/reappeared reflected-XSS and time-based-blind SQLi findings get a non-destructive differential re-test (reflection-encoding check; timing differential against a neutralized control payload) to cut false positives before human triage. Not real exploitation, and only these two classes — everything else still gets human triage as-is. |

## Grid integration

`<scope>.findings.json` is the ingest surface. Its `open_findings[]` array is
already flattened (template_id, severity, host, matched_at, first_seen, …), so a
thin adapter can upsert it into whichever side of GridPulse's SQLite/Postgres
model you want, and Sentinel can treat confirmed-bad findings as a detection
source — closing the "gridwatch runs separately" gap rather than standing up a
second dashboard.

The `store.py` logic (the `Store` class) is deliberately the only DB-aware part;
swap SQLite for Postgres there without touching the pipeline.

## Scope discipline

`--intrusive` templates take real actions against targets (the NocoDB template
creates an account). Only run this against assets you own or are explicitly
authorised to test.
