# gridscan — MVP to full-fledged: roadmap

Working notes from a 2026-07-28 planning discussion on what's next after the initial
build (scanner + management UI + review/triage workflow + non-destructive XSS/SQLi
verification). Four buckets, in recommended priority order for a single-org,
~3-domain deployment.

## 1. Operational resilience (recommended first)

- **No external monitoring of the scanner/VM itself.** If the host or the daily
  timer silently dies, nothing alerts anyone. This already bit once: the VM became
  fully unreachable due to a local Tailscale outage, with no signal until someone
  happened to check. A simple external heartbeat / dead-man's-switch (e.g. the
  scanner pings a healthcheck URL on every successful run; alert if it doesn't fire
  within N hours) closes this cheaply.
- **No DB backup/restore story.** `gridscan.db` is the entire finding history. One
  corrupted file (crash mid-write, bad disk) loses everything with no way back.
  Needs a scheduled backup (even a simple `sqlite3 .backup` cron to another disk/
  off-box target) and a documented restore procedure.
- **No deploy pipeline.** Every change so far has been manual `scp` + service
  restart directly against the production VM. Works today; risky as change volume
  grows. Worth at least a scripted deploy (not necessarily full CI/CD) so a deploy
  can't be a stray typo away from breaking prod.

## 2. Detection breadth

- Non-destructive verification (shipped 2026-07-28) only covers reflected-XSS and
  time-based-blind SQLi. Every other finding class still gets zero automated
  confidence signal — pure human triage.
- No subdomain-takeover-specific logic beyond whatever nuclei's own templates
  already catch.
- No WAF/CDN-awareness — a target sitting behind Cloudflare etc. could cause
  silent false negatives that look identical to "nothing found."
- Template updates are manual (`nuclei -update-templates`), not scheduled.
- Single fixed daily cadence, no differential "scan changed/new hosts more often"
  logic.

## 3. Product completeness (the UI)

- Auth is local username/password only — no SSO, no 2FA.
- No historical trend charts (findings over time, by severity).
- No ticketing integration (Jira/Linear) — findings don't create/sync tickets.
- Audit trail is a flat text log, not structured/queryable.
- Test coverage is ad hoc scratch scripts run during development, not a real,
  repeatable test suite.

## 4. Scale — explicitly not worth it right now

Single-box, SQLite, one daily timer. The README already says this correctly:
irrelevant at ~3-domain, one-org scale. Don't build multi-worker sharding or a
bigger DB engine speculatively — revisit only if scope grows materially.

## Recommendation

Start with **#1** — the heartbeat/dead-man's-switch and DB backup are each a few
hours of work and directly prevent a failure mode already experienced firsthand.
Let #2 and #3 be driven by whatever actually turns out to be annoying in practice,
rather than building any of it speculatively.
