#!/usr/bin/env python3
"""
gridscan - self-hosted attack-surface scanner.

Give it a target (domain, IP, CIDR, or a file of targets) and it runs the same
flow a hosted ASM platform runs: discover -> probe -> scan -> deduped findings
with lifecycle tracking. Engine is Nuclei; discovery is the ProjectDiscovery
OSS chain (subfinder/dnsx/naabu/httpx). State lives in SQLite so findings get
first_seen/last_seen/resolved lifecycle instead of a fresh dump every run.

This tool only orchestrates other tools + manages state. It does no scanning of
its own. Point it only at infrastructure you own or are authorised to test.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import shutil
import smtplib
import sqlite3
import subprocess
import sys
import tempfile
import urllib.request
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------

# Live/current-run log file, separate from the stderr->journal path: lets
# gridscan-ui tail a running scan without needing journal-group access (it
# doesn't have that, but it is in the `gridscan` group and this file lives
# under a group-readable directory - see LIVE_LOG_PATH default). This is a
# "current run" view only, truncated at the start of every scan() call - not
# a cumulative history (per-run historical reports are a separate feature).
LIVE_LOG_PATH = os.environ.get("GRIDSCAN_LIVE_LOG", "/var/lib/gridscan/logs/current.log")

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def _reset_live_log() -> None:
    """Truncate (or create) the live log file fresh. Called at the start of
    scan(). Best-effort: if the directory can't be created or the file can't
    be written (e.g. permissions not set up yet at a fresh deployment), this
    must never fail the scan - it's a cosmetic feature."""
    try:
        path = Path(LIVE_LOG_PATH)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("")
    except OSError:
        pass

def _append_live_log(line: str) -> None:
    """Best-effort append of one already-formatted log line to the live log
    file. Same never-fail-the-scan contract as _reset_live_log() above."""
    try:
        path = Path(LIVE_LOG_PATH)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a") as f:
            f.write(line + "\n")
    except OSError:
        pass

def log(msg: str) -> None:
    line = f"[{datetime.now().strftime('%H:%M:%S')}] {msg}"
    print(line, file=sys.stderr)
    _append_live_log(line)

def have(tool: str) -> bool:
    return shutil.which(tool) is not None

def classify(target: str) -> str:
    """Return one of: url, cidr, ip, domain."""
    t = target.strip()
    if t.startswith(("http://", "https://")):
        return "url"
    try:
        ipaddress.ip_network(t, strict=False)
        return "cidr" if "/" in t else "ip"
    except ValueError:
        return "domain"

def read_targets(args_targets: list[str], target_file: str | None) -> list[str]:
    targets: list[str] = list(args_targets)
    if target_file:
        for line in Path(target_file).read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                targets.append(line)
    # de-dup, preserve order
    seen, out = set(), []
    for t in targets:
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out


# ---------------------------------------------------------------------------
# tool wrappers  (file-based handoff -> auditable, resumable, debuggable)
# ---------------------------------------------------------------------------

def run(cmd: list[str], stdin_file: str | None = None) -> str:
    """Run a command, return stdout. Raises on non-zero exit."""
    log("  $ " + " ".join(cmd))
    stdin = open(stdin_file) if stdin_file else None
    try:
        proc = subprocess.run(
            cmd, stdin=stdin, capture_output=True, text=True, check=False
        )
    finally:
        if stdin:
            stdin.close()
    if proc.returncode != 0:
        log(f"  ! {cmd[0]} exited {proc.returncode}: {proc.stderr.strip()[:300]}")
    return proc.stdout


def step_subfinder(domain: str, work: Path) -> Path:
    work.mkdir(parents=True, exist_ok=True)
    out = work / "subdomains.txt"
    if not have("subfinder"):
        log("  subfinder missing -> using bare domain only")
        out.write_text(domain + "\n")
        return out
    data = run(["subfinder", "-d", domain, "-silent", "-all"])
    hosts = set(data.split()) | {domain}
    out.write_text("\n".join(sorted(hosts)) + "\n")
    log(f"  subfinder: {len(hosts)} hosts")
    return out


def step_dnsx(hosts_file: Path, work: Path) -> Path:
    out = work / "resolved.txt"
    if not have("dnsx"):
        shutil.copy(hosts_file, out)
        return out
    data = run(["dnsx", "-silent", "-l", str(hosts_file)])
    out.write_text(data if data.strip() else hosts_file.read_text())
    return out


def step_naabu(hosts_file: Path, work: Path, top_ports: str) -> Path:
    """Returns a file of host:port lines. Falls back to input if naabu absent."""
    out = work / "ports.txt"
    if not have("naabu"):
        log("  naabu missing -> httpx will probe default web ports")
        shutil.copy(hosts_file, out)
        return out
    data = run(["naabu", "-silent", "-l", str(hosts_file), "-top-ports", top_ports])
    out.write_text(data)
    log(f"  naabu: {len(data.split())} open host:port")
    return out


def step_httpx(targets_file: Path, work: Path) -> tuple[Path, Path]:
    """Probe for live HTTP services. Returns (urls_file, jsonl_file)."""
    urls = work / "live_urls.txt"
    j = work / "httpx.jsonl"
    if not have("httpx"):
        log("  httpx missing -> assuming https:// for every target")
        lines = [
            t if t.startswith("http") else f"https://{t}"
            for t in targets_file.read_text().split()
        ]
        urls.write_text("\n".join(lines) + "\n")
        j.write_text("")
        return urls, j
    data = run([
        "httpx", "-silent", "-l", str(targets_file),
        "-json", "-tech-detect", "-status-code", "-title",
        "-no-color",
    ])
    j.write_text(data)
    live = []
    for line in data.splitlines():
        try:
            live.append(json.loads(line)["url"])
        except (json.JSONDecodeError, KeyError):
            continue
    urls.write_text("\n".join(live) + "\n")
    log(f"  httpx: {len(live)} live services")
    return urls, j


def parse_httpx_items(httpx_jsonl: Path) -> list[dict]:
    """Parse httpx's JSONL output (as written by step_httpx() above) into the
    same per-service fields Store.ingest_assets() persists to the `assets`
    table: url, host, port, tech, status_code, title. Shared by
    ingest_assets() (DB write, used by a real scan) and discover() (JSON
    preview, no DB write, used by --discover-only) so a discovery preview and
    a real scan always agree exactly on what "a live service" looks like -
    this is the one place that reads httpx.jsonl's shape."""
    items: list[dict] = []
    for line in (httpx_jsonl.read_text().splitlines() if httpx_jsonl.exists() else []):
        try:
            a = json.loads(line)
        except json.JSONDecodeError:
            continue
        items.append({
            "url": a.get("url"),
            "host": a.get("host"),
            "port": a.get("port"),
            "tech": a.get("tech", []),
            "status_code": a.get("status_code"),
            "title": a.get("title"),
        })
    return items


def step_nuclei(urls_file: Path, work: Path, severity: str,
                tags: str | None, intrusive: bool, rate: int) -> Path:
    out = work / "findings.jsonl"
    if not have("nuclei"):
        log("  ! nuclei missing -> cannot scan. install it (see README).")
        out.write_text("")
        return out
    cmd = [
        "nuclei", "-l", str(urls_file), "-jsonl", "-o", str(out),
        "-severity", severity, "-rate-limit", str(rate),
        "-no-color", "-silent",
    ]
    if tags:
        cmd += ["-tags", tags]
    if not intrusive:
        cmd += ["-exclude-tags", "intrusive"]
    run(cmd)
    n = sum(1 for _ in out.open()) if out.exists() else 0
    log(f"  nuclei: {n} raw findings")
    return out


# ---------------------------------------------------------------------------
# state store (SQLite) + lifecycle
# ---------------------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    finding_key TEXT PRIMARY KEY,
    scope       TEXT NOT NULL,
    template_id TEXT, name TEXT, severity TEXT,
    host TEXT, matched_at TEXT, matcher_name TEXT,
    extracted TEXT, type TEXT,
    status TEXT NOT NULL DEFAULT 'open',    -- open | resolved
    triage_status TEXT NOT NULL DEFAULT 'unreviewed',
    first_seen TEXT, last_seen TEXT, resolved_at TEXT
);
CREATE TABLE IF NOT EXISTS assets (
    scope TEXT NOT NULL, url TEXT NOT NULL,
    host TEXT, port INTEGER, tech TEXT, status_code INTEGER, title TEXT,
    first_seen TEXT, last_seen TEXT,
    triage_status TEXT NOT NULL DEFAULT 'unreviewed',
    PRIMARY KEY (scope, url)
);
CREATE TABLE IF NOT EXISTS runs (
    run_id INTEGER PRIMARY KEY AUTOINCREMENT,
    scope TEXT, started_at TEXT, finished_at TEXT, targets TEXT, summary TEXT,
    triggered_by TEXT NOT NULL DEFAULT 'scheduler'
);
"""

# /var/lib/gridscan/discovery, not /etc/gridscan: the scanning systemd units
# (gridscan.service etc.) only have ReadWritePaths=/var/lib/gridscan under
# ProtectSystem=strict - /etc/gridscan is read-only there, so a marker placed
# in /etc/gridscan could be read but never deleted by the scanner, and a
# failed unlink() would silently discard an already-read value (real bug,
# caught in production: the DB kept showing "scheduler" and the file was
# never consumed). gridscan-ui already has ReadWritePaths on this exact
# discovery dir too (for SELECTED_URLS_FILE), so both sides can read+write.
TRIGGERED_BY_FILE = os.environ.get("GRIDSCAN_TRIGGERED_BY_FILE", "/var/lib/gridscan/discovery/triggered_by.txt")


def consume_triggered_by() -> str:
    """Best-effort: gridscan-ui writes the acting username here right before
    starting a scan unit; the daily timer never writes it, so an absent/empty
    file correctly means 'scheduler'. Consumed (deleted) on read so a stale
    value can't leak into the next (e.g. timer-driven) run."""
    path = Path(TRIGGERED_BY_FILE)
    try:
        user = path.read_text().strip()
        path.unlink(missing_ok=True)
    except OSError:
        return "scheduler"
    return user or "scheduler"


def run_filename(scope: str, started_iso: str, triggered_by: str, ext: str) -> str:
    dt = datetime.fromisoformat(started_iso).strftime("%Y%m%d-%H%M%S")
    safe_user = re.sub(r"[^A-Za-z0-9_.-]", "_", triggered_by)
    return f"{scope}_{dt}_{safe_user}.{ext}"

def finding_key(f: dict) -> str:
    raw = f"{f.get('template-id')}|{f.get('matched-at')}|{f.get('matcher-name','')}"
    return hashlib.sha1(raw.encode()).hexdigest()

def flatten(f: dict) -> dict:
    info = f.get("info", {})
    return {
        "template_id": f.get("template-id"),
        "name": info.get("name"),
        "severity": info.get("severity", "unknown"),
        "host": f.get("host"),
        "matched_at": f.get("matched-at"),
        "matcher_name": f.get("matcher-name", ""),
        "extracted": json.dumps(f.get("extracted-results", [])),
        "type": f.get("type"),
    }


class Store:
    def __init__(self, path: str):
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        self._migrate_assets_triage_status()
        self._migrate_runs_triggered_by()
        self._migrate_findings_triage_status()

    def _migrate_assets_triage_status(self) -> None:
        """Idempotent migration for DBs created before the assets-triage
        feature: CREATE TABLE IF NOT EXISTS above is a no-op on a table that
        already exists, so it never adds `triage_status` to a pre-existing
        assets table on its own. Check PRAGMA table_info(assets) for the
        column and ALTER TABLE ADD COLUMN it in if missing. Safe to call on
        every Store() construction (brand-new DBs already have the column
        from the CREATE TABLE above, so this is a no-op for them too)."""
        cols = [row[1] for row in self.db.execute("PRAGMA table_info(assets)").fetchall()]
        if "triage_status" not in cols:
            self.db.execute(
                "ALTER TABLE assets ADD COLUMN triage_status TEXT NOT NULL DEFAULT 'unreviewed'"
            )
            self.db.commit()

    def _migrate_runs_triggered_by(self) -> None:
        """Same idempotent-ALTER pattern as _migrate_assets_triage_status,
        for DBs created before per-run report filenames needed the actor."""
        cols = [row[1] for row in self.db.execute("PRAGMA table_info(runs)").fetchall()]
        if "triggered_by" not in cols:
            self.db.execute(
                "ALTER TABLE runs ADD COLUMN triggered_by TEXT NOT NULL DEFAULT 'scheduler'"
            )
            self.db.commit()

    def _migrate_findings_triage_status(self) -> None:
        """Same idempotent-ALTER pattern as _migrate_assets_triage_status, for
        DBs created before findings got their own (vulnerability-specific)
        triage vocabulary, separate from the assets one."""
        cols = [row[1] for row in self.db.execute("PRAGMA table_info(findings)").fetchall()]
        if "triage_status" not in cols:
            self.db.execute(
                "ALTER TABLE findings ADD COLUMN triage_status TEXT NOT NULL DEFAULT 'unreviewed'"
            )
            self.db.commit()

    def ingest_findings(self, scope: str, jsonl: Path, covered_hosts: set[str] | None = None) -> dict:
        ts = now_iso()
        seen: set[str] = set()
        new, reappeared = [], []

        prior = {
            r["finding_key"]: dict(r)
            for r in self.db.execute(
                "SELECT finding_key, status, host, template_id, name, severity, matched_at"
                " FROM findings WHERE scope=?", (scope,)
            )
        }

        for line in (jsonl.read_text().splitlines() if jsonl.exists() else []):
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                continue
            k = finding_key(raw)
            seen.add(k)
            row = flatten(raw)
            if k not in prior:
                new.append((k, row))
                self.db.execute(
                    """INSERT INTO findings
                       (finding_key, scope, template_id, name, severity, host,
                        matched_at, matcher_name, extracted, type,
                        status, first_seen, last_seen)
                       VALUES (?,?,?,?,?,?,?,?,?,?, 'open', ?, ?)""",
                    (k, scope, row["template_id"], row["name"], row["severity"],
                     row["host"], row["matched_at"], row["matcher_name"],
                     row["extracted"], row["type"], ts, ts),
                )
                prior[k] = {"status": "open", "host": row["host"], "template_id": row["template_id"],
                            "name": row["name"], "severity": row["severity"], "matched_at": row["matched_at"]}
            else:
                if prior[k]["status"] == "resolved":
                    reappeared.append((k, row))
                self.db.execute(
                    """UPDATE findings SET last_seen=?, status='open',
                       resolved_at=NULL, severity=?, name=? WHERE finding_key=?""",
                    (ts, row["severity"], row["name"], k),
                )

        # Anything previously open, not seen this run, AND on a host this run
        # actually covered -> resolved. covered_hosts=None (a normal full-scope
        # scan) keeps the old "not seen -> resolved" behavior; a curated/partial
        # run (--urls-file) or any host that didn't respond this time must never
        # silently "fix" findings on hosts it never reached - that was a real
        # recurring bug (a narrow scan under the same scope marked everything
        # else as falsely resolved).
        resolved = [
            k for k, info in prior.items()
            if info["status"] == "open" and k not in seen
            and (covered_hosts is None or info["host"] in covered_hosts)
        ]
        for k in resolved:
            self.db.execute(
                "UPDATE findings SET status='resolved', resolved_at=? WHERE finding_key=?",
                (ts, k),
            )

        self.db.commit()
        return {
            "new": len(new), "reappeared": len(reappeared),
            "resolved": len(resolved), "total_seen": len(seen),
            "new_items": [r for _, r in new],
            "reappeared_items": [r for _, r in reappeared],
            "resolved_items": [prior[k] for k in resolved],
        }

    def ingest_assets(self, scope: str, httpx_jsonl: Path) -> int:
        ts = now_iso()
        n = 0
        for a in parse_httpx_items(httpx_jsonl):
            self.db.execute(
                """INSERT INTO assets (scope, url, host, port, tech, status_code, title, first_seen, last_seen)
                   VALUES (?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(scope, url) DO UPDATE SET
                     last_seen=excluded.last_seen, tech=excluded.tech,
                     status_code=excluded.status_code, title=excluded.title""",
                (scope, a.get("url"), a.get("host"), a.get("port"),
                 json.dumps(a.get("tech", [])), a.get("status_code"),
                 a.get("title"), ts, ts),
            )
            n += 1
        self.db.commit()
        return n

    def open_findings(self, scope: str) -> list[sqlite3.Row]:
        return list(self.db.execute(
            "SELECT * FROM findings WHERE scope=? AND status='open' "
            "ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
            "WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, template_id",
            (scope,),
        ))

    def record_run(self, scope, started, targets, summary, triggered_by="scheduler") -> int:
        """Insert the run row and return its new run_id (AUTOINCREMENT), via
        cursor.lastrowid on the same connection/cursor that did the INSERT -
        verified directly against this schema (INTEGER PRIMARY KEY
        AUTOINCREMENT) to return the actual row id, not just "rowid of last
        insert on this connection" in some looser sense."""
        cur = self.db.execute(
            "INSERT INTO runs (scope, started_at, finished_at, targets, summary, triggered_by) VALUES (?,?,?,?,?,?)",
            (scope, started, now_iso(), json.dumps(targets), json.dumps(summary), triggered_by),
        )
        self.db.commit()
        return cur.lastrowid


# ---------------------------------------------------------------------------
# report + notify
# ---------------------------------------------------------------------------

def build_report(scope: str, store: Store, delta: dict) -> str:
    rows = store.open_findings(scope)
    by_sev: dict[str, list] = {}
    for r in rows:
        by_sev.setdefault(r["severity"], []).append(r)

    order = ["critical", "high", "medium", "low", "info", "unknown"]
    lines = [f"# gridscan report - {scope}", "", f"_Generated {now_iso()}_", ""]
    counts = " | ".join(
        f"{s}: {len(by_sev.get(s, []))}" for s in order if by_sev.get(s)
    ) or "no open findings"
    lines += [f"**Open findings:** {counts}", ""]
    lines += [
        f"**This run:** {delta['new']} new, {delta['reappeared']} reappeared, "
        f"{delta['resolved']} resolved.", "",
    ]

    for sev in order:
        items = by_sev.get(sev)
        if not items:
            continue
        lines += [f"## {sev.upper()} ({len(items)})", ""]
        for r in items:
            extra = json.loads(r["extracted"] or "[]")
            extra_s = f" — {', '.join(extra)}" if extra else ""
            first = (r["first_seen"] or "")[:10]
            lines.append(f"- **{r['name'] or r['template_id']}** (`{r['template_id']}`)")
            lines.append(f"  - {r['matched_at']}{extra_s}")
            lines.append(f"  - first seen {first}")
        lines.append("")
    return "\n".join(lines)


def notify(webhook: str, scope: str, delta: dict) -> None:
    crit_high = [i for i in delta["new_items"] if i["severity"] in ("critical", "high")]
    if not delta["new"] and not delta["resolved"]:
        return
    text = (f"*gridscan* `{scope}`: {delta['new']} new "
            f"({len(crit_high)} crit/high), {delta['resolved']} resolved, "
            f"{delta['reappeared']} reappeared.")
    for i in crit_high[:10]:
        text += f"\n• [{i['severity']}] {i['name']} — {i['matched_at']}"
    try:
        req = urllib.request.Request(
            webhook, data=json.dumps({"text": text}).encode(),
            headers={"Content-Type": "application/json"},
        )
        urllib.request.urlopen(req, timeout=10)
        log("  notify: sent")
    except Exception as e:  # noqa: BLE001
        log(f"  ! notify failed: {e}")


def notify_email(scope: str, delta: dict) -> None:
    """Email counterpart to notify() above - same trigger condition (skip
    unless there are new or resolved findings this run), same
    never-crash-the-scan-over-a-failed-notification resilience (log() and
    return, don't raise). Config comes straight from os.environ (SMTP_HOST/
    SMTP_PORT/SMTP_USERNAME/SMTP_PASSWORD/SMTP_FROM/SMTP_TO), same as
    SLACK_WEBHOOK is wired in as an env var for this notify path - if
    SMTP_HOST isn't set, email is simply not configured and this is a silent
    no-op, same as an unset --notify skips notify()."""
    if not delta["new"] and not delta["resolved"]:
        return

    host = os.environ.get("SMTP_HOST")
    if not host:
        return  # email not configured - optional feature, skip silently

    try:
        port = int(os.environ.get("SMTP_PORT", "") or 25)
    except ValueError:
        port = 25
    username = os.environ.get("SMTP_USERNAME", "")
    password = os.environ.get("SMTP_PASSWORD", "")
    from_addr = os.environ.get("SMTP_FROM") or username
    to_addr = os.environ.get("SMTP_TO", "")
    if not from_addr or not to_addr:
        log("  ! notify_email skipped: SMTP_FROM/SMTP_TO not configured")
        return

    crit_high = [i for i in delta["new_items"] if i["severity"] in ("critical", "high")]
    subject = (f"gridscan {scope}: {delta['new']} new "
               f"({len(crit_high)} crit/high), {delta['resolved']} resolved")

    body_lines = [
        f"gridscan report for scope: {scope}",
        "",
        f"{delta['new']} new, {delta['reappeared']} reappeared, "
        f"{delta['resolved']} resolved this run.",
        "",
    ]
    if crit_high:
        body_lines.append("New critical/high findings:")
        for i in crit_high[:20]:
            body_lines.append(f"  - [{i['severity']}] {i['name']} - {i['matched_at']}")
        body_lines.append("")
    body_lines.append("See the gridscan-ui dashboard for the full report.")

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = to_addr
    msg.set_content("\n".join(body_lines))

    try:
        with smtplib.SMTP(host, port, timeout=10) as smtp:
            smtp.ehlo()
            try:
                if smtp.has_extn("starttls"):
                    smtp.starttls()
                    smtp.ehlo()
            except smtplib.SMTPException:
                pass  # best-effort: fall back to unencrypted rather than failing
            if username and password:
                smtp.login(username, password)
            smtp.send_message(msg)
        log("  notify_email: sent")
    except Exception as e:  # noqa: BLE001
        log(f"  ! notify_email failed: {e}")


# ---------------------------------------------------------------------------
# pipeline
# ---------------------------------------------------------------------------

def discover(targets: list[str], args, work: Path) -> tuple[Path, Path, list[dict]]:
    """Discovery + probe phase only: subfinder/dnsx (subdomains), naabu (port
    discovery for IP/CIDR targets), httpx (live-service probe + tech
    detection). Extracted from scan() so the full scan() pipeline and the
    --discover-only CLI mode (human-reviewed preview, no nuclei, no DB
    writes) share this exact logic instead of it being duplicated.

    Returns (live_urls_file, httpx_jsonl_file, items) where `items` is the
    same per-service list (url, host, port, tech, status_code, title) that
    Store.ingest_assets() persists - see parse_httpx_items()."""
    domains = [t for t in targets if classify(t) == "domain"]
    nets = [t for t in targets if classify(t) in ("ip", "cidr")]
    urls = [t for t in targets if classify(t) == "url"]

    probe_input = work / "probe_input.txt"
    pooled: list[str] = list(urls)

    # domains -> subdomain discovery -> resolve
    if domains:
        log("discovery: domains")
        all_hosts = work / "hosts.txt"
        hostset: set[str] = set()
        for d in domains:
            sub = step_subfinder(d, work / d.replace("/", "_"))
            hostset |= set(sub.read_text().split())
        all_hosts.write_text("\n".join(sorted(hostset)) + "\n")
        resolved = step_dnsx(all_hosts, work)
        pooled += resolved.read_text().split()

    # ips/cidrs -> port scan
    if nets:
        log("discovery: ip ranges")
        netfile = work / "nets.txt"
        netfile.write_text("\n".join(nets) + "\n")
        ports = step_naabu(netfile, work, args.top_ports)
        pooled += ports.read_text().split()

    probe_input.write_text("\n".join(sorted(set(pooled))) + "\n")

    log("probe: httpx")
    live_urls, httpx_json = step_httpx(probe_input, work)
    items = parse_httpx_items(httpx_json)
    return live_urls, httpx_json, items


def _hosts_from_urls_file(path: Path) -> set[str]:
    hosts = set()
    for line in path.read_text().splitlines():
        line = line.strip()
        host = urlparse(line).hostname if line else None
        if host:
            hosts.add(host)
    return hosts


def _finish_scan(scope: str, store: Store, started: str, targets: list,
                  httpx_json: Path | None, findings: Path, args,
                  covered_hosts: set[str] | None = None) -> None:
    """Shared tail for a real scan, used by both scan() (normal, fully
    auto-discovered pipeline) and scan_urls_file() (--urls-file: nuclei runs
    against a human-curated URL list instead): ingest assets (only if a
    httpx.jsonl actually exists - scan() always has one from discover();
    --urls-file has none, since it skips probing entirely) + findings, write
    the latest and per-run-snapshot report/findings-JSON files, record the
    run, and notify. --discover-only never reaches this function - it has no
    findings to ingest and must not touch runs/findings at all."""
    if httpx_json is not None:
        store.ingest_assets(scope, httpx_json)
    delta = store.ingest_findings(scope, findings, covered_hosts)

    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)
    report_md = build_report(scope, store, delta)
    (out_dir / f"{scope}.report.md").write_text(report_md)

    delta_counts = {"new": delta["new"], "reappeared": delta["reappeared"],
                     "resolved": delta["resolved"], "total_seen": delta["total_seen"]}

    open_rows = [dict(r) for r in store.open_findings(scope)]
    findings_json = json.dumps(
        {"scope": scope, "generated": now_iso(),
         "delta": delta_counts,
         # Full objects for "what changed this scan", not just counts - the
         # per-run snapshot is the only place this is ever persisted.
         "new_items": delta["new_items"],
         "reappeared_items": delta["reappeared_items"],
         "resolved_items": delta["resolved_items"],
         "open_findings": open_rows}, indent=2,
    )
    (out_dir / f"{scope}.findings.json").write_text(findings_json)

    triggered_by = consume_triggered_by()
    store.record_run(scope, started, targets, delta_counts, triggered_by)

    # Per-run historical snapshot (additive - the "latest" files above are
    # unchanged): same report_md/findings_json content already computed for
    # this run, also written under a self-describing filename
    # (scope_date-time_user) so each scan is its own file in `ls` output,
    # not just an opaque run_id.
    (out_dir / run_filename(scope, started, triggered_by, "report.md")).write_text(report_md)
    (out_dir / run_filename(scope, started, triggered_by, "findings.json")).write_text(findings_json)

    if args.notify:
        notify(args.notify, scope, delta)
    notify_email(scope, delta)

    log(f"done: {delta['new']} new / {delta['resolved']} resolved / "
        f"{len(open_rows)} open. reports in {out_dir}/")
    print(f"\n{report_md}")


def scan(targets: list[str], args) -> None:
    _reset_live_log()  # fresh live-log for this run, before any log() calls below
    started = now_iso()
    scope = args.scope or (targets[0] if targets else "default")
    store = Store(args.db)

    with tempfile.TemporaryDirectory(prefix="gridscan_") as tmp:
        work = Path(args.workdir) if args.workdir else Path(tmp)
        work.mkdir(parents=True, exist_ok=True)

        live_urls, httpx_json, _items = discover(targets, args, work)

        log("scan: nuclei")
        findings = step_nuclei(
            live_urls, work, args.severity, args.tags,
            args.intrusive, args.rate,
        )

        log("state: ingest")
        _finish_scan(scope, store, started, targets, httpx_json, findings, args,
                     covered_hosts=_hosts_from_urls_file(live_urls))


def scan_urls_file(urls: list[str], args) -> None:
    """--urls-file CLI mode: skip discover() entirely (no subfinder/dnsx/
    naabu/httpx calls at all) and feed a human-curated, already-probed URL
    list straight into nuclei, then continue with the exact same
    ingest/report/notify/record_run tail a normal scan() run gets (see
    _finish_scan()) - this is a real scan, findings DO get written to the
    DB, unlike --discover-only.

    Note: the `targets` value passed to record_run() here is the curated URL
    list itself (there is no separate "declared scope targets" list in this
    mode - normal target/--target-file input is rejected alongside
    --urls-file, see main()). The runs.targets column for this run will
    therefore show the specific URLs that were scanned, not a domain/CIDR
    scope declaration - that's a reasonable, simple choice; the exact
    selected subset is implicit in what findings got created either way."""
    _reset_live_log()
    started = now_iso()
    scope = args.scope or "default"
    store = Store(args.db)

    with tempfile.TemporaryDirectory(prefix="gridscan_") as tmp:
        work = Path(args.workdir) if args.workdir else Path(tmp)
        work.mkdir(parents=True, exist_ok=True)

        live_urls = work / "live_urls.txt"
        live_urls.write_text("\n".join(urls) + "\n")

        log(f"scan (curated URL list, {len(urls)} urls): nuclei")
        findings = step_nuclei(
            live_urls, work, args.severity, args.tags,
            args.intrusive, args.rate,
        )

        log("state: ingest")
        _finish_scan(scope, store, started, urls, None, findings, args,
                     covered_hosts=_hosts_from_urls_file(live_urls))


def run_discover_only(targets: list[str], args) -> None:
    """--discover-only CLI mode: run discover() (subfinder/dnsx/naabu/httpx)
    and write its results as a JSON preview file, then exit. No nuclei call,
    and no Store()/DB access at all in this function - runs/findings tables
    are completely untouched, this is a preview, not a real scan."""
    _reset_live_log()
    scope = args.scope or (targets[0] if targets else "default")

    with tempfile.TemporaryDirectory(prefix="gridscan_") as tmp:
        work = Path(args.workdir) if args.workdir else Path(tmp)
        work.mkdir(parents=True, exist_ok=True)
        _live_urls, _httpx_json, items = discover(targets, args, work)

    out_path = (
        Path(args.discover_output) if args.discover_output
        else Path(args.output) / f"{scope}.discovery.json"
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"scope": scope, "generated": now_iso(), "items": items}
    out_path.write_text(json.dumps(payload, indent=2))
    log(f"discover-only: {len(items)} live services -> {out_path}")


# ---------------------------------------------------------------------------
# cli
# ---------------------------------------------------------------------------

def main() -> None:
    p = argparse.ArgumentParser(
        prog="gridscan",
        description="Self-hosted attack-surface scanner (Nuclei + PD OSS chain).",
    )
    p.add_argument("targets", nargs="*", help="domain, IP, CIDR, or URL")
    p.add_argument("-f", "--target-file", help="file with one target per line")
    p.add_argument("-s", "--scope", help="logical scope name (default: first target)")
    p.add_argument("--db", default="gridscan.db", help="SQLite state DB")
    p.add_argument("-o", "--output", default="./out", help="report output dir")
    p.add_argument("--workdir", help="keep intermediate files here (default: temp)")
    p.add_argument("--severity", default="low,medium,high,critical",
                   help="nuclei severities to include")
    p.add_argument("--tags", help="restrict to nuclei template tags (e.g. misconfig,cve)")
    p.add_argument("--intrusive", action="store_true",
                   help="allow intrusive templates (create accounts, etc.) - "
                        "REQUIRED to reproduce findings like NocoDB open-signup. "
                        "Off by default; only use on infra you own.")
    p.add_argument("--rate", type=int, default=150, help="nuclei rate limit (req/s)")
    p.add_argument("--top-ports", default="100", help="naabu top-ports for IP ranges")
    p.add_argument("--notify", help="webhook URL for new crit/high findings")
    p.add_argument(
        "--discover-only", action="store_true",
        help="run discovery+probe only (subfinder/dnsx/naabu/httpx), write a JSON "
             "preview of live services to --discover-output and exit - no nuclei "
             "call, no DB writes (runs/findings tables untouched). Still needs "
             "targets/--target-file, same as a normal scan. Mutually exclusive "
             "with --urls-file.",
    )
    p.add_argument(
        "--discover-output",
        help="where to write --discover-only's JSON preview "
             "(default: <output>/<scope>.discovery.json). Only valid with --discover-only.",
    )
    p.add_argument(
        "--urls-file",
        help="skip discovery/probing entirely and run nuclei directly against this "
             "newline-separated file of URLs - a real scan (findings ARE written to "
             "the DB), just against a human-curated URL list instead of freshly "
             "auto-discovered targets. Mutually exclusive with --discover-only and "
             "with positional targets/--target-file.",
    )
    args = p.parse_args()

    if args.discover_only and args.urls_file:
        p.error("--discover-only and --urls-file are mutually exclusive")
    if args.discover_output and not args.discover_only:
        p.error("--discover-output only applies together with --discover-only")
    if args.urls_file and (args.targets or args.target_file):
        p.error(
            "--urls-file replaces target discovery input - do not also pass "
            "positional targets or --target-file"
        )

    if args.urls_file:
        urls = [
            line.strip() for line in Path(args.urls_file).read_text().splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        if not urls:
            p.error(f"--urls-file {args.urls_file} contains no URLs")
        if not have("nuclei"):
            log("WARNING: nuclei not found on PATH. Detection will be skipped. "
                "See README for install.")
        scan_urls_file(urls, args)
        return

    targets = read_targets(args.targets, args.target_file)
    if not targets:
        p.error("no targets given (positional args or --target-file)")

    if args.discover_only:
        run_discover_only(targets, args)
        return

    if not have("nuclei"):
        log("WARNING: nuclei not found on PATH. Detection will be skipped. "
            "See README for install.")
    scan(targets, args)


if __name__ == "__main__":
    main()
