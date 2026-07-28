"""
gridscan-ui backend.

FastAPI management API for the gridscan security scanner. Reads/writes the
same SQLite DB, scope file, and env file that gridscan.py (the scan engine)
uses. It does not modify gridscan.py's schema and reuses gridscan.py's own
Store class and classify() target-classification logic directly (imported
from the local gridscan.py copy in this same directory - see the module
docstring in that file for provenance; it is an unmodified copy of the
deployed scanner script).

Environment variables (all optional unless noted):
  GRIDSCAN_UI_SECRET_KEY   REQUIRED. Signing key for session cookies. The app
                           refuses to start without this - no default secret.
  GRIDSCAN_UI_DB           Path to the gridscan-ui SQLite users DB (multi-user,
                           two-role auth store - separate from GRIDSCAN_DB
                           below, which is the scanner's own state DB and is
                           never touched by the user-auth code). Default
                           /var/lib/gridscan-ui/gridscan_ui.db
  GRIDSCAN_UI_CREDENTIALS  Legacy single-user credentials path, read exactly
                           once - at startup, only if the users table in
                           GRIDSCAN_UI_DB is still empty - to migrate that one
                           user in as the initial admin. Never consulted again
                           after the users table has any row. Path to
                           {"username":..., "password_hash": <bcrypt>} JSON
                           file. Default /etc/gridscan-ui/credentials.json
  GRIDSCAN_SCOPE_FILE      Path to scope.txt. Default /etc/gridscan/scope.txt
  GRIDSCAN_ENV_FILE        Path to gridscan.env (holds SLACK_WEBHOOK=... and
                           SMTP_HOST/SMTP_PORT/SMTP_USERNAME/SMTP_PASSWORD/
                           SMTP_FROM/SMTP_TO=...). Default
                           /etc/gridscan/gridscan.env
  GRIDSCAN_AUDIT_LOG       Append-only audit log path.
                           Default /var/log/gridscan-ui/audit.log
  GRIDSCAN_DB              Path to the gridscan SQLite state DB. Not named in
                           the original spec - added because the API has to
                           read the DB from somewhere. Default
                           /var/lib/gridscan/gridscan.db
  GRIDSCAN_OUTPUT_DIR      Path to the scanner's report output directory -
                           same directory gridscan.py's `-o/--output` writes
                           `<scope>.report.md` / `<scope>.findings.json`
                           (latest) and `<scope>.<run_id>.report.md` /
                           `<scope>.<run_id>.findings.json` (per-run
                           snapshots) into. Must match the `--output` value
                           actually used by the deployed gridscan.service, the
                           same way GRIDSCAN_DB above must match gridscan.py's
                           `--db`. Default /var/lib/gridscan/out
  GRIDSCAN_UI_COOKIE_SECURE  "true"/"false", default "true". Controls the
                           `Secure` flag on cookies. Added so this can be
                           exercised over plain http in local/dev testing
                           (browsers silently drop `Secure` cookies sent over
                           http, and so does curl's cookie jar) - set to
                           "false" only for local dev, never in production.
  GRIDSCAN_LIVE_LOG        Path to the scanner's live/current-run log file
                           (written by gridscan.py's log(), see that file).
                           Same env var name and same default as gridscan.py
                           uses, so both processes agree on the path without
                           this file re-deriving it. Default
                           /var/lib/gridscan/logs/current.log
  GRIDSCAN_SCOPE_NAME      Logical scope name this UI instance manages (the
                           same value gridscan.py's `--scope`/`-s` records
                           findings/assets/runs under - see get_runs() etc.,
                           which all take `scope` as a query param rather
                           than hardcoding it here). Prior to the discovery
                           feature below there was no single constant for
                           this - the frontend hardcodes "prod" ad hoc in a
                           few places (js/api.js, dashboard.js, assets.js,
                           findings.js) instead of reading it from anywhere.
                           This constant is introduced only for the new
                           discovery-file default paths below, which need a
                           scope name server-side; it does not change any
                           existing endpoint's behavior. Default "prod"
                           (matches the frontend's existing hardcoded value).
  GRIDSCAN_DISCOVERY_FILE  Path to the JSON file gridscan.py's
                           `--discover-only` mode writes (see that file's
                           docstring for the exact shape). Read (never
                           written) by GET /api/scan/discovery and by
                           POST /api/scan/run-selected, which cross-checks
                           submitted URLs against this file's contents
                           before allowing a curated-selection scan to
                           start. Default
                           /var/lib/gridscan/discovery/<GRIDSCAN_SCOPE_NAME>.discovery.json
  GRIDSCAN_SELECTED_URLS_FILE  Path POST /api/scan/run-selected atomically
                           writes the admin-approved URL subset to (one URL
                           per line) before starting
                           gridscan-scan-selected.service, which is expected
                           to run gridscan.py with `--urls-file` pointed at
                           this same path. Default
                           /var/lib/gridscan/discovery/<GRIDSCAN_SCOPE_NAME>.selected.txt
"""

from __future__ import annotations

import difflib
import fnmatch
import json
import os
import re
import secrets
import smtplib
import sqlite3
import stat
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from pathlib import Path
from typing import List, Optional
from urllib.parse import urlparse

import bcrypt
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from pydantic import BaseModel

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gridscan import Store, classify, run_filename, TRIGGERED_BY_FILE  # noqa: E402  (local copy, see docstring)

# ---------------------------------------------------------------------------
# configuration
# ---------------------------------------------------------------------------

SECRET_KEY = os.environ.get("GRIDSCAN_UI_SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError(
        "GRIDSCAN_UI_SECRET_KEY environment variable must be set - "
        "refusing to start with no session-signing secret."
    )

USERS_DB_PATH = os.environ.get("GRIDSCAN_UI_DB", "/var/lib/gridscan-ui/gridscan_ui.db")
CREDENTIALS_PATH = os.environ.get("GRIDSCAN_UI_CREDENTIALS", "/etc/gridscan-ui/credentials.json")
SCOPE_FILE = os.environ.get("GRIDSCAN_SCOPE_FILE", "/etc/gridscan/scope.txt")
ENV_FILE = os.environ.get("GRIDSCAN_ENV_FILE", "/etc/gridscan/gridscan.env")
AUDIT_LOG = os.environ.get("GRIDSCAN_AUDIT_LOG", "/var/log/gridscan-ui/audit.log")
DB_PATH = os.environ.get("GRIDSCAN_DB", "/var/lib/gridscan/gridscan.db")
OUTPUT_DIR = os.environ.get("GRIDSCAN_OUTPUT_DIR", "/var/lib/gridscan/out")
COOKIE_SECURE = os.environ.get("GRIDSCAN_UI_COOKIE_SECURE", "true").lower() != "false"
LIVE_LOG_PATH = os.environ.get("GRIDSCAN_LIVE_LOG", "/var/lib/gridscan/logs/current.log")
SCOPE_NAME = os.environ.get("GRIDSCAN_SCOPE_NAME", "prod")
DISCOVERY_FILE = os.environ.get(
    "GRIDSCAN_DISCOVERY_FILE", f"/var/lib/gridscan/discovery/{SCOPE_NAME}.discovery.json"
)
SELECTED_URLS_FILE = os.environ.get(
    "GRIDSCAN_SELECTED_URLS_FILE", f"/var/lib/gridscan/discovery/{SCOPE_NAME}.selected.txt"
)

SESSION_COOKIE_NAME = "session"
CSRF_COOKIE_NAME = "csrf_token"
SESSION_MAX_AGE = 8 * 3600  # 8 hours

MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_SECONDS = 60

serializer = URLSafeTimedSerializer(SECRET_KEY, salt="gridscan-ui-session")

# Used by login() when the supplied username doesn't match, so bcrypt.checkpw
# still runs (same cost factor as the real credentials hash) and a wrong
# username can't be distinguished from a wrong password by response timing.
_DUMMY_PASSWORD_HASH = bcrypt.hashpw(b"gridscan-ui-timing-safety-dummy", bcrypt.gensalt()).decode()

app = FastAPI(title="gridscan-ui")

# ---------------------------------------------------------------------------
# in-memory login rate limiting (per source IP)
# ---------------------------------------------------------------------------

_rate_limit_state: dict[str, dict] = {}


def _check_rate_limit(ip: str) -> None:
    entry = _rate_limit_state.get(ip)
    if entry and entry.get("locked_until"):
        if datetime.now(timezone.utc) < entry["locked_until"]:
            raise HTTPException(
                status_code=429,
                detail="Too many failed login attempts. Try again later.",
            )
        # lock expired -> reset
        _rate_limit_state.pop(ip, None)


def _record_login_failure(ip: str) -> None:
    entry = _rate_limit_state.setdefault(ip, {"failures": 0, "locked_until": None})
    entry["failures"] += 1
    if entry["failures"] >= MAX_LOGIN_ATTEMPTS:
        entry["locked_until"] = datetime.now(timezone.utc) + timedelta(seconds=LOCKOUT_SECONDS)


def _record_login_success(ip: str) -> None:
    _rate_limit_state.pop(ip, None)


# ---------------------------------------------------------------------------
# user store (SQLite - multi-user, two-role auth; separate from GRIDSCAN_DB)
# ---------------------------------------------------------------------------

USERS_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    name TEXT,
    email TEXT,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('admin', 'viewer')),
    created_at TEXT NOT NULL
);
"""


def _users_conn() -> sqlite3.Connection:
    """Open a fresh connection to the users DB, ensuring the schema exists.
    Mirrors the existing per-call `Store(DB_PATH)` pattern used elsewhere in
    this file (e.g. get_runs/get_findings) rather than holding one long-lived
    connection - cheap for sqlite and keeps every request self-contained."""
    path = Path(USERS_DB_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.executescript(USERS_SCHEMA)
    return conn


def _admin_count(conn: sqlite3.Connection) -> int:
    return conn.execute("SELECT COUNT(*) FROM users WHERE role='admin'").fetchone()[0]


def _hash_password(password: str) -> str:
    """bcrypt-hash a password. Same 72-byte truncation approach as login()
    below (see the comment there): bcrypt truncates internally anyway for
    in-range passwords, so this doesn't weaken the hash, it just stops an
    oversized password from raising ValueError."""
    password_bytes = password.encode("utf-8")[:72]
    return bcrypt.hashpw(password_bytes, bcrypt.gensalt()).decode()


def _verify_password(password: str, password_hash: str) -> bool:
    password_bytes = password.encode("utf-8")[:72]
    return bcrypt.checkpw(password_bytes, password_hash.encode("utf-8"))


def _migrate_legacy_credentials() -> None:
    """One-time, idempotent startup migration: if the users table is empty
    AND the legacy single-user GRIDSCAN_UI_CREDENTIALS JSON file exists,
    migrate that one user in as role='admin' (name/email left NULL). Runs at
    import time (see call at module scope below, after audit_log() exists).
    Once the users table has any row - including right after this runs once -
    this is a no-op and credentials.json is never read by anything else."""
    conn = _users_conn()
    try:
        if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] > 0:
            return  # already migrated (or users created some other way)

        path = Path(CREDENTIALS_PATH)
        if not path.exists():
            return  # nothing to migrate, and no legacy file to fall back to

        try:
            data = json.loads(path.read_text())
            legacy_username = data["username"]
            legacy_password_hash = data["password_hash"]
        except (json.JSONDecodeError, KeyError) as e:
            audit_log(
                "legacy credentials migration skipped: file malformed",
                f"path={CREDENTIALS_PATH} error={e}",
            )
            return

        conn.execute(
            "INSERT INTO users (username, name, email, password_hash, role, created_at) "
            "VALUES (?, NULL, NULL, ?, 'admin', ?)",
            (legacy_username, legacy_password_hash, datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()
        audit_log(
            "legacy single-user credentials migrated into users table",
            f"username={legacy_username} role=admin source={CREDENTIALS_PATH}",
        )
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# auth helpers
# ---------------------------------------------------------------------------

def _get_session_username(request: Request) -> Optional[str]:
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        return None
    try:
        data = serializer.loads(token, max_age=SESSION_MAX_AGE)
        return data.get("username")
    except (BadSignature, SignatureExpired):
        return None


def require_auth(request: Request) -> str:
    """FastAPI dependency: 401s if there is no valid session. Injected into
    every protected route rather than checked ad hoc in each handler.

    The signed session cookie only carries `username` (never `role` - see
    login()), so on every request this re-checks the users table: this is
    what makes a role change take effect on the very next request instead of
    requiring re-login, and it's also what rejects a session whose user was
    deleted after the session was issued (no matching row -> 401)."""
    username = _get_session_username(request)
    if username is None:
        raise HTTPException(status_code=401, detail="Not authenticated")

    conn = _users_conn()
    try:
        row = conn.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone()
    finally:
        conn.close()
    if row is None:
        raise HTTPException(status_code=401, detail="Not authenticated")

    return username


def require_admin(username: str = Depends(require_auth)) -> str:
    """FastAPI dependency: like require_auth, but additionally 403s unless
    the current user's role (looked up fresh from the DB, never from the
    cookie) is 'admin'. Depends on require_auth so it gets the same
    session-validity/401 behavior for free; FastAPI caches require_auth's
    result per-request, so this doesn't cost a second cookie decode.

    Apply this to every mutating endpoint that should be admin-only. Reuse
    it the same way (`Depends(require_admin)`) for any new mutating endpoint
    added elsewhere (e.g. a future POST /api/scan/stop)."""
    conn = _users_conn()
    try:
        row = conn.execute("SELECT role FROM users WHERE username=?", (username,)).fetchone()
    finally:
        conn.close()
    if row is None or row["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")
    return username


def require_csrf(request: Request) -> None:
    """Double-submit CSRF check for mutating endpoints."""
    header = request.headers.get("X-CSRF-Token")
    cookie = request.cookies.get(CSRF_COOKIE_NAME)
    if not header or not cookie or not secrets.compare_digest(header, cookie):
        raise HTTPException(status_code=403, detail="Missing or invalid CSRF token")


# ---------------------------------------------------------------------------
# scope-file target validation (adapted from gridscan.classify())
# ---------------------------------------------------------------------------

# classify() itself never rejects anything - anything that isn't an IP/CIDR
# and doesn't start with http(s):// falls through to "domain" by default.
# So for the "domain" bucket we additionally apply a plausible-hostname
# regex; ip/cidr/url are already validated inside classify() (ipaddress
# parsing, and startswith() + netloc check respectively).
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.[A-Za-z]{2,63}$"
)


def _line_is_valid_target(line: str) -> bool:
    kind = classify(line)
    if kind in ("ip", "cidr"):
        return True
    if kind == "url":
        return bool(urlparse(line).netloc)
    if kind == "domain":
        return bool(_DOMAIN_RE.match(line))
    return False


def validate_scope_content(content: str) -> list[tuple[int, str]]:
    """Return list of (line_number, raw_line) for every invalid line."""
    bad: list[tuple[int, str]] = []
    for i, raw_line in enumerate(content.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if not _line_is_valid_target(line):
            bad.append((i, raw_line))
    return bad


# ---------------------------------------------------------------------------
# atomic file writes + audit log
# ---------------------------------------------------------------------------

def atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        try:
            st = os.stat(str(path))
            os.chmod(tmp_path, stat.S_IMODE(st.st_mode))
            os.chown(tmp_path, -1, st.st_gid)
        except FileNotFoundError:
            pass  # target doesn't exist yet - nothing to preserve
        os.replace(tmp_path, str(path))
    except Exception:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise


def audit_log(action: str, detail: str = "") -> None:
    path = Path(AUDIT_LOG)
    path.parent.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).isoformat()
    with open(path, "a") as f:
        f.write(f"[{ts}] {action}\n")
        for line in detail.splitlines():
            f.write(f"    {line}\n")


def update_env_file(path: Path, key: str, value: str) -> None:
    """Replace (or append) a KEY=value line in a simple env file, preserving
    all other lines untouched. Atomic write."""
    lines: list[str] = []
    found = False
    if path.exists():
        for line in path.read_text().splitlines():
            if line.startswith(f"{key}="):
                lines.append(f"{key}={value}")
                found = True
            else:
                lines.append(line)
    if not found:
        lines.append(f"{key}={value}")
    atomic_write(path, "\n".join(lines) + "\n")


def read_env_file(path: Path) -> dict[str, str]:
    """Parse a simple KEY=value env file (the same format update_env_file()
    writes) into a dict. Ignores blank lines, comments, and any line without
    an '='. Internal helper only - never expose the raw dict this returns
    directly from an endpoint response (see get_smtp_settings() below, which
    picks out only the non-secret fields)."""
    values: dict[str, str] = {}
    if path.exists():
        for line in path.read_text().splitlines():
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            values[key] = value
    return values


def update_env_file_multi(path: Path, updates: dict[str, str]) -> None:
    """Like update_env_file(), but replaces/appends several KEY=value lines
    in one read + one atomic write, preserving every other line (including
    keys not present in `updates`) untouched. Used by the SMTP settings
    endpoint below, which touches 6 keys at once and must not do 6 separate
    writes."""
    lines: list[str] = []
    seen: set[str] = set()
    if path.exists():
        for line in path.read_text().splitlines():
            key = line.split("=", 1)[0] if "=" in line else None
            if key in updates:
                lines.append(f"{key}={updates[key]}")
                seen.add(key)
            else:
                lines.append(line)
    for key, value in updates.items():
        if key not in seen:
            lines.append(f"{key}={value}")
    atomic_write(path, "\n".join(lines) + "\n")


# audit_log() now exists - safe to run the one-time legacy-credentials
# migration (see _migrate_legacy_credentials() docstring above).
_migrate_legacy_credentials()


# ---------------------------------------------------------------------------
# security headers (all responses)
# ---------------------------------------------------------------------------

@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "img-src 'self'; connect-src 'self'; frame-ancestors 'none'"
    )
    return response


# ---------------------------------------------------------------------------
# auth endpoints
# ---------------------------------------------------------------------------

class LoginRequest(BaseModel):
    username: str
    password: str


@app.post("/api/login")
def login(body: LoginRequest, request: Request):
    ip = request.client.host if request.client else "unknown"
    _check_rate_limit(ip)

    conn = _users_conn()
    try:
        row = conn.execute(
            "SELECT username, password_hash FROM users WHERE username=?", (body.username,)
        ).fetchone()
    finally:
        conn.close()

    # bcrypt (this pyca/bcrypt version) raises ValueError instead of silently
    # truncating passwords over 72 bytes. Truncate ourselves first - this is
    # what bcrypt does internally anyway for in-range passwords, so it does
    # not weaken the check, but it stops an oversized password from raising
    # an unhandled exception.
    password_bytes = body.password.encode("utf-8")[:72]

    # Always run bcrypt.checkpw, even when the username doesn't exist in the
    # users table (checking against a dummy hash of the same cost factor
    # instead of skipping it). This used to short-circuit via `and`, so a
    # wrong username returned in ~1ms (no bcrypt call) while a right-
    # username/wrong-password attempt took ~190ms (bcrypt cost-12) - a clear
    # timing oracle for username enumeration, on top of a right-username/500
    # vs wrong-username/401 oracle for oversized passwords before the
    # truncation fix above. (Previously "right username" meant matching the
    # single hardcoded credentials.json user via a constant-time string
    # compare; now it's an indexed primary-key lookup in the users table -
    # that lookup itself isn't constant-time, but its cost is negligible next
    # to bcrypt's ~190ms, so the property this defends - no username oracle
    # via response timing - is unchanged.)
    username_ok = row is not None
    hash_to_check = row["password_hash"] if username_ok else _DUMMY_PASSWORD_HASH
    password_ok = bcrypt.checkpw(password_bytes, hash_to_check.encode("utf-8"))
    ok = username_ok and password_ok
    if not ok:
        _record_login_failure(ip)
        raise HTTPException(status_code=401, detail="Invalid username or password")

    _record_login_success(ip)
    username = row["username"]

    # Deliberately no `role` in the signed cookie payload - require_auth() and
    # require_admin() always re-look-up the user's current role (and even
    # existence) from the users table on every request instead, so a role
    # change or account deletion takes effect on the very next request rather
    # than requiring the old session to expire or be re-issued.
    session_token = serializer.dumps({"username": username})
    csrf_token = secrets.token_urlsafe(32)

    response = JSONResponse({"status": "ok", "username": username})
    response.set_cookie(
        SESSION_COOKIE_NAME, session_token,
        httponly=True, samesite="strict", secure=COOKIE_SECURE,
        max_age=SESSION_MAX_AGE, path="/",
    )
    response.set_cookie(
        CSRF_COOKIE_NAME, csrf_token,
        httponly=False, samesite="strict", secure=COOKIE_SECURE,
        max_age=SESSION_MAX_AGE, path="/",
    )
    return response


@app.post("/api/logout")
def logout():
    response = JSONResponse({"status": "ok"})
    response.delete_cookie(SESSION_COOKIE_NAME, path="/", samesite="strict", secure=COOKIE_SECURE)
    response.delete_cookie(CSRF_COOKIE_NAME, path="/", samesite="strict", secure=COOKIE_SECURE)
    return response


@app.get("/api/session")
def session_info(request: Request):
    username = _get_session_username(request)
    return {"authenticated": username is not None, "username": username}


# ---------------------------------------------------------------------------
# read endpoints
# ---------------------------------------------------------------------------

@app.get("/api/runs")
def get_runs(scope: Optional[str] = None, limit: int = 20, offset: int = 0, user: str = Depends(require_auth)):
    store = Store(DB_PATH)
    query = "SELECT run_id, started_at, finished_at, targets, summary, triggered_by FROM runs"
    params: list = []
    if scope:
        query += " WHERE scope=?"
        params.append(scope)
    query += " ORDER BY run_id DESC LIMIT ? OFFSET ?"
    params.append(limit)
    params.append(offset)
    rows = store.db.execute(query, params).fetchall()
    return [dict(r) for r in rows]


# SQLite's INTEGER column is a signed 64-bit value; a run_id outside this
# range can never match a row (fine) but raises an unhandled OverflowError
# from the sqlite3 module before it ever gets that far - same "crash oracle"
# class of bug as the pre-existing bcrypt-length one, just on this new
# endpoint. Reject up front with the same 404 an out-of-range-but-in-int64
# run_id (e.g. 0 or -1) already gets, rather than letting the query raise.
_SQLITE_INT_MIN = -(2**63)
_SQLITE_INT_MAX = 2**63 - 1


def _run_snapshot_path(run_id: int, ext: str) -> tuple[Store, str, Path] | None:
    """Shared lookup for both /report and /findings-delta below: resolve a
    run_id to its scope + snapshot file path, with the same defense-in-depth
    check (scope is DB-derived, not request-derived, but ultimately traces
    back to gridscan.py's --scope/first-target arg, which PUT /api/scope can
    influence - a scope-file line can be a full URL like
    "https://host/../../x" and still pass validate_scope_content()'s
    scheme/netloc-only check). Returns None if run_id doesn't exist at all
    (caller 404s) or the resolved path escapes OUTPUT_DIR (caller treats as
    not-found too, rather than serving it)."""
    if not (_SQLITE_INT_MIN <= run_id <= _SQLITE_INT_MAX):
        return None
    store = Store(DB_PATH)
    row = store.db.execute(
        "SELECT scope, started_at, triggered_by FROM runs WHERE run_id=?", (run_id,)
    ).fetchone()
    if row is None:
        return None
    scope = row["scope"]
    path = Path(OUTPUT_DIR) / run_filename(scope, row["started_at"], row["triggered_by"], ext)
    out_root = Path(OUTPUT_DIR).resolve()
    resolved = path.resolve()
    if resolved != out_root and out_root not in resolved.parents:
        return None
    return store, scope, path


@app.get("/api/runs/{run_id}/report")
def get_run_report(run_id: int, user: str = Depends(require_auth)):
    """Historical per-run report snapshot (read-only, any role - same as the
    rest of /api/runs). Runs recorded before this feature shipped have no
    snapshot file - that's `available: false`, not an error (still 200);
    only a run_id that doesn't exist in the DB at all is 404."""
    found = _run_snapshot_path(run_id, "report.md")
    if found is None:
        raise HTTPException(status_code=404, detail="run not found")
    _store, scope, path = found
    if not path.exists():
        return {"run_id": run_id, "scope": scope, "report_md": None, "available": False}
    return {"run_id": run_id, "scope": scope, "report_md": path.read_text(), "available": True}


@app.get("/api/runs/{run_id}/findings-delta")
def get_run_findings_delta(run_id: int, user: str = Depends(require_auth)):
    """What this specific scan found/changed: new/reappeared/resolved
    findings, read from the same per-run findings.json snapshot the report
    endpoint above uses. available:false (not an error) for runs recorded
    before this shipped, or if the file is unreadable/malformed."""
    found = _run_snapshot_path(run_id, "findings.json")
    if found is None:
        raise HTTPException(status_code=404, detail="run not found")
    _store, scope, path = found
    if not path.exists():
        return {"run_id": run_id, "scope": scope, "available": False}
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError:
        return {"run_id": run_id, "scope": scope, "available": False}
    if not isinstance(data, dict):
        return {"run_id": run_id, "scope": scope, "available": False}
    return {
        "run_id": run_id, "scope": scope, "available": True,
        "delta": data.get("delta"),
        "new_items": data.get("new_items", []),
        "reappeared_items": data.get("reappeared_items", []),
        "resolved_items": data.get("resolved_items", []),
        "open_findings": data.get("open_findings", []),
    }


@app.get("/api/runs/{run_id}/report/download")
def download_run_report(run_id: int, user: str = Depends(require_auth)):
    found = _run_snapshot_path(run_id, "report.md")
    if found is None:
        raise HTTPException(status_code=404, detail="run not found")
    _store, _scope, path = found
    if not path.exists():
        raise HTTPException(status_code=404, detail="no report file for this run")
    return FileResponse(path, media_type="text/markdown", filename=path.name)


@app.get("/api/runs/{run_id}/findings/download")
def download_run_findings(run_id: int, user: str = Depends(require_auth)):
    found = _run_snapshot_path(run_id, "findings.json")
    if found is None:
        raise HTTPException(status_code=404, detail="run not found")
    _store, _scope, path = found
    if not path.exists():
        raise HTTPException(status_code=404, detail="no findings file for this run")
    return FileResponse(path, media_type="application/json", filename=path.name)


def _parse_multi_values(values: Optional[List[str]]) -> Optional[list[str]]:
    """Normalize a severity/status query param that may have been supplied
    as repeated params (?severity=critical&severity=high), as one
    comma-separated value (?severity=critical,high), or a mix of both, into
    a flat de-duplicated list (first-seen order preserved). Returns None if
    nothing usable was supplied - same "omitted/empty means all" semantics
    the single-value version of this filter had before."""
    if not values:
        return None
    result: list[str] = []
    seen: set[str] = set()
    for raw in values:
        for part in raw.split(","):
            part = part.strip()
            if part and part not in seen:
                seen.add(part)
                result.append(part)
    return result or None


# Glob-to-LIKE translation for the findings host filter below: '*' becomes
# SQL's '%' (any run of characters); any literal '%'/'_' in the input (or a
# literal occurrence of the escape character itself) is escaped so it can't
# be mistaken for one of LIKE's own wildcards - this is what makes an
# exact, no-'*' host filter behave as a true exact match even for a host
# that happens to contain '_' (e.g. "weird_host.example.com"), rather than
# '_' silently acting as "match any one character" the way plain LIKE would
# otherwise treat it.
_LIKE_ESCAPE_CHAR = "\\"


def _glob_to_like_pattern(glob: str) -> str:
    out = []
    for ch in glob:
        if ch == "*":
            out.append("%")
        elif ch in ("%", "_", _LIKE_ESCAPE_CHAR):
            out.append(_LIKE_ESCAPE_CHAR + ch)
        else:
            out.append(ch)
    return "".join(out)


def _as_contains_glob(term: str) -> str:
    """A plain word typed into a host search box should behave like a normal
    search - substring match - not require an exact/full match. If the user
    already wrote an explicit '*' themselves, respect their glob as-is rather
    than double-wrapping it."""
    if "*" in term:
        return term
    return f"*{term}*"


def _matches_findings_filters(row: dict, severity_list, status_list, triage_list, host) -> bool:
    """Same filter semantics as the SQL WHERE clause below, applied in Python
    to an in-memory row (used for the run_id path, which reads a JSON
    snapshot rather than querying the live table)."""
    if severity_list and row.get("severity") not in severity_list:
        return False
    if status_list and row.get("status") not in status_list:
        return False
    if triage_list and row.get("triage_status") not in triage_list:
        return False
    if host:
        # fnmatchcase on lowercased strings to match SQL LIKE's
        # case-insensitivity exactly (plain fnmatch normcase is a no-op on
        # POSIX, i.e. case-sensitive there - not what we want here).
        # _as_contains_glob makes a plain word substring-match like a normal
        # search box, same as the SQL LIKE path above.
        if not fnmatch.fnmatchcase((row.get("host") or "").lower(), _as_contains_glob(host).lower()):
            return False
    return True


@app.get("/api/findings")
def get_findings(
    scope: Optional[str] = None,
    severity: Optional[List[str]] = Query(None),
    status: Optional[List[str]] = Query(None),
    triage_status: Optional[List[str]] = Query(None),
    host: Optional[str] = None,
    run_id: Optional[int] = None,
    user: str = Depends(require_auth),
):
    severity_list = _parse_multi_values(severity)
    status_list = _parse_multi_values(status)
    triage_list = _parse_multi_values(triage_status)

    if run_id is not None:
        # "Findings as of scan #run_id" - read the same per-run open_findings
        # snapshot the By-scan panel already uses, then apply the exact same
        # filters as the live-table path below, just in Python since this
        # data isn't in a queryable table.
        found = _run_snapshot_path(run_id, "findings.json")
        if found is None:
            raise HTTPException(status_code=404, detail="run not found")
        _store, _scope, path = found
        if not path.exists():
            return []
        try:
            data = json.loads(path.read_text())
        except json.JSONDecodeError:
            return []
        rows = data.get("open_findings", []) if isinstance(data, dict) else []
        return [r for r in rows if _matches_findings_filters(r, severity_list, status_list, triage_list, host)]

    store = Store(DB_PATH)
    clauses = []
    params: list = []
    if scope:
        clauses.append("scope=?")
        params.append(scope)
    if severity_list:
        clauses.append(f"severity IN ({','.join('?' for _ in severity_list)})")
        params.extend(severity_list)
    if status_list:
        clauses.append(f"status IN ({','.join('?' for _ in status_list)})")
        params.extend(status_list)
    if triage_list:
        clauses.append(f"triage_status IN ({','.join('?' for _ in triage_list)})")
        params.extend(triage_list)
    if host:
        # Glob-style match ('*' wildcard) translated to a SQL LIKE, not a
        # client-side fnmatch/regex post-filter - stays index-friendly and
        # consistent with every other filter here. A plain word with no '*'
        # behaves as a substring search (_as_contains_glob), same as any
        # normal search box - an explicit '*' from the user is respected
        # as-is instead of being wrapped again.
        clauses.append(f"host LIKE ? ESCAPE '{_LIKE_ESCAPE_CHAR}'")
        params.append(_glob_to_like_pattern(_as_contains_glob(host)))
    query = "SELECT * FROM findings"
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    query += (
        " ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
        "WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, template_id"
    )
    rows = store.db.execute(query, params).fetchall()
    return [dict(r) for r in rows]


@app.get("/api/assets")
def get_assets(
    scope: Optional[str] = None,
    tech: Optional[str] = None,
    status_code: Optional[int] = None,
    host: Optional[str] = None,
    user: str = Depends(require_auth),
):
    store = Store(DB_PATH)
    clauses = []
    params: list = []
    if scope:
        clauses.append("scope=?")
        params.append(scope)
    if tech:
        # tech is stored as a JSON-array string (see gridscan.py's
        # ingest_assets/flatten) - a plain substring match against that raw
        # string is good enough here (consistent with "don't over-engineer"
        # guidance) rather than parsing the JSON and matching array membership.
        clauses.append("tech LIKE ?")
        params.append(f"%{tech}%")
    if status_code is not None:
        clauses.append("status_code=?")
        params.append(status_code)
    if host:
        # Substring/glob search, same semantics as the findings host filter
        # above - a plain word matches anywhere in the hostname.
        clauses.append(f"host LIKE ? ESCAPE '{_LIKE_ESCAPE_CHAR}'")
        params.append(_glob_to_like_pattern(_as_contains_glob(host)))
    query = "SELECT * FROM assets"
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    rows = store.db.execute(query, params).fetchall()
    return [dict(r) for r in rows]


@app.get("/api/scope")
def get_scope(user: str = Depends(require_auth)):
    path = Path(SCOPE_FILE)
    content = path.read_text() if path.exists() else ""
    return {"content": content}


# ---------------------------------------------------------------------------
# write endpoints
# ---------------------------------------------------------------------------

class ScopeUpdate(BaseModel):
    content: str


@app.put("/api/scope")
def put_scope(
    body: ScopeUpdate,
    user: str = Depends(require_auth),
    _admin: str = Depends(require_admin),
    _csrf: None = Depends(require_csrf),
):
    bad_lines = validate_scope_content(body.content)
    if bad_lines:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "one or more lines are not a valid domain, IP, CIDR, or URL",
                "invalid_lines": [
                    {"line_number": n, "content": c} for n, c in bad_lines
                ],
            },
        )

    path = Path(SCOPE_FILE)
    old_content = path.read_text() if path.exists() else ""
    atomic_write(path, body.content)

    diff = "\n".join(
        difflib.unified_diff(
            old_content.splitlines(), body.content.splitlines(),
            fromfile="old", tofile="new", lineterm="",
        )
    )
    audit_log(f"scope changed by {user}", diff or "(no textual diff)")
    return {"status": "ok"}


def _mask_secret_url(url: str) -> str:
    """Mask a secret URL for safe display: keep the scheme+host prefix (not
    secret in itself - e.g. https://hooks.slack.com/services/ is the same
    for every Slack workspace) and reveal only the LAST 4 characters of
    whatever comes after it, replacing the rest with a fixed placeholder
    rather than one asterisk per real character - so this string can't be
    used to infer the secret's actual length either. If 4 or fewer
    characters follow the prefix, none of them are shown at all."""
    parsed = urlparse(url)
    prefix = f"{parsed.scheme}://{parsed.netloc}/"
    tail = url[len(prefix):] if url.startswith(prefix) else url
    if len(tail) <= 4:
        return f"{prefix}****"
    return f"{prefix}****...{tail[-4:]}"


@app.get("/api/settings/slack")
def get_slack_settings(admin: str = Depends(require_admin)):
    """Masked preview only - safe to call on every page load (unlike the
    reveal endpoint below, this never returns the real value, so it doesn't
    need require_csrf or its own audit-log entry)."""
    webhook = read_env_file(Path(ENV_FILE)).get("SLACK_WEBHOOK", "")
    if not webhook:
        return {"configured": False, "masked": None}
    return {"configured": True, "masked": _mask_secret_url(webhook)}


class WebhookUpdate(BaseModel):
    webhook_url: str


@app.post("/api/webhook")
def post_webhook(
    body: WebhookUpdate,
    user: str = Depends(require_auth),
    _admin: str = Depends(require_admin),
    _csrf: None = Depends(require_csrf),
):
    parsed = urlparse(body.webhook_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise HTTPException(status_code=400, detail="webhook_url must be a valid http:// or https:// URL")

    update_env_file(Path(ENV_FILE), "SLACK_WEBHOOK", body.webhook_url)
    audit_log(f"webhook rotated by {user}")  # never log the actual value
    return {"status": "ok"}


@app.post("/api/settings/slack/reveal")
def reveal_slack_webhook(
    user: str = Depends(require_auth),
    _admin: str = Depends(require_admin),
    _csrf: None = Depends(require_csrf),
):
    """Deliberately POST + require_csrf, not a passive GET, even though it
    doesn't mutate anything - revealing the real secret is a sensitive,
    explicit action and gets the same "not just a GET" treatment and its
    own distinct audit-log entry, same as rotating it does below."""
    webhook = read_env_file(Path(ENV_FILE)).get("SLACK_WEBHOOK", "")
    if not webhook:
        raise HTTPException(status_code=400, detail="Slack webhook not configured")

    audit_log(f"slack webhook revealed by {user}")
    return {"webhook_url": webhook}


@app.post("/api/settings/slack/test")
def test_slack_webhook(
    user: str = Depends(require_auth),
    _admin: str = Depends(require_admin),
    _csrf: None = Depends(require_csrf),
):
    """Send a one-off test message to the CURRENTLY SAVED Slack webhook -
    read internally from ENV_FILE, same read-only-internally /
    never-return-externally pattern as the rest of this file. Uses
    urllib.request the same way gridscan.py's own notify() does (see that
    function) rather than adding a new HTTP client dependency."""
    webhook = read_env_file(Path(ENV_FILE)).get("SLACK_WEBHOOK", "")
    if not webhook:
        raise HTTPException(status_code=400, detail="Slack webhook not configured")

    payload = {
        "text": "gridscan-ui: this is a test notification. If you can see this, Slack alerts are working."
    }
    try:
        req = urllib.request.Request(
            webhook, data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
        )
        urllib.request.urlopen(req, timeout=10)
    except urllib.error.HTTPError as e:
        raise HTTPException(
            status_code=502,
            detail=f"Slack webhook delivery failed: HTTP {e.code} {e.reason}",
        )
    except Exception as e:  # noqa: BLE001 - report whatever went wrong (timeout, DNS, etc.)
        raise HTTPException(status_code=502, detail=f"Slack webhook delivery failed: {e}")

    audit_log(f"slack test message sent by {user}")  # never log the webhook value
    return {"status": "sent"}


# ---------------------------------------------------------------------------
# SMTP settings (same env file / same sensitivity class as scope + webhook -
# require_admin throughout. Non-secret fields are readable via GET; the
# password is write-only, same convention as the webhook above)
# ---------------------------------------------------------------------------

SMTP_ENV_KEYS = ("SMTP_HOST", "SMTP_PORT", "SMTP_USERNAME", "SMTP_PASSWORD", "SMTP_FROM", "SMTP_TO")


class SmtpUpdate(BaseModel):
    host: str
    port: int
    username: str
    from_addr: str
    to_addr: str
    # Optional: omit or send "" to keep the currently-stored password
    # unchanged. Only a non-empty value replaces it.
    password: Optional[str] = None


@app.get("/api/settings/smtp")
def get_smtp_settings(admin: str = Depends(require_admin)):
    values = read_env_file(Path(ENV_FILE))
    port_raw = values.get("SMTP_PORT", "")
    try:
        port = int(port_raw)
    except ValueError:
        port = None
    return {
        "host": values.get("SMTP_HOST", ""),
        "port": port,
        "username": values.get("SMTP_USERNAME", ""),
        "from_addr": values.get("SMTP_FROM", ""),
        "to_addr": values.get("SMTP_TO", ""),
        # never the value itself - just whether one is set
        "password_configured": bool(values.get("SMTP_PASSWORD", "")),
    }


@app.put("/api/settings/smtp")
def put_smtp_settings(
    body: SmtpUpdate,
    user: str = Depends(require_auth),
    _admin: str = Depends(require_admin),
    _csrf: None = Depends(require_csrf),
):
    if not (1 <= body.port <= 65535):
        raise HTTPException(status_code=400, detail="port must be between 1 and 65535")

    path = Path(ENV_FILE)
    old_values = read_env_file(path)

    updates = {
        "SMTP_HOST": body.host,
        "SMTP_PORT": str(body.port),
        "SMTP_USERNAME": body.username,
        "SMTP_FROM": body.from_addr,
        "SMTP_TO": body.to_addr,
    }
    if body.password:
        updates["SMTP_PASSWORD"] = body.password
    # else: password omitted/empty -> SMTP_PASSWORD line left untouched by
    # update_env_file_multi() below (it only rewrites keys present in `updates`)

    changed_fields = [
        label
        for key, label in (
            ("SMTP_HOST", "host"), ("SMTP_PORT", "port"), ("SMTP_USERNAME", "username"),
            ("SMTP_FROM", "from_addr"), ("SMTP_TO", "to_addr"),
        )
        if old_values.get(key, "") != updates[key]
    ]
    if body.password:
        changed_fields.append("password")  # never log whether/how the value differs

    update_env_file_multi(path, updates)

    audit_log(
        f"smtp settings updated by {user}",
        f"changed={','.join(changed_fields) if changed_fields else '(none)'}",
    )
    return {"status": "ok"}


@app.post("/api/settings/smtp/test")
def test_smtp_settings(
    user: str = Depends(require_auth),
    _admin: str = Depends(require_admin),
    _csrf: None = Depends(require_csrf),
):
    """Send a real test email via the CURRENTLY SAVED SMTP config (read
    internally from ENV_FILE - never returns the password). Best-effort:
    STARTTLS is attempted whenever the server advertises it, auth only if
    both username and password are set, short timeout so an unreachable/
    misconfigured host can't hang the request."""
    values = read_env_file(Path(ENV_FILE))
    host = values.get("SMTP_HOST", "")
    if not host:
        raise HTTPException(status_code=400, detail="SMTP not configured")

    try:
        port = int(values.get("SMTP_PORT", ""))
    except ValueError:
        raise HTTPException(status_code=400, detail="SMTP_PORT is not configured correctly")

    username = values.get("SMTP_USERNAME", "")
    password = values.get("SMTP_PASSWORD", "")
    from_addr = values.get("SMTP_FROM", "") or username
    to_addr = values.get("SMTP_TO", "")
    if not from_addr or not to_addr:
        raise HTTPException(status_code=400, detail="SMTP from/to address not configured")

    msg = EmailMessage()
    msg["Subject"] = "gridscan-ui SMTP test"
    msg["From"] = from_addr
    msg["To"] = to_addr
    msg.set_content(
        "This is a test message from gridscan-ui, sent via POST /api/settings/smtp/test "
        "to confirm the configured SMTP settings work."
    )

    try:
        with smtplib.SMTP(host, port, timeout=10) as smtp:
            smtp.ehlo()
            try:
                if smtp.has_extn("starttls"):
                    smtp.starttls()
                    smtp.ehlo()
            except smtplib.SMTPException:
                pass  # best-effort: fall back to unencrypted rather than failing the test
            if username and password:
                smtp.login(username, password)
            smtp.send_message(msg)
    except Exception as e:  # noqa: BLE001 - surface the real SMTP error to the caller
        raise HTTPException(status_code=502, detail=f"SMTP test failed: {e}")

    audit_log(f"smtp test email sent by {user}")
    return {"status": "sent"}


@app.post("/api/scan/trigger")
def trigger_scan(
    user: str = Depends(require_auth),
    _admin: str = Depends(require_admin),
    _csrf: None = Depends(require_csrf),
):
    # Hardcoded unit name - there is deliberately no parameter, code path, or
    # flag anywhere in this app that can start gridscan-intrusive.service or
    # pass --intrusive to anything.
    Path(TRIGGERED_BY_FILE).write_text(user)
    try:
        proc = subprocess.run(
            # --no-block: gridscan.service is Type=oneshot and its ExecStart can
            # run for up to ~1hr; without --no-block, "systemctl start" blocks
            # until the scan itself finishes, so this call would time out on
            # every single trigger (and any timeout value here is meaningless -
            # it'll never return in time). --no-block returns as soon as the job
            # is queued via D-Bus, which is what the trigger endpoint actually
            # needs: fire-and-forget, then poll /api/scan/status separately.
            ["sudo", "-n", "systemctl", "start", "--no-block", "gridscan.service"],
            capture_output=True, text=True, timeout=15,
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="systemctl start did not return in time")
    except FileNotFoundError as e:
        raise HTTPException(status_code=500, detail=f"sudo/systemctl not available: {e}")

    if proc.returncode != 0:
        raise HTTPException(
            status_code=502,
            detail=f"failed to start gridscan.service: {proc.stderr.strip() or proc.stdout.strip()}",
        )
    return {"status": "triggered"}


@app.post("/api/scan/stop")
def stop_scan(
    user: str = Depends(require_auth),
    _admin: str = Depends(require_admin),
    _csrf: None = Depends(require_csrf),
):
    # Hardcoded unit name - same principle as trigger_scan() above: no
    # parameter, no code path that can stop any unit other than
    # gridscan.service. This is a distinct exact-argv sudoers rule from the
    # existing `start --no-block` one (sudoers matches exact argv; "stop"
    # is not covered by the "start --no-block" grant and needs its own
    # NOPASSWD line - see deployment notes).
    #
    # Unlike trigger_scan()'s "start --no-block" (which has to return
    # immediately because the oneshot unit's ExecStart can run for up to
    # ~1hr), "stop" is expected to return quickly once systemd delivers
    # SIGTERM and kills the unit's process group - so no --no-block here,
    # and a much shorter timeout than "1hr" is reasonable to actually wait on.
    try:
        proc = subprocess.run(
            ["sudo", "-n", "systemctl", "stop", "gridscan.service"],
            capture_output=True, text=True, timeout=30,
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="systemctl stop did not return in time")
    except FileNotFoundError as e:
        raise HTTPException(status_code=500, detail=f"sudo/systemctl not available: {e}")

    if proc.returncode != 0:
        raise HTTPException(
            status_code=502,
            detail=f"failed to stop gridscan.service: {proc.stderr.strip() or proc.stdout.strip()}",
        )
    return {"status": "stopped"}


@app.get("/api/scan/status")
def scan_status(user: str = Depends(require_auth)):
    try:
        proc = subprocess.run(
            ["systemctl", "is-active", "gridscan.service"],
            capture_output=True, text=True, timeout=10,
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="systemctl is-active did not return in time")
    except FileNotFoundError as e:
        raise HTTPException(status_code=500, detail=f"systemctl not available: {e}")

    state = (proc.stdout.strip() or proc.stderr.strip() or "unknown")
    return {"status": state}


@app.get("/api/scan/logs")
def scan_logs(user: str = Depends(require_auth)):
    # Any authenticated user (viewer or admin) - watching a running scan's
    # live log is read-only and not a control action, unlike trigger/stop.
    path = Path(LIVE_LOG_PATH)
    if not path.exists():
        return {"exists": False, "content": ""}
    return {"exists": True, "content": path.read_text()}


# ---------------------------------------------------------------------------
# discover-then-select-then-scan workflow
#
# Additional flow alongside trigger_scan()/the daily systemd timer above,
# not a replacement for either: gridscan-discover.service runs gridscan.py
# --discover-only (subfinder/dnsx/naabu/httpx, no nuclei, no DB writes) so a
# human can review what was found before committing to a full vulnerability
# scan; gridscan-scan-selected.service then runs gridscan.py --urls-file
# against only the reviewed/approved subset. Two new systemd units, two new
# exact-argv sudoers NOPASSWD rules - same one-unit-per-hardcoded-argv
# pattern as trigger_scan()/stop_scan() above, see deployment notes for the
# unit files and sudoers lines.
# ---------------------------------------------------------------------------

def _systemctl_start_unit(unit_name: str, failure_verb: str = "start") -> None:
    """Shared subprocess pattern for the three "start a scan-family unit"
    endpoints (trigger_scan() above still has its own inlined copy of this,
    left as-is to keep this change surgical - this helper is only used by
    the two new endpoints below). Exact mirror of trigger_scan()'s
    subprocess.run() call: same sudo -n / --no-block / timeout=15 /
    capture_output=True, text=True, and the same TimeoutExpired /
    FileNotFoundError / non-zero-exit handling."""
    try:
        proc = subprocess.run(
            ["sudo", "-n", "systemctl", "start", "--no-block", unit_name],
            capture_output=True, text=True, timeout=15,
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="systemctl start did not return in time")
    except FileNotFoundError as e:
        raise HTTPException(status_code=500, detail=f"sudo/systemctl not available: {e}")

    if proc.returncode != 0:
        raise HTTPException(
            status_code=502,
            detail=f"failed to {failure_verb} {unit_name}: {proc.stderr.strip() or proc.stdout.strip()}",
        )


def _unit_status(unit_name: str) -> str:
    """Shared subprocess pattern for the three "is this scan-family unit
    running" endpoints - exact mirror of the existing scan_status()'s
    systemctl is-active call below, just parameterized on unit name rather
    than duplicated ad hoc for each new sibling endpoint."""
    try:
        proc = subprocess.run(
            ["systemctl", "is-active", unit_name],
            capture_output=True, text=True, timeout=10,
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="systemctl is-active did not return in time")
    except FileNotFoundError as e:
        raise HTTPException(status_code=500, detail=f"systemctl not available: {e}")
    return proc.stdout.strip() or proc.stderr.strip() or "unknown"


@app.post("/api/scan/discover")
def trigger_discover(
    user: str = Depends(require_auth),
    _admin: str = Depends(require_admin),
    _csrf: None = Depends(require_csrf),
):
    """Starts gridscan-discover.service (gridscan.py --discover-only under
    the hood: subfinder/dnsx/naabu/httpx only, no nuclei, no DB writes).
    Hardcoded unit name, same as trigger_scan()/stop_scan() - no parameter
    anywhere in this app can point this at a different unit."""
    _systemctl_start_unit("gridscan-discover.service")
    return {"status": "triggered"}


@app.get("/api/scan/discover/status")
def discover_status(user: str = Depends(require_auth)):
    return {"status": _unit_status("gridscan-discover.service")}


@app.get("/api/scan/run-selected/status")
def run_selected_status(user: str = Depends(require_auth)):
    return {"status": _unit_status("gridscan-scan-selected.service")}


@app.get("/api/scan/discovery")
def get_discovery(user: str = Depends(require_auth)):
    """Read-only for both roles (same reasoning as GET /api/scan/logs above:
    viewing discovery results isn't a control action). Returns
    {"available": false} if discovery has never been run yet (file doesn't
    exist) or the file is unreadable/corrupt - never a 500 for "no discovery
    yet", which is an expected, normal state on a fresh deployment."""
    path = Path(DISCOVERY_FILE)
    if not path.exists():
        return {"available": False}
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError:
        return {"available": False}
    # gridscan.py's --discover-only always writes a JSON object (see
    # run_discover_only()) - but this file is corruption-prone the same way
    # any other output file is (crash mid-write, disk full, wrong path
    # pointed at it), so guard against valid-but-wrong-shaped JSON (e.g. a
    # bare list/string/number/null) the same way the JSONDecodeError branch
    # above guards against invalid JSON: neither is a 500, both are "no
    # usable discovery data yet".
    if not isinstance(data, dict):
        return {"available": False}
    data["available"] = True
    return data


class RunSelectedRequest(BaseModel):
    urls: List[str]


@app.post("/api/scan/run-selected")
def run_selected(
    body: RunSelectedRequest,
    user: str = Depends(require_auth),
    _admin: str = Depends(require_admin),
    _csrf: None = Depends(require_csrf),
):
    """Validate the submitted URLs against the most recent discovery result,
    write the validated subset to SELECTED_URLS_FILE, then start
    gridscan-scan-selected.service (expected to run gridscan.py --urls-file
    against that same file).

    The membership check below is the security-relevant part of this
    endpoint: without it, an admin session (or a CSRF-bypassed request from
    an admin's browser) could submit an arbitrary out-of-scope URL list and
    have it scanned as if it had been through discovery/review. Every
    submitted URL MUST already appear in DISCOVERY_FILE's `items` - if any
    one doesn't, the whole request is rejected with 400 rather than
    silently dropping the unknown entries and scanning the rest.
    """
    if not body.urls:
        raise HTTPException(status_code=400, detail="no urls selected")

    discovery_path = Path(DISCOVERY_FILE)
    if not discovery_path.exists():
        raise HTTPException(
            status_code=400,
            detail="no discovery results available - run Discover first",
        )
    try:
        discovery_data = json.loads(discovery_path.read_text())
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="discovery results file is unreadable")
    # Same "valid JSON, wrong shape" guard as GET /api/scan/discovery above -
    # a corrupt/partial file can parse to a non-dict top-level value (or an
    # `items` entry that isn't itself an object), which would otherwise raise
    # an unhandled AttributeError/TypeError below instead of failing closed
    # with the same 400 the JSONDecodeError case already gets.
    if not isinstance(discovery_data, dict):
        raise HTTPException(status_code=400, detail="discovery results file is unreadable")

    known_urls = {
        item.get("url") for item in discovery_data.get("items", []) if isinstance(item, dict)
    }
    unknown = [u for u in body.urls if u not in known_urls]
    if unknown:
        raise HTTPException(
            status_code=400,
            detail=(
                f"{len(unknown)} submitted URL(s) were not part of the most recent "
                "discovery result - run Discover again if the target set has changed"
            ),
        )

    # de-dup, preserve submitted order (same convention as gridscan.py's own
    # read_targets())
    seen: set = set()
    selected: list[str] = []
    for u in body.urls:
        if u not in seen:
            seen.add(u)
            selected.append(u)

    atomic_write(Path(SELECTED_URLS_FILE), "\n".join(selected) + "\n")
    Path(TRIGGERED_BY_FILE).write_text(user)

    # Audit-log the approved selection as soon as it's durably written, not
    # only after systemctl also succeeds: the security-relevant action here
    # is "this admin approved exactly this URL subset for scanning" - that's
    # already true once SELECTED_URLS_FILE is written, independent of
    # whether the downstream systemd job happens to start cleanly (compare
    # trigger_scan()/stop_scan(), which have no equivalent prior state
    # change to record and so log nothing at all either way).
    audit_log(
        f"selected-scan triggered by {user}",
        f"{len(selected)} url(s) selected"
        if len(selected) > 20
        else "\n".join(selected),
    )

    _systemctl_start_unit("gridscan-scan-selected.service", failure_verb="start")
    return {"status": "triggered", "count": len(selected)}


# ---------------------------------------------------------------------------
# findings triage (any authenticated user - see FindingTriageUpdate/
# put_finding_triage below for why this is require_auth, not require_admin)
# ---------------------------------------------------------------------------

FINDING_TRIAGE_STATUSES = ("unreviewed", "confirmed", "false_positive", "accepted_risk", "remediating")


class FindingTriageUpdate(BaseModel):
    finding_key: str
    triage_status: str


@app.put("/api/findings/triage")
def put_finding_triage(
    body: FindingTriageUpdate,
    user: str = Depends(require_auth),
    _csrf: None = Depends(require_csrf),
):
    # Deliberately require_auth only, not require_admin: triaging a finding
    # (confirmed/false positive/accepted risk/remediating) is not a
    # scan-config or user-management change - it's closer to the live-log
    # viewing and per-run report reading already allowed for viewers
    # elsewhere in this file. Unlike trigger/stop/scope/webhook (which change
    # what actually gets scanned or notified), a wrong triage call here can
    # always be corrected by re-triaging - so both roles are allowed, same
    # reasoning as GET /api/scan/logs above.
    if body.triage_status not in FINDING_TRIAGE_STATUSES:
        raise HTTPException(
            status_code=400,
            detail=f"triage_status must be one of {', '.join(FINDING_TRIAGE_STATUSES)}",
        )

    store = Store(DB_PATH)
    row = store.db.execute(
        "SELECT triage_status FROM findings WHERE finding_key=?",
        (body.finding_key,),
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="finding not found")

    old_status = row["triage_status"]
    store.db.execute(
        "UPDATE findings SET triage_status=? WHERE finding_key=?",
        (body.triage_status, body.finding_key),
    )
    store.db.commit()

    audit_log(
        f"finding triage changed by {user}",
        f"finding_key={body.finding_key} {old_status} -> {body.triage_status}",
    )
    return {"status": "ok", "finding_key": body.finding_key, "triage_status": body.triage_status}


# ---------------------------------------------------------------------------
# user management endpoints (admin only)
# ---------------------------------------------------------------------------

MIN_PASSWORD_LENGTH = 8


class UserCreate(BaseModel):
    username: str
    password: str
    name: Optional[str] = None
    email: Optional[str] = None
    role: str


class UserUpdate(BaseModel):
    name: Optional[str] = None
    email: Optional[str] = None
    role: Optional[str] = None
    password: Optional[str] = None


@app.get("/api/users")
def list_users(admin: str = Depends(require_admin)):
    conn = _users_conn()
    try:
        rows = conn.execute(
            "SELECT username, name, email, role, created_at FROM users ORDER BY username"
        ).fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]


@app.post("/api/users", status_code=201)
def create_user(
    body: UserCreate,
    admin: str = Depends(require_admin),
    _csrf: None = Depends(require_csrf),
):
    if not body.username or not body.username.strip():
        raise HTTPException(status_code=400, detail="username is required")
    if body.role not in ("admin", "viewer"):
        raise HTTPException(status_code=400, detail="role must be 'admin' or 'viewer'")
    if len(body.password) < MIN_PASSWORD_LENGTH:
        raise HTTPException(
            status_code=400, detail=f"password must be at least {MIN_PASSWORD_LENGTH} characters"
        )

    conn = _users_conn()
    try:
        existing = conn.execute(
            "SELECT 1 FROM users WHERE username=?", (body.username,)
        ).fetchone()
        if existing:
            raise HTTPException(status_code=409, detail="username already exists")

        password_hash = _hash_password(body.password)
        created_at = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT INTO users (username, name, email, password_hash, role, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (body.username, body.name, body.email, password_hash, body.role, created_at),
        )
        conn.commit()
    finally:
        conn.close()

    # never audit-log the password itself
    audit_log(f"user created by {admin}", f"username={body.username} role={body.role}")
    return {"status": "ok", "username": body.username}


@app.put("/api/users/{username}")
def update_user(
    username: str,
    body: UserUpdate,
    admin: str = Depends(require_admin),
    _csrf: None = Depends(require_csrf),
):
    updates = body.model_dump(exclude_unset=True)
    if not updates:
        raise HTTPException(status_code=400, detail="no fields to update")
    if "role" in updates and updates["role"] not in ("admin", "viewer"):
        raise HTTPException(status_code=400, detail="role must be 'admin' or 'viewer'")
    if "password" in updates and (
        not updates["password"] or len(updates["password"]) < MIN_PASSWORD_LENGTH
    ):
        raise HTTPException(
            status_code=400, detail=f"password must be at least {MIN_PASSWORD_LENGTH} characters"
        )

    conn = _users_conn()
    try:
        # BEGIN IMMEDIATE takes SQLite's write lock right away, before the
        # last-admin check below reads the current admin count - otherwise
        # this is a classic check-then-act TOCTOU: two concurrent demote
        # requests for two different admins (with exactly 2 admins total)
        # can both read admin_count()==2, both pass the "> 1" check, and
        # both commit, leaving zero admins. Taking the write lock up front
        # forces the second request to block until the first one's UPDATE
        # is committed, so its admin-count read is never stale.
        conn.execute("BEGIN IMMEDIATE")
        target = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if target is None:
            raise HTTPException(status_code=404, detail="user not found")

        # Last-admin lockout protection: refuse to demote the last remaining
        # admin account, whether that's the caller demoting themselves or
        # demoting someone else - the invariant being protected is "the
        # system always has at least one admin", not "an admin can't touch
        # their own row".
        if "role" in updates and updates["role"] != "admin" and target["role"] == "admin":
            if _admin_count(conn) <= 1:
                raise HTTPException(
                    status_code=409,
                    detail="cannot demote the last remaining admin account",
                )

        set_clauses: list[str] = []
        params: list = []
        changed_fields: list[str] = []
        if "name" in updates:
            set_clauses.append("name=?")
            params.append(updates["name"])
            changed_fields.append("name")
        if "email" in updates:
            set_clauses.append("email=?")
            params.append(updates["email"])
            changed_fields.append("email")
        if "role" in updates:
            set_clauses.append("role=?")
            params.append(updates["role"])
            changed_fields.append(f"role={updates['role']}")
        if "password" in updates:
            set_clauses.append("password_hash=?")
            params.append(_hash_password(updates["password"]))
            changed_fields.append("password")  # never log the value

        params.append(username)
        conn.execute(f"UPDATE users SET {', '.join(set_clauses)} WHERE username=?", params)
        conn.commit()
    finally:
        conn.close()

    audit_log(f"user updated by {admin}", f"target={username} changed={','.join(changed_fields)}")
    return {"status": "ok"}


@app.delete("/api/users/{username}")
def delete_user(
    username: str,
    admin: str = Depends(require_admin),
    _csrf: None = Depends(require_csrf),
):
    if username == admin:
        raise HTTPException(
            status_code=409, detail="cannot delete your own account via this endpoint"
        )

    conn = _users_conn()
    try:
        # See the matching comment in update_user() above: BEGIN IMMEDIATE
        # closes the same check-then-act TOCTOU gap here (concurrent delete
        # of two different admins, or a concurrent delete + demote, could
        # otherwise both pass the "> 1 admin" check and leave zero admins).
        conn.execute("BEGIN IMMEDIATE")
        target = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if target is None:
            raise HTTPException(status_code=404, detail="user not found")

        if target["role"] == "admin" and _admin_count(conn) <= 1:
            raise HTTPException(
                status_code=409, detail="cannot delete the last remaining admin account"
            )

        conn.execute("DELETE FROM users WHERE username=?", (username,))
        conn.commit()
    finally:
        conn.close()

    audit_log(f"user deleted by {admin}", f"target={username} role={target['role']}")
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# self-service account endpoints (any authenticated user)
# ---------------------------------------------------------------------------

class AccountUpdate(BaseModel):
    name: Optional[str] = None
    email: Optional[str] = None
    current_password: Optional[str] = None
    new_password: Optional[str] = None
    # Present only so we can detect and reject an attempt to change it here -
    # role changes are admin-only, via PUT /api/users/{username}.
    role: Optional[str] = None


@app.get("/api/account")
def get_account(username: str = Depends(require_auth)):
    conn = _users_conn()
    try:
        row = conn.execute(
            "SELECT username, name, email, role FROM users WHERE username=?", (username,)
        ).fetchone()
    finally:
        conn.close()
    if row is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return dict(row)


@app.put("/api/account")
def update_account(
    body: AccountUpdate,
    username: str = Depends(require_auth),
    _csrf: None = Depends(require_csrf),
):
    updates = body.model_dump(exclude_unset=True)

    # `"role" in updates` (not `updates.get("role") is not None`): a caller
    # that explicitly sends `"role": null` still counts as "sent role" here -
    # exclude_unset=True keeps it in `updates` since it was provided, so the
    # old `is not None` check let that exact payload through with a 200
    # instead of the 400 below (role was never actually written either way -
    # see the pop() and the fact only "name"/"email"/password go into
    # set_clauses further down - but the rejection response itself
    # shouldn't be bypassable by a null value).
    if "role" in updates:
        raise HTTPException(
            status_code=400,
            detail=(
                "role cannot be changed via /api/account - ask an admin to "
                "change it via PUT /api/users/{username}"
            ),
        )
    updates.pop("role", None)

    changing_password = "new_password" in updates or "current_password" in updates
    current_password = updates.pop("current_password", None)
    new_password = updates.pop("new_password", None)
    if changing_password:
        if not current_password or not new_password:
            raise HTTPException(
                status_code=400,
                detail="current_password and new_password are both required to change password",
            )
        if len(new_password) < MIN_PASSWORD_LENGTH:
            raise HTTPException(
                status_code=400,
                detail=f"new password must be at least {MIN_PASSWORD_LENGTH} characters",
            )

    conn = _users_conn()
    try:
        row = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if row is None:
            raise HTTPException(status_code=401, detail="Not authenticated")

        if changing_password and not _verify_password(current_password, row["password_hash"]):
            raise HTTPException(status_code=401, detail="current password is incorrect")

        set_clauses: list[str] = []
        params: list = []
        changed_fields: list[str] = []
        if "name" in updates:
            set_clauses.append("name=?")
            params.append(updates["name"])
            changed_fields.append("name")
        if "email" in updates:
            set_clauses.append("email=?")
            params.append(updates["email"])
            changed_fields.append("email")
        if changing_password:
            set_clauses.append("password_hash=?")
            params.append(_hash_password(new_password))
            changed_fields.append("password")  # never log the value

        if set_clauses:
            params.append(username)
            conn.execute(f"UPDATE users SET {', '.join(set_clauses)} WHERE username=?", params)
            conn.commit()
    finally:
        conn.close()

    if changed_fields:
        # Sessions are stateless (same known tradeoff as logout already has -
        # an old session cookie remains valid until it expires even after a
        # password change; not solved differently here).
        audit_log(f"account updated by {username}", f"changed={','.join(changed_fields)}")
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# static frontend (mounted last so it never shadows /api/* routes above)
# ---------------------------------------------------------------------------

FRONTEND_DIR = os.environ.get(
    "GRIDSCAN_UI_FRONTEND_DIR",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "frontend"),
)
app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
