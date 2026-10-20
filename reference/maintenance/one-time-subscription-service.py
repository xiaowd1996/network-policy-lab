#!/usr/bin/python3
"""Serve one-use subscriptions and retire isolated temporary proxy leases.

The service stores only SHA-256 token digests.  Real download/access tokens are
kept in the root-only nginx map and the private handout, never in logs.
"""

import hashlib
import os
import re
import sqlite3
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


LISTEN_HOST = os.environ.get("ONE_TIME_LISTEN_HOST", "127.0.0.1")
LISTEN_PORT = int(os.environ.get("ONE_TIME_LISTEN_PORT", "18081"))
STATE_DB = Path(os.environ.get("ONE_TIME_STATE_DB", "/var/lib/one-time-subscriptions/state.sqlite3"))
POLL_SECONDS = float(os.environ.get("ONE_TIME_POLL_SECONDS", "2"))
TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")
DOWNLOAD_RE = re.compile(r"^/once/([A-Za-z0-9_-]{43})/mihomo\.yaml$")
ACCESS_RE = re.compile(r"^/lease/([A-Za-z0-9_-]{43})$")


def token_digest(token):
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def open_db():
    db = sqlite3.connect(STATE_DB, timeout=10)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=FULL")
    return db


def established_on_port(port):
    wanted = f"{int(port):04X}"
    count = 0
    for proc_path in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            lines = Path(proc_path).read_text(encoding="ascii").splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            fields = line.split()
            if len(fields) >= 4 and fields[1].rsplit(":", 1)[-1] == wanted and fields[3] == "01":
                count += 1
    return count


def expire_lease(lease_id, unit_name):
    with open_db() as db:
        changed = db.execute(
            "UPDATE leases SET state='expired', expired_at=? WHERE id=? AND state='active'",
            (int(time.time()), lease_id),
        ).rowcount
    if not changed:
        return
    subprocess.run(
        ["/bin/systemctl", "stop", unit_name],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=20,
        check=False,
    )
    print(f"lease expired: {lease_id}", flush=True)


def monitor_loop():
    while True:
        now = int(time.time())
        try:
            with open_db() as db:
                rows = db.execute(
                    "SELECT id, port, unit_name, first_proxy_at, zero_since, absolute_expires_at, inactivity_seconds "
                    "FROM leases WHERE state='active'"
                ).fetchall()
            for row in rows:
                if now >= row["absolute_expires_at"]:
                    expire_lease(row["id"], row["unit_name"])
                    continue
                active = established_on_port(row["port"])
                if active:
                    with open_db() as db:
                        db.execute(
                            "UPDATE leases SET first_proxy_at=COALESCE(first_proxy_at, ?), zero_since=NULL "
                            "WHERE id=? AND state='active'",
                            (now, row["id"]),
                        )
                elif row["first_proxy_at"] is not None:
                    if row["zero_since"] is None:
                        with open_db() as db:
                            db.execute(
                                "UPDATE leases SET zero_since=? WHERE id=? AND state='active' AND zero_since IS NULL",
                                (now, row["id"]),
                            )
                    elif now - row["zero_since"] >= row["inactivity_seconds"]:
                        expire_lease(row["id"], row["unit_name"])
        except Exception as exc:
            print(f"monitor error: {type(exc).__name__}", flush=True)
        time.sleep(POLL_SECONDS)


class Handler(BaseHTTPRequestHandler):
    server_version = ""
    sys_version = ""

    def log_message(self, _format, *_args):
        return

    def send_empty(self, status):
        self.send_response(status)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_HEAD(self):
        match = DOWNLOAD_RE.fullmatch(self.path)
        if not match:
            self.send_empty(404)
            return
        digest = token_digest(match.group(1))
        with open_db() as db:
            row = db.execute(
                "SELECT yaml_path FROM leases WHERE download_hash=? AND state='ready'", (digest,)
            ).fetchone()
        if row is None or not Path(row["yaml_path"]).is_file():
            self.send_empty(404)
            return
        size = Path(row["yaml_path"]).stat().st_size
        self.send_response(200)
        self.send_header("Content-Type", "text/yaml; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(size))
        self.end_headers()

    def do_GET(self):
        if self.path == "/auth":
            self.handle_auth()
            return
        match = DOWNLOAD_RE.fullmatch(self.path)
        if not match:
            self.send_empty(404)
            return
        digest = token_digest(match.group(1))
        now = int(time.time())
        with open_db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT id, yaml_path, absolute_seconds FROM leases WHERE download_hash=? AND state='ready'",
                (digest,),
            ).fetchone()
            if row is None or not Path(row["yaml_path"]).is_file():
                db.rollback()
                self.send_empty(404)
                return
            body = Path(row["yaml_path"]).read_bytes()
            changed = db.execute(
                "UPDATE leases SET state='active', consumed_at=?, absolute_expires_at=? "
                "WHERE id=? AND state='ready'",
                (now, now + int(row["absolute_seconds"]), row["id"]),
            ).rowcount
            if changed != 1:
                db.rollback()
                self.send_empty(404)
                return
            db.commit()
        self.send_response(200)
        self.send_header("Content-Type", "text/yaml; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def handle_auth(self):
        uri = self.headers.get("X-Original-URI", "")
        match = ACCESS_RE.fullmatch(uri)
        if not match or not TOKEN_RE.fullmatch(match.group(1)):
            self.send_empty(404)
            return
        digest = token_digest(match.group(1))
        now = int(time.time())
        with open_db() as db:
            row = db.execute(
                "SELECT id, absolute_expires_at FROM leases WHERE access_hash=? AND state='active'",
                (digest,),
            ).fetchone()
            if row is None or now >= int(row["absolute_expires_at"]):
                self.send_empty(404)
                return
            db.execute(
                "UPDATE leases SET first_proxy_at=COALESCE(first_proxy_at, ?), zero_since=NULL "
                "WHERE id=? AND state='active'",
                (now, row["id"]),
            )
        self.send_empty(204)

    def do_POST(self):
        if self.path == "/auth":
            self.handle_auth()
        else:
            self.send_empty(404)


def main():
    STATE_DB.parent.mkdir(parents=True, exist_ok=True)
    thread = threading.Thread(target=monitor_loop, name="lease-monitor", daemon=True)
    thread.start()
    server = ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
