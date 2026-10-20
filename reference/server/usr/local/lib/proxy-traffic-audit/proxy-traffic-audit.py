#!/usr/bin/python3
import json
import os
import sqlite3
import sys
import time
import urllib.request
from datetime import datetime, timedelta, timezone


API_URL = os.environ.get("TRAFFIC_API_URL", "http://127.0.0.1:9090/connections")
TOKEN_FILE = os.environ.get("TRAFFIC_TOKEN_FILE", "/etc/proxy-traffic-audit/token")
DB_PATH = os.environ.get("TRAFFIC_DB", "/var/lib/proxy-traffic-audit/traffic.sqlite3")
POLL_SECONDS = float(os.environ.get("TRAFFIC_POLL_SECONDS", "1"))
RETENTION_DAYS = int(os.environ.get("TRAFFIC_RETENTION_DAYS", "30"))


def open_database():
    db = sqlite3.connect(DB_PATH, timeout=10)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=NORMAL")
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS traffic_daily (
            day TEXT NOT NULL,
            target TEXT NOT NULL,
            target_type TEXT NOT NULL,
            destination_port TEXT NOT NULL,
            outbound TEXT NOT NULL,
            mode TEXT NOT NULL,
            upload_bytes INTEGER NOT NULL DEFAULT 0,
            download_bytes INTEGER NOT NULL DEFAULT 0,
            updated_at INTEGER NOT NULL,
            PRIMARY KEY (day, target, target_type, destination_port, outbound, mode)
        );
        CREATE TABLE IF NOT EXISTS connection_state (
            id TEXT PRIMARY KEY,
            upload_bytes INTEGER NOT NULL,
            download_bytes INTEGER NOT NULL,
            last_seen INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS traffic_daily_day_idx ON traffic_daily(day);
        """
    )
    return db


def classify_mode(rule, outbound):
    text = (rule or "").lower()
    if "-hk" in text:
        return "HK"
    if "-xo" in text:
        return "XO"
    if "-auto" in text or "openai-official" in text:
        return "AUTO"
    if rule == "final" and outbound == "direct":
        return "AUTO"
    return "UNKNOWN"


def classify_outbound(chains):
    values = [str(x) for x in (chains or [])]
    if "xo-shared" in values:
        return "xo-shared"
    if "direct" in values:
        return "direct"
    return " > ".join(values) if values else "unknown"


def fetch_snapshot(token):
    request = urllib.request.Request(
        API_URL,
        headers={"Authorization": "Bearer " + token, "Accept": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=3) as response:
        return json.load(response)


def record_snapshot(db, snapshot, now):
    day = datetime.fromtimestamp(now, timezone.utc).astimezone().date().isoformat()
    dirty = False
    for item in snapshot.get("connections", []):
        connection_id = str(item.get("id") or "")
        if not connection_id:
            continue
        metadata = item.get("metadata") or {}
        host = str(metadata.get("host") or "").strip().lower().rstrip(".")
        destination_ip = str(metadata.get("destinationIP") or "").strip()
        if host:
            target, target_type = host, "domain"
        elif destination_ip:
            target, target_type = destination_ip, "ip"
        else:
            target, target_type = "(unknown)", "unknown"
        destination_port = str(metadata.get("destinationPort") or "")
        outbound = classify_outbound(item.get("chains"))
        rule = str(item.get("rule") or "")
        mode = classify_mode(rule, outbound)
        upload = max(0, int(item.get("upload") or 0))
        download = max(0, int(item.get("download") or 0))
        previous = db.execute(
            "SELECT upload_bytes, download_bytes, last_seen FROM connection_state WHERE id = ?",
            (connection_id,),
        ).fetchone()
        if previous is None:
            upload_delta, download_delta = upload, download
        else:
            upload_delta = max(0, upload - int(previous[0]))
            download_delta = max(0, download - int(previous[1]))
        if upload_delta or download_delta:
            dirty = True
            db.execute(
                """
                INSERT INTO traffic_daily
                    (day, target, target_type, destination_port, outbound, mode,
                     upload_bytes, download_bytes, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(day, target, target_type, destination_port, outbound, mode)
                DO UPDATE SET
                    upload_bytes = upload_bytes + excluded.upload_bytes,
                    download_bytes = download_bytes + excluded.download_bytes,
                    updated_at = excluded.updated_at
                """,
                (
                    day,
                    target,
                    target_type,
                    destination_port,
                    outbound,
                    mode,
                    upload_delta,
                    download_delta,
                    now,
                ),
            )
        if previous is None or upload_delta or download_delta or now - int(previous[2]) >= 60:
            dirty = True
            db.execute(
                """
                INSERT INTO connection_state(id, upload_bytes, download_bytes, last_seen)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    upload_bytes = excluded.upload_bytes,
                    download_bytes = excluded.download_bytes,
                    last_seen = excluded.last_seen
                """,
                (connection_id, upload, download, now),
            )
    if now % 60 == 0:
        stale_state_before = now - 86400
        cutoff_day = (datetime.now().astimezone().date() - timedelta(days=RETENTION_DAYS)).isoformat()
        db.execute("DELETE FROM connection_state WHERE last_seen < ?", (stale_state_before,))
        db.execute("DELETE FROM traffic_daily WHERE day < ?", (cutoff_day,))
        dirty = True
    if dirty:
        db.commit()


def main():
    with open(TOKEN_FILE, "r", encoding="utf-8") as handle:
        token = handle.read().strip()
    if not token:
        raise RuntimeError("empty API token")
    db = open_database()
    failures = 0
    while True:
        started = time.monotonic()
        try:
            snapshot = fetch_snapshot(token)
            record_snapshot(db, snapshot, int(time.time()))
            failures = 0
        except Exception as exc:
            failures += 1
            if failures == 1 or failures % 60 == 0:
                print(f"collector error ({failures}): {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
        elapsed = time.monotonic() - started
        time.sleep(max(0.1, POLL_SECONDS - elapsed))


if __name__ == "__main__":
    main()
