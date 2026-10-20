#!/usr/bin/python3
"""Collect only isolated proxy metadata; never persist HTTP payloads or secrets."""
import collections
import json
import os
import re
import sqlite3
import time
import urllib.request
from pathlib import Path

ROOT = Path('/var/lib/proxy-diagnostic')
SETTINGS = Path('/etc/proxy-diagnostic/collector.json')


def target(value):
    value = str(value or '').lower().rstrip('.')
    return value if re.fullmatch(r'[a-z0-9_.:\[\]-]{1,253}', value) else '(unknown)'


def main():
    os.umask(0o077)
    settings = json.loads(SETTINGS.read_text())
    db = sqlite3.connect(ROOT / 'traffic.sqlite3')
    db.execute('PRAGMA journal_mode=WAL')
    db.executescript('''
    CREATE TABLE IF NOT EXISTS totals(ts INTEGER PRIMARY KEY, upload INTEGER, download INTEGER, active INTEGER);
    CREATE TABLE IF NOT EXISTS connections(id TEXT PRIMARY KEY, first_seen INTEGER, last_seen INTEGER,
      target TEXT, port TEXT, outbound TEXT, rule TEXT, upload INTEGER, download INTEGER, state TEXT);
    CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, ts INTEGER, category TEXT, connection_id TEXT, target TEXT);
    CREATE TABLE IF NOT EXISTS cursors(path TEXT PRIMARY KEY, offset INTEGER);
    CREATE INDEX IF NOT EXISTS events_ts ON events(ts);
    ''')
    failures = 0
    while True:
        now = int(time.time())
        try:
            req = urllib.request.Request(settings['api'] + '/connections',
                headers={'Authorization': 'Bearer ' + settings['secret']})
            with urllib.request.urlopen(req, timeout=3) as response:
                snapshot = json.load(response)
            db.execute('INSERT OR REPLACE INTO totals VALUES(?,?,?,?)',
                (now, snapshot.get('uploadTotal', 0), snapshot.get('downloadTotal', 0), len(snapshot.get('connections', []))))
            active = set()
            for item in snapshot.get('connections', []):
                ident = str(item.get('id', ''))
                if not ident:
                    continue
                active.add(ident)
                meta = item.get('metadata') or {}
                chains = item.get('chains') or []
                outbound = 'XO' if 'xo-shared' in chains else 'HK' if 'direct' in chains else 'unknown'
                db.execute('''INSERT INTO connections VALUES(?,?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(id) DO UPDATE SET last_seen=excluded.last_seen,upload=MAX(upload,excluded.upload),
                    download=MAX(download,excluded.download),state='active' ''',
                    (ident, now, now, target(meta.get('host') or meta.get('destinationIP')),
                     str(meta.get('destinationPort', '')), outbound, str(item.get('rule', ''))[:180],
                     max(0, int(item.get('upload', 0))), max(0, int(item.get('download', 0))), 'active'))
            for (ident,) in db.execute("SELECT id FROM connections WHERE state='active'").fetchall():
                if ident not in active:
                    db.execute("UPDATE connections SET state='closed' WHERE id=?", (ident,))
            failures = 0
        except Exception as exc:
            failures += 1
            if failures == 1 or failures % 60 == 0:
                db.execute('INSERT INTO events(ts,category) VALUES(?,?)', (now, 'collector_' + type(exc).__name__))
        log = ROOT / 'proxy.log'
        if log.exists():
            row = db.execute('SELECT offset FROM cursors WHERE path=?', (str(log),)).fetchone()
            offset = row[0] if row else 0
            if log.stat().st_size < offset:
                offset = 0
            with log.open('rb') as source:
                source.seek(offset)
                for block in source:
                    line = block.decode('utf-8', errors='replace')
                    # Persist event classifications, never the raw exception or request path.
                    ident = re.search(r'\[([0-9]+)(?: |\])', line)
                    dest = re.search(r'(?:connection to|packet connection to) ([a-zA-Z0-9_.:\[\]-]+)', line)
                    category = None
                    for name, pattern in [('timeout', r'timeout|timed out|deadline exceeded'),
                         ('refused', r'connection refused'), ('reset', r'reset'), ('EOF', r'\bEOF\b'),
                         ('tls_error', r'TLS.*error|handshake.*fail'), ('connection_target', r'connection to'),
                         ('inbound', r'inbound connection from'), ('other_error', r'ERROR|WARN')]:
                        if re.search(pattern, line, re.I):
                            category = name
                            break
                    if category:
                        db.execute('INSERT INTO events(ts,category,connection_id,target) VALUES(?,?,?,?)',
                            (now, category, ident.group(1) if ident else None, target(dest.group(1)) if dest else None))
                db.execute('INSERT OR REPLACE INTO cursors VALUES(?,?)', (str(log), source.tell()))
        if now % 60 == 0:
            cutoff = now - 7 * 86400
            db.execute('DELETE FROM totals WHERE ts<?', (cutoff,))
            db.execute('DELETE FROM events WHERE ts<?', (cutoff,))
            db.execute('DELETE FROM connections WHERE last_seen<?', (cutoff,))
        db.commit()
        time.sleep(0.25)


if __name__ == '__main__':
    main()
