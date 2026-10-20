#!/usr/bin/python3
"""Identify diagnostic TCP users via route tags and auth-scoped lifecycle events."""
import datetime
import json
import os
from pathlib import Path
import re
import sqlite3
import time
import urllib.request

ROOT=Path('/var/lib/proxy-diagnostic-tcp')
SETTINGS=Path('/etc/proxy-diagnostic-tcp/collector.json')


def safe_target(v):
    value=str(v or '').lower().rstrip('.')
    return value if re.fullmatch(r'[a-z0-9_.:\[\]-]{1,253}',value) else '(unknown)'


def main():
    os.umask(0o077)
    settings=json.loads(SETTINGS.read_text())
    c=sqlite3.connect(ROOT/'traffic.sqlite3',timeout=10)
    c.execute('PRAGMA journal_mode=WAL')
    c.executescript('''CREATE TABLE IF NOT EXISTS connections(id TEXT PRIMARY KEY,start INTEGER,last_seen INTEGER,
      host TEXT,port TEXT,source_ip TEXT,source_port TEXT,outbound TEXT,rule TEXT,upload INTEGER,download INTEGER,state TEXT);
      CREATE TABLE IF NOT EXISTS lifecycle(id TEXT PRIMARY KEY,start INTEGER,mode TEXT,source_ip TEXT,source_port TEXT,target TEXT);
      CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY,ts INTEGER,connection_id TEXT,mode TEXT,category TEXT,target TEXT);
      CREATE TABLE IF NOT EXISTS samples(ts INTEGER PRIMARY KEY,active INTEGER);
      CREATE TABLE IF NOT EXISTS cursors(path TEXT PRIMARY KEY,offset INTEGER);
      CREATE INDEX IF NOT EXISTS events_ts ON events(ts);''')
    origins={}
    failures=0
    while True:
        now=int(time.time())
        try:
            req=urllib.request.Request(settings['api']+'/connections',headers={'Authorization':'Bearer '+settings['secret']})
            with urllib.request.urlopen(req,timeout=3) as r:snapshot=json.load(r)
            active=set()
            for item in snapshot.get('connections',[]):
                tags=item.get('chains') or []
                if not set(tags).intersection(settings['outbounds']):continue
                ident=str(item['id']);active.add(ident);m=item.get('metadata') or {}
                outbound='XO' if 'EXAMPLE_USER_15' in tags else 'HK'
                c.execute('''INSERT INTO connections VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET
                  last_seen=excluded.last_seen,upload=MAX(upload,excluded.upload),download=MAX(download,excluded.download),state='active' ''',
                  (ident,now,now,safe_target(m.get('host') or m.get('destinationIP')),str(m.get('destinationPort','')),
                   safe_target(m.get('sourceIP')),str(m.get('sourcePort','')),outbound,str(item.get('rule',''))[:250],
                   int(item.get('upload') or 0),int(item.get('download') or 0),'active'))
            for (ident,) in c.execute("SELECT id FROM connections WHERE state='active'").fetchall():
                if ident not in active:c.execute("UPDATE connections SET state='closed' WHERE id=?",(ident,))
            c.execute('INSERT OR REPLACE INTO samples VALUES(?,?)',(now,len(active)))
            failures=0
        except Exception as exc:
            failures+=1
            if failures==1 or failures%60==0:
                c.execute('INSERT INTO events(ts,category) VALUES(?,?)',(now,'collector_'+type(exc).__name__))
        log=Path(settings['log'])
        if log.exists():
            saved=c.execute('SELECT offset FROM cursors WHERE path=?',(str(log),)).fetchone()
            offset=saved[0] if saved else 0
            if log.stat().st_size<offset:offset=0
            with log.open('rb') as f:
                f.seek(offset)
                for block in f:
                    line=block.decode('utf-8',errors='replace')
                    ident=re.search(r'\[([0-9]+) [^]]+\]',line)
                    if not ident:continue
                    ident=ident.group(1)
                    timestamp=re.search(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})',line)
                    ts=int(datetime.datetime.strptime(timestamp.group(1),'%Y-%m-%d %H:%M:%S').replace(
                        tzinfo=datetime.timezone(datetime.timedelta(hours=8))).timestamp()) if timestamp else now
                    peer=re.search(r'inbound connection from ([0-9.]+):([0-9]+)',line)
                    if peer:
                        origins[ident]=(ts,peer.group(1),peer.group(2))
                        if len(origins)>20000:
                            origins={k:v for k,v in origins.items() if v[0]>now-600}
                    mode=None
                    for user,m in settings['users'].items():
                        if 'inbound/trojan' in line and '['+user+']' in line:mode=m;break
                    dest=re.search(r'connection to ([a-zA-Z0-9_.:\[\]-]+)',line)
                    if mode:
                        origin=origins.pop(ident,(ts,'(unknown)',''))
                        c.execute('INSERT OR IGNORE INTO lifecycle VALUES(?,?,?,?,?,?)',
                            (ident,origin[0],mode,origin[1],origin[2],safe_target(dest.group(1)) if dest else '(unknown)'))
                        c.execute('INSERT INTO events(ts,connection_id,mode,category,target) VALUES(?,?,?,?,?)',
                            (ts,ident,mode,'authenticated_target',safe_target(dest.group(1)) if dest else '(unknown)'))
                    elif 'outbound/' in line and any('['+tag+']' in line for tag in settings['outbounds']):
                        c.execute('INSERT INTO events(ts,connection_id,category,target) VALUES(?,?,?,?)',
                            (ts,ident,'outbound_selected',safe_target(dest.group(1)) if dest else '(unknown)'))
                    if re.search(r'\bERROR\b|\bWARN\b',line):
                        known=c.execute('SELECT mode,target FROM lifecycle WHERE id=?',(ident,)).fetchone()
                        if known:
                            category='other_error'
                            for name,pat in [('timeout','timeout|timed out|deadline'),('refused','refused'),
                                ('reset','reset'),('EOF',r'\bEOF\b'),('tls','TLS|handshake')]:
                                if re.search(pat,line,re.I):category=name;break
                            c.execute('INSERT INTO events(ts,connection_id,mode,category,target) VALUES(?,?,?,?,?)',
                                (ts,ident,known[0],category,known[1]))
                c.execute('INSERT OR REPLACE INTO cursors VALUES(?,?)',(str(log),f.tell()))
        if now%60==0:
            cutoff=now-7*86400
            c.execute('DELETE FROM events WHERE ts<?',(cutoff,));c.execute('DELETE FROM samples WHERE ts<?',(cutoff,))
            c.execute('DELETE FROM connections WHERE last_seen<?',(cutoff,));c.execute('DELETE FROM lifecycle WHERE start<?',(cutoff,))
        c.commit()
        time.sleep(.1)


if __name__=='__main__':
    try:main()
    except Exception as e:
        print(json.dumps({'collector_error_type':type(e).__name__}));raise SystemExit(1)
