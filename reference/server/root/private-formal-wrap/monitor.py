#!/usr/bin/python3
"""Metadata-only wrapper transport observer, also usable as a read-only report."""
import collections
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import time

ROOT=Path(os.environ.get('RELAY_BRIDGE_ROOT','/var/lib/proxy-relay-wrap'))
LISTEN_PORT=int(os.environ.get('RELAY_MONITOR_PORT','18444'))
PEER_PREFIX=os.environ.get('RELAY_MONITOR_PEER','203.0.113.10:')
SCOPE=os.environ.get('RELAY_MONITOR_SCOPE','203.0.113.10')


def observe():
    os.umask(0o077);ROOT.mkdir(mode=0o700,exist_ok=True)
    db=sqlite3.connect(ROOT/'transport.sqlite3')
    db.execute('PRAGMA journal_mode=WAL');db.execute('PRAGMA synchronous=NORMAL')
    db.executescript('''CREATE TABLE IF NOT EXISTS samples(ts REAL,peer_port INTEGER,state TEXT,
      send_queue INTEGER,metrics TEXT);CREATE INDEX IF NOT EXISTS samples_ts ON samples(ts);
      CREATE TABLE IF NOT EXISTS events(ts REAL,peer_port INTEGER,category TEXT,metadata TEXT);
      CREATE TABLE IF NOT EXISTS health(ts REAL,ok INTEGER,active INTEGER);
      CREATE INDEX IF NOT EXISTS events_ts ON events(ts);''')
    known={};last_prune=time.time()
    while True:
        now=time.time();raw=subprocess.run(['ss','-ntieH','sport = :'+str(LISTEN_PORT)],capture_output=True,text=True,timeout=3).stdout
        row=None;seen=set()
        for line in raw.splitlines():
            if not line[:1].isspace():
                row=None;parts=line.split()
                if len(parts)>=5 and parts[3].endswith(':'+str(LISTEN_PORT)) and parts[4].startswith(PEER_PREFIX):
                    row={'state':parts[0],'send_queue':int(parts[2]),'port':int(parts[4].rsplit(':',1)[1]),'key':parts[4]}
            elif row:
                m=dict(re.findall(r'\b(rtt|rto|retrans|bytes_retrans|bytes_sent|bytes_acked|bytes_received|unacked|cwnd|mss|lost):([^\s]+)',line))
                port=row['port'];key=row['key'];seen.add(key);ack=int(m.get('bytes_acked',0));retry=int(m.get('bytes_retrans',0))
                old=known.setdefault(key,{'ack':ack,'retry':retry,'progress':now,'reported':False})
                if ack!=old['ack'] or row['send_queue']==0:old['progress']=now;old['reported']=False
                delta=max(0,retry-old['retry'])
                if delta:db.execute('INSERT INTO events VALUES(?,?,?,?)',(now,port,'retransmission',json.dumps({'increment':delta})))
                if row['state']=='ESTAB' and row['send_queue']>0 and now-old['progress']>=10 and not old['reported']:
                    db.execute('INSERT INTO events VALUES(?,?,?,?)',(now,port,'pending_ack_10s',json.dumps({'metrics':m,'send_queue':row['send_queue']})));old['reported']=True
                db.execute('INSERT INTO samples VALUES(?,?,?,?,?)',(now,port,row['state'],row['send_queue'],json.dumps(m)))
                old.update(ack=ack,retry=retry);row=None
        known={k:v for k,v in known.items() if k in seen}
        db.execute('INSERT INTO health VALUES(?,?,?)',(now,1,len(seen)))
        if now-last_prune>=300:
            for table in ['samples','events','health']:db.execute('DELETE FROM '+table+' WHERE ts<?',(now-3*86400,))
            last_prune=now
        db.commit();time.sleep(2)


def scope_views(c):
    bridge=ROOT/'flows.sqlite3'
    if not bridge.is_file():return False
    c.execute('ATTACH DATABASE ? AS wrap',(bridge.as_uri()+'?mode=ro',))
    for table in ['lifecycle','connections']:
        cols=[x[1] for x in c.execute('PRAGMA main.table_info('+table+')')]
        expression=[]
        for col in cols:
            if col=='source_ip':
                assert SCOPE in ['203.0.113.10','direct-packaged']
                expression.append("CASE WHEN t.source_ip='127.0.0.1' AND EXISTS(SELECT 1 FROM wrap.sessions w WHERE w.main_source_port=CAST(t.source_port AS INTEGER) AND w.start<=t.start+2 AND (w.end IS NULL OR w.end>=t.start-2)) THEN '"+SCOPE+"' ELSE t.source_ip END AS source_ip")
            else:expression.append('t.'+col)
        c.execute('CREATE TEMP VIEW '+table+' AS SELECT '+','.join(expression)+' FROM main.'+table+' t')
    return True


def report():
    cut=time.time()-1800
    c=sqlite3.connect('file:/var/lib/proxy-diagnostic-tcp/traffic.sqlite3?mode=ro',uri=True)
    mapped=scope_views(c)
    peer=SCOPE
    counts=c.execute('SELECT mode,COUNT(*) FROM lifecycle WHERE start>=? AND source_ip=? GROUP BY mode',(cut,peer)).fetchall()
    errors=c.execute("SELECT e.category,COUNT(*) FROM events e JOIN lifecycle l ON l.id=e.connection_id WHERE e.ts>=? AND l.source_ip=? AND e.category NOT IN ('authenticated_target','outbound_selected') GROUP BY e.category",(cut,peer)).fetchall()
    domains=c.execute('SELECT host,outbound,COUNT(*),SUM(upload),SUM(download) FROM connections WHERE start>=? AND source_ip=? GROUP BY host,outbound ORDER BY SUM(upload+download) DESC LIMIT 20',(cut,peer)).fetchall()
    out={'window_minutes':30,'exact_bridge_tuple_mapping_enabled':mapped,'diagnostic_authenticated_modes':counts,'diagnostic_error_counts':errors,'domains_and_exits_sampled':domains,'client_devices_and_full_https_urls_unavailable':True}
    if mapped:
        out['bridge_transport_totals_including_health_probes']=c.execute('SELECT COUNT(*),SUM(upload),SUM(download),SUM(end IS NULL) FROM wrap.sessions WHERE start>=?',(cut,)).fetchone()
        out['bridge_sessions_matched_to_diagnostic_auth']=c.execute("SELECT COUNT(*) FROM main.lifecycle l WHERE l.start>=? AND l.source_ip='127.0.0.1' AND EXISTS(SELECT 1 FROM wrap.sessions w WHERE w.main_source_port=CAST(l.source_port AS INTEGER) AND w.start<=l.start+2 AND (w.end IS NULL OR w.end>=l.start-2))",(cut,)).fetchone()[0]
    p=ROOT/'transport.sqlite3'
    if p.is_file():
        t=sqlite3.connect(p.as_uri()+'?mode=ro',uri=True)
        out['wrapper_tcp_events']=t.execute('SELECT category,COUNT(*) FROM events WHERE ts>=? GROUP BY category',(cut,)).fetchall()
        out['observed_retrans_increment_lower_bound']=sum(json.loads(m).get('increment',0) for m, in t.execute("SELECT metadata FROM events WHERE ts>=? AND category='retransmission'",(cut,)))
    print(json.dumps(out,ensure_ascii=True))


if __name__=='__main__':
    try:report() if '--report' in sys.argv else observe()
    except Exception as exc:
        print(json.dumps({'monitor_error_type':type(exc).__name__}),flush=True);raise SystemExit(1)
