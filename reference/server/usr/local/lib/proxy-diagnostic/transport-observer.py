#!/usr/bin/python3
"""Passive one-second socket observer. No payloads, passwords or subscription URLs."""
import argparse
import collections
import hashlib
import json
from pathlib import Path
import re
import signal
import sqlite3
import subprocess
import threading
import time

DATA=Path('/var/lib/proxy-diagnostic-transport')
IDENTITY=Path('/var/lib/proxy-diagnostic-tcp/traffic.sqlite3')
STOP=threading.Event()
STATES={'ESTAB','SYN-RECV','SYN-SENT','FIN-WAIT-1','FIN-WAIT-2','CLOSE-WAIT','LAST-ACK','CLOSING','TIME-WAIT','CLOSE'}
FIELDS=['rtt','rto','retrans','bytes_retrans','bytes_sent','bytes_acked','bytes_received',
        'unacked','lastsnd','lastrcv','lastack','cwnd','mss','lost','segs_out','segs_in']

def endpoint(value):
    host,port=value.rsplit(':',1)
    return host.strip('[]'),int(port)

def sockets(raw):
    rows=[];current=None
    for line in raw.splitlines():
        words=line.split()
        if words and words[0] in STATES and len(words)>=5:
            try:
                local=endpoint(words[3]);peer=endpoint(words[4])
                if local[1]!=443:current=None;continue
                current={'state':words[0],'recv_queue':int(words[1]),'send_queue':int(words[2]),
                         'peer_ip':peer[0],'peer_port':peer[1],'metrics':{}}
                cookie=re.search(r'\bsk:([a-fA-F0-9]+)',line)
                current['cookie']=cookie[1] if cookie else ''
                rows.append(current)
            except (ValueError,IndexError):current=None
        elif current:
            for name in FIELDS:
                m=re.search(r'\b'+name+r':([0-9./]+)',line)
                if m:current['metrics'][name]=m[1]
    return rows

def integer(metrics,name):
    try:return int(str(metrics.get(name,'0')).split('/')[0])
    except ValueError:return 0

def identities(db,cutoff):
    tuples={};peers=set()
    for ident,start,mode,ip,port,target in db.execute(
            'SELECT id,start,mode,source_ip,source_port,target FROM lifecycle WHERE start>=? ORDER BY start',(cutoff,)):
        if not str(port).isdigit():continue
        tuples[(ip,int(port))]={'connection_id':ident,'start':start,'mode':mode,'target':target}
        peers.add(ip)
    return tuples,peers

def event(db,ts,key,category,meta):
    db.execute('INSERT INTO events(ts,socket_key,category,metadata) VALUES(?,?,?,?)',
               (ts,key,category,json.dumps(meta,separators=(',',':'))))

def selftest():
    raw='ESTAB 0 100 198.51.100.20:443 192.0.2.1:50000 uid:1 ino:1 sk:abcd\n\t cubic rto:400 rtt:90/10 bytes_sent:500 bytes_acked:300 bytes_retrans:100 unacked:2\n'
    r=sockets(raw);assert len(r)==1 and r[0]['cookie']=='abcd'
    assert r[0]['send_queue']==100 and integer(r[0]['metrics'],'bytes_retrans')==100
    assert r[0]['peer_port']==50000
    print(json.dumps({'parser_selftest':True}))

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--dry-run',action='store_true')
    parser.add_argument('--self-test',action='store_true');args=parser.parse_args()
    if args.self_test:selftest();return
    source=sqlite3.connect(IDENTITY.as_uri()+'?mode=ro',uri=True,timeout=5)
    links,peers=identities(source,time.time()-86400)
    if args.dry_run:
        raw=subprocess.run(['ss','-ntieH','sport = :443'],capture_output=True,text=True,check=True,timeout=5).stdout
        found=sockets(raw)
        matched=[r for r in found if (r['peer_ip'],r['peer_port']) in links]
        print(json.dumps({'dry_run':True,'socket_rows':len(found),'authenticated_tuple_matches':len(matched),
                          'metric_fields':sorted({k for r in matched for k in r['metrics']}),
                          'no_packet_capture':True,'no_proxy_changes':True}));return
    DATA.mkdir(mode=0o700,parents=True,exist_ok=True)
    db=sqlite3.connect(DATA/'transport.sqlite3',timeout=5)
    db.execute('PRAGMA journal_mode=WAL');db.execute('PRAGMA journal_size_limit=8388608')
    db.executescript('''CREATE TABLE IF NOT EXISTS samples(id INTEGER PRIMARY KEY,ts REAL,socket_key TEXT,metadata TEXT);
      CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY,ts REAL,socket_key TEXT,category TEXT,metadata TEXT);
      CREATE TABLE IF NOT EXISTS status(ts REAL PRIMARY KEY,active_matched INTEGER,active_peer_only INTEGER,loop_ms INTEGER);
      CREATE INDEX IF NOT EXISTS samples_ts ON samples(ts);
      CREATE INDEX IF NOT EXISTS events_ts ON events(ts);
      CREATE INDEX IF NOT EXISTS samples_socket ON samples(socket_key,ts);''')
    boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    known={};refresh=0;cleanup=0
    signal.signal(signal.SIGTERM,lambda *args:STOP.set());signal.signal(signal.SIGINT,lambda *args:STOP.set())
    while not STOP.is_set():
        started=time.monotonic();now=time.time()
        try:
            if now-refresh>=5:links,peers=identities(source,now-86400);refresh=now
            active_pairs={(ip,int(port)) for ip,port in source.execute(
                "SELECT source_ip,source_port FROM connections WHERE state='active' AND last_seen>=?",(int(now)-5,)) if str(port).isdigit()}
            raw=subprocess.run(['ss','-ntieH','sport = :443'],capture_output=True,text=True,check=True,timeout=3).stdout
            seen=set();matched=0;peer_only=0
            for row in sockets(raw):
                addr=(row['peer_ip'],row['peer_port']);identity=links.get(addr)
                if not identity and row['peer_ip'] not in peers:continue
                ph=hashlib.sha256(row['peer_ip'].encode()).hexdigest()[:12]
                key=hashlib.sha256((boot+'|'+ph+'|'+str(row['peer_port'])+'|'+row['cookie']).encode()).hexdigest()[:24]
                seen.add(key)
                prior=known.get(key)
                if identity and addr not in active_pairs and identity['start']<now-5:
                    if not prior or prior['meta'].get('connection_id')!=identity['connection_id']:identity=None
                scope='authenticated_tuple' if identity else 'peer_only_not_identity_proof'
                matched+=bool(identity);peer_only+=not bool(identity)
                meta={k:row[k] for k in ['state','recv_queue','send_queue','metrics','peer_port']}
                meta.update({'peer_hash':ph,'scope':scope})
                if identity:meta.update({k:identity[k] for k in ['connection_id','mode','target']})
                ack=integer(row['metrics'],'bytes_acked');retrans=integer(row['metrics'],'bytes_retrans')
                if prior is None:
                    prior={'ack':ack,'retrans':retrans,'last_ack_progress':now,'last_sample':0,'stall_reported':False,
                           'last_retrans_event':0,'meta':meta,'seen':now}
                    event(db,now,key,'socket_first_observed',meta)
                if ack!=prior['ack'] or row['send_queue']==0:
                    prior['last_ack_progress']=now;prior['stall_reported']=False
                delta=max(0,retrans-prior['retrans'])
                if delta and now-prior['last_retrans_event']>=5:
                    event(db,now,key,'retransmission_observed',meta|{'increment_since_previous_sample':delta})
                    prior['last_retrans_event']=now
                stall=row['send_queue']>0 and now-prior['last_ack_progress']>=10
                if stall and not prior['stall_reported']:
                    category='pending_send_no_ack_progress_10s' if row['state']=='ESTAB' else 'closing_ack_pending_10s_not_application_timeout'
                    event(db,now,key,category,meta|{'no_ack_progress_seconds':round(now-prior['last_ack_progress'],1)})
                    prior['stall_reported']=True
                if now-prior['last_sample']>=5 or delta or row['state']!=prior['meta']['state'] or (stall and now-prior['last_sample']>=1):
                    db.execute('INSERT INTO samples(ts,socket_key,metadata) VALUES(?,?,?)',(now,key,json.dumps(meta,separators=(',',':'))))
                    prior['last_sample']=now
                prior.update({'ack':ack,'retrans':retrans,'meta':meta,'seen':now});known[key]=prior
            for key in list(known):
                if key not in seen:
                    event(db,now,key,'socket_no_longer_observed_not_proof_of_error',known[key]['meta'])
                    del known[key]
            db.execute('INSERT INTO status VALUES(?,?,?,?)',(now,matched,peer_only,round((time.monotonic()-started)*1000)))
            if now-cleanup>=300:
                cutoff=now-3*86400
                for table in ['samples','events','status']:db.execute('DELETE FROM '+table+' WHERE ts<?',(cutoff,))
                for table,limit in [('samples',60000),('events',30000)]:
                    row=db.execute('SELECT id FROM '+table+' ORDER BY id DESC LIMIT 1 OFFSET ?',(limit,)).fetchone()
                    if row:db.execute('DELETE FROM '+table+' WHERE id<=?',(row[0],))
                cleanup=now
            db.commit()
        except Exception as exc:
            event(db,now,'observer','observer_error',{'error_type':type(exc).__name__});db.commit()
        STOP.wait(max(0.1,1-(time.monotonic()-started)))
    source.close();db.close()

if __name__=='__main__':
    try:main()
    except Exception as exc:
        print(json.dumps({'observer_error_type':type(exc).__name__}));raise SystemExit(1)
