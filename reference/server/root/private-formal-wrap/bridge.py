#!/usr/bin/python3
"""Fixed loopback bridge with exact main-443 source-tuple accounting; no payload logs."""
import json
import os
from pathlib import Path
import selectors
import signal
import socket
import sqlite3
import time
import uuid

ROOT=Path(os.environ.get('RELAY_BRIDGE_ROOT','/var/lib/proxy-relay-wrap'))
LISTEN_PORT=int(os.environ.get('RELAY_BRIDGE_PORT','18445'))
LIMIT=256*1024


def run():
    os.umask(0o077)
    ROOT.mkdir(mode=0o700,exist_ok=True)
    db=sqlite3.connect(ROOT/'flows.sqlite3',timeout=5)
    db.execute('PRAGMA journal_mode=WAL');db.execute('PRAGMA synchronous=NORMAL')
    db.executescript('''CREATE TABLE IF NOT EXISTS sessions(
      id TEXT PRIMARY KEY,start REAL,end REAL,main_source_ip TEXT,main_source_port INTEGER,
      upload INTEGER,download INTEGER,state TEXT,last_activity REAL,error_category TEXT);
      CREATE INDEX IF NOT EXISTS session_tuple ON sessions(main_source_port,start,end);
      CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY,ts REAL,session_id TEXT,category TEXT);
      CREATE TABLE IF NOT EXISTS status(ts INTEGER PRIMARY KEY,active INTEGER,upload INTEGER,download INTEGER);''')
    db.execute("UPDATE sessions SET end=?,state='bridge_restart_closed' WHERE end IS NULL",(time.time(),));db.commit()
    sel=selectors.DefaultSelector();pairs={};running=True
    listener=socket.socket();listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    listener.bind(('127.0.0.1',LISTEN_PORT));listener.listen(512);listener.setblocking(False)
    sel.register(listener,selectors.EVENT_READ,None)

    def stop(signum,frame):
        nonlocal running
        running=False

    signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)

    def update(row):
        db.execute('''INSERT INTO sessions VALUES(?,?,?,?,?,?,?,?,?,?)
          ON CONFLICT(id) DO UPDATE SET end=excluded.end,upload=excluded.upload,
          download=excluded.download,state=excluded.state,last_activity=excluded.last_activity,
          error_category=excluded.error_category''',
          (row['id'],row['start'],row.get('end'),'127.0.0.1',row['port'],row['up'],row['down'],
           row['state'],row['last'],row.get('error')))

    def close(row,category):
        if row['id'] not in pairs:return
        row['end']=time.time();row['state']='closed';row['error']=None if category in ['eof','service_stop'] else category
        if row['up'] and not row['down']:
            db.execute('INSERT INTO events(ts,session_id,category) VALUES(?,?,?)',
              (row['end'],row['id'],'client_bytes_without_server_bytes_at_close'))
        db.execute('INSERT INTO events(ts,session_id,category) VALUES(?,?,?)',(row['end'],row['id'],category))
        update(row)
        for s in row['sockets']:
            try:sel.unregister(s)
            except Exception:pass
            s.close()
        pairs.pop(row['id'],None)

    def interests(row):
        if row['id'] not in pairs:return
        for i,s in enumerate(row['sockets']):
            read=(not row['eof'][i]) and len(row['buf'][1-i])<LIMIT
            write=bool(row['buf'][i])
            flags=(selectors.EVENT_READ if read else 0)|(selectors.EVENT_WRITE if write else 0)
            try:
                if flags:
                    try:sel.modify(s,flags,(row,i))
                    except KeyError:sel.register(s,flags,(row,i))
                else:
                    try:sel.unregister(s)
                    except KeyError:pass
            except (OSError,ValueError):close(row,'selector_error');return

    last_flush=time.monotonic();last_prune=last_flush
    print(json.dumps({'bridge_started':True,'fixed_destination':'127.0.0.1:443','payload_logging':False}),flush=True)
    while running:
        for key,flags in sel.select(.5):
            if key.data is None:
                try:client,address=listener.accept()
                except BlockingIOError:continue
                upstream=socket.socket()
                now=time.time();row={'id':uuid.uuid4().hex,'start':now,'last':now,'up':0,'down':0,
                  'sockets':[client,upstream],'buf':[bytearray(),bytearray()],'eof':[False,False],
                  'shutdown':[False,False],'state':'connecting'}
                try:
                    # Only a local connection: bounded connect does not depend on WAN latency.
                    upstream.settimeout(2);upstream.bind(('127.0.0.1',0));row['port']=upstream.getsockname()[1]
                    upstream.connect(('127.0.0.1',443))
                    for s in row['sockets']:s.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1);s.setblocking(False)
                    row['state']='active';pairs[row['id']]=row;update(row);interests(row)
                except Exception as exc:
                    row['port']=row.get('port',0);row['end']=time.time();row['state']='connect_failed';row['error']=type(exc).__name__
                    update(row)
                    for s in row['sockets']:s.close()
                continue
            row,i=key.data
            if row['id'] not in pairs:continue
            try:
                if flags & selectors.EVENT_READ:
                    try:data=key.fileobj.recv(min(32768,LIMIT-len(row['buf'][1-i])))
                    except BlockingIOError:data=None
                    if data is not None:
                        row['last']=time.time()
                        if data:row['buf'][1-i].extend(data)
                        else:row['eof'][i]=True
                if flags & selectors.EVENT_WRITE and row['buf'][i]:
                    try:n=key.fileobj.send(row['buf'][i])
                    except BlockingIOError:n=0
                    if n:
                        del row['buf'][i][:n];row['last']=time.time()
                        row['up' if i==1 else 'down']+=n
                for j in [0,1]:
                    if row['eof'][j] and not row['buf'][1-j] and not row['shutdown'][1-j]:
                        try:row['sockets'][1-j].shutdown(socket.SHUT_WR)
                        except OSError:pass
                        row['shutdown'][1-j]=True
                if all(row['eof']) and not any(row['buf']):close(row,'eof')
                else:interests(row)
            except (OSError,ValueError) as exc:close(row,type(exc).__name__)
        tick=time.monotonic()
        if tick-last_flush>=1:
            for row in pairs.values():update(row)
            db.execute('INSERT OR REPLACE INTO status VALUES(?,?,?,?)',(int(time.time()),len(pairs),
              sum(r['up'] for r in pairs.values()),sum(r['down'] for r in pairs.values())))
            db.commit();last_flush=tick
        if tick-last_prune>=300:
            cut=time.time()-14*86400
            db.execute('DELETE FROM sessions WHERE end IS NOT NULL AND end<?',(cut,))
            db.execute('DELETE FROM events WHERE ts<?',(cut,));db.execute('DELETE FROM status WHERE ts<?',(cut,))
            db.commit();last_prune=tick
    for row in list(pairs.values()):close(row,'service_stop')
    db.commit();db.close();sel.close();listener.close()


if __name__=='__main__':
    try:run()
    except Exception as exc:
        print(json.dumps({'bridge_error_type':type(exc).__name__}),flush=True)
        raise SystemExit(1)
