#!/usr/bin/python3
"""Server health, header-only TCP flags and transport canaries; no payload logs."""
import datetime
import hashlib
import json
import os
import re
import signal
import socket
import sqlite3
import ssl
import subprocess
import threading
import time
from pathlib import Path

DATA = Path('/var/lib/proxy-diagnostic')
STOP = threading.Event()
HOST = '198.51.100.20'


def database():
    db = sqlite3.connect(DATA / 'health.sqlite3', timeout=10)
    db.execute('PRAGMA journal_mode=WAL')
    return db


def counters(path):
    lines = Path(path).read_text().splitlines()
    result = {}
    for i in range(0, len(lines)-1, 2):
        names, values = lines[i].split(), lines[i+1].split()
        if names[0] == values[0]:
            for key, value in zip(names[1:], values[1:]):
                if value.lstrip('-').isdigit():
                    result[names[0].rstrip(':') + '.' + key] = int(value)
    return result


def receive(sock, n):
    data = b''
    while len(data) < n:
        block = sock.recv(n-len(data))
        if not block:
            raise EOFError()
        data += block
    return data


def probe(xo=None):
    phase = 'connect'
    started = time.monotonic()
    sock = None
    try:
        host = 'chatgpt.com' if xo else HOST
        if xo:
            sock = socket.create_connection((xo['server'], xo['server_port']), timeout=5)
            sock.settimeout(5)
            phase = 'socks_auth'
            sock.sendall(b'\x05\x01\x02')
            if receive(sock, 2) != b'\x05\x02':
                raise ValueError()
            user, password = xo['username'].encode(), xo['password'].encode()
            sock.sendall(b'\x01' + bytes([len(user)]) + user + bytes([len(password)]) + password)
            if receive(sock, 2) != b'\x01\x00':
                raise ValueError()
            phase = 'socks_destination'
            dest = host.encode()
            sock.sendall(b'\x05\x01\x00\x03' + bytes([len(dest)]) + dest + b'\x01\xbb')
            head = receive(sock, 4)
            if head[1] != 0:
                return {'ok': False, 'phase': phase, 'socks_code': head[1], 'ms': round((time.monotonic()-started)*1000)}
            if head[3] == 1:
                receive(sock, 6)
            elif head[3] == 4:
                receive(sock, 18)
            elif head[3] == 3:
                receive(sock, receive(sock, 1)[0]+2)
        else:
            sock = socket.create_connection((HOST, 443), timeout=5)
        phase = 'tls'
        sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
        sock.settimeout(5)
        phase = 'http'
        path = '/cdn-cgi/trace' if xo else '/'
        sock.sendall(f'GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n'.encode())
        data = b''
        while b'\r\n' not in data and len(data) < 16384:
            block = sock.recv(4096)
            if not block:
                raise EOFError()
            data += block
        status = int(data.split(b' ', 2)[1])
        return {'ok': True, 'status': status, 'phase': 'http_response', 'ms': round((time.monotonic()-started)*1000)}
    except Exception as exc:
        return {'ok': False, 'phase': phase, 'error_type': type(exc).__name__, 'ms': round((time.monotonic()-started)*1000)}
    finally:
        if sock:
            sock.close()


def canaries():
    db = database()
    config = json.loads(Path('/etc/proxy-diagnostic/config.json').read_text())
    xo = next(x for x in config['outbounds'] if x.get('tag') == 'xo-shared')
    while not STOP.is_set():
        for label, argument in [('public443_tls', None), ('XO_chatgpt_tls', xo)]:
            result = probe(argument)
            db.execute('INSERT INTO probes VALUES(?,?,?)', (time.time(), label, json.dumps(result)))
            db.commit()
        STOP.wait(30)
    db.close()


def resources():
    db = database()
    config = json.loads(Path('/etc/proxy-diagnostic/config.json').read_text())
    xo = next(x for x in config['outbounds'] if x.get('tag') == 'xo-shared')
    xo_ip, xo_port = socket.gethostbyname(xo['server']), int(xo['server_port'])
    wanted = ['Tcp.RetransSegs','Tcp.OutSegs','Tcp.InErrs','Tcp.OutRsts',
        'TcpExt.ListenOverflows','TcpExt.ListenDrops','TcpExt.TCPBacklogDrop','TcpExt.TCPReqQFullDrop',
        'TcpExt.SyncookiesSent','TcpExt.TCPTimeouts','TcpExt.TCPSynRetrans','TcpExt.TCPAbortOnMemory']
    while not STOP.is_set():
        try:
            stats = counters('/proc/net/snmp') | counters('/proc/net/netstat')
            mem = {k: int(v.split()[0]) for k,v in (l.split(':',1) for l in Path('/proc/meminfo').read_text().splitlines())}
            payload = {'load1': float(Path('/proc/loadavg').read_text().split()[0]), 'mem_available_kb': mem['MemAvailable'],
                'tcp': {k: stats.get(k) for k in wanted}}
            net = {}
            for line in Path('/proc/net/dev').read_text().splitlines()[2:]:
                iface, values = line.split(':');v = list(map(int, values.split()))
                net[iface.strip()] = {'rx_bytes':v[0],'rx_errors':v[2],'rx_drops':v[3],
                    'tx_bytes':v[8],'tx_errors':v[10],'tx_drops':v[11]}
            payload['interfaces'] = net
            rows = subprocess.run(['ss','-lnt'],capture_output=True,text=True,timeout=3).stdout.splitlines()[1:]
            payload['listeners'] = []
            for row in rows:
                f = row.split()
                if len(f)>3 and f[3].rsplit(':',1)[-1] in ['443','8080','19150']:
                    payload['listeners'].append({'port':f[3].rsplit(':',1)[-1],'queue':int(f[1]),'limit':int(f[2])})
            raw = subprocess.run(['ss','-ntiH','state','established'],capture_output=True,text=True,timeout=3).stdout
            peer = None
            for line in raw.splitlines():
                if 'rtt:' not in line:
                    fields = line.split()
                    try:
                        src,sp=fields[2].rsplit(':',1);dst,dp=fields[3].rsplit(':',1)
                        sp,dp=int(sp),int(dp)
                        peer = ('client443',dst,dp) if sp==443 else ('XO_out',src,sp) if dst.strip('[]')==xo_ip and dp==xo_port else None
                    except (ValueError,IndexError):
                        peer = None
                    continue
                if not peer:
                    continue
                values = {}
                for name in ['rtt','retrans','bytes_retrans','unacked']:
                    match = re.search(r'\b'+name+r':([0-9./]+)',line)
                    if match:
                        values[name] = match.group(1)
                db.execute('INSERT INTO tcp_sockets VALUES(?,?,?,?,?)',
                    (time.time(),peer[0],hashlib.sha256(peer[1].encode()).hexdigest()[:12],peer[2],json.dumps(values)))
            db.execute('INSERT INTO resources VALUES(?,?)', (time.time(),json.dumps(payload)))
            if int(time.time()) % 300 < 5:
                cutoff = time.time()-7*86400
                for table in ['resources','probes','tcp_flags','tcp_sockets']:
                    db.execute('DELETE FROM ' + table + ' WHERE ts<?',(cutoff,))
            db.commit()
        except Exception as exc:
            db.execute('INSERT INTO probes VALUES(?,?,?)',(time.time(),'monitor_error',json.dumps({'error_type':type(exc).__name__})))
            db.commit()
        STOP.wait(5)
    db.close()


def main():
    os.umask(0o077)
    db = database()
    db.executescript('''CREATE TABLE IF NOT EXISTS resources(ts REAL,payload TEXT);
      CREATE TABLE IF NOT EXISTS probes(ts REAL,label TEXT,result TEXT);
      CREATE TABLE IF NOT EXISTS tcp_flags(ts REAL,leg TEXT,peer TEXT,peer_port INTEGER,flags TEXT,seq TEXT);
      CREATE TABLE IF NOT EXISTS tcp_sockets(ts REAL,leg TEXT,peer_hash TEXT,port INTEGER,metrics TEXT);
      CREATE INDEX IF NOT EXISTS tcp_flags_ts ON tcp_flags(ts);
      CREATE INDEX IF NOT EXISTS probes_ts ON probes(ts);''')
    db.commit()
    config = json.loads(Path('/etc/proxy-diagnostic/config.json').read_text())
    xo = next(x for x in config['outbounds'] if x.get('tag')=='xo-shared')
    xo_ip = socket.gethostbyname(xo['server'])
    xo_port = int(xo['server_port'])
    route = subprocess.run(['ip','route','get','1.1.1.1'],capture_output=True,text=True,check=True).stdout
    interface = re.search(r'\bdev (\S+)',route).group(1)
    expression = f'tcp and (port 443 or (host {xo_ip} and port {xo_port})) and (tcp[13] & 7 != 0)'
    capture = subprocess.Popen(['tcpdump','-i',interface,'-nn','-tt','-l','-s','96',expression],
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,bufsize=1)
    def stop(*args):
        STOP.set()
        capture.terminate()
    signal.signal(signal.SIGTERM,stop)
    signal.signal(signal.SIGINT,stop)
    threads = [threading.Thread(target=resources,daemon=True),threading.Thread(target=canaries,daemon=True)]
    for thread in threads:
        thread.start()
    pattern = re.compile(r'^(\d+\.\d+) IP (\S+) > (\S+): Flags \[([^]]+)\](?:, seq ([0-9:]+))?')
    for line in capture.stdout:
        m = pattern.match(line)
        if not m:
            continue
        ts,src,dst,flags,seq = m.groups()
        try:
            src_ip,src_port=src.rsplit('.',1);dst_ip,dst_port=dst.rsplit('.',1)
            src_port,dst_port=int(src_port),int(dst_port)
        except ValueError:
            continue
        if src_ip == HOST and src_port == 443:
            leg,peer,port='server443_to_peer',dst_ip,dst_port
        elif dst_ip == HOST and dst_port == 443:
            leg,peer,port='peer_to_server443',src_ip,src_port
        elif dst_ip==xo_ip and dst_port==xo_port:
            leg,peer,port='server_to_XO',src_ip,src_port
        elif src_ip==xo_ip and src_port==xo_port:
            leg,peer,port='XO_to_server',dst_ip,dst_port
        else:
            # Other direct HTTPS sockets are server-wide, not a specific subscription.
            leg,peer,port='server_https_other',src_ip if dst_port==443 else dst_ip,src_port if dst_port==443 else dst_port
        db.execute('INSERT INTO tcp_flags VALUES(?,?,?,?,?,?)',(float(ts),leg,peer,port,flags,seq))
        db.commit()
    capture.wait(timeout=5)
    stderr = capture.stderr.read()
    drops = re.search(r'(\d+) packets dropped by kernel',stderr)
    db.execute('INSERT INTO probes VALUES(?,?,?)',(time.time(),'capture_exit',json.dumps({'returncode':capture.returncode,
        'kernel_drops':int(drops.group(1)) if drops else None})))
    db.commit()
    STOP.set()
    for thread in threads:
        thread.join(timeout=20)
    db.close()


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(json.dumps({'health_error_type':type(exc).__name__}),flush=True)
        raise SystemExit(1)
