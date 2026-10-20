#!/usr/bin/python3
"""Read-only formal packaging metadata; no raw logs or credential-bearing output."""
import collections
import json
from pathlib import Path
import re
import sqlite3
import time

ROOT=Path('/var/lib/proxy-formal-wrap');cut=time.time()-1800
c=sqlite3.connect((ROOT/'flows.sqlite3').as_uri()+'?mode=ro',uri=True)
t=sqlite3.connect((ROOT/'transport.sqlite3').as_uri()+'?mode=ro',uri=True)
flows=c.execute('SELECT COUNT(*),SUM(upload),SUM(download),SUM(end IS NULL) FROM sessions WHERE start>=?',(cut,)).fetchone()
errors=c.execute('SELECT error_category,COUNT(*) FROM sessions WHERE start>=? AND error_category IS NOT NULL GROUP BY error_category',(cut,)).fetchall()
events=t.execute('SELECT category,COUNT(*) FROM events WHERE ts>=? GROUP BY category',(cut,)).fetchall()
retry=sum(json.loads(x).get('increment',0) for x, in t.execute("SELECT metadata FROM events WHERE ts>=? AND category='retransmission'",(cut,)))
classes=collections.Counter()
p=Path('/root/private-formal-wrap/server.log')
if p.is_file():
    for line in p.read_text(errors='replace').splitlines()[-5000:]:
        if not re.search(r'\bERROR\b|\bWARN\b',line):continue
        category='other_error'
        for label,pattern in [('timeout','timeout|deadline|timed out'),('EOF',r'\bEOF\b'),
          ('connection_reset','connection reset'),('TLS','TLS|handshake'),('network_unreachable','network is unreachable')]:
            if re.search(pattern,line,re.I):category=label;break
        classes[category]+=1
print(json.dumps({'window_minutes':30,'fixed_bridge_flows_upload_download_active':flows,
  'bridge_error_counts':errors,'outer_tcp_events':events,'observed_retrans_increment_lower_bound':retry,
  'recent_wrapper_log_error_classes_not_strictly_time_scoped':dict(classes),
  'main_domain_audit_preserved':True,'bridge_bytes_include_TLS_overhead':True,
  'bytes_not_attributed_to_A_D_by_this_metadata_report':True,'raw_logs_and_secrets_output':False}))
