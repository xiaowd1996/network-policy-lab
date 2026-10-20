from migrate import *
def main():
 m=json.loads((PRIVATE/'manifest-source.json').read_text())
 expected=[x for x in m['files'] if x['path'].startswith(('/etc/','/srv/','/usr/local/lib/','/usr/local/bin/sing-box'))]
 code=r'''
import pathlib,json,hashlib,subprocess,time,os
expected=EXPECTED_VALUE
changed=[]
for x in expected:
 p=pathlib.Path(x['path'])
 if not p.is_file() or hashlib.sha256(p.read_bytes()).hexdigest()!=x['sha256']:changed.append(hashlib.sha256(x['path'].encode()).hexdigest()[:12])
raw=subprocess.run(['journalctl','-k','--since','2026-10-18 16:45:00 UTC','--no-pager','-o','json'],capture_output=True,text=True).stdout
events=[]
for line in raw.splitlines():
 try:r=json.loads(line);text=r.get('MESSAGE','')
 except Exception:continue
 if any(x in text.lower() for x in ['out of memory','killed process','oom-kill']):
  events.append({'utc_epoch_us':r.get('__REALTIME_TIMESTAMP'),'category':'killed_process' if 'Killed process' in text else 'oom','health_monitor':('2474969' in text),'backup_process':('2588191' in text),'message_digest':hashlib.sha256(text.encode()).hexdigest()[:12]})
health=subprocess.run(['journalctl','-u','proxy-diagnostic-health','--since','2026-10-18 16:45:00 UTC','--no-pager','-o','json'],capture_output=True,text=True).stdout
health_events=[]
for line in health.splitlines():
 try:r=json.loads(line);text=r.get('MESSAGE','')
 except Exception:continue
 if any(x in text.lower() for x in ['killed','exited','failed','restart','started']):
  category='oom' if 'oom' in text.lower() else 'killed' if 'killed' in text.lower() else 'restart' if 'restart' in text.lower() else 'started' if 'started' in text.lower() else 'exit'
  health_events.append({'utc_epoch_us':r.get('__REALTIME_TIMESTAMP'),'category':category})
print(json.dumps({'protected_files_compared':len(expected),'changed_ids':changed,'kernel_events':events,'health_events':health_events}))
'''.replace('EXPECTED_VALUE',repr(expected))
 r=ssh(OLD,code);private_json('source-preservation.json',r);print(json.dumps(r))
if __name__=='__main__':main()
