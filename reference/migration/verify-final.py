from migrate import *
CODE=r'''
import pathlib,json,subprocess,hashlib,sqlite3,time,os
OLD='198.51.100.20';NEW='198.51.100.10'
def run(args):return subprocess.run(args,capture_output=True,text=True).stdout.strip()
host=HOST_VALUE
services=['nginx','sing-box']+[p.stem for p in pathlib.Path('/etc/systemd/system').glob('proxy*.service')]
states={u:{k:v for k,v in (l.split('=',1) for l in run(['systemctl','show',u,'-p','MainPID','-p','ActiveState','-p','UnitFileState','-p','NRestarts']).splitlines() if '=' in l)} for u in services}
digest=hashlib.sha256();count=0
for root in ['/etc/nginx','/etc/sing-box','/etc/proxy-traffic-audit','/etc/proxy-diagnostic','/etc/proxy-diagnostic-tcp','/srv']:
 for p in sorted(pathlib.Path(root).rglob('*')):
  if p.is_file() and not p.is_symlink():digest.update(str(p).encode());digest.update(hashlib.sha256(p.read_bytes()).digest());count+=1
report={'host':host,'services':states,'protected_digest':digest.hexdigest(),'protected_files':count,'disk':run(['df','-h','/']),'memory':run(['free','-m'])}
if host==NEW:
 d=sqlite3.connect('file:/var/lib/proxy-diagnostic/health.sqlite3?mode=ro',uri=True)
 report['health_resource_samples']=d.execute('select count(*) from resources').fetchone()[0]
 report['health_last_resource_age_seconds']=round(time.time()-d.execute('select max(ts) from resources').fetchone()[0])
 rows=d.execute('select label,result from probes where ts>?',(time.time()-300,)).fetchall();d.close()
 summary={}
 for label,raw in rows:
  r=json.loads(raw);x=summary.setdefault(label,{'total':0,'ok':0,'errors':{}});x['total']+=1;x['ok']+=int(bool(r.get('ok')))
  if not r.get('ok'):x['errors'][r.get('error_type',str(r.get('returncode')))]=x['errors'].get(r.get('error_type',str(r.get('returncode'))),0)+1
 report['health_last_5_minutes']=summary
 cert=pathlib.Path('/var/lib/sing-box/acme/certificates/acme-v02.api.letsencrypt.org-directory')/NEW/(NEW+'.crt')
 report['certificate']=run(['openssl','x509','-in',str(cert),'-noout','-dates','-ext','subjectAltName'])
 report['listeners']=run(['ss','-lntH']).splitlines()
else:
 report['owned_temp_snapshots']=[{'path':str(p),'bytes':p.stat().st_size,'mtime':p.stat().st_mtime} for p in pathlib.Path('/var/tmp').glob('hk-migration-history-*.sqlite3') if p.is_file() and not p.is_symlink()]
print(json.dumps(report))
'''
def main():
 for host in [OLD,NEW]:
  for attempt in range(3):
   try:r=ssh(host,CODE.replace('HOST_VALUE',repr(host)));break
   except RuntimeError:
    if attempt==2:raise
    time.sleep(2)
  private_json('final-'+host+'.json',r)
  print(json.dumps(r),flush=True)
if __name__=='__main__':main()
