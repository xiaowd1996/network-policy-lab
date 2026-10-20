"""Run on the NEW host only. Stage, validate, then atomically install."""
import hashlib
import json
import os
from pathlib import Path
import pwd
import grp
import re
import shutil
import subprocess
import sys
import tarfile
import time

OLD='198.51.100.20';NEW='198.51.100.10'
ROOT=Path('/root/hk-migration-20261019');CANDIDATE=ROOT/'candidate'

def run(args,required=True):
 p=subprocess.run(args,capture_output=True)
 if p.returncode and required:
  (ROOT/'last-check-error.private').write_bytes(p.stdout+b'\n'+p.stderr)
  raise RuntimeError('command_failed_'+Path(args[0]).name)
 return p

def atomic(p,data,mode=0o600,uid=0,gid=0):
 p.parent.mkdir(parents=True,exist_ok=True)
 q=p.with_name('.migration-pending-'+p.name)
 with q.open('wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
 os.chmod(q,mode);os.chown(q,uid,gid);os.replace(q,p)

def stage():
 assert NEW in run(['ip','-4','addr']).stdout.decode()
 assert not CANDIDATE.exists(),'candidate_already_staged'
 CANDIDATE.mkdir(mode=0o700)
 meta={}
 for filename in ['source-configs.tgz','source-web.tgz']:
  with tarfile.open(ROOT/filename) as archive:
   for m in archive.getmembers():
    name=m.name.lstrip('/')
    assert '..' not in Path(name).parts and name and not m.isdev()
    p=CANDIDATE/name
    if m.isdir():p.mkdir(parents=True,exist_ok=True)
    elif m.isfile():
     p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(archive.extractfile(m).read())
    elif m.issym():
     p.parent.mkdir(parents=True,exist_ok=True)
     if not p.is_symlink():p.symlink_to(m.linkname)
    else:raise RuntimeError('unsupported_archive_entry')
    meta[name]={'mode':m.mode,'uid':m.uid,'gid':m.gid,'dir':m.isdir(),'link':m.linkname if m.issym() else None}
 changes=[];yaml_count=0
 for p in CANDIDATE.rglob('*'):
  if not p.is_file() or p.is_symlink():continue
  rel=p.relative_to(CANDIDATE).as_posix()
  archival=any(x in rel for x in ['/backups/','private-subscription-backups/','private-relay-backups/','private-web-preview-backups/','private-wrap-test-'])
  if archival or rel.startswith('var/lib/sing-box/acme/'):continue
  if p.suffix not in ['.json','.yaml','.txt','.py','.conf','.nft','.service','.md','.sh','.ps1']:continue
  raw=p.read_bytes()
  try:raw.decode('utf-8')
  except UnicodeError:continue
  updated=raw.replace(OLD.encode(),NEW.encode())
  if raw!=updated:
   p.write_bytes(updated);changes.append({'file_id':hashlib.sha256(rel.encode()).hexdigest()[:12],'substitutions':raw.count(OLD.encode())})
  if rel.startswith('srv/') and p.suffix=='.yaml':
   import yaml
   a=yaml.safe_load(raw);b=yaml.safe_load(updated);assert a['rules']==b['rules']
   def secrets(obj):
    if isinstance(obj,dict):return {k:v for k,v in obj.items() if k in ['password','uuid','secret','public-key','short-id']} | {k:secrets(v) for k,v in obj.items() if isinstance(v,(dict,list))}
    if isinstance(obj,list):return [secrets(x) for x in obj]
    return None
   assert secrets(a)==secrets(b)
   assert b['rules'][-2]=='NETWORK,UDP,REJECT'
   assert all(n['server'] in [NEW,'203.0.113.10'] for n in b['proxies'])
   yaml_count+=1
 # No service should capture or expose packet payloads as part of this migration.
 (ROOT/'metadata.json').write_text(json.dumps(meta))
 receipt={'staged':True,'files':sum(not x['dir'] for x in meta.values()),'changed_files':len(changes),'yaml_parsed':yaml_count,'changes':changes}
 atomic(ROOT/'stage-receipt.json',json.dumps(receipt).encode())
 print(json.dumps({k:v for k,v in receipt.items() if k!='changes'}))

def install():
 assert (ROOT/'stage-receipt.json').exists()
 assert run(['systemctl','is-active','sing-box'],False).returncode!=0
 # Preserve fresh-host configuration independently of the source archive.
 backup=ROOT/'destination-before';backup.mkdir(mode=0o700,exist_ok=False)
 for f in ['/etc/nginx','/etc/systemd/system','/etc/sysctl.conf']:
  p=Path(f)
  if p.is_dir():shutil.copytree(p,backup/p.name,symlinks=True)
  elif p.is_file():shutil.copy2(p,backup/p.name)
 manifest=json.loads((ROOT/'manifest-source.json').read_text());extra=json.loads((ROOT/'extra-source.json').read_text())
 uidmap={0:0,33:pwd.getpwnam('www-data').pw_uid};gidmap={0:0,33:grp.getgrnam('www-data').gr_gid}
 for name in ['sing-box','proxy-audit']:
  old=manifest['accounts'][name];pw=old['passwd'].split(':');gr=old['group'].split(':')
  try:grp.getgrnam(name)
  except KeyError:run(['groupadd','--system',name])
  try:pwd.getpwnam(name)
  except KeyError:run(['useradd','--system','--gid',name,'--home-dir',pw[5],'--shell','/usr/sbin/nologin',name])
  uidmap[int(pw[2])]=pwd.getpwnam(name).pw_uid;gidmap[int(gr[2])]=grp.getgrnam(name).gr_gid
 meta=json.loads((ROOT/'metadata.json').read_text())
 for rel,m in sorted(meta.items(),key=lambda kv:len(Path(kv[0]).parts)):
  source=CANDIDATE/rel;dest=Path('/')/rel
  uid=uidmap.get(m['uid'],m['uid']);gid=gidmap.get(m['gid'],m['gid'])
  if m['dir']:
   dest.mkdir(parents=True,exist_ok=True);os.chmod(dest,m['mode']);os.chown(dest,uid,gid)
  elif m['link'] is not None:
   dest.parent.mkdir(parents=True,exist_ok=True)
   if dest.is_symlink():
    assert os.readlink(dest)==m['link'],'unexpected_symlink'
   elif not dest.exists():dest.symlink_to(m['link'])
   else:raise RuntimeError('symlink_conflict')
  else:atomic(dest,source.read_bytes(),m['mode'],uid,gid)
 for d in extra['dirs']:
  p=Path(d['path']);p.mkdir(parents=True,exist_ok=True);p.chmod(d['mode']);os.chown(p,uidmap.get(d['uid'],d['uid']),gidmap.get(d['gid'],d['gid']))
 # Nginx opens this existing metadata-only access log before diagnostics start.
 ingress=Path('/var/lib/proxy-diagnostic/ingress.log');ingress.touch(mode=0o640,exist_ok=True)
 os.chown(ingress,pwd.getpwnam('www-data').pw_uid,grp.getgrnam('www-data').gr_gid)
 configs=['/etc/sing-box/config.json','/etc/proxy-diagnostic/config.json','/root/private-relay-wrap/server.json','/root/private-direct-wrap/server.json','/root/private-formal-wrap/server.json','/root/private-xo2-wrap-20261012/server.json']
 # Relay-XO2 uses a file certificate generated by the main ACME provider after start.
 # Validate its syntax now with the archived certificate, then restore new-IP paths.
 relay=Path('/root/private-relay-xo2-20261014/server.json');raw=relay.read_bytes();d=json.loads(raw)
 for i in d['inbounds']:
  tls=i.get('tls',{})
  for k in ['certificate_path','key_path']:
   if k in tls:tls[k]=tls[k].replace(NEW,OLD)
 temp=ROOT/'relay-preflight.json';atomic(temp,json.dumps(d).encode());configs.append(str(temp))
 for cfg in configs:run(['/usr/local/bin/sing-box','check','-c',cfg])
 run(['nginx','-t'])
 run(['systemctl','daemon-reload']);run(['systemctl','unmask','--runtime','nginx.service'])
 # Check effective non-root readability before activating anything.
 run(['runuser','-u','sing-box','--','/usr/local/bin/sing-box','check','-c','/etc/sing-box/config.json'])
 print(json.dumps({'installed':True,'singbox_checks':len(configs)+1,'nginx_checked':True,'source_services_untouched':True}))

def start():
 run(['systemctl','enable','nginx','sing-box'])
 run(['systemctl','start','nginx']);run(['systemctl','start','sing-box'])
 print(json.dumps({'main_started':True,'certificate_pending':True}))

def sidecars():
 cert=Path('/var/lib/sing-box/acme/certificates/acme-v02.api.letsencrypt.org-directory')/NEW/(NEW+'.crt')
 assert cert.is_file(),'new_certificate_missing'
 run(['/usr/local/bin/sing-box','check','-c','/root/private-relay-xo2-20261014/server.json'])
 services=json.loads((ROOT/'manifest-source.json').read_text())['services']
 # Start dependencies and destination before activating cgroup-scoped XO2 cutover.
 order=['proxy-diagnostic','proxy-relay-wrap-guard','proxy-relay-wrap-bridge','proxy-relay-xo2-server','proxy-relay-xo2-cutover','proxy-relay-wrap-server','proxy-direct-wrap-bridge','proxy-direct-wrap-server','proxy-formal-wrap-bridge','proxy-formal-wrap-server','proxy-xo2-wrap-server']
 order += [x.removesuffix('.service') for x in services if x.removesuffix('.service') not in order and x!='sing-box.service']
 for unit in order:
  run(['systemctl','enable',unit]);run(['systemctl','start',unit])
 result={u:run(['systemctl','is-active',u],False).stdout.decode().strip() for u in ['nginx','sing-box']+order}
 assert all(x=='active' for x in result.values())
 atomic(ROOT/'services-started.json',json.dumps(result).encode())
 print(json.dumps({'services':result,'new_certificate':True}))

if __name__=='__main__':
 try:{'stage':stage,'install':install,'start':start,'sidecars':sidecars}[sys.argv[1]]()
 except Exception as e:
  import traceback
  (ROOT/'deploy-error.private').write_text(traceback.format_exc());print(json.dumps({'failed':type(e).__name__,'category':str(e) if isinstance(e,RuntimeError) else 'private_details_saved'}));sys.exit(1)
