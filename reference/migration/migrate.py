"""Scoped migration helpers. Never print credentials or subscription paths."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

OLD = '198.51.100.20'
NEW = '198.51.100.10'
KEY = r'C:\Users\EXAMPLE_USER\.ssh\example_ed25519'
PRIVATE = Path(r'C:\Users\EXAMPLE_USER\.private\hk-migration-example')
HERE = Path(__file__).resolve().parent

def ssh(host, code, timeout=90):
    p = subprocess.run(['ssh','-i',KEY,'-o','BatchMode=yes','-o','ConnectTimeout=15',
                        '-o','StrictHostKeyChecking=yes',f'root@{host}','python3 -'],
                       input=code.encode(),capture_output=True,timeout=timeout)
    if p.returncode:
        # Tracebacks and external commands can contain credentials: keep private.
        PRIVATE.mkdir(parents=True,exist_ok=True)
        (PRIVATE / ('error-'+host+'.txt')).write_bytes(p.stdout+b'\n'+p.stderr)
        raise RuntimeError('remote_operation_failed_'+host)
    return json.loads(p.stdout)

def private_json(name, data):
    PRIVATE.mkdir(parents=True,exist_ok=True)
    p = PRIVATE / name
    temp = p.with_suffix('.pending')
    temp.write_text(json.dumps(data,ensure_ascii=False,indent=2),encoding='utf-8')
    os.replace(temp,p)

INVENTORY = r'''
import hashlib,json,os,pathlib,re,subprocess
def cmd(args):
 try:p=subprocess.run(args,capture_output=True,text=True);return p.stdout.strip()
 except FileNotFoundError:return ''
units=[]
for row in cmd(['systemctl','list-unit-files','--type=service','--type=socket','--type=timer','--no-legend','--no-pager']).splitlines():
 name=row.split()[0]
 if re.search(r'sing-box|nginx|proxy|wrap|xo2|diagnostic|relay|cert|acme|xcodex',name,re.I):
  props=cmd(['systemctl','show',name,'-p','FragmentPath','-p','DropInPaths','-p','User','-p','Group','-p','MainPID','-p','ActiveState','-p','UnitFileState','-p','NRestarts','-p','ControlGroup'])
  units.append(dict([('name',name)]+[x.split('=',1) for x in props.splitlines() if '=' in x]))
trees={}
for root in ['/etc/nginx','/etc/sing-box','/etc/proxy-traffic-audit','/srv','/usr/local/lib','/var/lib/sing-box','/root']:
 p=pathlib.Path(root)
 if p.exists():
  children=[]
  for f in p.iterdir():
   name=f.name
   if re.fullmatch(r'[A-Za-z0-9_-]{25,}',name):name='<redacted>'
   children.append({'name':name,'dir':f.is_dir(),'size':f.stat().st_size if f.is_file() else None})
  trees[root]=children
listeners=[]
for l in cmd(['ss','-lntH']).splitlines():
 c=l.split();listeners.append(c[3])
configs=[]
for root in ['/etc/sing-box','/etc/nginx','/etc/proxy-traffic-audit']:
 for f in pathlib.Path(root).rglob('*'):
  if f.is_file():configs.append({'path':str(f),'sha256':hashlib.sha256(f.read_bytes()).hexdigest(),'size':f.stat().st_size})
yamls=[]
for root in ['/srv']:
 for f in pathlib.Path(root).rglob('*.yaml'):
  try:
   import yaml
   d=yaml.safe_load(f.read_text()); ps=d.get('proxies',[]);rules=d.get('rules',[])
   yamls.append({'id':hashlib.sha256(str(f).encode()).hexdigest()[:12],'size':f.stat().st_size,'rules':len(rules),'nodes':len(ps),'types':sorted(set(str(x.get('type')) for x in ps)),'servers':sorted(set(str(x.get('server')) for x in ps)),'udp_reject':next((i for i,x in enumerate(rules) if x=='NETWORK,UDP,REJECT'),None),'relative_providers':all(not str(x.get('path','')).startswith(('/','C:','D:')) for x in d.get('rule-providers',{}).values())})
  except Exception:yamls.append({'parse_failed':True})
fire=cmd(['nft','-j','list','ruleset'])
print(json.dumps({'utc':cmd(['date','-u','+%FT%TZ']),'os':cmd(['cat','/etc/os-release']),'units':units,'trees':trees,'listeners':listeners,'configs':configs,'yaml':yamls,'disk':cmd(['df','-B1','/']),'memory':cmd(['free','-m']),'network':cmd(['ip','-j','addr']),'nft_sha256':hashlib.sha256(fire.encode()).hexdigest(),'local_units':[p.name for p in pathlib.Path('/etc/systemd/system').glob('*') if p.is_file()],'packages':cmd(['dpkg-query','-W','-f=${Package} ${Version}\n','nginx','nftables','python3-yaml','python3-requests','python3-websocket','python3-cryptography','curl','openssl','rsync'])}))
'''

def inventory():
    for host in [OLD,NEW]:
        result=ssh(host,INVENTORY)
        private_json('inventory-'+host+'.json',result)
        print(json.dumps({'host':host,'inventory':result},ensure_ascii=True))

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('action',choices=['inventory'])
    args=parser.parse_args()
    try:
        if args.action=='inventory':inventory()
    except Exception as e:
        print(json.dumps({'error_type':type(e).__name__,'message':str(e) if isinstance(e,RuntimeError) else 'private_error_saved'}));sys.exit(1)
