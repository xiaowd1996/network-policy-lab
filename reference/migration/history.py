"""Read-only source snapshots; histories remain separate from new-host counters."""
from transfer import *
import gzip
import shlex
import socket
import paramiko

DISCOVER=r'''
import pathlib,json
dbs=[];roots=[]
for base in pathlib.Path('/var/lib').glob('proxy*'):
 roots.append(str(base))
 for p in base.glob('*.sqlite3'):dbs.append({'path':str(p),'bytes':p.stat().st_size})
roots+=['/var/lib/sing-box','/var/log/nginx']
print(json.dumps({'dbs':dbs,'roots':roots}))
'''

def main():
 sock=socket.socket();sock.settimeout(20);sock.setsockopt(socket.IPPROTO_IP,31,socket.htonl(5));sock.bind(('192.168.1.20',0));sock.connect((OLD,22))
 connection=paramiko.SSHClient();connection.load_system_host_keys(r'C:\Users\EXAMPLE_USER\.ssh\known_hosts');connection.set_missing_host_key_policy(paramiko.RejectPolicy())
 connection.connect(OLD,username='root',key_filename=KEY,sock=sock,allow_agent=False,look_for_keys=False,timeout=20)
 connection.get_transport().set_keepalive(15)
 def remote(command,code=None,target=None):
  inp,out,err=connection.exec_command(command,timeout=600)
  if code is not None:inp.write(code);inp.channel.shutdown_write()
  if target is not None:
   while True:
    block=out.read(1024*1024)
    if not block:break
    target.write(block)
   data=None
  else:data=out.read()
  errors=err.read();rc=out.channel.recv_exit_status();return rc,data,errors
 rc,data,_=remote('python3 -',DISCOVER);assert not rc
 info=json.loads(data);private_json('history-source.json',info)
 print(json.dumps({'databases':len(info['dbs']),'database_bytes':sum(x['bytes'] for x in info['dbs'])}),flush=True)
 home=PRIVATE/'history';home.mkdir(exist_ok=True)
 receipts=[]
 for i,item in enumerate(info['dbs']):
  # SQLite online backup streams through an isolated disk-backed temporary file,
  # not RAM. Source databases stay read-only; no checkpoint/service pause.
  code="import sqlite3,gzip,sys,tempfile,os,shutil\nfd,p=tempfile.mkstemp(prefix='hk-migration-history-',suffix='.sqlite3',dir='/var/tmp');os.close(fd)\ntry:\n a=sqlite3.connect('file:'+"+repr(item['path'])+"+'?mode=ro',uri=True,timeout=30);a.execute('BEGIN');a.execute('SELECT count(*) FROM sqlite_master').fetchone();b=sqlite3.connect(p);a.backup(b,pages=128,sleep=.05);a.close();b.close()\n with open(p,'rb') as f,gzip.GzipFile(fileobj=sys.stdout.buffer,mode='wb',compresslevel=1) as z:shutil.copyfileobj(f,z,1024*1024)\nfinally:\n os.unlink(p)"
  target=home/('db-'+str(i)+'.sqlite3.gz')
  with target.open('wb') as f:
   rc,_,errors=remote('nice -n 15 ionice -c 3 python3 -',code,f)
  (PRIVATE/'history-last-stderr.private').write_bytes(errors)
  assert not rc,'consistent_db_backup_failed'
  receipts.append({'source':item['path'],'archive':target.name,'bytes':target.stat().st_size,'sha256':hashlib.sha256(target.read_bytes()).hexdigest()})
  print(json.dumps({'database_snapshot':i+1,'total':len(info['dbs']),'compressed_bytes':target.stat().st_size}),flush=True)
 private_json('history-db-manifest.json',receipts)
 output=home/'logs.tgz'
 command="tar --ignore-failed-read --exclude='*.sqlite3' --exclude='*.sqlite3-wal' --exclude='*.sqlite3-shm' --exclude='acme' -czf - -C / "+' '.join(shlex.quote(x.lstrip('/')) for x in info['roots'])
 with output.open('wb') as f:
  rc,_,errors=remote(command,None,f)
 (PRIVATE/'history-tar-stderr.private').write_bytes(errors)
 assert rc in [0,1],'log_backup_failed'
 connection.close()
 receipts.append({'archive':'logs.tgz','bytes':output.stat().st_size,'sha256':hashlib.sha256(output.read_bytes()).hexdigest()})
 private_json('history-receipt.json',receipts)
 print(json.dumps({'history_backup_complete':True,'compressed_bytes':sum(x['bytes'] for x in receipts)}),flush=True)
 files=list(home.iterdir())+[PRIVATE/'history-db-manifest.json',PRIVATE/'history-receipt.json']
 ssh(NEW,"import pathlib,json\np=pathlib.Path('/root/hk-migration-20261019/history-source-107-151-244-133');p.mkdir(mode=0o700,exist_ok=True);print(json.dumps({'history_directory':True}))")
 for p in files:
  dest='/root/hk-migration-20261019/history-source-107-151-244-133/'+p.name
  result=subprocess.run(['scp','-q','-i',KEY,'-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',str(p),f'root@{NEW}:{dest}'],capture_output=True,timeout=600)
  assert not result.returncode,'history_upload_failed'
 code=r'''
import pathlib,json,hashlib
root=pathlib.Path('/root/hk-migration-20261019/history-source-107-151-244-133')
items=json.loads((root/'history-receipt.json').read_bytes())
for x in items:assert hashlib.sha256((root/x['archive']).read_bytes()).hexdigest()==x['sha256']
print(json.dumps({'history_uploaded_verified':True,'archives':len(items),'bytes':sum(x['bytes'] for x in items)}))
'''
 receipt=ssh(NEW,code,timeout=120);private_json('history-upload.json',receipt);print(json.dumps(receipt))
if __name__=='__main__':
 try:main()
 except Exception as e:
  import traceback
  (PRIVATE/'history-error.private').write_text(traceback.format_exc());print(json.dumps({'history_failed':type(e).__name__}));sys.exit(1)
