from migrate import *
import tarfile

SSH=['ssh','-i',KEY,'-o','BatchMode=yes','-o','ConnectTimeout=15','-o','StrictHostKeyChecking=yes']
MANIFEST=r'''
import pathlib,json,subprocess,hashlib
roots=['/etc/nginx','/etc/sing-box','/etc/proxy-traffic-audit','/usr/local/lib/proxy-traffic-audit','/usr/local/lib/proxy-diagnostic','/usr/local/bin/sing-box','/var/lib/sing-box/acme','/srv']
roots += [str(p) for p in pathlib.Path('/etc').glob('proxy-*') if str(p) not in roots]
roots += [str(p) for p in pathlib.Path('/root').glob('private*')]
roots += [str(p) for p in pathlib.Path('/etc/systemd/system').glob('*') if p.is_file() and p.name.startswith(('proxy-','sing-box'))]
roots += [str(p) for p in pathlib.Path('/etc/logrotate.d').glob('proxy-*')]
roots += [str(p) for p in pathlib.Path('/etc/sysctl.d').glob('*') if p.is_file() and p.name not in ['README.sysctl','99-sysctl.conf']]
roots=[p for p in roots if pathlib.Path(p).exists()]
files=[]
for r in roots:
 p=pathlib.Path(r)
 for f in ([p] if p.is_file() else p.rglob('*')):
  if f.is_file() and not f.is_symlink():files.append({'path':str(f),'sha256':hashlib.sha256(f.read_bytes()).hexdigest(),'size':f.stat().st_size,'mode':f.stat().st_mode&0o777,'uid':f.stat().st_uid,'gid':f.stat().st_gid})
accounts={}
for name in ['sing-box','proxy-audit','www-data']:
 accounts[name]={'passwd':subprocess.run(['getent','passwd',name],capture_output=True,text=True).stdout.strip(),'group':subprocess.run(['getent','group',name],capture_output=True,text=True).stdout.strip()}
print(json.dumps({'roots':roots,'files':files,'accounts':accounts,'services':[p.name for p in pathlib.Path('/etc/systemd/system').glob('*.service') if p.name.startswith(('proxy-','sing-box'))]}))
'''

def export():
    m=ssh(OLD,MANIFEST);private_json('manifest-source.json',m)
    output=PRIVATE/'source-configs.tgz'
    if output.exists():raise RuntimeError('backup_already_exists')
    import shlex
    command='tar --ignore-failed-read -czf - -C / '+ ' '.join(shlex.quote(p.lstrip('/')) for p in m['roots'])
    with output.open('wb') as f:
        p=subprocess.run(SSH+[f'root@{OLD}',command],stdout=f,stderr=subprocess.PIPE,timeout=600)
    (PRIVATE/'export-stderr.txt').write_bytes(p.stderr)
    assert p.returncode in [0,1], 'backup_failed'
    with tarfile.open(output,'r:gz') as tf:
        names=tf.getnames();assert 'etc/sing-box/config.json' in names
    receipt={'bytes':output.stat().st_size,'sha256':hashlib.sha256(output.read_bytes()).hexdigest(),'files':len(m['files']),'archive_entries':len(names)}
    private_json('backup-receipt.json',receipt);print(json.dumps(receipt))

def upload():
    source=PRIVATE/'source-configs.tgz'
    # Dedicated fresh staging path, not an existing checkout or live directory.
    ssh(NEW,"import pathlib,json\np=pathlib.Path('/root/hk-migration-20261019');p.mkdir(mode=0o700,exist_ok=True)\nprint(json.dumps({'staged':True}))")
    p=subprocess.run(['scp','-q','-i',KEY,'-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',str(source),f'root@{NEW}:/root/hk-migration-20261019/source-configs.tgz.pending'],capture_output=True,timeout=600)
    assert p.returncode==0,'upload_failed'
    ssh(NEW,"import pathlib,os,json\np=pathlib.Path('/root/hk-migration-20261019/source-configs.tgz.pending');p.chmod(0o600);os.replace(p,p.with_name('source-configs.tgz'));print(json.dumps({'atomic_upload':True}))")
    code="import pathlib,hashlib,json\np=pathlib.Path('/root/hk-migration-20261019/source-configs.tgz')\nprint(json.dumps({'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'bytes':p.stat().st_size}))"
    receipt=ssh(NEW,code)
    assert receipt['sha256']==hashlib.sha256(source.read_bytes()).hexdigest()
    print(json.dumps({'uploaded_verified':True,**receipt}))

if __name__=='__main__':
    try:
        {'export':export,'upload':upload}[sys.argv[1]]()
    except Exception as e:
        print(json.dumps({'failed':type(e).__name__,'detail':str(e) if isinstance(e,RuntimeError) else 'private_detail'}));sys.exit(1)
