from migrate import *
code=r'''
import gzip,hashlib,json,pathlib,sqlite3,tempfile,os,shutil
root=pathlib.Path('/root/hk-migration-20261019/history-source-107-151-244-133')
items=json.loads((root/'history-db-manifest.json').read_bytes());results=[]
for i,item in enumerate(items):
 source=root/item['archive'];assert hashlib.sha256(source.read_bytes()).hexdigest()==item['sha256']
 fd,target=tempfile.mkstemp(prefix='verify-history-',suffix='.sqlite3',dir=root);os.close(fd)
 try:
  with gzip.open(source,'rb') as src,open(target,'wb') as dst:shutil.copyfileobj(src,dst,1024*1024)
  db=sqlite3.connect('file:'+target+'?mode=ro',uri=True)
  check=db.execute('PRAGMA quick_check').fetchall();db.close();assert check==[('ok',)]
  results.append({'database':i+1,'quick_check':'ok','bytes':os.stat(target).st_size})
 finally:
  p=pathlib.Path(target);assert p.resolve().parent==root.resolve() and p.name.startswith('verify-history-');p.unlink()
receipt={'databases':len(results),'all_integrity_ok':True,'uncompressed_database_bytes':sum(x['bytes'] for x in results),'results':results}
(root/'integrity-receipt.json').write_text(json.dumps(receipt))
print(json.dumps({k:v for k,v in receipt.items() if k!='results'}))
'''
r=ssh(NEW,code,timeout=600);private_json('history-integrity.json',r);print(json.dumps(r))
