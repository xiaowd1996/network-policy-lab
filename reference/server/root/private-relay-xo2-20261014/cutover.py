#!/usr/bin/python3
import json,pathlib,signal,subprocess,time
TABLE='proxy_relay_xo2'
CG=pathlib.Path('/sys/fs/cgroup/system.slice/proxy-relay-wrap-bridge.service')
def invoke(args,data=None):
 p=subprocess.run(args,input=data,capture_output=True,timeout=5)
 if p.returncode:raise RuntimeError('narrow_nft_failed')
 return p.stdout
def remove():
 if subprocess.run(['nft','list','table','ip',TABLE],capture_output=True).returncode==0:
  invoke(['nft','delete','table','ip',TABLE])
def install():
 assert CG.is_dir()
 text='table ip '+TABLE+' {\n chain output {\n type nat hook output priority -101; policy accept;\n ip daddr 127.0.0.1 tcp dport 443 socket cgroupv2 level 2 "system.slice/proxy-relay-wrap-bridge.service" counter dnat to 127.0.0.1:18452\n }\n}\n'
 exists=subprocess.run(['nft','list','table','ip',TABLE],capture_output=True).returncode==0
 text=('delete table ip '+TABLE+'\n' if exists else '')+text
 invoke(['nft','-c','-f','-'],text.encode());invoke(['nft','-f','-'],text.encode())
 return CG.stat().st_ino
running=True
def stop(*args):
 global running
 running=False
signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
try:
 current=install();print(json.dumps({'only_33_bridge_new_connections_cutover':True}),flush=True)
 while running:
  time.sleep(2)
  if CG.is_dir() and CG.stat().st_ino!=current:current=install()
finally:remove()
