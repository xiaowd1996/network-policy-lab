#!/usr/bin/python3
import json,pathlib,subprocess,sys
TABLE='proxy_relay_wrap'
if sys.argv[1]=='remove':
 p=subprocess.run(['nft','delete','table','inet',TABLE],capture_output=True)
 print(json.dumps({'guard_removed':p.returncode==0}));raise SystemExit(0)
text='table inet '+TABLE+' {\n chain guard {\n type filter hook input priority -10; policy accept;\n tcp dport 18444 meta nfproto ipv6 drop;\n tcp dport 18444 ip saddr != 203.0.113.10 drop;\n }\n}\n'
p=pathlib.Path('/root/private-relay-wrap/guard.nft');p.write_text(text);p.chmod(0o600)
probe=subprocess.run(['nft','list','table','inet',TABLE],capture_output=True)
if probe.returncode==0:raise SystemExit(0)
checked=subprocess.run(['nft','-c','-f',str(p)],capture_output=True);assert checked.returncode==0
if sys.argv[1]=='dry-run':print(json.dumps({'nft_guard_valid':True}));raise SystemExit(0)
loaded=subprocess.run(['nft','-f',str(p)],capture_output=True);assert loaded.returncode==0
print(json.dumps({'guard_loaded':True}))
