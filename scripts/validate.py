"""Credential-safe static checks. No server/network writes and no file-content output."""
import ast
import ipaddress
import json
from pathlib import Path
import re
import sys
import yaml

ROOT=Path(__file__).resolve().parents[1]
DNS={'1.1.1.1','1.0.0.1','8.8.8.8','8.8.4.4','223.5.5.5','223.6.6.6','114.114.114.114','119.29.29.29'}
DOCS=[ipaddress.ip_network(n) for n in ['192.0.2.0/24','198.51.100.0/24','203.0.113.0/24']]
IP=re.compile(r'(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)')
FORBIDDEN_SUFFIX={'.key','.pem','.pfx','.p12','.crt','.pub','.sqlite','.sqlite3','.db','.log','.tgz','.zip','.gz','.private'}
errors=[]
counts={'files':0,'python':0,'json':0,'yaml':0}

def error(path,kind):errors.append({'file':path.relative_to(ROOT).as_posix(),'category':kind})

for path in ROOT.rglob('*'):
    if not path.is_file() or '.git' in path.relative_to(ROOT).parts or '__pycache__' in path.parts:continue
    counts['files']+=1
    if path.suffix.lower() in FORBIDDEN_SUFFIX:error(path,'forbidden_file_type');continue
    try:text=path.read_text(encoding='utf-8')
    except UnicodeError:error(path,'binary_or_non_utf8');continue
    if re.search(r'-----BEGIN (?:[A-Z ]+ )?(?:PRIVATE KEY|CERTIFICATE)-----',text):error(path,'key_or_certificate')
    if re.search(r'\b(?:ghp|gho|github_pat)_[A-Za-z0-9_]{20,}',text):error(path,'github_credential')
    if re.search(r'ssh-(?:ed25519|rsa)\s+[A-Za-z0-9+/]{25,}',text):error(path,'ssh_key')
    if re.search(r'(?i)(?:socks5?|https?)://[^\s/:]+:[^\s/@]+@',text):error(path,'credential_in_url')
    if re.search(r'/(?:diagnostic-subscription|s|once|lease)/[A-Za-z0-9_-]{28,}',text):error(path,'subscription_token_path')
    for match in IP.finditer(text):
        try:addr=ipaddress.ip_address(match.group())
        except ValueError:continue
        if not (match.group() in DNS or addr.is_loopback or addr.is_unspecified or addr.is_private or addr.is_multicast or addr.is_link_local or match.group().startswith('198.18.') or any(addr in net for net in DOCS)):
            error(path,'non_example_public_address')
    try:
        if path.suffix=='.py':ast.parse(text);counts['python']+=1
        if path.name.endswith('.json') or path.name.endswith('.json.example'):json.loads(text);counts['json']+=1
        if path.name.endswith(('.yaml','.yml','.yaml.example')):yaml.safe_load(text);counts['yaml']+=1
    except Exception:error(path,'syntax_or_parse_error')

daily=yaml.safe_load((ROOT/'examples/mihomo/daily.yaml.example').read_text(encoding='utf-8'))
rules=daily['rules']
if len(rules)!=531 or rules[-2]!='NETWORK,UDP,REJECT':error(ROOT/'examples/mihomo/daily.yaml.example','daily_rule_contract')
if any(not p.get('password','EXAMPLE_').startswith('EXAMPLE_') for p in daily['proxies']):error(ROOT/'examples/mihomo/daily.yaml.example','unexpected_node_credential')
print(json.dumps({'ok':not errors,'counts':counts,'daily_rules':len(rules),'errors':errors},ensure_ascii=True))
sys.exit(1 if errors else 0)
