#!/usr/bin/env python3
"""Add WeChat bypass rules without replacing existing subscription policy.

Dry run by default. --apply backs up and atomically updates served YAML files.
--validation writes a credential-free core-check configuration during dry run.
"""
import argparse
import copy
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
import urllib.request

import yaml

ROOT = Path('/srv/private-subscriptions')
BACKUP_PREFIX = 'wechat-'
RULES = [
    'PROCESS-NAME,com.tencent.mm,DIRECT',
    'DOMAIN-SUFFIX,weixin.qq.com,DIRECT',
    'DOMAIN-SUFFIX,weixin.com,DIRECT',
    'DOMAIN-SUFFIX,wechat.com,DIRECT',
    'DOMAIN-SUFFIX,wechatapp.com,DIRECT',
    'DOMAIN-SUFFIX,qq.com,DIRECT',
    'DOMAIN-SUFFIX,qpic.cn,DIRECT',
    'DOMAIN-SUFFIX,gtimg.com,DIRECT',
    'DOMAIN-SUFFIX,tencent.com,DIRECT',
    'DOMAIN-SUFFIX,tenpay.com,DIRECT',
]


def transform(text):
    before = yaml.safe_load(text)
    original_rules = before.get('rules')
    if not isinstance(original_rules, list) or text.splitlines().count('rules:') != 1:
        raise ValueError('Unexpected rules format')
    if 'NETWORK,UDP,REJECT' not in original_rules:
        raise ValueError('Unexpected UDP policy')
    missing = [rule for rule in RULES if rule not in original_rules]
    if not missing:
        return text, before
    # Portfolio-only revision, 2026-10-20: a YAML block sequence may legally
    # be indentless. Preserve its indentation instead of assuming two spaces.
    # The original production copy has not been changed or deployed here.
    tail = text.split('rules:\n', 1)[1]
    first_item = re.search(r'^( *)- ', tail, flags=re.MULTILINE)
    if first_item is None:
        raise ValueError('Unexpected rules sequence layout')
    indent = first_item.group(1)
    block = 'rules:\n' + indent + '# WeChat domains bypass locally before UDP rejection.\n'
    block += ''.join(indent + '- ' + rule + '\n' for rule in missing)
    result = text.replace('rules:\n', block, 1)
    after = yaml.safe_load(result)
    expected = copy.deepcopy(before)
    expected['rules'] = missing + original_rules
    if after != expected:
        raise ValueError('Unexpected change outside additive rules')
    assert all(after['rules'].index(rule) < after['rules'].index('NETWORK,UDP,REJECT') for rule in RULES)
    return result, after


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def atomic_write(path, text, stat):
    fd, temp = tempfile.mkstemp(prefix='.wechat-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp, stat.st_mode & 0o777)
        os.chown(temp, stat.st_uid, stat.st_gid)
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--validation', type=Path)
    args = parser.parse_args()
    files = sorted(ROOT.rglob('mihomo.yaml'))
    if not files:
        raise SystemExit('No subscriptions found')
    unchanged = {p: digest(p) for p in ROOT.rglob('*') if p.is_file() and p not in files}
    prepared = []
    reference_rules = None
    for path in files:
        original = path.read_text(encoding='utf-8')
        updated, parsed = transform(original)
        if reference_rules is not None and parsed['rules'] != reference_rules:
            raise ValueError('Subscription policies differ; review before deployment')
        reference_rules = parsed['rules']
        prepared.append((path, original, updated, path.stat()))
    if args.validation:
        # Retain policy but replace all node credentials/addresses for offline validation.
        sanitized = {k: copy.deepcopy(parsed[k]) for k in ('rules', 'rule-providers', 'proxy-groups', 'dns', 'find-process-mode') if k in parsed}
        sanitized['proxies'] = [{'name': p['name'], 'type': 'direct'} for p in parsed['proxies']]
        sanitized['mode'] = 'rule'
        sanitized['log-level'] = 'warning'
        args.validation.write_text(yaml.safe_dump(sanitized, allow_unicode=True, sort_keys=False), encoding='utf-8')
    if not args.apply:
        print(json.dumps({'subscriptions': len(prepared), 'rules_added': len(RULES), 'dry_run': True, 'other_fields_unchanged': True}))
        return
    backup = Path('/root/private-subscription-backups') / (BACKUP_PREFIX + datetime.datetime.now().strftime('%Y%m%d-%H%M%S-%f'))
    backup.mkdir(parents=True, mode=0o700)
    for path, original, updated, stat in prepared:
        destination = backup / path.relative_to(ROOT)
        destination.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        shutil.copy2(path, destination)
    try:
        for path, original, updated, stat in prepared:
            atomic_write(path, updated, stat)
        for path, original, updated, stat in prepared:
            assert path.read_text(encoding='utf-8') == updated
            assert path.stat().st_uid == stat.st_uid and path.stat().st_gid == stat.st_gid
            # Confirm the serving endpoint returns the exact updated bytes; never print URLs/tokens.
            url = 'http://127.0.0.1:8080/' + path.relative_to(ROOT).as_posix()
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(url, timeout=5) as response:
                assert response.status == 200 and response.read() == updated.encode('utf-8')
        assert all(digest(p) == value for p, value in unchanged.items())
    except Exception:
        for path, original, updated, stat in prepared:
            atomic_write(path, original, stat)
        raise RuntimeError('Verification failed; original subscriptions restored') from None
    print(json.dumps({'updated': len(prepared), 'served_verified': len(prepared), 'other_files_unchanged': True, 'backup': str(backup)}))


if __name__ == '__main__':
    main()
