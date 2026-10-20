#!/usr/bin/env python3
"""Server-side preflight/deploy/readback; output never includes subscription paths."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import urllib.request

BASE = Path(__file__).parent
spec = importlib.util.spec_from_file_location('torrent_update', BASE / 'update-torrent-direct.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
ROOT = Path('/srv/private-subscriptions')
FILES = sorted(ROOT.rglob('mihomo.yaml'))
PROTECTED = ['/etc/sing-box/config.json', '/etc/nginx/nginx.conf', '/etc/nftables.conf']
UNITS = ['sing-box', 'nginx', 'proxy-traffic-audit']


def snapshot():
    return {
        'files': {p: hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in PROTECTED},
        'pids': {u: subprocess.check_output(['systemctl', 'show', u, '--property=MainPID', '--value'], text=True).strip() for u in UNITS},
    }


def main():
    assert len(FILES) == 4, 'Unexpected subscription count'
    expected = {}
    for p in FILES:
        updated, parsed = module.transform(p.read_text(encoding='utf-8'))
        assert module.transform(updated)[0] == updated, 'Not idempotent'
        assert parsed['rules'][:len(module.RULES)] == module.RULES
        assert parsed['rules'].index('NETWORK,UDP,REJECT') >= len(module.RULES)
        expected[p] = updated.encode('utf-8')
    print(json.dumps({'preflight': 'passed', 'subscriptions': len(FILES), 'idempotent': True}), flush=True)
    before = snapshot()
    subprocess.run([sys.executable, str(BASE / 'update-torrent-direct.py'), '--apply'], check=True)
    assert before == snapshot(), 'Protected configuration or service PID changed'
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    for p in FILES:
        url = 'https://198.51.100.30/' + p.relative_to(ROOT).as_posix()
        # Uses system CA verification, never insecure or custom trust bypass.
        with opener.open(url, timeout=15) as response:
            assert response.status == 200 and response.read() == expected[p], 'HTTPS readback mismatch'
    print(json.dumps({'https_verified': len(FILES), 'protected_configs_unchanged': True,
                      'service_pids_unchanged': True, 'tls_verified': True}))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # HTTP exceptions may contain a credential-bearing URL: do not print it.
        print(json.dumps({'verification_failed': type(error).__name__}))
        sys.exit(1)
