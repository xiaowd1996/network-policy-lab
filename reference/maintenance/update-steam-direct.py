#!/usr/bin/env python3
"""Keep Steam multiplayer/P2P local without reopening general UDP.

The process/path rules cover Steam and games on arbitrary ports. Narrow Valve
port rules are a fallback when Windows process lookup is unavailable. This
does not restart services or clients and does not change node credentials.
"""
import copy
import importlib.util
from pathlib import Path

import yaml

spec = importlib.util.spec_from_file_location(
    'subscription_update', Path(__file__).with_name('update-wechat-direct.py'))
gateway = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gateway)

RULES = [
    'PROCESS-NAME,steam.exe,DIRECT',
    'PROCESS-NAME,steamservice.exe,DIRECT',
    # Covers games in both the default and custom Steam Library locations.
    r'PROCESS-PATH-REGEX,(?i).*\\steamapps\\common\\.*\.exe,DIRECT',
    # Valve-documented ports. Do not globally bypass UDP 3478: browsers also
    # use it for WebRTC/STUN, while Steam/game process rules already cover it.
    'AND,((NETWORK,UDP),(DST-PORT,27000-27250)),DIRECT',
    'AND,((NETWORK,UDP),(DST-PORT,4379)),DIRECT',
    'AND,((NETWORK,UDP),(DST-PORT,4380)),DIRECT',
    'AND,((NETWORK,TCP),(DST-PORT,27015-27050)),DIRECT',
]


def transform(text):
    before = yaml.safe_load(text)
    original = before.get('rules')
    if not isinstance(original, list) or text.splitlines().count('rules:') != 1:
        raise ValueError('Unexpected subscription structure')
    if before.get('find-process-mode') not in ('strict', 'always'):
        raise ValueError('Process detection must be enabled')
    if 'NETWORK,UDP,REJECT' not in original:
        raise ValueError('Unexpected baseline UDP policy')
    if original[:len(RULES)] == RULES:
        return text, before

    remaining = [rule for rule in original if rule not in RULES]
    expected = copy.deepcopy(before)
    expected['rules'] = RULES + remaining

    lines = text.splitlines(keepends=True)
    marker = next(i for i, line in enumerate(lines)
                  if line.rstrip('\r\n') == 'rules:')
    rendered_rules = yaml.safe_dump(
        {'rules': expected['rules']}, allow_unicode=True, sort_keys=False)
    result = ''.join(lines[:marker]) + rendered_rules
    after = yaml.safe_load(result)
    if after != expected:
        raise ValueError('Unexpected change outside additive Steam rules')
    assert len(set(RULES)) == len(RULES)
    assert all(after['rules'].index(rule) < after['rules'].index('NETWORK,UDP,REJECT')
               for rule in RULES)
    return result, after


if __name__ == '__main__':
    gateway.transform = transform
    gateway.RULES = RULES
    gateway.BACKUP_PREFIX = 'steam-direct-'
    gateway.main()
