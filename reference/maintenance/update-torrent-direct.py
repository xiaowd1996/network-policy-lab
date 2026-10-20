#!/usr/bin/env python3
"""Prepend torrent-client DIRECT rules; reuse atomic subscription deployment.

Client identity covers peers, DHT, trackers and web seeds on arbitrary ports.
Public tracker geosite is supplemental, not a universal BitTorrent detector.
Does not restart services or clients, or change credentials/DNS/proxy nodes.
"""
import copy
import importlib.util
from pathlib import Path

import yaml

spec = importlib.util.spec_from_file_location(
    'subscription_update', Path(__file__).with_name('update-wechat-direct.py'))
gateway = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gateway)

PROCESSES = (
    # Local custom Flutter/libtorrent app: verified applicationId and BINARY_NAME.
    'com.codexchat.magnet_downloader', 'magnet_downloader.exe', 'magnet_downloader',
    # Android torrent clients. Exact package matches, not generic Java processes.
    'com.xunlei.downloadprovider', 'com.delphicoder.flud',
    'org.proninyaroslav.libretorrent', 'com.utorrent.client',
    'com.bittorrent.client', 'org.frostwire.android', 'com.biglybt.android.client',
    # Desktop torrent clients and their download engines.
    'qBittorrent', 'qbittorrent.exe', 'qbittorrent-nox',
    # qBitController only talks to the qBittorrent Web UI; keep that control
    # channel local as well (especially when the Web UI uses an RFC1918 IP).
    'dev.bartuzen.qbitcontroller',
    # Syncthing traffic must never consume the Hong Kong relay quota. Include
    # the Windows daemon/tray wrappers and the common Android package names.
    'syncthing', 'syncthing.exe', 'syncthingtray', 'syncthingtray.exe',
    'com.nutomic.syncthingandroid', 'com.github.catfriend1.syncthingandroid',
    'Transmission', 'transmission-daemon', 'transmission-daemon.exe',
    'transmission-qt.exe', 'transmission-qt',
    'Thunder', 'Thunder.exe', 'ThunderVIP.exe', 'DownloadSDKServer.exe',
    'uTorrent', 'uTorrent.exe', 'BitTorrent', 'BitTorrent.exe',
    'BitComet', 'BitComet.exe', 'BitComet_x64.exe',
    'aria2', 'aria2.exe', 'aria2c', 'aria2c.exe',
    'WebTorrent', 'WebTorrent.exe', 'Folx',
    'deluge', 'deluged', 'deluge.exe', 'deluged.exe',
)
RULES = ['PROCESS-NAME,' + name + ',DIRECT' for name in PROCESSES]
RULES += ['GEOSITE,category-public-tracker,DIRECT']


def transform(text):
    before = yaml.safe_load(text)
    original = before.get('rules')
    if not isinstance(original, list) or text.splitlines().count('rules:') != 1:
        raise ValueError('Unexpected subscription structure')
    if before.get('find-process-mode') not in ('strict', 'always'):
        raise ValueError('Process detection must be enabled')
    if not before.get('dns', {}).get('direct-nameserver'):
        raise ValueError('Independent direct DNS must already be configured')
    if 'NETWORK,UDP,REJECT' not in original:
        raise ValueError('Unexpected baseline UDP policy')
    if original[:len(RULES)] == RULES:
        return text, before
    # Older subscriptions may already contain a shorter version of this block.
    # Remove only rules owned by this updater, then rebuild the complete block
    # at the highest priority without disturbing any other rule's order.
    remaining = [rule for rule in original if rule not in RULES]
    expected = copy.deepcopy(before)
    expected['rules'] = RULES + remaining
    lines = text.splitlines(keepends=True)
    marker = next(i for i, line in enumerate(lines) if line.rstrip('\r\n') == 'rules:')
    # `rules` is deliberately the final top-level key in generated profiles.
    # Re-serialize only that credential-free section; the proxy definitions,
    # tokens, DNS configuration and all preceding bytes remain untouched.
    rendered_rules = yaml.safe_dump(
        {'rules': expected['rules']}, allow_unicode=True, sort_keys=False)
    result = ''.join(lines[:marker]) + rendered_rules
    after = yaml.safe_load(result)
    if after != expected:
        raise ValueError('Unexpected change outside additive torrent rules')
    assert len(set(RULES)) == len(RULES)
    return result, after


if __name__ == '__main__':
    gateway.transform = transform
    gateway.RULES = RULES
    gateway.BACKUP_PREFIX = 'torrent-direct-'
    gateway.main()
