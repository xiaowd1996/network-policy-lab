#!/usr/bin/env python3
"""Atomically update all private Mihomo subscriptions without logging tokens."""

from __future__ import annotations

import datetime as dt
import os
from pathlib import Path
import shutil
import tempfile


SUBSCRIPTION_ROOT = Path("/srv/private-subscriptions")
BACKUP_BASE = Path("/root/private-subscription-backups")

PROVIDERS = """rule-providers:
  private_domain:
    type: http
    behavior: domain
    format: mrs
    path: ./ruleset/private-domain.mrs
    url: https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/private.mrs
    interval: 86400
    proxy: AUTO · 智能分流
  cn_domain:
    type: http
    behavior: domain
    format: mrs
    path: ./ruleset/cn-domain.mrs
    url: https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/cn.mrs
    interval: 86400
    proxy: AUTO · 智能分流
  private_ip:
    type: http
    behavior: ipcidr
    format: mrs
    path: ./ruleset/private-ip.mrs
    url: https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/private.mrs
    interval: 86400
    proxy: AUTO · 智能分流
  cn_ip:
    type: http
    behavior: ipcidr
    format: mrs
    path: ./ruleset/cn-ip.mrs
    url: https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/cn.mrs
    interval: 86400
    proxy: AUTO · 智能分流
""".rstrip()

RULES = """rules:
  # Steam multiplayer stays local; retain general UDP rejection below.
  - PROCESS-NAME,steam.exe,DIRECT
  - PROCESS-NAME,steamservice.exe,DIRECT
  - PROCESS-PATH-REGEX,(?i).*\\\\steamapps\\\\common\\\\.*\\.exe,DIRECT
  - AND,((NETWORK,UDP),(DST-PORT,27000-27250)),DIRECT
  - AND,((NETWORK,UDP),(DST-PORT,4379)),DIRECT
  - AND,((NETWORK,UDP),(DST-PORT,4380)),DIRECT
  - AND,((NETWORK,TCP),(DST-PORT,27015-27050)),DIRECT

  # qBittorrent downloads, qBitController control traffic and Syncthing stay local.
  - PROCESS-NAME,qBittorrent,DIRECT
  - PROCESS-NAME,qbittorrent.exe,DIRECT
  - PROCESS-NAME,qbittorrent-nox,DIRECT
  - PROCESS-NAME,dev.bartuzen.qbitcontroller,DIRECT
  - PROCESS-NAME,syncthing,DIRECT
  - PROCESS-NAME,syncthing.exe,DIRECT
  - PROCESS-NAME,syncthingtray,DIRECT
  - PROCESS-NAME,syncthingtray.exe,DIRECT
  - PROCESS-NAME,com.nutomic.syncthingandroid,DIRECT
  - PROCESS-NAME,com.github.catfriend1.syncthingandroid,DIRECT
  - GEOSITE,category-public-tracker,DIRECT

  # SAGE journals use XO; other ordinary overseas traffic remains on HK.
  - DOMAIN,journals.sagepub.com,XO · 强制美国

  # OpenAI official dependencies and IP-check sites must enter AUTO before CN rules.
  - DOMAIN-SUFFIX,openai.com,AUTO · 智能分流
  - DOMAIN-SUFFIX,chatgpt.com,AUTO · 智能分流
  - DOMAIN-SUFFIX,oaistatic.com,AUTO · 智能分流
  - DOMAIN-SUFFIX,oaiusercontent.com,AUTO · 智能分流
  - DOMAIN-SUFFIX,oaistatsig.com,AUTO · 智能分流
  - DOMAIN-SUFFIX,openaimerge.com,AUTO · 智能分流
  - DOMAIN-SUFFIX,ct.sendgrid.net,AUTO · 智能分流
  - DOMAIN-SUFFIX,intercom.io,AUTO · 智能分流
  - DOMAIN-SUFFIX,intercomcdn.com,AUTO · 智能分流
  - DOMAIN,cdn.workos.com,AUTO · 智能分流
  - DOMAIN,challenges.cloudflare.com,AUTO · 智能分流
  - DOMAIN,forwarder.workos.com,AUTO · 智能分流
  - DOMAIN,humb.apple.com,AUTO · 智能分流
  - DOMAIN,images.workoscdn.com,AUTO · 智能分流
  # Keep every ChatGPT payment dependency on the XO exit.
  - DOMAIN-SUFFIX,stripe.com,XO · 强制美国
  - DOMAIN-SUFFIX,stripe.network,XO · 强制美国
  - DOMAIN-SUFFIX,stripecdn.com,XO · 强制美国
  - DOMAIN,o207216.ingest.sentry.io,AUTO · 智能分流
  - DOMAIN,o33249.ingest.sentry.io,AUTO · 智能分流
  - DOMAIN,rum.browser-intake-datadoghq.com,AUTO · 智能分流
  - DOMAIN,setup.workos.com,AUTO · 智能分流
  - DOMAIN,workos.imgix.net,AUTO · 智能分流
  - DOMAIN-SUFFIX,ippure.com,AUTO · 智能分流
  - DOMAIN-SUFFIX,ipapi.co,AUTO · 智能分流
  - DOMAIN-SUFFIX,ipinfo.io,AUTO · 智能分流
  - DOMAIN-SUFFIX,icanhazip.com,AUTO · 智能分流
  - DOMAIN,myip.ipip.net,AUTO · 智能分流
  - DOMAIN,api.123169.xyz,AUTO · 智能分流

  # QQ downloads and private/LAN destinations stay on the local network.
  - PROCESS-NAME,QQ.exe,DIRECT
  - PROCESS-NAME,QQEX.exe,DIRECT
  - PROCESS-NAME,com.tencent.mobileqq,DIRECT
  - PROCESS-NAME,com.tencent.tim,DIRECT
  - IP-CIDR,127.0.0.0/8,DIRECT,no-resolve
  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve
  - IP-CIDR,172.16.0.0/12,DIRECT,no-resolve
  - IP-CIDR,192.168.0.0/16,DIRECT,no-resolve
  - IP-CIDR,169.254.0.0/16,DIRECT,no-resolve
  - RULE-SET,private_domain,DIRECT
  - RULE-SET,private_ip,DIRECT,no-resolve

  # Mainland domains/IPs are direct. The built-ins are offline fallbacks.
  - RULE-SET,cn_domain,DIRECT
  - RULE-SET,cn_ip,DIRECT
  - GEOSITE,CN,DIRECT
  - GEOIP,CN,DIRECT

  # The server ingress is TCP-only: non-mainland UDP is rejected to force TCP fallback.
  - NETWORK,UDP,REJECT
  - MATCH,出口模式
""".rstrip()


def replace_top_level(text: str, header: str, replacement: str, insert_before: str) -> str:
    lines = text.splitlines()
    start = next((i for i, line in enumerate(lines) if line.startswith(f"{header}:")), None)
    if start is not None:
        end = len(lines)
        for i in range(start + 1, len(lines)):
            line = lines[i]
            if line and not line[0].isspace() and ":" in line:
                end = i
                break
        lines[start:end] = replacement.splitlines() + [""]
        return "\n".join(lines).rstrip() + "\n"

    insert = next((i for i, line in enumerate(lines) if line.startswith(f"{insert_before}:")), None)
    if insert is None:
        raise ValueError(f"missing top-level {insert_before} block")
    lines[insert:insert] = replacement.splitlines() + [""]
    return "\n".join(lines).rstrip() + "\n"


def main() -> None:
    files = sorted(SUBSCRIPTION_ROOT.rglob("mihomo.yaml"))
    if not files:
        raise SystemExit("No Mihomo subscriptions found; nothing changed.")

    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    backup_root = BACKUP_BASE / stamp
    updated: list[tuple[Path, str, os.stat_result]] = []

    for path in files:
        text = path.read_text(encoding="utf-8")
        if "AUTO · 智能分流" not in text or "出口模式" not in text:
            raise SystemExit("Unexpected subscription format; nothing changed.")
        result = replace_top_level(text, "rule-providers", PROVIDERS, "proxies")
        result = replace_top_level(result, "rules", RULES, "rules")
        updated.append((path, result, path.stat()))

    for path, _result, _stat in updated:
        relative = path.relative_to(SUBSCRIPTION_ROOT)
        backup = backup_root / relative
        backup.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, backup)

    for path, result, stat in updated:
        fd, temp_name = tempfile.mkstemp(prefix=".mihomo.", dir=path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(result)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temp_name, stat.st_mode)
            os.chown(temp_name, stat.st_uid, stat.st_gid)
            os.replace(temp_name, path)
        finally:
            if os.path.exists(temp_name):
                os.unlink(temp_name)

    print(f"UPDATED={len(updated)}")
    print(f"BACKUP={backup_root}")


if __name__ == "__main__":
    main()
