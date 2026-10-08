#!/usr/bin/env python3
"""Deterministic differential battery generator.

Emits JSONL lines {"dir":..., "evidence":[...]} exercising the classifier:
  - real-world-style banners/titles/sysDescrs/hostnames (fixed set),
  - per-rule targeted strings built from each rule's own literals/needles
    embedded in noise (gate-passing and gate-failing variants),
  - seeded ASCII + UTF-8 fuzz,
  - multi-evidence batches (port_open + banner + snmp combos).

Run:  python gen_battery.py <corpus_dir> <out.jsonl> [seed]
"""
import json
import random
import re
import sys
from pathlib import Path

corpus = sys.argv[1]
out_path = sys.argv[2]
seed = int(sys.argv[3]) if len(sys.argv) > 3 else 20261005
rng = random.Random(seed)

lines = []


def emit(evidence):
    lines.append({"dir": corpus.replace("\\", "/"), "evidence": evidence})


def ev(kind, field, value, conf=None, port=None, ip=None):
    e = {"source": "battery", "kind": kind, "ip": ip or "192.0.2.10",
         "confidence": conf if conf is not None else 0.9,
         "observed_at": "2026-10-05T01:00:00Z", "raw_data": {field: value}}
    if port is not None:
        e["port"] = port
    return e


# ---- 1. fixed real-world-style battery ----
FIXED = [
    ("banner", "banner", "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13"),
    ("banner", "banner", "SSH-2.0-OpenSSH_for_Windows_9.5"),
    ("banner", "banner", "220 Microsoft FTP Service (Version 4.0)."),
    ("banner", "banner", "220 (vsFTPd 3.0.3)"),
    ("banner", "banner", "220 ProFTPD Server (Debian) [::ffff:192.0.2.4]"),
    ("banner", "banner", "dropbear\r\n\x00\x00curve25519"),
    ("banner", "banner", "RTSP/1.0 200 OK"),
    ("http", "banner", "HTTP/1.1 200 OK"),
    ("http", "server", "nginx/1.24.0 (Ubuntu)"),
    ("http", "title", "MiWiFi - Xiaomi Router"),
    ("http", "title", "GL.iNet Admin Panel"),
    ("http", "server", "Apache/2.4.41 (Unix) OpenSSL/1.1.1"),
    ("http", "banner", "HTTP/1.0 401 Unauthorized"),
    ("snmp", "sys_descr", "Linux rpi3b-storage 6.1.0-v8+ #1 SMP PREEMPT aarch64"),
    ("snmp", "sys_descr", "Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.0(2)SE11"),
    ("snmp", "sys_descr", "HWIC-ESW switches"),
    ("snmp", "sys_object_id", "1.3.6.1.4.1.9.1.696"),
    ("snmp", "sys_descr", "BCM96338 ADSL Router"),
    ("hostname", "hostname", "viomi-waterheater-e13_miap5E55"),
    ("hostname", "hostname", "yeelink-light-lamp22_mibt63AA"),
    ("hostname", "hostname", "chuangmi_camera_039a01"),
    ("hostname", "hostname", "rpi3b-storage"),
    ("hostname", "hostname", "rpi400"),
    ("hostname", "hostname", "orangepi-zero3"),
    ("hostname", "hostname", "nanopineo"),
    ("hostname", "hostname", "R4S-FNOS"),
    ("hostname", "hostname", "Z4S-2PSE"),
    ("hostname", "hostname", "Mijia_Hub_V2-ab12"),
    ("hostname", "hostname", "esp32c3-aabbcc"),
    ("hostname", "hostname", "esp32c6-1122334455"),
    ("hostname", "hostname", "MiAiSoundbox-LX06"),
    ("hostname", "hostname", "XiaoAiTongXueX6A"),
    ("hostname", "hostname", "philips-light-sread9_mibt1234"),
    ("hostname", "hostname", "xiaomi-repeater-v2_miio123456"),
    ("hostname", "hostname", "MacBookPro.local"),
    ("hostname", "hostname", "redmi-notebook"),
    ("hostname", "hostname", "jetson-ubuntu"),
    ("hostname", "hostname", "Mi-10-pad-6.ts.net"),
    ("hostname", "hostname", "bananapim5"),
    ("hostname", "hostname", "HUAWEI-P40-AL00U"),
    ("hostname", "hostname", "android-7d2f1c9a3b0e4d5f"),
    ("hostname", "hostname", "DESKTOP-ABC1234.corp.example.com"),
    ("mdns", "services", "_smb._tcp,_adisk._tcp"),
    ("mdns", "hostname", "nas.local"),
    ("mdns", "txt.model", "Hub V2"),
    ("mdns", "txt.vendor", "Xiaomi"),
    ("ssdp", "server", "lunzn,fastrhino-r68s"),
    ("ssdp", "server", "MiniDLNA 1.3.2"),
    ("ssdp", "usn", "uuid:hikvision-abc123::upnp:rootdevice"),
    ("ssdp", "location", "http://192.0.2.9:49152/description.xml"),
    ("smb", "os", "Windows 6.1"),
    ("smb", "dialect", "3.1.1"),
    ("smb_negotiate", "dialect", "2.1"),
    ("tls", "subject_cn", "MIWIFI R4AA"),
    ("tls", "issuer_org", "Synology Inc."),
    ("rtsp_banner", "status", "RTSP/1.0 200 OK"),
    ("rtsp_banner", "server", "Hikvision-IPCamera"),
    ("onvif_response", "status_code", "200"),
    ("onvif_response", "auth_required", "true"),
    ("metric", "content_sample", "node_exporter 1.6.1"),
    ("metric", "url", "http://192.0.2.3:9100/metrics"),
    ("cdp", "platform", "cisco WS-C2960S-24TS-L"),
    ("cdp", "sys_desc", "Cisco IOS Software"),
    ("banner", "banner", "220-QTV Microsoft FTP Service (Version 4.0)."),
    ("snmp", "sys_descr", "TiMOS-C-4.0.4 ALU cpm ALCATEL SR 7750 Copyright"),
    ("banner", "banner", "X2 WS_FTP Server 4.01 (456789)"),
    ("http", "title", "title with trailing spaces   "),
    ("http", "banner", "   200 OK spaced response"),
]
for kind, field, value in FIXED:
    emit([ev(kind, field, value)])

# multi-evidence batches (loop A + loop B interplay)
emit([
    {"source": "probe", "kind": "port_open", "ip": "192.0.2.20", "port": 445,
     "confidence": 1.0, "observed_at": "2026-10-05T01:00:00Z"},
    ev("banner", "banner", "SSH-2.0-dropbear_2020.81", conf=0.9, port=22),
    ev("http", "title", "Router Admin", conf=0.9, port=80),
    ev("snmp", "sys_descr", "Linux nanopi 5.10.0", conf=0.95, port=161),
])
emit([ev("port_open", "banner", "")])
emit([
    {"source": "probe", "kind": "port_open", "ip": "192.0.2.21", "port": 23,
     "confidence": 1.0, "observed_at": "2026-10-05T01:00:00Z"},
    ev("hostname", "hostname", "esp32-dev", conf=0.8),
])

# ---- 2. per-rule targeted strings ----
def extract_rules():
    rules = []
    for f in sorted(Path(corpus).glob("*.yaml")):
        # cheap top-level split on "- id:" blocks is fragile; use a YAML lib
        try:
            import yaml
            doc = yaml.safe_load(f.read_text(encoding="utf8"))
        except Exception:
            continue
        if not isinstance(doc, dict):
            continue
        for r in doc.get("rules") or []:
            if not isinstance(r, dict):
                continue
            m = r.get("match") or {}
            rules.append((r.get("id", ""), m))
    return rules


needles_cache = {}


def rule_needles(m):
    """Extract literal fragments a rule could match, for targeted strings."""
    op = m.get("op", "")
    val = m.get("value", "")
    frags = []
    if op in ("contains", "contains_any", "equals", "prefix", "prefix_ci"):
        vals = val if isinstance(val, list) else [val]
        for v in vals:
            if isinstance(v, str) and v:
                frags.append(v)
    elif op == "regex":
        if not isinstance(val, str):
            return []
        if val in needles_cache:
            return needles_cache[val]
        # strip anchors, flags, groups; pull literal runs of >=4 alnum chars
        pat = re.sub(r"\(\?[a-z:=-]+\)", "", val)
        pat = re.sub(r"[\^\$]", "", pat)
        runs = re.findall(r"[A-Za-z0-9][A-Za-z0-9 ._\-/]{3,40}[A-Za-z0-9]", pat)
        needles_cache[val] = runs
        frags = runs
    return [f for f in frags if isinstance(f, str) and 4 <= len(f) <= 60]


NOISE = ["zz", "x9", "q1w2", "__", "!!", "01"]
for rid, m in extract_rules():
    kind = m.get("kind") or rng.choice(["banner", "http", "snmp", "hostname"])
    field = m.get("field") or "banner"
    for frag in rule_needles(m)[:2]:
        # gate-passing: fragment embedded in noise
        s = rng.choice(NOISE) + frag + rng.choice(NOISE)
        emit([ev(kind, field, s)])
        # near-miss: fragment with one char mutated (often still passes)
        if len(frag) > 5:
            pos = rng.randrange(1, len(frag) - 1)
            mutated = frag[:pos] + "#" + frag[pos + 1:]
            emit([ev(kind, field, mutated)])

# ---- 3. seeded fuzz ----
ALPHA = "abcdeXYZ019.-_ /:#@!\t"
UTF8 = "abcéíßİſK_utilities 物联网\r\n"
for _ in range(3000):
    n = rng.randrange(0, 60)
    s = "".join(rng.choice(ALPHA) for _ in range(n))
    kind = rng.choice(["banner", "http", "snmp", "hostname", "mdns", "ssdp", "tls"])
    field = rng.choice(["banner", "server", "title", "sys_descr", "hostname", "services"])
    e = ev(kind, field, s, conf=rng.choice([0.0, 0.5, 0.9, 1.0]))
    if rng.random() < 0.3:
        e["port"] = rng.choice([0, 22, 80, 443, 161, 445, 9100])
    emit([e])
for _ in range(600):
    n = rng.randrange(1, 40)
    s = "".join(rng.choice(UTF8) for _ in range(n))
    emit([ev(rng.choice(["banner", "hostname", "http"]), "banner", s)])

with open(out_path, "w", encoding="utf8", newline="\n") as f:
    for item in lines:
        f.write(json.dumps(item, ensure_ascii=False) + "\n")
print(f"wrote {len(lines)} lines to {out_path}")
