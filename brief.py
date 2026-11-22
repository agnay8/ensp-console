"""任务书解析：抽取纯文本，并识别设备、网段、协议等关键要素。

只做「读出来 + 标出要素」，不做语义推断；配置骨架明确标注为待补全。
"""

from __future__ import annotations

import re
from pathlib import Path

# 设备名：常见前缀 + 1~2 位编号（3 位以上视为型号，如 AR2220 / S5700）
DEVICE_RE = re.compile(r"\b((?:AR|CE|NE|SR|LSW|SW|FW|RT|R|S)\d{1,2})\b")
IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})(?:/(\d{1,2}))?\b")
VLAN_RE = re.compile(r"(?:VLAN|vlan)\s*(?:batch\s*)?((?:\d{1,4}[\s,，、]*)+)")
AREA_RE = re.compile(r"(?:area|区域)\s*([\d.]+)", re.I)
AS_RE = re.compile(r"\bAS\s*(\d{1,5})\b")
ROUTER_ID_RE = re.compile(r"router[- ]?id\s*([\d.]+)", re.I)
MASK_RE = re.compile(r"\b(255\.(?:255|0)\.(?:255|0)\.(?:255|0))\b")

PROTOCOLS = [
    "OSPF", "BGP", "RIP", "IS-IS", "VRRP", "MSTP", "RSTP", "STP", "VLAN",
    "NAT", "ACL", "DHCP", "PPP", "PPPoE", "Eth-Trunk", "链路聚合", "端口安全",
    "静态路由", "默认路由", "QoS", "MPLS", "IPv6", "GRE", "IPSec", "LACP", "BFD",
]

PROTOCOL_ALIAS = {
    "ospf": "OSPF", "bgp": "BGP", "rip": "RIP", "isis": "IS-IS", "is-is": "IS-IS",
    "vrrp": "VRRP", "stp": "STP", "vlan": "VLAN", "nat": "NAT", "acl": "ACL",
    "dhcp": "DHCP", "ppp": "PPP", "mpls": "MPLS", "ipv6": "IPv6", "bfd": "BFD",
}


def extract_text(path: Path) -> tuple[str, str]:
    """返回 (纯文本, 文件类型)。"""
    suffix = path.suffix.lower()

    if suffix in (".txt", ".md", ".text"):
        for enc in ("utf-8", "utf-8-sig", "gbk", "gb18030"):
            try:
                return path.read_text(encoding=enc), suffix.lstrip(".")
            except UnicodeDecodeError:
                continue
        return path.read_text(encoding="utf-8", errors="replace"), suffix.lstrip(".")

    if suffix == ".docx":
        from docx import Document

        doc = Document(str(path))
        parts: list[str] = [p.text for p in doc.paragraphs if p.text.strip()]
        for table in doc.tables:
            for row in table.rows:
                cells = [c.text.strip() for c in row.cells]
                if any(cells):
                    parts.append(" | ".join(cells))
        return "\n".join(parts), "docx"

    if suffix == ".pdf":
        from pypdf import PdfReader

        reader = PdfReader(str(path))
        pages = []
        for page in reader.pages:
            try:
                pages.append(page.extract_text() or "")
            except Exception:
                pages.append("")
        return "\n".join(pages), "pdf"

    raise ValueError(f"不支持的格式 {suffix}，请用 .txt / .md / .docx / .pdf")


def _valid_ip(ip: str) -> bool:
    return all(0 <= int(part) <= 255 for part in ip.split("."))


def analyse(text: str) -> dict:
    devices = sorted({m.group(1) for m in DEVICE_RE.finditer(text)})

    ips: list[str] = []
    nets: list[str] = []
    for m in IP_RE.finditer(text):
        ip, prefix = m.group(1), m.group(2)
        if not _valid_ip(ip):
            continue
        masked = ip.startswith("255.") or ip.endswith(".0")
        if prefix:
            nets.append(f"{ip}/{prefix}")
        elif masked:
            nets.append(ip)
        else:
            ips.append(ip)

    lower = text.lower()
    protocols = [p for p in PROTOCOLS if p.lower() in lower]

    vlans: list[int] = []
    for m in VLAN_RE.finditer(text):
        for token in re.findall(r"\d{1,4}", m.group(1)):
            v = int(token)
            if 1 <= v <= 4094 and v not in vlans:
                vlans.append(v)

    areas = sorted({m.group(1) for m in AREA_RE.finditer(text)})
    asns = sorted({m.group(1) for m in AS_RE.finditer(text)})
    router_ids = sorted({m.group(1) for m in ROUTER_ID_RE.finditer(text) if _valid_ip(m.group(1))})
    masks = sorted({m.group(1) for m in MASK_RE.finditer(text)})

    sections = _outline(text)

    return {
        "devices": devices,
        "ips": sorted(set(ips)),
        "networks": sorted(set(nets)),
        "masks": masks,
        "protocols": protocols,
        "vlans": sorted(vlans),
        "areas": areas,
        "asNumbers": asns,
        "routerIds": router_ids,
        "sections": sections,
        "charCount": len(text),
        "lineCount": len([l for l in text.splitlines() if l.strip()]),
    }


def _outline(text: str) -> list[str]:
    """抓取像小标题的行：一、1. 1) （一） 第X章 等。"""
    pat = re.compile(r"^\s*(?:第[一二三四五六七八九十百]+[章节部分]|[一二三四五六七八九十]+[、.]|\d+[、.)）]|（[一二三四五六七八九十]+）)")
    out = []
    for line in text.splitlines():
        s = line.strip()
        if s and len(s) <= 40 and not s.endswith(("。", "；", "，", ".", ";")) and pat.match(s):
            out.append(s)
        if len(out) >= 40:
            break
    return out


def build_skeleton(devices: list[str], info: dict) -> dict[str, list[str]]:
    """按设备生成配置骨架，全部为可编辑占位，不含真实地址。"""
    supports_ospf = "OSPF" in info.get("protocols", [])
    supports_vlan = "VLAN" in info.get("protocols", [])

    out: dict[str, list[str]] = {}
    for index, name in enumerate(devices, start=1):
        cmds = ["system-view", f"sysname {name}"]

        if supports_vlan and "VLAN" in info.get("protocols", []):
            vlans = info.get("vlans") or []
            if vlans:
                cmds.append(f"vlan batch {' '.join(str(v) for v in vlans)}")

        cmds += [
            "# TODO 按任务书配置接口地址，例如：",
            "# interface GigabitEthernet0/0/0",
            "#  ip address 10.0.0.1 255.255.255.0",
        ]

        if supports_ospf:
            rid = f"{index}.{index}.{index}.{index}"
            area = info["areas"][0] if info.get("areas") else "0"
            cmds += [
                "# TODO 按任务书配置 Loopback 与 OSPF 宣告网段",
                f"ospf 1 router-id {rid}",
                f" area {area}",
            ]
            for net in (info.get("networks") or [])[:4]:
                if "/" in net:
                    ip, prefix = net.split("/", 1)
                    cmds.append(f"  # network {ip} {_wildcard(int(prefix))}")
            cmds.append("quit")

        cmds += ["return", "save"]
        out[name] = cmds

    return out


def _wildcard(prefix: int) -> str:
    if not 0 <= prefix <= 32:
        return "0.0.0.255"
    bits = (1 << (32 - prefix)) - 1
    return ".".join(str((bits >> shift) & 0xFF) for shift in (24, 16, 8, 0))
