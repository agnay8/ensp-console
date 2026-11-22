"""网络工具集：ping / tracert / 端口扫描 / DNS / 子网计算 / 下载测速 / pcap 分析。

除端口扫描是 async 外，其余为同步函数，由路由放进线程池执行。
"""

from __future__ import annotations

import asyncio
import ipaddress
import random
import re
import socket
import struct
import subprocess
import time
import urllib.request
from typing import Any


def _decode(data: bytes) -> str:
    for enc in ("gbk", "utf-8", "latin-1"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", "replace")


def _valid_host(host: str) -> str:
    h = (host or "").strip()
    if not h or any(c.isspace() for c in h):
        raise ValueError("主机不能为空且不能含空格")
    if len(h) > 253:
        raise ValueError("主机名过长")
    return h


# ---------------------------------------------------------------------------
# Ping
# ---------------------------------------------------------------------------

REPLY_CN = re.compile(r"来自\s*(\S+?)\s*的回复[:：]\s*字节[=＝]\s*(\d+)\s*时间[=<＜]\s*(\d+)?ms\s*TTL[=＝]\s*(\d+)")
REPLY_EN = re.compile(r"Reply from\s*(\S+?):\s*bytes[=]\s*(\d+)\s*time[=<]\s*(\d+)?ms\s*TTL[=]\s*(\d+)", re.I)
STATS_CN = re.compile(r"已发送\s*=\s*(\d+)[，,]\s*已接收\s*=\s*(\d+)[，,]\s*丢失\s*=\s*(\d+)\s*\((\d+)%")
STATS_EN = re.compile(r"Sent\s*=\s*(\d+).*?Received\s*=\s*(\d+).*?Lost\s*=\s*(\d+)\s*\((\d+)%", re.I | re.S)
RTT_CN = re.compile(r"最短\s*=\s*(\d+)ms[，,]\s*最长\s*=\s*(\d+)ms[，,]\s*平均\s*=\s*(\d+)ms")
RTT_EN = re.compile(r"Minimum\s*=\s*(\d+)ms.*?Maximum\s*=\s*(\d+)ms.*?Average\s*=\s*(\d+)ms", re.I | re.S)


def run_ping(host: str, count: int = 4, timeout_ms: int = 1000, size: int = 32) -> dict:
    host = _valid_host(host)
    count = max(1, min(20, int(count)))
    timeout_ms = max(100, min(10000, int(timeout_ms)))

    cmd = ["ping", "-n", str(count), "-w", str(timeout_ms)]
    if size and size != 32:
        cmd += ["-l", str(max(1, min(65500, int(size))))]
    cmd.append(host)

    started = time.monotonic()
    try:
        proc = subprocess.run(
            cmd, capture_output=True, timeout=count * timeout_ms / 1000 + 10
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "ping 执行超时", "host": host}

    text = _decode(proc.stdout or b"") + _decode(proc.stderr or b"")
    elapsed = round((time.monotonic() - started) * 1000)

    replies = []
    for m in list(REPLY_CN.finditer(text)) + list(REPLY_EN.finditer(text)):
        replies.append(
            {
                "from": m.group(1),
                "bytes": int(m.group(2)),
                "timeMs": int(m.group(3)) if m.group(3) else 0,
                "ttl": int(m.group(4)),
            }
        )

    stats = STATS_CN.search(text) or STATS_EN.search(text)
    rtt = RTT_CN.search(text) or RTT_EN.search(text)

    if stats:
        sent, received, lost, loss_pct = (int(g) for g in stats.groups())
    else:
        sent, received, lost, loss_pct = count, len(replies), count - len(replies), None

    result = {
        "ok": True,
        "host": host,
        "count": count,
        "sent": sent,
        "received": received,
        "lost": lost,
        "lossPercent": loss_pct if loss_pct is not None else (round(lost * 100 / sent, 1) if sent else 100),
        "reachable": received > 0,
        "replies": replies[:50],
        "elapsedMs": elapsed,
        "raw": text.strip()[:4000],
    }
    if rtt:
        result["rtt"] = {"min": int(rtt.group(1)), "max": int(rtt.group(2)), "avg": int(rtt.group(3))}
    return result


# ---------------------------------------------------------------------------
# Traceroute
# ---------------------------------------------------------------------------

TRACE_LINE = re.compile(r"^\s*(\d+)\s+(.+)$")
HOP_IP = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
HOP_MS = re.compile(r"(<\s*)?(\d+)\s*(?:ms|毫秒)", re.I)


def run_traceroute(host: str, max_hops: int = 16, timeout_ms: int = 1000) -> dict:
    host = _valid_host(host)
    max_hops = max(1, min(64, int(max_hops)))
    timeout_ms = max(100, min(5000, int(timeout_ms)))

    cmd = ["tracert", "-d", "-h", str(max_hops), "-w", str(timeout_ms), host]
    started = time.monotonic()
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=max_hops * timeout_ms / 1000 * 3 + 20)
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "tracert 执行超时", "host": host}

    text = _decode(proc.stdout or b"") + _decode(proc.stderr or b"")
    elapsed = round((time.monotonic() - started) * 1000)

    hops = []
    for line in text.splitlines():
        m = TRACE_LINE.match(line)
        if not m:
            continue
        idx = int(m.group(1))
        body = m.group(2)
        if idx <= 0:
            continue
        ip_match = HOP_IP.search(body)
        times = [
            ("<" if m.group(1) else "") + m.group(2) for m in HOP_MS.finditer(body)
        ]
        hops.append(
            {
                "hop": idx,
                "ip": ip_match.group(1) if ip_match else None,
                "timeout": ip_match is None,
                "timesMs": times[:3],
                "note": "" if ip_match else "请求超时",
            }
        )

    return {
        "ok": True,
        "host": host,
        "hops": hops,
        "hopCount": len(hops),
        "reached": bool(hops) and hops[-1]["ip"] is not None,
        "elapsedMs": elapsed,
        "raw": text.strip()[:6000],
    }


# ---------------------------------------------------------------------------
# 端口扫描
# ---------------------------------------------------------------------------

COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 67: "DHCP", 69: "TFTP",
    80: "HTTP", 110: "POP3", 123: "NTP", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
    161: "SNMP", 162: "SNMP Trap", 179: "BGP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 514: "Syslog", 587: "SMTP Submission", 636: "LDAPS", 873: "Rsync",
    993: "IMAPS", 995: "POP3S", 1080: "SOCKS", 1194: "OpenVPN", 1433: "MSSQL",
    1521: "Oracle", 1723: "PPTP", 2049: "NFS", 2375: "Docker", 2376: "Docker TLS",
    3128: "Squid", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5672: "RabbitMQ",
    5900: "VNC", 6379: "Redis", 8080: "HTTP Alt", 8443: "HTTPS Alt", 8888: "HTTP Alt",
    9000: "Portainer", 9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB",
}

PRESETS = {
    "common": [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 6379, 8080, 8443],
    "web": [80, 443, 8000, 8080, 8081, 8443, 8888, 9000, 9090],
    "网络设备": [22, 23, 80, 443, 161, 830, 8080],
    "数据库": [1433, 1521, 3306, 5432, 6379, 9200, 11211, 27017],
    "全部常用": list(range(1, 1025)),
}


def parse_port_spec(spec: str) -> list[int]:
    ports: set[int] = set()
    for part in str(spec or "").replace("，", ",").split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            start, end = int(a), int(b)
            if start > end:
                start, end = end, start
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    valid = sorted(p for p in ports if 1 <= p <= 65535)
    return valid[:2048]


async def run_port_scan(
    host: str, ports: list[int], timeout: float = 1.0, concurrency: int = 200
) -> dict:
    host = _valid_host(host)
    if not ports:
        raise ValueError("没有要扫描的端口")

    timeout = max(0.2, min(10.0, float(timeout)))
    concurrency = max(1, min(512, int(concurrency)))
    semaphore = asyncio.Semaphore(concurrency)
    started = time.monotonic()

    async def probe(port: int):
        async with semaphore:
            try:
                fut = asyncio.open_connection(host, port)
                reader, writer = await asyncio.wait_for(fut, timeout=timeout)
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                return port, True
            except Exception:
                return port, False

    results = await asyncio.gather(*(probe(p) for p in ports))
    open_ports = [
        {"port": p, "service": COMMON_SERVICES.get(p, "")} for p, alive in results if alive
    ]
    elapsed = round((time.monotonic() - started) * 1000, 1)

    return {
        "ok": True,
        "host": host,
        "scanned": len(ports),
        "open": open_ports,
        "openCount": len(open_ports),
        "elapsedMs": int(elapsed),
    }


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------

QTYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28, "SRV": 33}
QTYPE_NAMES = {v: k for k, v in QTYPES.items()}


def _encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        if not label:
            continue
        raw = label.encode("idna")
        if len(raw) > 63:
            raise ValueError("域名标签过长")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def _read_name(data: bytes, pos: int, depth: int = 0) -> tuple[str, int]:
    if depth > 12:
        return "", pos
    labels: list[str] = []
    while pos < len(data):
        length = data[pos]
        if length == 0:
            return ".".join(labels), pos + 1
        if length & 0xC0 == 0xC0:
            pointer = ((length & 0x3F) << 8) | data[pos + 1]
            tail, _ = _read_name(data, pointer, depth + 1)
            if tail:
                labels.append(tail)
            return ".".join(labels), pos + 2
        labels.append(data[pos + 1: pos + 1 + length].decode("ascii", "replace"))
        pos += 1 + length
    return ".".join(labels), pos


def run_dns_query(name: str, qtype: str = "A", server: str = "", timeout: float = 5.0) -> dict:
    dm = (name or "").strip()
    if not dm:
        raise ValueError("域名不能为空")
    qtype = (qtype or "A").upper()
    if qtype not in QTYPES:
        raise ValueError(f"不支持的记录类型 {qtype}")

    server = (server or "").strip() or "223.5.5.5"
    timeout = max(1.0, min(15.0, float(timeout)))

    tid = random.randint(0, 65535)
    packet = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0) + _encode_name(dm) + struct.pack("!HH", QTYPES[qtype], 1)

    started = time.monotonic()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (server, 53))
        data, _addr = sock.recvfrom(4096)
    except socket.timeout:
        return {"ok": False, "error": f"DNS 服务器 {server} 无响应", "name": dm, "type": qtype}
    finally:
        sock.close()
    elapsed = round((time.monotonic() - started) * 1000, 1)

    if len(data) < 12:
        return {"ok": False, "error": "DNS 响应过短", "name": dm, "type": qtype}

    rid, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", data[:12])
    rcode = flags & 0x000F
    rcode_text = {
        0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"
    }.get(rcode, f"RCODE{rcode}")

    pos = 12
    for _ in range(qdcount):
        _, pos = _read_name(data, pos)
        pos += 4

    answers = []
    for _ in range(ancount):
        if pos >= len(data):
            break
        owner, pos = _read_name(data, pos)
        if pos + 10 > len(data):
            break
        rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", data[pos: pos + 10])
        pos += 10
        rdata = data[pos: pos + rdlen]
        pos += rdlen

        value: Any = None
        tname = QTYPE_NAMES.get(rtype, str(rtype))
        try:
            if rtype == 1 and rdlen == 4:
                value = ".".join(str(b) for b in rdata)
            elif rtype == 28 and rdlen == 16:
                value = socket.inet_ntop(socket.AF_INET6, rdata)
            elif rtype in (2, 5, 12):
                value, _ = _read_name(data, pos - rdlen)
            elif rtype == 15 and rdlen > 2:
                pref = struct.unpack("!H", rdata[:2])[0]
                host, _ = _read_name(data, pos - rdlen + 2)
                value = f"{pref} {host}"
            elif rtype == 16:
                chunks = []
                i = 0
                while i < len(rdata):
                    ln = rdata[i]
                    chunks.append(rdata[i + 1: i + 1 + ln].decode("utf-8", "replace"))
                    i += 1 + ln
                value = " ".join(chunks)
        except Exception:
            value = rdata.hex()

        answers.append(
            {"name": owner, "type": tname, "ttl": ttl, "value": value or rdata.hex()}
        )

    return {
        "ok": rcode == 0,
        "name": dm,
        "type": qtype,
        "server": server,
        "status": rcode_text,
        "answers": answers,
        "answerCount": len(answers),
        "elapsedMs": int(elapsed),
    }


# ---------------------------------------------------------------------------
# 子网计算
# ---------------------------------------------------------------------------

def subnet_calc(cidr: str) -> dict:
    raw = (cidr or "").strip().replace(" ", "")
    if not raw:
        raise ValueError("请输入 IP 或网段，例如 192.168.1.0/24")
    try:
        iface = ipaddress.ip_interface(raw)
        net = iface.network
    except ValueError as exc:
        raise ValueError(f"地址格式不对：{exc}") from exc

    hosts = list(net.hosts()) if net.num_addresses > 2 else []
    first = str(hosts[0]) if hosts else None
    last = str(hosts[-1]) if hosts else None

    return {
        "ok": True,
        "input": raw,
        "ip": str(iface.ip),
        "version": net.version,
        "network": str(net.network_address),
        "broadcast": str(net.broadcast_address) if net.version == 4 else None,
        "prefix": net.prefixlen,
        "netmask": str(net.netmask),
        "wildcard": str(net.hostmask),
        "firstHost": first,
        "lastHost": last,
        "hostCount": max(0, net.num_addresses - 2) if net.version == 4 and net.prefixlen < 31 else (1 if net.prefixlen == 32 else net.num_addresses),
        "totalAddresses": net.num_addresses,
        "isPrivate": net.is_private,
        "cidr": str(net),
        "binary": {
            "ip": ".".join(format(int(o), "08b") for o in str(iface.ip).split(".")) if net.version == 4 else "",
            "mask": ".".join(format(int(o), "08b") for o in str(net.netmask).split(".")) if net.version == 4 else "",
        },
    }


def subnet_split(cidr: str, new_prefix: int, limit: int = 128) -> dict:
    raw = (cidr or "").strip().replace(" ", "")
    try:
        net = ipaddress.ip_network(raw, strict=False)
    except ValueError as exc:
        raise ValueError(f"网段格式不对：{exc}") from exc

    new_prefix = int(new_prefix)
    if not (net.prefixlen < new_prefix <= net.max_prefixlen):
        raise ValueError(f"新掩码 /{new_prefix} 必须大于原掩码 /{net.prefixlen}")

    total = 2 ** (new_prefix - net.prefixlen)
    subs = []
    for idx, sub in enumerate(net.subnets(new_prefix=new_prefix)):
        if idx >= limit:
            break
        hosts = list(sub.hosts()) if sub.num_addresses > 2 else []
        subs.append(
            {
                "cidr": str(sub),
                "network": str(sub.network_address),
                "broadcast": str(sub.broadcast_address),
                "firstHost": str(hosts[0]) if hosts else None,
                "lastHost": str(hosts[-1]) if hosts else None,
                "hostCount": max(0, sub.num_addresses - 2),
            }
        )

    return {
        "ok": True,
        "parent": str(net),
        "newPrefix": new_prefix,
        "totalSubnets": total,
        "returned": len(subs),
        "truncated": total > len(subs),
        "subnets": subs,
    }


# ---------------------------------------------------------------------------
# 下载测速
# ---------------------------------------------------------------------------

SPEED_ENDPOINTS = [
    "https://speed.cloudflare.com/__down?bytes=25000000",
    "https://speed.cloudflare.com/__down?bytes=10000000",
]


def run_speed_test(url: str = "", duration: float = 6.0) -> dict:
    target = (url or "").strip()
    if not target:
        target = SPEED_ENDPOINTS[0]
    if not target.lower().startswith(("http://", "https://")):
        raise ValueError("测速地址必须是 http(s) URL")

    duration = max(2.0, min(30.0, float(duration)))
    request = urllib.request.Request(target, headers={"User-Agent": "Mozilla/5.0 eNSP-Console"})

    total = 0
    chunks = 0
    started = time.monotonic()
    first_byte_ms = None
    error = None

    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            while time.monotonic() - started < duration:
                chunk = response.read(65536)
                if not chunk:
                    break
                if first_byte_ms is None:
                    first_byte_ms = int((time.monotonic() - started) * 1000)
                total += len(chunk)
                chunks += 1
    except Exception as exc:
        error = str(exc)

    elapsed = time.monotonic() - started
    if total == 0 and error:
        return {"ok": False, "error": error, "url": target}

    mbps = (total * 8) / elapsed / 1_000_000 if elapsed > 0 else 0
    return {
        "ok": True,
        "url": target,
        "durationSec": round(elapsed, 2),
        "bytes": total,
        "chunks": chunks,
        "mbps": round(mbps, 2),
        "mbPerSec": round(total / elapsed / 1_000_000, 3) if elapsed > 0 else 0,
        "firstByteMs": first_byte_ms,
        "partial": error is not None,
        "error": error,
    }


# ---------------------------------------------------------------------------
# pcap 分析
# ---------------------------------------------------------------------------

PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
TCP_FLAGS = {0x01: "FIN", 0x02: "SYN", 0x04: "RST", 0x08: "PSH", 0x10: "ACK", 0x20: "URG"}


def _proto_name(num: int) -> str:
    return {1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 89: "OSPF", 112: "VRRP"}.get(num, f"IP({num})")


def analyze_pcap(data: bytes) -> dict:
    if len(data) < 24:
        raise ValueError("文件太小，不是有效的 pcap")
    if data[:4] == PCAPNG_MAGIC:
        raise ValueError("这是 pcapng 格式，请在 Wireshark 里另存为 pcap 后再上传")

    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    else:
        raise ValueError("不认识的 pcap magic，可能不是抓包文件")

    try:
        _magic, vmaj, vmin, _tz, _sig, snaplen, network = struct.unpack(endian + "IHHIIII", data[:24])
    except struct.error as exc:
        raise ValueError("pcap 头解析失败") from exc

    pos = 24
    packets = 0
    total_bytes = 0
    first_ts = None
    last_ts = None
    protocols: dict[str, int] = {}
    conversations: dict[str, dict] = {}
    sources: dict[str, int] = {}
    destinations: dict[str, int] = {}
    tcp_flags: dict[str, int] = {}
    max_packets = 200_000

    while pos + 16 <= len(data) and packets < max_packets:
        ts_sec, ts_usec, incl_len, _orig_len = struct.unpack(endian + "IIII", data[pos: pos + 16])
        pos += 16
        if incl_len > len(data) - pos:
            break
        pkt = data[pos: pos + incl_len]
        pos += incl_len
        packets += 1
        total_bytes += incl_len

        ts = ts_sec + ts_usec / 1_000_000
        if first_ts is None or ts < first_ts:
            first_ts = ts
        if last_ts is None or ts > last_ts:
            last_ts = ts

        if network != 1 or len(pkt) < 14:
            protocols["非以太网"] = protocols.get("非以太网", 0) + 1
            continue

        ethertype = struct.unpack("!H", pkt[12:14])[0]
        if ethertype == 0x0806:
            protocols["ARP"] = protocols.get("ARP", 0) + 1
            continue
        if ethertype == 0x86DD:
            protocols["IPv6"] = protocols.get("IPv6", 0) + 1
            continue
        if ethertype != 0x0800:
            protocols["其他二层"] = protocols.get("其他二层", 0) + 1
            continue

        ip = pkt[14:]
        if len(ip) < 20:
            continue
        ihl = (ip[0] & 0x0F) * 4
        proto = ip[9]
        src_ip = ".".join(str(b) for b in ip[12:16])
        dst_ip = ".".join(str(b) for b in ip[16:20])
        name = _proto_name(proto)
        protocols[name] = protocols.get(name, 0) + 1
        sources[src_ip] = sources.get(src_ip, 0) + 1
        destinations[dst_ip] = destinations.get(dst_ip, 0) + 1

        sport = dport = None
        if proto in (6, 17) and len(ip) >= ihl + 4:
            sport, dport = struct.unpack("!HH", ip[ihl: ihl + 4])
        if proto == 6 and len(ip) >= ihl + 14:
            flags = ip[ihl + 13]
            for bit, label in TCP_FLAGS.items():
                if flags & bit:
                    tcp_flags[label] = tcp_flags.get(label, 0) + 1

        if sport is not None:
            left, right = f"{src_ip}:{sport}", f"{dst_ip}:{dport}"
        else:
            left, right = src_ip, dst_ip
        key = " <-> ".join(sorted([left, right]))
        conv = conversations.setdefault(key, {"session": key, "packets": 0, "bytes": 0, "protocol": name})
        conv["packets"] += 1
        conv["bytes"] += incl_len

    top_conv = sorted(conversations.values(), key=lambda c: c["packets"], reverse=True)[:12]
    top_src = sorted(sources.items(), key=lambda kv: kv[1], reverse=True)[:8]
    top_dst = sorted(destinations.items(), key=lambda kv: kv[1], reverse=True)[:8]

    return {
        "ok": True,
        "linkType": network,
        "packetCount": packets,
        "byteCount": total_bytes,
        "truncated": packets >= max_packets,
        "durationSec": round((last_ts - first_ts), 3) if first_ts and last_ts else 0,
        "startTime": (
            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(first_ts)) if first_ts else None
        ),
        "endTime": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(last_ts)) if last_ts else None,
        "protocols": dict(sorted(protocols.items(), key=lambda kv: kv[1], reverse=True)),
        "topConversations": top_conv,
        "topSources": [{"ip": ip, "packets": n} for ip, n in top_src],
        "topDestinations": [{"ip": ip, "packets": n} for ip, n in top_dst],
        "tcpFlags": tcp_flags,
        "snaplen": snaplen,
        "version": f"{vmaj}.{vmin}",
    }
