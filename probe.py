"""设备在线探测。

第一性原理
----------
"设备在线"的本质，是它的虚拟硬件此刻存在于 eNSP 的运行时里。
不同设备类别，同一个事实的**投影**不同：

* AR 路由器 / 交换机：eNSP 会为运行中的设备启动 console 服务
  （0.0.0.0:2000x，由 eNSP_Client 进程监听）。端口能连上，即设备在跑。
* PC / 终端（SimPC）：拓扑里 com_port 恒为 0，既没有 console 服务，也没有
  独立进程；宿主的 TCP / ICMP 都到不了它（eNSP 虚拟网络与宿主隔离，实测
  100% 丢包）。它唯一可从外部观测的特征，是插在链路上的虚拟网卡——这反映为
  **上游设备对应端口的 PHY 状态**：端口 up = 网卡存在 = PC 已启动；
  端口 down = PC 未启动。

所以判定不能只看端口，而要按设备类别选择投影：
    有 console  -> 直连探活（端口即证据）
    无 console  -> 借上游设备的端口状态反推（链路即证据）

混用两者，就会把没有 console 的 PC 误判成离线——这属于"指标不适用"，
而不是"设备离线"。
"""

from __future__ import annotations

import asyncio
import re
from typing import Any

# 端口名缩写归一：GigabitEthernet0/0/20 / GE0/0/20 / ge0/0/20 -> ge0/0/20
PORT_PREFIX = (
    ("xgigabitethernet", "xge"),
    ("gigabitethernet", "ge"),
    ("fastethernet", "fe"),
    ("ethernet", "eth"),
)


def normalize_port(name: str) -> str:
    s = (name or "").strip().lower().replace(" ", "")
    for full, short in PORT_PREFIX:
        if s.startswith(full):
            return short + s[len(full):]
    return s


def parse_interface_brief(output: str) -> dict[str, str]:
    """从 display interface brief 提取 {端口: up|down}，按 PHY 列判定。"""
    states: dict[str, str] = {}
    for raw in (output or "").splitlines():
        line = raw.strip()
        if not line or line.lower().startswith("interface"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        port, phy = parts[0], parts[1].lower()
        if not re.search(r"\d", port):
            continue
        phy = phy.replace("*", "")
        if phy.startswith("up"):
            states[normalize_port(port)] = "up"
        elif phy.startswith("down"):
            states[normalize_port(port)] = "down"
    return states


async def _tcp_alive(host: str, port: int, timeout: float) -> bool:
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
    except Exception:
        return False
    try:
        writer.close()
        await writer.wait_closed()
    except Exception:
        pass
    return True


async def _query_parent(parent: dict, timeout: float) -> tuple[dict[str, str], str | None]:
    """登录上游设备，读一次 display interface brief。"""
    from patrol import inspect_telnet

    target = {
        "name": parent.get("name"),
        "host": parent.get("host") or "127.0.0.1",
        "port": int(parent["consolePort"]),
    }
    result = await inspect_telnet(target, ["display interface brief"], "", "", timeout)
    text = ""
    for item in result.get("raw") or []:
        if item.get("output"):
            text += item["output"] + "\n"
    return parse_interface_brief(text), result.get("error")


def _family(model: str | None) -> str:
    """AR2220 -> AR22，S5700 V200R001C00 -> S57。"""
    s = (model or "").strip().upper()
    m = re.match(r"([A-Z]+\d{2})", s)
    return m.group(1) if m else s


async def _detect_model(host: str, port: int, timeout: float) -> str | None:
    """读 display version 里的实际型号，用来核对端口背后是不是拓扑里那台设备。"""
    from patrol import console_send, open_console

    console = await open_console(host, port, timeout=timeout)
    try:
        output = await console_send(console, "display version", timeout=timeout)
    finally:
        try:
            await console.close()
        except Exception:
            pass
    match = re.search(r"\(([A-Z]+\d+)[^)]*\)", output or "")
    return match.group(1) if match else None


def _mac_fmt(mac: str | None) -> str:
    if not mac:
        return ""
    parts = [mac[i:i + 4] for i in range(0, len(mac), 4)]
    return "-".join(parts).upper()


def normalize_mac(value: str | None) -> str:
    """00-E0-FC-25-8E-2D 与 00e0-fc25-8e2d 统一成同一形态。"""
    return re.sub(r"[^0-9A-Fa-f]", "", value or "").upper()


MAC_RE = re.compile(r"([0-9A-Fa-f]{4}[-:][0-9A-Fa-f]{4}[-:][0-9A-Fa-f]{4})")


async def _detect_mac(host: str, port: int, timeout: float) -> str | None:
    """读 display bridge mac-address 拿设备系统 MAC——端口的真身份。"""
    from patrol import console_send, open_console

    console = await open_console(host, port, timeout=timeout)
    try:
        output = await console_send(console, "display bridge mac-address", timeout)
    finally:
        try:
            await console.close()
        except Exception:
            pass
    match = MAC_RE.search(output or "")
    return normalize_mac(match.group(1)) if match else None


async def probe_devices(
    devices: list[dict],
    links: list[dict] | None = None,
    timeout: float = 8.0,
    concurrency: int = 8,
) -> dict[str, Any]:
    devices = [d for d in (devices or []) if d.get("name")]
    links = links or []
    by_name = {d["name"]: d for d in devices}
    sem = asyncio.Semaphore(max(1, int(concurrency)))
    results: dict[str, dict] = {}

    # ---- 1. 有 console 的设备：直连探活 + 身份核对 -------------------------
    # 端口号是 eNSP 的全局资源，端口能连只说明"某台设备"在监听，不能说明
    # 是拓扑里那台。真正的身份特征是拓扑里的 system_mac 与设备实报的系统 MAC：
    # 一致才算在线；不一致说明端口被另一个拓扑的设备占用，判"不是本设备"。
    async def check_console(dev: dict) -> None:
        port = int(dev["consolePort"])
        host = dev.get("host") or "127.0.0.1"
        async with sem:
            alive = await _tcp_alive(host, port, min(timeout, 3.0))

        expected_mac = normalize_mac(dev.get("systemMac"))
        topo_model = dev.get("model") or ""
        detected_mac = None
        detected_model = None
        identity = None

        if alive:
            if expected_mac:
                try:
                    detected_mac = await _detect_mac(host, port, timeout)
                except Exception:
                    detected_mac = None
                if detected_mac:
                    identity = detected_mac == expected_mac
            if identity is None and topo_model:
                try:
                    detected_model = await _detect_model(host, port, timeout)
                except Exception:
                    detected_model = None
                if detected_model:
                    identity = _family(detected_model) == _family(topo_model)

        online = alive and identity is not False
        mismatch = alive and identity is False

        detail = f"console {host}:{port} {'可连接' if alive else '无响应'}"
        if identity is True and detected_mac:
            detail += f"；系统 MAC {_mac_fmt(detected_mac)} 与拓扑一致"
        elif identity is True:
            detail += f"；型号 {detected_model} 与拓扑一致"
        elif mismatch and detected_mac:
            detail += (
                f"；端口上是另一台设备（MAC {_mac_fmt(detected_mac)}），"
                f"本拓扑要求 {_mac_fmt(expected_mac)}，判为不是本设备"
            )
        elif mismatch and detected_model:
            detail += f"；端口实际是 {detected_model}，与拓扑 {topo_model} 不符"
        elif alive and identity is None:
            detail += "；设备未返回系统 MAC，身份未验证"

        results[dev["name"]] = {
            "name": dev["name"],
            "consolePort": port,
            "host": host,
            "online": online,
            "method": "console",
            "detail": detail,
            "detectedMac": detected_mac,
            "expectedMac": expected_mac,
            "detectedModel": detected_model,
            "topologyModel": topo_model,
            "identity": identity,
            "identityMismatch": mismatch,
            "modelMatched": (None if identity is None else identity) if topo_model else None,
            "identityWarning": mismatch,
        }

    await asyncio.gather(*(check_console(d) for d in devices if d.get("consolePort")))

    # ---- 2. 无 console 的设备：找直连上游（必须有 console 才可查） ----------
    # Cloud / Hub 这类设备本身没有 console，也不承载业务，直接标为不适用
    skip_models = {"CLOUD", "HUB", "MCS"}
    for dev in devices:
        if dev.get("consolePort"):
            continue
        if str(dev.get("model") or "").upper() in skip_models:
            results[dev["name"]] = {
                "name": dev["name"],
                "consolePort": None,
                "host": None,
                "online": None,
                "method": "none",
                "detail": f"{dev.get('model')} 属于非受管设备，无 console，不参与探活",
                "applicable": False,
            }

    peers_of: dict[str, list[tuple[str, str]]] = {}
    for link in links:
        a, b = link.get("from"), link.get("to")
        if a in by_name and not by_name[a].get("consolePort") and a not in results:
            peers_of.setdefault(a, []).append((b, link.get("toPort") or ""))
        if b in by_name and not by_name[b].get("consolePort") and b not in results:
            peers_of.setdefault(b, []).append((a, link.get("fromPort") or ""))

    grouped: dict[str, list[tuple[str, str]]] = {}
    unresolved: dict[str, str] = {}
    for child, peers in peers_of.items():
        usable = [
            (p, port)
            for p, port in peers
            if p in by_name and by_name[p].get("consolePort")
        ]
        if not usable:
            unresolved[child] = "直连的对端也没有 console，无法推断"
            continue
        for parent, port in usable:
            grouped.setdefault(parent, []).append((child, port))

    # ---- 3. 上游在线才去查端口；远端未开机则链路必不通 ----------------------
    candidates: dict[str, list[tuple[bool | None, str]]] = {}
    queryable = [p for p in grouped if (results.get(p) or {}).get("online")]
    parsed = await asyncio.gather(*(_query_parent(by_name[p], timeout) for p in queryable))
    states_by_parent = dict(zip(queryable, parsed))

    for parent, pairs in grouped.items():
        info = results.get(parent) or {}
        if info.get("identityMismatch"):
            # 上游端口被别的拓扑设备占用，它的接口状态不能代表本拓扑链路
            for child, port in pairs:
                candidates.setdefault(child, []).append(
                    (None, f"上游 {parent} 的 console 端口被其他拓扑的设备占用，链路状态不可信")
                )
            continue
        if not info.get("online"):
            for child, port in pairs:
                candidates.setdefault(child, []).append(
                    (False, f"上游 {parent} 未开机，链路不可能导通")
                )
            continue
        states, err = states_by_parent.get(parent, ({}, None))
        for child, port in pairs:
            state = states.get(normalize_port(port))
            if state is None:
                detail = f"{parent} 上未读到端口 {port}"
                if err:
                    detail += f"（{err}）"
                candidates.setdefault(child, []).append((None, detail))
            else:
                candidates.setdefault(child, []).append(
                    (state == "up", f"{parent} {port} = {state}")
                )

    for child, items in candidates.items():
        if any(flag is True for flag, _ in items):
            online, detail = True, next(d for f, d in items if f is True)
        elif any(flag is None for flag, _ in items):
            online, detail = None, next(d for f, d in items if f is None)
        else:
            online, detail = False, items[0][1]
        results[child] = {
            "name": child,
            "consolePort": None,
            "host": None,
            "online": online,
            "method": "link",
            "detail": detail,
        }

    for child, reason in unresolved.items():
        results[child] = {
            "name": child,
            "consolePort": None,
            "host": None,
            "online": None,
            "method": "none",
            "detail": reason,
        }

    ordered = []
    for dev in devices:
        ordered.append(
            results.get(dev["name"])
            or {
                "name": dev["name"],
                "consolePort": dev.get("consolePort"),
                "host": None,
                "online": None,
                "method": "none",
                "detail": "无法判定",
            }
        )

    return {
        "devices": ordered,
        "total": len(ordered),
        "onlineCount": sum(1 for r in ordered if r["online"] is True),
        "offlineCount": sum(1 for r in ordered if r["online"] is False),
        "unknownCount": sum(1 for r in ordered if r["online"] is None),
    }
