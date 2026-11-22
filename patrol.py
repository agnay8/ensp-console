"""设备自动化巡检：SSH / Telnet 采集，并把 display 输出解析成结构化指标。

指标解析只依赖正则与行结构，不猜语义；解析不到就返回 None，原始输出始终保留。
"""

from __future__ import annotations

import asyncio
import re
import time
from datetime import datetime
from typing import Any, Callable

DEFAULT_COMMANDS = [
    "display version",
    "display cpu-usage",
    "display memory-usage",
    "display interface brief",
    "display transceiver diagnosis interface",
]

ERROR_HINTS = ("Error:", "Unrecognized command", "Wrong parameter", "Incomplete command", "Too many parameters")


# ---------------------------------------------------------------------------
# 解析工具
# ---------------------------------------------------------------------------

def _search(patterns: list[str], text: str) -> str | None:
    for pattern in patterns:
        m = re.search(pattern, text, re.I | re.M)
        if m:
            return m.group(1)
    return None


def _num(value: str | None) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def parse_cpu(output: str) -> float | None:
    raw = _search(
        [
            r"CPU Usage\s*:\s*(\d+(?:\.\d+)?)\s*%",
            r"cpu-usage\s*:\s*(\d+(?:\.\d+)?)\s*%",
            r"CPU utilization for five seconds:\s*(\d+(?:\.\d+)?)%",
        ],
        output,
    )
    return _num(raw)


def parse_memory(output: str) -> float | None:
    raw = _search(
        [
            r"Memory Using Percentage Is:\s*(\d+(?:\.\d+)?)%",
            r"Memory Usage\s*:\s*(\d+(?:\.\d+)?)\s*%",
            r"memory-usage\s*:\s*(\d+(?:\.\d+)?)\s*%",
            # 表格格式：System Total Memory(KB)  524288  262144  262144  50%
            r"System Total Memory[^\n]*?(\d+(?:\.\d+)?)\s*%",
        ],
        output,
    )
    return _num(raw)


def parse_temperature(output: str) -> float | None:
    raw = _search(
        [
            r"Temperature\s*:\s*(\d+(?:\.\d+)?)",
            r"Temperature\(Celsius\)\s*:\s*(\d+(?:\.\d+)?)",
            r"(\d+(?:\.\d+)?)\s*℃",
        ],
        output,
    )
    return _num(raw)


def _transceiver_table(output: str) -> tuple[float | None, float | None]:
    """表格式：表头 RX power / TX power 下列出数字。"""
    lines = [l.rstrip() for l in output.splitlines()]
    for idx, line in enumerate(lines):
        if not re.search(r"RX\s*power", line, re.I):
            continue
        header = line.lower()
        for follow in lines[idx + 1: idx + 4]:
            if not follow.strip():
                continue
            numbers = re.findall(r"-?\d+(?:\.\d+)?", follow)
            if len(numbers) < 3:
                continue
            columns = [c.strip() for c in re.split(r"\s{2,}", header.strip()) if c.strip()]
            rx_idx = tx_idx = None
            for pos, name in enumerate(columns):
                if "rx" in name:
                    rx_idx = pos
                elif "tx" in name:
                    tx_idx = pos
            if rx_idx is not None and rx_idx < len(numbers):
                rx = _num(numbers[rx_idx])
                tx = _num(numbers[tx_idx]) if tx_idx is not None and tx_idx < len(numbers) else None
                return rx, tx
            if len(numbers) >= 5:
                return _num(numbers[3]), _num(numbers[4])
            break
    return None, None


def parse_transceiver(output: str) -> tuple[float | None, float | None]:
    rx = _num(_search([r"RX\s*Power\s*(?:\(dBM\))?\s*:\s*(-?\d+(?:\.\d+)?)"], output))
    tx = _num(_search([r"TX\s*Power\s*(?:\(dBM\))?\s*:\s*(-?\d+(?:\.\d+)?)"], output))
    if rx is None or tx is None:
        table_rx, table_tx = _transceiver_table(output)
        rx = rx if rx is not None else table_rx
        tx = tx if tx is not None else table_tx
    return rx, tx


def parse_interfaces(output: str) -> tuple[int | None, int | None]:
    up = down = 0
    seen = False
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        if not re.match(r"^(GigabitEthernet|XGigabitEthernet|Ethernet|FastEthernet|Vlanif|LoopBack|GE\d)", parts[0], re.I):
            continue
        phy = parts[1].lower().lstrip("*")
        seen = True
        if phy == "up":
            up += 1
        elif phy in ("down", "off", "administratively"):
            down += 1
    return (up, down) if seen else (None, None)


def parse_version(output: str) -> dict:
    model = _search([r"VRP \(R\) software, Version [\d.]+ \(([^)]+)\)"], output)
    version = _search([r"VRP \(R\) software, Version ([\d.]+)"], output)
    uptime = _search([r"uptime is (.+)"], output)
    return {"model": model, "version": version, "uptime": uptime}


# ---------------------------------------------------------------------------
# 指标定义
# ---------------------------------------------------------------------------

def _level_high(value: float | None, warn: float, crit: float) -> str:
    if value is None:
        return "na"
    if value >= crit:
        return "crit"
    if value >= warn:
        return "warn"
    return "ok"


def _level_low(value: float | None, warn: float, crit: float) -> str:
    if value is None:
        return "na"
    if value <= crit:
        return "crit"
    if value <= warn:
        return "warn"
    return "ok"


def build_metrics(raw_results: list[dict]) -> list[dict]:
    """把原始命令回显转成指标列表。"""
    by_command = {r["command"]: r.get("output") or "" for r in raw_results}
    joined = "\n".join(by_command.values())

    cpu_output = by_command.get("display cpu-usage", "")
    mem_output = by_command.get("display memory-usage", "")
    if_output = by_command.get("display interface brief", "")
    trans_output = by_command.get("display transceiver diagnosis interface", "") or by_command.get(
        "display transceiver interface", ""
    )
    ver_output = by_command.get("display version", "")

    metrics: list[dict] = []

    cpu = parse_cpu(cpu_output)
    metrics.append(
        {
            "key": "cpu",
            "label": "CPU 使用率",
            "value": cpu,
            "unit": "%",
            "level": _level_high(cpu, 70, 90),
            "command": "display cpu-usage",
        }
    )

    mem = parse_memory(mem_output)
    metrics.append(
        {
            "key": "memory",
            "label": "内存使用率",
            "value": mem,
            "unit": "%",
            "level": _level_high(mem, 75, 90),
            "command": "display memory-usage",
        }
    )

    temp = parse_temperature(joined) if re.search(r"temperature", joined, re.I) else parse_temperature(ver_output)
    metrics.append(
        {
            "key": "temperature",
            "label": "温度",
            "value": temp,
            "unit": "℃",
            "level": _level_high(temp, 60, 75),
            "command": "display temperature",
        }
    )

    rx, tx = parse_transceiver(trans_output)
    metrics.append(
        {
            "key": "rx_power",
            "label": "光模块收光",
            "value": rx,
            "unit": "dBm",
            "level": _level_low(rx, -20, -25),
            "command": "display transceiver diagnosis interface",
        }
    )
    metrics.append(
        {
            "key": "tx_power",
            "label": "光模块发光",
            "value": tx,
            "unit": "dBm",
            "level": "ok" if tx is not None else "na",
            "command": "display transceiver diagnosis interface",
        }
    )

    up, down = parse_interfaces(if_output)
    metrics.append(
        {
            "key": "if_up",
            "label": "接口 UP",
            "value": up,
            "unit": "个",
            "level": "ok" if up else "na",
            "command": "display interface brief",
        }
    )
    metrics.append(
        {
            "key": "if_down",
            "label": "接口 DOWN",
            "value": down,
            "unit": "个",
            # 接入口有 down 属常态，只作信息展示，不参与告警统计
            "level": "na",
            "command": "display interface brief",
        }
    )

    info = parse_version(ver_output)
    for key, label in (("model", "设备型号"), ("version", "软件版本"), ("uptime", "运行时长")):
        metrics.append(
            {
                "key": key,
                "label": label,
                "value": info.get(key),
                "unit": "",
                "level": "na",
                "command": "display version",
                "text": True,
            }
        )

    return metrics


def _has_error(output: str) -> str | None:
    for hint in ERROR_HINTS:
        if hint.lower() in output.lower():
            line = next((l.strip() for l in output.splitlines() if hint.lower() in l.lower()), hint)
            return line[:160]
    return None


# ---------------------------------------------------------------------------
# 连接：Telnet（复用 eNSP console 实现）
# ---------------------------------------------------------------------------
# 连接：Telnet console
# ---------------------------------------------------------------------------

async def drain_console(console, idle: float = 0.25, limit: float = 1.0) -> int:
    """清掉设备多发出来的提示符。

    部分 VRP 版本（如 AR1220）每条命令会把提示符回显两次，第二个提示符若留在
    缓冲区里，下一条命令会立刻"读到提示符"而返回空，再下一条才拿到上一条的输出，
    整批命令就此错位一格。命令之间清一次缓冲即可对齐。
    """
    dropped = 0
    deadline = time.monotonic() + limit
    while time.monotonic() < deadline:
        try:
            data = await asyncio.wait_for(console.reader.read(4096), timeout=idle)
        except asyncio.TimeoutError:
            break
        if not data:
            break
        dropped += len(data)
    return dropped


async def open_console(host: str, port: int, username: str = "", password: str = "", timeout: float = 8.0):
    from ensp_mcp.console import Console

    console = Console(host=host, port=int(port))
    credentials = (username, password) if username else None
    await console.open(timeout=timeout, credentials=credentials)
    await drain_console(console)
    try:
        await console.disable_paging()
    except Exception:
        pass
    await drain_console(console)
    return console


async def console_send(console, command: str, timeout: float | None = None) -> str:
    output = await console.send(command, timeout=timeout) if timeout else await console.send(command)
    await drain_console(console)
    return output


async def inspect_telnet(
    device: dict, commands: list[str], username: str, password: str, timeout: float
) -> dict:
    started = time.monotonic()
    console = None
    result = {
        "device": device["name"],
        "host": device["host"],
        "port": device["port"],
        "protocol": "telnet",
        "ok": False,
        "error": None,
        "raw": [],
    }
    try:
        console = await open_console(
            device["host"], device["port"], username, password, timeout=timeout
        )
        raw = []
        for command in commands:
            text = command.strip()
            if not text or text.startswith("#"):
                continue
            try:
                output = await console_send(console, text)
                raw.append({"command": text, "output": output, "error": _has_error(output)})
            except Exception as exc:
                partial = getattr(exc, "partial_output", "") or ""
                raw.append({"command": text, "output": partial, "error": str(exc)})
                break
        result["raw"] = raw
        result["ok"] = any(r.get("output") for r in raw)
        if not result["ok"]:
            result["error"] = "命令没有返回任何输出"
    except Exception as exc:
        result["error"] = str(exc)
    finally:
        if console is not None:
            try:
                await console.close()
            except Exception:
                pass
        result["elapsedMs"] = max(1, int((time.monotonic() - started) * 1000))
    return result


# ---------------------------------------------------------------------------
# 连接：SSH（paramiko）
# ---------------------------------------------------------------------------

def _ssh_read(channel, idle: float = 0.8, cap: float = 20.0) -> str:
    chunks: list[str] = []
    start = time.monotonic()
    last = time.monotonic()
    while time.monotonic() - start < cap:
        if channel.recv_ready():
            data = channel.recv(65535)
            chunks.append(data.decode("utf-8", "replace"))
            last = time.monotonic()
        else:
            if time.monotonic() - last > idle:
                break
            time.sleep(0.1)
    return "".join(chunks)


def inspect_ssh(
    device: dict, commands: list[str], username: str, password: str, timeout: float
) -> dict:
    import paramiko

    started = time.monotonic()
    result = {
        "device": device["name"],
        "host": device["host"],
        "port": device["port"],
        "protocol": "ssh",
        "ok": False,
        "error": None,
        "raw": [],
    }
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=device["host"],
            port=int(device["port"]),
            username=username or "admin",
            password=password or "",
            timeout=timeout,
            banner_timeout=timeout,
            auth_timeout=timeout,
            look_for_keys=False,
            allow_agent=False,
        )
        channel = client.invoke_shell(term="vt100", width=200, height=1000)
        time.sleep(0.8)
        _ssh_read(channel, idle=0.6, cap=5)
        channel.send("screen-length 0 temporary\n")
        time.sleep(0.4)
        _ssh_read(channel, idle=0.4, cap=3)

        raw = []
        for command in commands:
            text = command.strip()
            if not text or text.startswith("#"):
                continue
            channel.send(text + "\n")
            output = _ssh_read(channel, idle=0.9, cap=timeout)
            raw.append(
                {
                    "command": text,
                    "output": output,
                    "view": "unknown",
                    "error": _has_error(output),
                }
            )
        result["raw"] = raw
        result["ok"] = any(r.get("output") for r in raw)
        if not result["ok"]:
            result["error"] = "命令没有返回任何输出"
        channel.close()
    except Exception as exc:
        result["error"] = str(exc)
    finally:
        try:
            client.close()
        except Exception:
            pass
        result["elapsedMs"] = max(1, int((time.monotonic() - started) * 1000))
    return result


# ---------------------------------------------------------------------------
# 调度
# ---------------------------------------------------------------------------

async def run_inspection(payload: dict) -> dict:
    devices = payload.get("devices") or []
    if not devices:
        raise ValueError("没有要巡检的设备")

    commands = [c.strip() for c in (payload.get("commands") or DEFAULT_COMMANDS) if c and c.strip()]
    if not commands:
        raise ValueError("巡检命令不能为空")

    username = payload.get("username") or ""
    password = payload.get("password") or ""
    timeout = float(payload.get("timeout") or 20)
    concurrency = max(1, min(16, int(payload.get("concurrency") or 4)))

    semaphore = asyncio.Semaphore(concurrency)

    async def one(device: dict):
        async with semaphore:
            proto = (device.get("protocol") or "telnet").lower()
            try:
                if proto == "ssh":
                    return await asyncio.wait_for(
                        asyncio.to_thread(
                            inspect_ssh,
                            device,
                            commands,
                            device.get("username") or username,
                            device.get("password") or password,
                            timeout,
                        ),
                        timeout=timeout * (len(commands) + 2),
                    )
                return await asyncio.wait_for(
                    inspect_telnet(
                        device,
                        commands,
                        device.get("username") or username,
                        device.get("password") or password,
                        timeout,
                    ),
                    timeout=timeout * (len(commands) + 2),
                )
            except asyncio.TimeoutError:
                return {
                    "device": device.get("name"),
                    "host": device.get("host"),
                    "port": device.get("port"),
                    "protocol": proto,
                    "ok": False,
                    "error": "巡检超时",
                    "raw": [],
                    "elapsedMs": int(timeout * (len(commands) + 2) * 1000),
                }

    raw_results = await asyncio.gather(*(one(d) for d in devices))

    for item in raw_results:
        item["metrics"] = build_metrics(item.get("raw") or [])
        levels = [m["level"] for m in item["metrics"]]
        item["warnCount"] = levels.count("warn")
        item["critCount"] = levels.count("crit")

    ok = sum(1 for r in raw_results if r["ok"])
    finished = datetime.now().astimezone()

    return {
        "ok": True,
        "finishedAt": finished.isoformat(timespec="seconds"),
        "devices": raw_results,
        "summary": {
            "total": len(raw_results),
            "succeeded": ok,
            "failed": len(raw_results) - ok,
            "warnCount": sum(r["warnCount"] for r in raw_results),
            "critCount": sum(r["critCount"] for r in raw_results),
        },
        "commands": commands,
    }


# ---------------------------------------------------------------------------
# 导出
# ---------------------------------------------------------------------------

SUMMARY_COLUMNS = [
    ("device", "设备"),
    ("address", "地址"),
    ("protocol", "协议"),
    ("status", "状态"),
    ("cpu", "CPU(%)"),
    ("memory", "内存(%)"),
    ("temperature", "温度(℃)"),
    ("rx_power", "收光(dBm)"),
    ("tx_power", "发光(dBm)"),
    ("if_up", "接口UP"),
    ("if_down", "接口DOWN"),
    ("model", "型号"),
    ("uptime", "运行时长"),
    ("elapsedMs", "耗时(ms)"),
    ("error", "错误"),
]


def _fmt(value: Any) -> Any:
    """整数值的浮点去掉 .0，导出到 CSV 时更干净。"""
    if value is None:
        return ""
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return value


def to_summary_rows(result: dict) -> list[list[Any]]:
    rows = []
    for item in result.get("devices") or []:
        metric_map = {m["key"]: m for m in item.get("metrics") or []}
        row = []
        for key, _label in SUMMARY_COLUMNS:
            if key == "address":
                row.append(f"{item.get('host')}:{item.get('port')}")
            elif key == "status":
                row.append("成功" if item.get("ok") else "失败")
            elif key == "error":
                row.append(item.get("error") or "")
            elif key == "elapsedMs":
                row.append(item.get("elapsedMs") or "")
            elif key == "protocol":
                row.append(item.get("protocol") or "")
            elif key == "device":
                row.append(item.get("device") or "")
            else:
                metric = metric_map.get(key)
                row.append(_fmt(metric.get("value") if metric else None))
        rows.append(row)
    return rows


def to_detail_rows(result: dict) -> list[list[Any]]:
    rows = []
    for item in result.get("devices") or []:
        for metric in item.get("metrics") or []:
            rows.append(
                [
                    item.get("device") or "",
                    f"{item.get('host')}:{item.get('port')}",
                    metric.get("label") or "",
                    _fmt(metric.get("value")),
                    metric.get("unit") or "",
                    {"ok": "正常", "warn": "警告", "crit": "异常", "na": "—"}.get(metric.get("level"), ""),
                ]
            )
    return rows
