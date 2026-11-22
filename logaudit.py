"""日志审计：采集设备日志、过滤导出、对导出文件做审计并出报告。

支持两种入口：
1. 在线采集：通过 console/SSH 执行 display logbuffer / display trapbuffer
2. 离线审计：把导出的 CSV / TXT 再传回来，重新解析后审计

解析只认结构（时间戳 + 模块/级别），不猜语义；级别、模块、时间拿不到就留空，
原始行始终保留，导出的文件里可以逐条追溯。
"""

from __future__ import annotations

import csv
import io
import re
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any

SEVERITY_TEXT = {
    0: "紧急",
    1: "告警",
    2: "严重",
    3: "错误",
    4: "警告",
    5: "通知",
    6: "信息",
    7: "调试",
}

SEVERITY_ORDER = {"紧急": 0, "告警": 1, "严重": 2, "错误": 3, "警告": 4, "通知": 5, "信息": 6, "调试": 7}

# Nov 22 2026 01:16:20-08:00 %%01IFNET/4/LINK_STATE(l)[3]:...
# 有的版本在时间与 %% 之间还带主机名：Nov 22 2026 01:16:20 R1 %%01DEV/4/ENTUP(l)[2]:...
LOG_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{4}\s+\d{2}:\d{2}:\d{2}(?:[+-]\d{2}:\d{2})?)\s+"
    r"(?:(?P<host>[^\s%]+)\s+)?"
    r"%%(?P<seq>\d{2})(?P<module>[A-Za-z0-9_]+)/(?P<sev>[0-7])/(?P<brief>[^\s:(]+)"
)

PART_RE = re.compile(
    r"%%(?P<seq>\d{2})(?P<module>[A-Za-z0-9_]+)/(?P<sev>[0-7])/(?P<brief>[^\s:(]+)"
)

# Nov 22 01:16:20 2026 ... 或无年份的 syslog
ALT_TS_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+(?:\d{4}\s+)?\d{2}:\d{2}:\d{2}(?:[+-]\d{2}:\d{2})?)"
)

SECURITY_PATTERNS = [
    (r"(?i)(failed|failure|invalid).{0,20}(login|password|authentication)|login failed|authentication fail", "登录失败"),
    (r"(?i)brute|attack|intrusion|flood", "攻击/洪水告警"),
    (r"(?i)aaa.{0,20}(fail|reject)", "AAA 认证拒绝"),
]

CONFIG_PATTERN = r"(?i)configuration|config change|Recorded command information|CFG/|CFGM/"
NEIGHBOR_PATTERN = r"(?i)(ospf|bgp|isis|vrrp).{0,40}(down|fail|change)"
ENV_PATTERN = r"(?i)(temperature|temp|fan|power|voltage|optical).{0,30}(alarm|fail|abnormal|high|low)"
BOOT_PATTERN = r"(?i)(boot|startup|reboot|restart).{0,30}(success|failed|complete)"


def _sev_text(num: int) -> str:
    return SEVERITY_TEXT.get(num, "信息")


def _parse_ts(raw: str) -> tuple[float | None, str]:
    """把日志时间转成时间戳；拿不到年份时按今年补。"""
    text = (raw or "").strip()
    formats = [
        "%b %d %Y %H:%M:%S%z",
        "%b %d %Y %H:%M:%S",
        "%b %d %H:%M:%S%z",
        "%b %d %H:%M:%S",
    ]
    for fmt in formats:
        try:
            dt = datetime.strptime(text.replace("  ", " "), fmt)
            if "%Y" not in fmt:
                dt = dt.replace(year=datetime.now().year)
            return dt.timestamp(), dt.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            continue
    return None, text


def parse_log_text(text: str, device: str = "") -> list[dict]:
    entries: list[dict] = []
    for raw in (text or "").splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        if line.strip().startswith("---- More ----"):
            continue
        match = LOG_RE.match(line.strip())
        if match:
            ts_raw = match.group("ts")
            ts, ts_text = _parse_ts(ts_raw)
            sev_num = int(match.group("sev"))
            # 从头部匹配结束处开始取消息，避免被时间里的冒号截断
            message = line.strip()[match.end():].lstrip(": ").strip()
            message = re.sub(r"^\([^)]{0,12}\)\[\d+\]:?\s*", "", message)
            entries.append(
                {
                    "device": device,
                    "ts": ts,
                    "time": ts_text,
                    "severity": _sev_text(sev_num),
                    "severityNum": sev_num,
                    "module": match.group("module"),
                    "brief": match.group("brief"),
                    "message": message[:600],
                    "raw": line.strip(),
                }
            )
            continue
        alt = ALT_TS_RE.match(line.strip())
        if alt:
            ts, ts_text = _parse_ts(alt.group("ts"))
            rest = line.strip()[alt.end():].strip(" :-")
            part = PART_RE.search(rest)
            if part:
                sev_num = int(part.group("sev"))
                module = part.group("module")
                brief = part.group("brief")
                message = rest[part.end():].lstrip(": ").strip()
            else:
                sev_num = 6
                module = ""
                brief = ""
                message = rest
            message = re.sub(r"^\([^)]{0,12}\)\[\d+\]:?\s*", "", message)
            entries.append(
                {
                    "device": device,
                    "ts": ts,
                    "time": ts_text,
                    "severity": _sev_text(sev_num),
                    "severityNum": sev_num,
                    "module": module,
                    "brief": brief,
                    "message": message[:600],
                    "raw": line.strip(),
                }
            )
            continue
        # 续行：并入上一条，避免多行日志被拆散
        if entries and line.startswith((" ", "\t")):
            entries[-1]["message"] = (entries[-1]["message"] + " " + line.strip())[:800]
            entries[-1]["raw"] = (entries[-1]["raw"] + " " + line.strip())[:900]
    return entries


async def collect(devices: list[dict], timeout: float = 20, concurrency: int = 4) -> dict:
    """并发登录设备抓日志。"""
    import asyncio

    from patrol import inspect_telnet

    sem = asyncio.Semaphore(max(1, int(concurrency)))
    out = {"entries": [], "devices": []}

    async def one(dev: dict) -> None:
        async with sem:
            result = await inspect_telnet(
                {
                    "name": dev.get("name"),
                    "host": dev.get("host") or "127.0.0.1",
                    "port": int(dev["port"]),
                },
                ["display logbuffer", "display trapbuffer"],
                dev.get("username") or "",
                dev.get("password") or "",
                timeout,
            )
        count = 0
        for item in result.get("raw") or []:
            if item.get("output"):
                parsed = parse_log_text(item["output"], dev.get("name") or "")
                out["entries"].extend(parsed)
                count += len(parsed)
        out["devices"].append(
            {
                "device": dev.get("name"),
                "ok": bool(result.get("ok")),
                "count": count,
                "error": result.get("error"),
            }
        )

    await asyncio.gather(*(one(d) for d in devices if d.get("port")))
    out["entries"].sort(key=lambda e: (e.get("ts") or 0))
    return out


def filter_entries(
    entries: list[dict],
    device: str = "",
    severity: str = "",
    keyword: str = "",
    limit: int = 5000,
) -> list[dict]:
    result = []
    for e in entries:
        if device and e.get("device") != device:
            continue
        if severity:
            if severity == "error":
                if (e.get("severityNum") or 9) > 3:
                    continue
            elif severity == "warn":
                if (e.get("severityNum") or 9) > 4:
                    continue
            elif e.get("severity") != severity:
                continue
        if keyword:
            hay = (e.get("message") or "") + (e.get("module") or "") + (e.get("device") or "")
            if keyword.lower() not in hay.lower():
                continue
        result.append(e)
        if len(result) >= limit:
            break
    return result


def summarise(entries: list[dict]) -> dict:
    by_sev = Counter(e.get("severity") or "信息" for e in entries)
    by_device = Counter(e.get("device") or "未知" for e in entries)
    by_module = Counter(e.get("module") or "其它" for e in entries)
    times = [e["ts"] for e in entries if e.get("ts")]
    return {
        "total": len(entries),
        "bySeverity": dict(by_sev),
        "byDevice": dict(by_device),
        "byModule": dict(by_module.most_common(10)),
        "start": min(times) if times else None,
        "end": max(times) if times else None,
        "errorRate": round(
            sum(v for k, v in by_sev.items() if SEVERITY_ORDER.get(k, 9) <= 3) / len(entries) * 100, 1
        )
        if entries
        else 0.0,
    }


def _template(message: str) -> str:
    """把变长部分抹掉，得到可聚合的日志模板。"""
    text = message or ""
    if "%%" in text:
        text = text.split("%%", 1)[1]
    text = re.sub(r"^0*\d+", "", text)  # 去掉序号前缀
    text = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "<IP>", text)
    text = re.sub(r"\b[0-9a-fA-F]{4,}\b", "<HEX>", text)
    text = re.sub(r"\b\d+\b", "<N>", text)
    text = re.sub(r"\s+", " ", text).strip(" :")
    return text[:120]


def audit(entries: list[dict], meta: dict | None = None) -> dict:
    meta = meta or {}
    findings: list[dict] = []
    summary = summarise(entries)

    def add(severity: str, category: str, title: str, detail: str, evidence: list[str], suggestion: str):
        findings.append(
            {
                "severity": severity,
                "category": category,
                "title": title,
                "detail": detail,
                "evidence": evidence[:6],
                "suggestion": suggestion,
            }
        )

    # 1. 严重/错误日志
    critical = [e for e in entries if (e.get("severityNum") or 9) <= 3]
    if critical:
        devices = Counter(e.get("device") for e in critical)
        add(
            "P1" if len(critical) >= 5 else "P2",
            "日志级别",
            f"存在 {len(critical)} 条严重及以上日志",
            "、".join(f"{k} {v} 条" for k, v in devices.most_common(5)),
            [f"{e.get('time')} [{e.get('device')}] {e.get('message')[:90]}" for e in critical[-5:]],
            "按时间线定位首次出现点，先处理根因设备，再清理衍生告警",
        )

    # 2. 登录失败 / 认证异常（同一条日志只归入第一条命中的规则）
    security_seen: set[int] = set()
    for pattern, label in SECURITY_PATTERNS:
        hits = []
        for idx, e in enumerate(entries):
            if idx in security_seen:
                continue
            if re.search(pattern, e.get("message") or ""):
                hits.append(e)
                security_seen.add(idx)
        if not hits:
            continue
        devices = Counter(e.get("device") for e in hits)
        add(
            "P1" if len(hits) >= 3 else "P2",
            "安全",
            f"{label} {len(hits)} 次",
            "、".join(f"{k} {v} 次" for k, v in devices.most_common(5)),
            [f"{e.get('time')} [{e.get('device')}] {e.get('message')[:90]}" for e in hits[-5:]],
            "核对源地址与账号；连续失败需封禁源 IP 并检查弱口令",
        )

    # 3. 配置变更
    changes = [e for e in entries if re.search(CONFIG_PATTERN, (e.get("message") or "") + (e.get("module") or ""))]
    if changes:
        devices = Counter(e.get("device") for e in changes)
        add(
            "P3",
            "变更",
            f"检测到 {len(changes)} 条配置/命令变更记录",
            "、".join(f"{k} {v} 条" for k, v in devices.most_common(5)),
            [f"{e.get('time')} [{e.get('device')}] {e.get('message')[:90]}" for e in changes[-5:]],
            "核对变更窗口与审批记录；异常时段变更优先回滚验证",
        )

    # 4. 接口震荡
    flaps: dict[tuple[str, str], int] = defaultdict(int)
    for e in entries:
        if "LINK_STATE" in (e.get("module") or "") or "line protocol" in (e.get("message") or "").lower():
            port = re.search(r"interface\s+(\S+)", e.get("message") or "", re.I)
            key = (e.get("device") or "", port.group(1) if port else "未知接口")
            flaps[key] += 1
    bad = {k: v for k, v in flaps.items() if v >= 4}
    if bad:
        add(
            "P2",
            "链路",
            f"{len(bad)} 个接口出现反复 up/down",
            "、".join(f"{d} {p} {v} 次" for (d, p), v in list(bad.items())[:5]),
            [
                f"{d} {p} 状态变化 {v} 次"
                for (d, p), v in list(bad.items())[:5]
            ],
            "检查光模块/尾纤、端口协商与对端设备；必要时更换模块",
        )

    # 5. 协议邻居
    neighbors = [e for e in entries if re.search(NEIGHBOR_PATTERN, e.get("message") or "")]
    if neighbors:
        add(
            "P2" if len(neighbors) >= 3 else "P3",
            "协议",
            f"协议邻居状态变化 {len(neighbors)} 次",
            "、".join(f"{k} {v} 次" for k, v in Counter(e.get("device") for e in neighbors).most_common(5)),
            [f"{e.get('time')} [{e.get('device')}] {e.get('message')[:90]}" for e in neighbors[-5:]],
            "核对邻居配置、链路质量与认证参数；震荡频繁时抓包确认",
        )

    # 6. 环境/硬件
    env = [e for e in entries if re.search(ENV_PATTERN, e.get("message") or "")]
    if env:
        add(
            "P1" if any((e.get("severityNum") or 9) <= 3 for e in env) else "P2",
            "硬件",
            f"环境/硬件告警 {len(env)} 条",
            "、".join(f"{k} {v} 条" for k, v in Counter(e.get("device") for e in env).most_common(5)),
            [f"{e.get('time')} [{e.get('device')}] {e.get('message')[:90]}" for e in env[-5:]],
            "检查风扇、电源、温度与光模块；硬件类告警不要只清日志",
        )

    # 7. 启动记录
    boots = [e for e in entries if re.search(BOOT_PATTERN, e.get("message") or "")]
    if boots:
        add(
            "P3",
            "可用性",
            f"发现 {len(boots)} 条设备启动/重启记录",
            "、".join(f"{k} {v} 条" for k, v in Counter(e.get("device") for e in boots).most_common(5)),
            [f"{e.get('time')} [{e.get('device')}] {e.get('message')[:90]}" for e in boots[-5:]],
            "确认是否为计划内重启；非计划重启需查电源、看门狗与崩溃记录",
        )

    # 8. 错误占比
    if entries and summary["errorRate"] >= 10:
        add(
            "P2",
            "日志质量",
            f"错误及以上日志占比 {summary['errorRate']}%",
            f"共 {summary['total']} 条日志，其中严重/错误 {sum(v for k, v in summary['bySeverity'].items() if SEVERITY_ORDER.get(k, 9) <= 3)} 条",
            [],
            "错误占比过高通常意味着持续故障，而不是偶发抖动",
        )

    findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 9))

    templates = Counter(_template(e.get("message") or "") for e in entries)
    timeline = _timeline(entries)

    return {
        "ok": True,
        "generatedAt": datetime.now().isoformat(timespec="seconds"),
        "meta": {
            "source": meta.get("source") or "在线采集",
            "devices": meta.get("devices") or sorted({e.get("device") for e in entries if e.get("device")}),
            "fileName": meta.get("fileName") or "",
        },
        "summary": summary,
        "findings": findings,
        "topTemplates": [{"text": t, "count": c} for t, c in templates.most_common(10) if t],
        "timeline": timeline,
        "counts": {
            "p1": sum(1 for f in findings if f["severity"] == "P1"),
            "p2": sum(1 for f in findings if f["severity"] == "P2"),
            "p3": sum(1 for f in findings if f["severity"] == "P3"),
        },
    }


def _timeline(entries: list[dict]) -> list[dict]:
    buckets: Counter = Counter()
    for e in entries:
        ts = e.get("ts")
        if not ts:
            continue
        hour = datetime.fromtimestamp(ts).strftime("%m-%d %H:00")
        buckets[hour] += 1
    return [{"hour": h, "count": c} for h, c in sorted(buckets.items())]


# ---------------------------------------------------------------------------
# 导入 / 导出
# ---------------------------------------------------------------------------

CSV_COLUMNS = ["设备", "时间", "级别", "模块", "简述", "内容", "原始"]


def to_csv(entries: list[dict]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(CSV_COLUMNS)
    for e in entries:
        writer.writerow(
            [
                e.get("device") or "",
                e.get("time") or "",
                e.get("severity") or "",
                e.get("module") or "",
                e.get("brief") or "",
                e.get("message") or "",
                e.get("raw") or "",
            ]
        )
    return buffer.getvalue()


def to_txt(entries: list[dict]) -> str:
    return "\n".join(e.get("raw") or e.get("message") or "" for e in entries)


def from_csv(text: str, default_device: str = "") -> list[dict]:
    entries = []
    reader = csv.DictReader(io.StringIO(text))
    for row in reader:
        if not row:
            continue
        sev = (row.get("级别") or "信息").strip()
        if sev not in SEVERITY_ORDER:
            sev = "信息"
        entries.append(
            {
                "device": (row.get("设备") or default_device).strip(),
                "ts": None,
                "time": (row.get("时间") or "").strip(),
                "severity": sev,
                "severityNum": SEVERITY_ORDER.get(sev, 6),
                "module": (row.get("模块") or "").strip(),
                "brief": (row.get("简述") or "").strip(),
                "message": (row.get("内容") or "").strip()[:600],
                "raw": (row.get("原始") or "").strip()[:900],
            }
        )
    return entries


def from_file(name: str, text: str) -> list[dict]:
    if name.lower().endswith(".csv"):
        return from_csv(text)
    return parse_log_text(text)


# ---------------------------------------------------------------------------
# HTML 报告
# ---------------------------------------------------------------------------

def _e(value: Any) -> str:
    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def build_report(data: dict) -> str:
    s = data["summary"]
    rows = []
    for f in data["findings"]:
        evidence = "<br>".join(_e(x) for x in f["evidence"]) or "—"
        rows.append(
            f"<tr><td><span class='sev {f['severity'].lower()}'>{f['severity']}</span></td>"
            f"<td>{_e(f['category'])}</td><td><b>{_e(f['title'])}</b><div class='muted'>{_e(f['detail'])}</div></td>"
            f"<td class='mono'>{evidence}</td><td class='fix'>{_e(f['suggestion'])}</td></tr>"
        )

    sev_rows = "".join(
        f"<tr><td>{_e(k)}</td><td class='num'>{v}</td></tr>"
        for k, v in sorted(s["bySeverity"].items(), key=lambda kv: SEVERITY_ORDER.get(kv[0], 9))
    )
    dev_rows = "".join(
        f"<tr><td>{_e(k)}</td><td class='num'>{v}</td></tr>" for k, v in s["byDevice"].items()
    )
    tpl_rows = "".join(
        f"<tr><td class='mono'>{_e(t['text'])}</td><td class='num'>{t['count']}</td></tr>"
        for t in data["topTemplates"]
    )
    timeline_rows = "".join(
        f"<tr><td>{_e(b['hour'])}</td><td class='num'>{b['count']}</td><td><span class='bar' style='width:{min(100, b['count'] * 3)}%'></span></td></tr>"
        for b in data["timeline"][-24:]
    )

    span = "—"
    if s["start"] and s["end"]:
        span = f"{datetime.fromtimestamp(s['start']):%Y-%m-%d %H:%M} ~ {datetime.fromtimestamp(s['end']):%H:%M}"

    return f"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>日志审计报告</title>
<style>
  body {{ font-family:"Microsoft YaHei",system-ui,sans-serif; color:#1a2230; margin:32px; line-height:1.65; }}
  h1 {{ font-size:22px; margin:0 0 4px; }}
  h2 {{ font-size:15px; margin:24px 0 8px; padding-left:8px; border-left:3px solid #2f6fed; }}
  .meta {{ color:#6b7785; font-size:12px; }}
  .cards {{ display:flex; gap:12px; margin-top:16px; flex-wrap:wrap; }}
  .card {{ flex:1 1 150px; border:1px solid #e3e8ef; border-radius:10px; padding:12px 14px; }}
  .card b {{ display:block; font-size:22px; color:#1d4ed8; }}
  .card span {{ color:#6b7785; font-size:12px; }}
  table {{ width:100%; border-collapse:collapse; font-size:12.5px; }}
  th, td {{ border-bottom:1px solid #e8edf3; padding:7px 8px; text-align:left; vertical-align:top; }}
  th {{ background:#f7f9fc; font-weight:600; }}
  .num {{ text-align:right; }}
  .mono {{ font-family:Consolas,monospace; font-size:11.5px; color:#4b5563; }}
  .muted {{ color:#6b7785; font-size:11.5px; }}
  .sev {{ display:inline-block; padding:1px 7px; border-radius:9px; font-size:11px; font-weight:700; }}
  .sev.p1 {{ background:#fde8e8; color:#b42318; }}
  .sev.p2 {{ background:#fdf1e3; color:#b45309; }}
  .sev.p3 {{ background:#fff7d6; color:#8a6100; }}
  .fix {{ color:#2f6fed; font-size:11.5px; }}
  .bar {{ display:inline-block; height:8px; background:#93b4f5; border-radius:4px; }}
  .foot {{ margin-top:26px; color:#98a2b3; font-size:11px; }}
</style></head><body>
<h1>日志审计报告</h1>
<div class="meta">来源：{_e(data['meta']['source'])} · 文件：{_e(data['meta']['fileName'] or '在线采集')} ·
设备：{_e('、'.join(data['meta']['devices']) or '—')} · 生成时间：{_e(data['generatedAt'])}</div>

<div class="cards">
  <div class="card"><b>{s['total']}</b><span>日志条数</span></div>
  <div class="card"><b>{data['counts']['p1']}</b><span>P1 发现</span></div>
  <div class="card"><b>{data['counts']['p2']}</b><span>P2 发现</span></div>
  <div class="card"><b>{s['errorRate']}%</b><span>错误及以上占比</span></div>
</div>

<div class="meta" style="margin-top:12px">时间范围：{_e(span)}</div>

<h2>审计发现</h2>
<table><thead><tr><th>级别</th><th>类别</th><th>问题</th><th>证据</th><th>建议</th></tr></thead>
<tbody>{''.join(rows) or '<tr><td colspan="5">未发现需要处理的问题</td></tr>'}</tbody></table>

<h2>级别分布</h2>
<table><thead><tr><th>级别</th><th class="num">条数</th></tr></thead><tbody>{sev_rows or '<tr><td colspan="2">—</td></tr>'}</tbody></table>

<h2>设备分布</h2>
<table><thead><tr><th>设备</th><th class="num">条数</th></tr></thead><tbody>{dev_rows or '<tr><td colspan="2">—</td></tr>'}</tbody></table>

<h2>高频日志模板</h2>
<table><thead><tr><th>模板</th><th class="num">次数</th></tr></thead><tbody>{tpl_rows or '<tr><td colspan="2">—</td></tr>'}</tbody></table>

<h2>时间分布</h2>
<table><thead><tr><th>小时</th><th class="num">条数</th><th>分布</th></tr></thead><tbody>{timeline_rows or '<tr><td colspan="3">—</td></tr>'}</tbody></table>

<div class="foot">由 eNSP 拓扑控制台生成 · 解析基于日志结构，未做语义推断；建议结合设备配置与拓扑一并判断。</div>
</body></html>"""
