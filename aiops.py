"""智能运维（AIOps）分析引擎。

能力对齐业界 AIOps 的核心模块，但全部在本机离线完成，不依赖大模型或外网：

1. 健康评分      —— 加权扣分模型，0-100 分 + A/B/C/D 分级
2. 动态基线      —— 用历史巡检的均值/标准差替代固定阈值，2σ 警告、3σ 严重
3. 告警聚合      —— 同一设备的多个指标问题收敛成一条事件，按 P1-P4 排优先级
4. 拓扑根因      —— 离线设备按链路相邻关系归并，指出最可能的源头
5. 趋势预测      —— 线性回归外推，预测光衰/CPU 等到阈值的时间
6. 配置合规      —— 对最新配置备份做基线规则检查
7. 报告导出      —— 自包含 HTML，可直接打印成 PDF 归档

数据来源只有三处：拓扑解析结果、data/runs 里的巡检历史、data/backups 里的配置备份。
没有数据就明确说"无法判定"，不编造结论。
"""

from __future__ import annotations

import base64
import difflib
import json
import math
import re
import statistics
from datetime import datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
RUNS_DIR = ROOT / "data" / "runs"
BACKUP_DIR = ROOT / "data" / "backups"
RENDERS = ROOT / "data" / "renders"
ACK_FILE = ROOT / "data" / "event_acks.json"
RULES_FILE = ROOT / "data" / "compliance_rules.json"

# 指标 -> (方向, 警告线, 严重线)；与巡检模块的静态判定保持一致
LIMITS = {
    "cpu": ("high", 70, 90),
    "memory": ("high", 75, 90),
    "temperature": ("high", 60, 75),
    "rx_power": ("low", -20, -25),
}

METRIC_LABEL = {
    "cpu": "CPU 使用率",
    "memory": "内存使用率",
    "temperature": "温度",
    "rx_power": "光模块收光",
}

GRADE_TEXT = {"A": "健康", "B": "良好", "C": "一般", "D": "危险"}

SEVERITY_ORDER = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}

DEFAULT_RULES = [
    {
        "severity": "P2",
        "pattern": r"^\s*telnet\s+server\s+enable\s*$",
        "message": "启用了 Telnet 明文远程管理",
        "suggestion": "改用 stelnet（SSH），并在 VTY 下关闭 telnet",
    },
    {
        "severity": "P2",
        "pattern": r"snmp-agent\s+community\s+(read|write)\s+\S*(public|private)",
        "message": "SNMP 团体名使用了 public/private",
        "suggestion": "改成复杂团体名，并用 ACL 限制可访问的网段",
    },
    {
        "severity": "P2",
        "pattern": r"authentication-mode\s+none",
        "message": "管理界面配置为免认证",
        "suggestion": "改为 AAA 或至少 password 认证",
    },
    {
        "severity": "P3",
        "pattern": r"^\s*(stp\s+disable|undo\s+stp\s+enable)\s*$",
        "message": "生成树被关闭，存在二层环路风险",
        "suggestion": "启用 STP/RSTP，接入层建议开启边缘端口",
    },
    {
        "severity": "P3",
        "pattern": r"^\s*http\s+server\s+enable\s*$",
        "message": "启用了 HTTP 明文 Web 管理",
        "suggestion": "改用 http secure-server，并限制源地址",
    },
]


def load_rules() -> list[dict]:
    if RULES_FILE.exists():
        try:
            data = json.loads(RULES_FILE.read_text(encoding="utf-8"))
            if isinstance(data, list) and data:
                rules = []
                for item in data:
                    if not isinstance(item, dict) or not item.get("pattern"):
                        continue
                    try:
                        re.compile(item["pattern"])
                    except re.error:
                        continue
                    rules.append(
                        {
                            "severity": item.get("severity") or "P3",
                            "pattern": item["pattern"],
                            "message": item.get("message") or "命中自定义规则",
                            "suggestion": item.get("suggestion") or "按基线要求整改",
                        }
                    )
                if rules:
                    return rules
        except Exception:
            pass
    return list(DEFAULT_RULES)


def save_rules(rules: list[dict]) -> list[dict]:
    cleaned = []
    for item in rules:
        if not isinstance(item, dict) or not item.get("pattern"):
            continue
        re.compile(item["pattern"])  # 语法错误直接抛给接口层
        cleaned.append(
            {
                "severity": item.get("severity") or "P3",
                "pattern": item["pattern"],
                "message": item.get("message") or "命中自定义规则",
                "suggestion": item.get("suggestion") or "按基线要求整改",
            }
        )
    RULES_FILE.parent.mkdir(parents=True, exist_ok=True)
    RULES_FILE.write_text(json.dumps(cleaned, ensure_ascii=False, indent=1), encoding="utf-8")
    return cleaned


def load_acks() -> dict:
    if not ACK_FILE.exists():
        return {}
    try:
        data = json.loads(ACK_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_ack(event_id: str, status: str, note: str = "") -> dict:
    data = load_acks()
    if status == "open":
        data.pop(event_id, None)
    else:
        data[event_id] = {
            "status": status,
            "note": note,
            "at": datetime.now().isoformat(timespec="seconds"),
        }
    ACK_FILE.parent.mkdir(parents=True, exist_ok=True)
    ACK_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
    return data


# ---------------------------------------------------------------------------
# 基础工具
# ---------------------------------------------------------------------------

def load_runs(limit: int = 30) -> list[dict]:
    if not RUNS_DIR.exists():
        return []
    files = sorted(RUNS_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime)[-limit:]
    runs = []
    for path in files:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if isinstance(data, dict) and data.get("devices"):
            runs.append(data)
    return runs


def _ts(run: dict) -> float:
    raw = run.get("finishedAt")
    if not raw:
        return 0.0
    try:
        return datetime.fromisoformat(raw).timestamp()
    except Exception:
        return 0.0


def _family(model: str | None) -> str:
    """把型号收敛成族：AR2220 -> AR22，S5700 V200R001C00 -> S57。"""
    s = (model or "").strip().upper()
    m = re.match(r"([A-Z]+\d{2})", s)
    return m.group(1) if m else s


def _metric_map(device: dict) -> dict[str, dict]:
    return {m.get("key"): m for m in (device.get("metrics") or []) if m.get("key")}


def _model_text(device: dict) -> str:
    metric = _metric_map(device).get("model") or {}
    value = metric.get("value") or metric.get("text") or ""
    return str(value)


def _grade(score: float) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    return "D"


# ---------------------------------------------------------------------------
# 健康评分
# ---------------------------------------------------------------------------

def _score_device(device: dict, extra_penalty: float = 0.0) -> dict:
    metrics = _metric_map(device)
    issues: list[dict] = []
    penalty = extra_penalty

    if not device.get("ok"):
        penalty += 40
        issues.append(
            {
                "level": "crit",
                "metric": "reachable",
                "label": "可达性",
                "value": None,
                "unit": "",
                "message": f"巡检失败：{device.get('error') or '无法连接'}",
            }
        )

    for key, (direction, warn, crit) in LIMITS.items():
        metric = metrics.get(key)
        if not metric or metric.get("value") is None:
            continue
        level = metric.get("level")
        if level == "crit":
            penalty += 18
        elif level == "warn":
            penalty += 7
        if level in ("warn", "crit"):
            issues.append(
                {
                    "level": level,
                    "metric": key,
                    "label": METRIC_LABEL.get(key, metric.get("label")),
                    "value": metric.get("value"),
                    "unit": metric.get("unit") or "",
                    "message": _metric_sentence(key, metric, direction, warn, crit),
                }
            )

    score = max(0.0, min(100.0, 100.0 - penalty))
    return {
        "score": round(score, 1),
        "grade": _grade(score),
        "issues": issues,
    }


def _metric_sentence(key: str, metric: dict, direction: str, warn: float, crit: float) -> str:
    value = metric.get("value")
    unit = metric.get("unit") or ""
    label = METRIC_LABEL.get(key, metric.get("label"))
    if direction == "high":
        if value >= crit:
            return f"{label} {value}{unit}，已超过严重线 {crit}{unit}"
        return f"{label} {value}{unit}，超过警告线 {warn}{unit}"
    if value <= crit:
        return f"{label} {value}{unit}，低于严重线 {crit}{unit}（弱光/中断风险）"
    return f"{label} {value}{unit}，低于警告线 {warn}{unit}"


# ---------------------------------------------------------------------------
# 动态基线
# ---------------------------------------------------------------------------

def _baseline(asset_series: dict[str, list[tuple[float, float]]], current: dict[str, float]) -> list[dict]:
    findings = []
    for key, points in asset_series.items():
        if key not in LIMITS or len(points) < 3:
            continue
        history = [v for _, v in points[:-1]]
        if len(history) < 3:
            continue
        mean = statistics.fmean(history)
        sigma = statistics.pstdev(history)
        if sigma <= 0:
            continue
        value = current.get(key)
        if value is None:
            continue
        z = (value - mean) / sigma
        if abs(z) < 2:
            continue
        findings.append(
            {
                "metric": key,
                "label": METRIC_LABEL.get(key, key),
                "value": value,
                "mean": round(mean, 2),
                "sigma": round(sigma, 2),
                "z": round(z, 2),
                "level": "crit" if abs(z) >= 3 else "warn",
                "message": f"偏离历史基线 {z:+.1f}σ（均值 {mean:.1f}，样本 {len(history)} 次）",
            }
        )
    return findings


# ---------------------------------------------------------------------------
# 趋势预测
# ---------------------------------------------------------------------------

def _slope(points: list[tuple[float, float]]) -> float | None:
    if len(points) < 3:
        return None
    t0 = points[0][0]
    xs = [(t - t0) / 86400 for t, _ in points]
    ys = [v for _, v in points]
    n = len(xs)
    mx = sum(xs) / n
    my = sum(ys) / n
    denom = sum((x - mx) ** 2 for x in xs)
    if denom <= 0:
        return None
    return sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / denom


def _trends(asset_series: dict[str, list[tuple[float, float]]], current: dict[str, float]) -> list[dict]:
    out = []
    for key, points in asset_series.items():
        if key not in LIMITS or len(points) < 3:
            continue
        points = sorted(points)
        span_days = (points[-1][0] - points[0][0]) / 86400 if points[-1][0] > points[0][0] else 0
        direction, warn, crit = LIMITS[key]
        limit = crit
        value = points[-1][1]
        unit = "%" if key in ("cpu", "memory") else ("℃" if key == "temperature" else "dBm")

        # 观测窗口太短时，斜率只是抖动放大，不能当作趋势
        if span_days < 0.25:
            out.append(
                {
                    "metric": key,
                    "label": METRIC_LABEL.get(key, key),
                    "current": round(value, 2),
                    "unit": unit,
                    "slope": None,
                    "trend": "unknown",
                    "limit": limit,
                    "etaDays": None,
                    "reliable": False,
                    "windowDays": round(span_days, 3),
                    "samples": [round(v, 2) for _, v in points],
                }
            )
            continue

        slope = _slope(points)
        if slope is None:
            continue
        eta = None
        if direction == "high" and slope > 0:
            eta = (limit - value) / slope
        elif direction == "low" and slope < 0:
            eta = (value - limit) / abs(slope)
        if eta is not None and (eta < 0 or eta > 365):
            eta = None
        trend = "stable"
        if slope > 0.05:
            trend = "rising"
        elif slope < -0.05:
            trend = "falling"
        out.append(
            {
                "metric": key,
                "label": METRIC_LABEL.get(key, key),
                "current": round(value, 2),
                "unit": unit,
                "slope": round(slope, 3),
                "trend": trend,
                "limit": limit,
                "etaDays": None if eta is None else int(math.ceil(eta)),
                "reliable": True,
                "windowDays": round(span_days, 3),
                "samples": [round(v, 2) for _, v in points],
            }
        )
    return out


def _comparison(runs: list[dict], assets: list[dict]) -> list[dict]:
    """最近两次巡检的指标变化，只看同一型号族，避免跨拓扑串数据。"""
    if len(runs) < 2:
        return []
    prev, cur = runs[-2], runs[-1]
    prev_map: dict[str, tuple[str, dict]] = {}
    for dev in prev.get("devices") or []:
        prev_map[dev.get("device")] = (
            _model_text(dev),
            {
                k: m.get("value")
                for k, m in _metric_map(dev).items()
                if isinstance(m.get("value"), (int, float))
            },
        )
    out = []
    for dev in cur.get("devices") or []:
        name = dev.get("device")
        if name not in prev_map:
            continue
        prev_model, prev_metrics = prev_map[name]
        if _family(prev_model) != _family(_model_text(dev)):
            continue
        current = {
            k: m.get("value")
            for k, m in _metric_map(dev).items()
            if isinstance(m.get("value"), (int, float))
        }
        for key in LIMITS:
            a, b = prev_metrics.get(key), current.get(key)
            if a is None or b is None:
                continue
            delta = round(b - a, 2)
            if abs(delta) < max(1.0, abs(a) * 0.1):
                continue
            out.append(
                {
                    "device": name,
                    "metric": key,
                    "label": METRIC_LABEL.get(key, key),
                    "prev": a,
                    "now": b,
                    "delta": delta,
                    "direction": "up" if delta > 0 else "down",
                }
            )
    out.sort(key=lambda x: abs(x["delta"]), reverse=True)
    return out[:12]


def _config_drift() -> dict:
    """最近两个配置备份批次之间，每台设备改了多少行。"""
    if not BACKUP_DIR.exists():
        return {"prev": "", "cur": "", "items": []}
    folders = sorted([p for p in BACKUP_DIR.iterdir() if p.is_dir()], key=lambda p: p.name)
    if len(folders) < 2:
        return {"prev": "", "cur": folders[-1].name if folders else "", "items": []}
    prev_dir, cur_dir = folders[-2], folders[-1]
    items = []
    for cur_file in sorted(cur_dir.glob("*.cfg")):
        prev_file = prev_dir / cur_file.name
        if not prev_file.exists():
            continue
        before = prev_file.read_text(encoding="utf-8", errors="replace").splitlines()
        after = cur_file.read_text(encoding="utf-8", errors="replace").splitlines()
        diff = list(difflib.unified_diff(before, after, lineterm=""))
        added = [ln[1:] for ln in diff if ln.startswith("+") and not ln.startswith("+++")]
        removed = [ln[1:] for ln in diff if ln.startswith("-") and not ln.startswith("---")]
        if not added and not removed:
            continue
        samples = [f"- {x}" for x in removed[:3]] + [f"+ {x}" for x in added[:3]]
        items.append(
            {
                "device": cur_file.stem,
                "added": len(added),
                "removed": len(removed),
                "samples": samples,
            }
        )
    return {"prev": prev_dir.name, "cur": cur_dir.name, "items": items}


# ---------------------------------------------------------------------------
# 配置合规
# ---------------------------------------------------------------------------

def _latest_backup() -> tuple[str, dict[str, str]]:
    if not BACKUP_DIR.exists():
        return "", {}
    folders = sorted([p for p in BACKUP_DIR.iterdir() if p.is_dir()], key=lambda p: p.name)
    if not folders:
        return "", {}
    folder = folders[-1]
    files = {}
    for path in folder.glob("*.cfg"):
        try:
            files[path.stem] = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
    return folder.name, files


def _compliance(configs: dict[str, str]) -> list[dict]:
    findings = []
    rules = load_rules()
    for device, text in configs.items():
        lines = [ln.rstrip() for ln in text.splitlines()]
        for rule in rules:
            pattern = rule["pattern"]
            for line in lines:
                if re.search(pattern, line, re.I):
                    findings.append(
                        {
                            "device": device,
                            "severity": rule["severity"],
                            "message": rule["message"],
                            "line": line.strip()[:120],
                            "suggestion": rule["suggestion"],
                        }
                    )
                    break
        # 配置过设备却没配 NTP，时间戳不可信，会影响日志关联
        if len(lines) >= 12 and not any(re.search(r"^\s*ntp-service", ln, re.I) for ln in lines):
            findings.append(
                {
                    "device": device,
                    "severity": "P4",
                    "message": "未配置 NTP 时间同步",
                    "line": "",
                    "suggestion": "配置 ntp-service unicast-server，保证日志时间可比对",
                }
            )
    return findings


# ---------------------------------------------------------------------------
# 告警聚合与根因
# ---------------------------------------------------------------------------

def _offline_groups(assets: list[dict], links: list[dict], trusted: bool) -> list[dict]:
    offline = {a["name"] for a in assets if a.get("reachable") is False}
    if not offline:
        return []

    groups: list[list[str]] = []
    seen: set[str] = set()
    adjacency: dict[str, set[str]] = {}
    if trusted:
        for link in links:
            a, b = link.get("from"), link.get("to")
            if a in offline and b in offline:
                adjacency.setdefault(a, set()).add(b)
                adjacency.setdefault(b, set()).add(a)

    for name in sorted(offline):
        if name in seen:
            continue
        stack = [name]
        component = []
        while stack:
            cur = stack.pop()
            if cur in seen:
                continue
            seen.add(cur)
            component.append(cur)
            stack.extend(adjacency.get(cur, ()))
        groups.append(component)

    events = []
    for component in groups:
        root = component[0]
        if len(component) > 1:
            root = max(component, key=lambda n: len(adjacency.get(n, ())))
        events.append(
            {
                "id": f"offline-{root}",
                "severity": "P1",
                "kind": "可用性",
                "title": f"{root} 不可达" + (f"，连带 {len(component) - 1} 台相邻设备" if len(component) > 1 else ""),
                "root": root,
                "affected": [n for n in component if n != root],
                "evidence": [f"{n} 巡检连接失败" for n in component],
                "suggestion": "确认 eNSP 中设备已启动、console 端口未被其它拓扑占用；再检查链路与地址配置",
            }
        )
    return events


def _device_events(assets: list[dict]) -> list[dict]:
    events = []
    for asset in assets:
        issues = asset.get("issues") or []
        if not issues:
            continue
        crit = [i for i in issues if i["level"] == "crit"]
        warn = [i for i in issues if i["level"] == "warn"]
        if not crit and not warn:
            continue
        severity = "P1" if crit else "P2"
        events.append(
            {
                "id": f"metric-{asset['name']}",
                "severity": severity,
                "kind": "性能",
                "title": f"{asset['name']} " + "、".join(i["label"] for i in crit + warn),
                "root": asset["name"],
                "affected": [],
                "evidence": [i["message"] for i in crit + warn],
                "suggestion": _suggest_for(crit + warn),
            }
        )
    return events


def _suggest_for(issues: list[dict]) -> str:
    keys = {i["metric"] for i in issues}
    parts = []
    if "cpu" in keys:
        parts.append("排查异常进程/广播风暴，必要时限速或扩容")
    if "memory" in keys:
        parts.append("检查内存泄漏与表项规模，重启前先备份配置")
    if "temperature" in keys:
        parts.append("检查风扇与机房温度，清理风道")
    if "rx_power" in keys:
        parts.append("检查光模块与尾纤，收光低于 -20dBm 需更换")
    if "reachable" in keys:
        parts.append("先恢复管理通道，再判断业务影响")
    return "；".join(parts) or "持续观察指标变化"


def _compliance_events(findings: list[dict]) -> list[dict]:
    by_device: dict[str, list[dict]] = {}
    for item in findings:
        by_device.setdefault(item["device"], []).append(item)

    events = []
    for device, items in by_device.items():
        severity = "P3" if any(i["severity"] == "P2" for i in items) else "P4"
        events.append(
            {
                "id": f"compliance-{device}",
                "severity": severity,
                "kind": "合规",
                "title": f"{device} 配置合规 {len(items)} 项",
                "root": device,
                "affected": [],
                "evidence": [f"{i['message']}：{i['line']}" if i["line"] else i["message"] for i in items],
                "suggestion": "；".join(dict.fromkeys(i["suggestion"] for i in items)),
            }
        )
    return events


# ---------------------------------------------------------------------------
# 主入口
# ---------------------------------------------------------------------------

def build_overview(inspect: dict | None, runs: list[dict] | None = None, topo_name: str = "") -> dict:
    runs = runs if runs is not None else load_runs()
    inspect = inspect or {}
    topo_devs = {d["name"]: d for d in (inspect.get("devices") or [])}
    links = inspect.get("links") or []
    latest = runs[-1] if runs else None

    assets: list[dict] = []
    mismatches: list[dict] = []
    topology_trusted = True

    if latest:
        for dev in latest.get("devices") or []:
            name = dev.get("device")
            metrics = {
                k: m.get("value")
                for k, m in _metric_map(dev).items()
                if isinstance(m.get("value"), (int, float))
            }
            run_model = _model_text(dev)
            topo = topo_devs.get(name)
            topo_model = (topo or {}).get("model") or ""
            matched = bool(topo) and _family(topo_model) == _family(run_model)
            if topo and not matched:
                mismatches.append({"device": name, "topology": topo_model, "inspected": run_model})
                topology_trusted = False
            score = _score_device(dev)
            assets.append(
                {
                    "name": name,
                    "model": run_model or topo_model,
                    "topologyModel": topo_model,
                    "consolePort": (topo or {}).get("consolePort"),
                    "reachable": bool(dev.get("ok")),
                    "inTopology": bool(topo),
                    "modelMatched": matched if topo else None,
                    "score": score["score"],
                    "grade": score["grade"],
                    "issues": score["issues"],
                    "metrics": metrics,
                }
            )
    else:
        for dev in topo_devs.values():
            assets.append(
                {
                    "name": dev["name"],
                    "model": dev.get("model"),
                    "topologyModel": dev.get("model"),
                    "consolePort": dev.get("consolePort"),
                    "reachable": None,
                    "inTopology": True,
                    "modelMatched": True,
                    "score": None,
                    "grade": None,
                    "issues": [],
                    "metrics": {},
                }
            )

    # 历史序列：同名且同型号族才纳入，避免不同拓扑的同名设备混在一起
    series: dict[str, dict[str, list[tuple[float, float]]]] = {a["name"]: {} for a in assets}
    for run in runs:
        ts = _ts(run)
        for dev in run.get("devices") or []:
            name = dev.get("device")
            if name not in series:
                continue
            asset = next(a for a in assets if a["name"] == name)
            if _family(_model_text(dev)) != _family(asset["model"]):
                continue
            for key, metric in _metric_map(dev).items():
                if key not in LIMITS or not isinstance(metric.get("value"), (int, float)):
                    continue
                series[name].setdefault(key, []).append((ts, float(metric["value"])))

    # 动态基线参与扣分
    for asset in assets:
        current = asset["metrics"]
        deviations = _baseline(series.get(asset["name"], {}), current)
        if deviations and asset["score"] is not None:
            penalty = sum(6 if d["level"] == "crit" else 3 for d in deviations)
            asset["score"] = round(max(0.0, asset["score"] - penalty), 1)
            asset["grade"] = _grade(asset["score"])
            for dev in deviations:
                asset["issues"].append(
                    {
                        "level": dev["level"],
                        "metric": dev["metric"],
                        "label": dev["label"],
                        "value": dev["value"],
                        "unit": "",
                        "message": dev["message"],
                    }
                )
        asset["deviations"] = deviations
        asset["trends"] = _trends(series.get(asset["name"], {}), current)

    backup_stamp, configs = _latest_backup()
    known = {a["name"] for a in assets}
    compliance = [c for c in _compliance(configs) if c["device"] in known]

    events = _offline_groups(assets, links, topology_trusted) + _device_events(assets)
    events += _compliance_events(compliance)
    events.sort(key=lambda e: (SEVERITY_ORDER.get(e["severity"], 9), e["root"]))

    acks = load_acks()
    for event in events:
        ack = acks.get(event["id"]) or {}
        event["status"] = ack.get("status") or "open"
        event["note"] = ack.get("note") or ""
        event["ackedAt"] = ack.get("at")

    scored = [a for a in assets if a["score"] is not None]
    overall = round(sum(a["score"] for a in scored) / len(scored), 1) if scored else None
    online = sum(1 for a in assets if a["reachable"] is True)
    counted = sum(1 for a in assets if a["reachable"] is not None)

    summary = _summary_text(assets, events, overall, latest, mismatches)

    return {
        "ok": True,
        "generatedAt": datetime.now().isoformat(timespec="seconds"),
        "topoName": topo_name,
        "dataSource": "inspection" if latest else "topology",
        "runId": (latest or {}).get("runId"),
        "runFinishedAt": (latest or {}).get("finishedAt"),
        "overallScore": overall,
        "overallGrade": _grade(overall) if overall is not None else None,
        "counts": {
            "assets": len(assets),
            "scored": len(scored),
            "online": online,
            "reachableChecked": counted,
            "p1": sum(1 for e in events if e["severity"] == "P1"),
            "p2": sum(1 for e in events if e["severity"] == "P2"),
            "p3": sum(1 for e in events if e["severity"] == "P3"),
            "p4": sum(1 for e in events if e["severity"] == "P4"),
            "compliant": len(compliance),
            "trendSamples": len(runs),
            "acked": sum(1 for e in events if e.get("status") == "ack"),
            "ignored": sum(1 for e in events if e.get("status") == "ignored"),
        },
        "assets": assets,
        "events": events,
        "compliance": compliance,
        "complianceStamp": backup_stamp,
        "comparison": _comparison(runs, assets),
        "drift": _config_drift(),
        "rules": load_rules(),
        "mismatches": mismatches,
        "topologyTrusted": topology_trusted,
        "summary": summary,
    }


def _summary_text(assets, events, overall, latest, mismatches) -> str:
    if not latest:
        return (
            "还没有可用的巡检数据。当前只能列出拓扑里的设备，无法给出健康评分。"
            "请先在「设备巡检」里对目标设备执行一次采集。"
        )
    p1 = sum(1 for e in events if e["severity"] == "P1")
    p2 = sum(1 for e in events if e["severity"] == "P2")
    scored = [a for a in assets if a["score"] is not None]
    worst = sorted(scored, key=lambda a: a["score"])[:2]
    parts = [
        f"最近一次巡检覆盖 {len(assets)} 台设备，综合健康分 {overall}"
        + (f"（{_grade(overall)} 级）" if overall is not None else "")
        + "。"
    ]
    if p1 or p2:
        parts.append(f"发现 {p1} 项 P1、{p2} 项 P2 事件，建议优先处理。" )
    else:
        parts.append("未发现 P1/P2 级事件，整体运行平稳。")
    if worst and worst[0]["score"] < 90:
        parts.append(
            "健康度最低的是 " + "、".join(f"{a['name']}（{a['score']} 分）" for a in worst) + "。"
        )
    if mismatches:
        parts.append(
            f"注意：{len(mismatches)} 台设备的巡检型号与当前拓扑不一致，"
            "拓扑关联与根因推断已降级为按设备独立分析。"
        )
    return "".join(parts)


# ---------------------------------------------------------------------------
# HTML 报告
# ---------------------------------------------------------------------------

def _img_data() -> str:
    if not RENDERS.exists():
        return ""
    files = sorted([p for p in RENDERS.glob("*.png") if p.is_file()], key=lambda p: p.stat().st_mtime)
    if not files:
        return ""
    try:
        return "data:image/png;base64," + base64.b64encode(files[-1].read_bytes()).decode()
    except Exception:
        return ""


def build_report(data: dict) -> str:
    img = _img_data()
    counts = data["counts"]
    rows = []
    for asset in data["assets"]:
        issues = "、".join(i["label"] for i in asset["issues"][:3]) or "—"
        score = "—" if asset["score"] is None else f"{asset['score']}"
        rows.append(
            f"<tr><td>{_e(asset['name'])}</td><td>{_e(asset.get('model') or '')}</td>"
            f"<td class='num'>{score}</td><td>{asset.get('grade') or '—'}</td>"
            f"<td>{_e(issues)}</td></tr>"
        )

    event_rows = []
    for e in data["events"]:
        affected = "、".join(e["affected"]) or "—"
        event_rows.append(
            f"<tr><td><span class='sev {e['severity'].lower()}'>{e['severity']}</span></td>"
            f"<td>{_e(e['kind'])}</td><td>{_e(e['title'])}</td><td>{_e(affected)}</td>"
            f"<td>{'<br>'.join(_e(x) for x in e['evidence'])}<div class='fix'>{_e(e['suggestion'])}</div></td></tr>"
        )

    compliance_rows = [
        f"<tr><td>{_e(c['device'])}</td><td>{c['severity']}</td><td>{_e(c['message'])}</td>"
        f"<td class='mono'>{_e(c['line'])}</td><td>{_e(c['suggestion'])}</td></tr>"
        for c in data["compliance"]
    ]

    trend_rows = []
    short_window = 0
    for asset in data["assets"]:
        for t in asset.get("trends") or []:
            if not t.get("reliable") or t.get("slope") is None:
                short_window += 1
                continue
            slope_txt = f"{t['slope']:+.3f}/天"
            eta = "—" if t["etaDays"] is None else f"{t['etaDays']} 天"
            trend_rows.append(
                f"<tr><td>{_e(asset['name'])}</td><td>{_e(t['label'])}</td>"
                f"<td class='num'>{t['current']}{t['unit']}</td>"
                f"<td class='num'>{slope_txt}</td><td>{eta}</td>"
                f"<td class='mono'>{' → '.join(str(v) for v in t['samples'][-6:])}</td></tr>"
            )
    trend_note = (
        f"<tr><td colspan='6'>历史样本跨度不足 6 小时，暂不外推趋势（{short_window} 组指标已跳过）。</td></tr>"
        if not trend_rows and short_window
        else ""
    )

    comparison_rows = "".join(
        f"<tr><td>{_e(c['device'])}</td><td>{_e(c['label'])}</td>"
        f"<td class='num'>{c['prev']}</td><td class='num'>{c['now']}</td>"
        f"<td class='num'>{c['delta']:+}</td></tr>"
        for c in data.get("comparison") or []
    )

    drift = data.get("drift") or {}
    drift_rows = "".join(
        f"<tr><td>{_e(d['device'])}</td><td class='num'>+{d['added']}</td><td class='num'>-{d['removed']}</td>"
        f"<td class='mono'>{'<br>'.join(_e(x) for x in d['samples'][:4])}</td></tr>"
        for d in drift.get("items") or []
    )

    mismatch_html = ""
    if data.get("mismatches"):
        items = "".join(
            f"<li>{_e(m['device'])}：拓扑 {_e(m['topology'])} / 实检 {_e(m['inspected'])}</li>"
            for m in data["mismatches"]
        )
        mismatch_html = (
            "<h2>数据一致性</h2><div class='warnbox'>"
            "<b>巡检对象与当前拓扑型号不一致，拓扑关联与根因传播已降级为按设备独立分析。</b>"
            f"<ul>{items}</ul>"
            "<div>通常是 eNSP 中运行的仍是上一个拓扑。请在 eNSP 里启动当前拓扑后再巡检。</div>"
            "</div>"
        )

    return f"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>智能运维报告 - {_e(data['topoName'] or 'eNSP')}</title>
<style>
  body {{ font-family: "Microsoft YaHei", system-ui, sans-serif; color:#1a2230; margin:32px; line-height:1.65; }}
  h1 {{ font-size:22px; margin:0 0 4px; }}
  h2 {{ font-size:15px; margin:26px 0 8px; padding-left:8px; border-left:3px solid #2f6fed; }}
  .meta {{ color:#6b7785; font-size:12px; }}
  .cards {{ display:flex; gap:12px; margin-top:16px; flex-wrap:wrap; }}
  .card {{ flex:1 1 140px; border:1px solid #e3e8ef; border-radius:10px; padding:12px 14px; }}
  .card b {{ display:block; font-size:22px; color:#1d4ed8; }}
  .card span {{ color:#6b7785; font-size:12px; }}
  .summary {{ background:#f5f8ff; border:1px solid #dbe6ff; border-radius:10px; padding:14px 16px; margin-top:14px; }}
  .warnbox {{ background:#fdf6e9; border:1px solid #f3ddb7; border-radius:10px; padding:12px 16px; font-size:12.5px; color:#8a5a00; }}
  .warnbox ul {{ margin:6px 0; padding-left:18px; }}
  .warnbox b {{ color:#8a4b00; }}
  table {{ width:100%; border-collapse:collapse; font-size:12.5px; }}
  th, td {{ border-bottom:1px solid #e8edf3; padding:7px 8px; text-align:left; vertical-align:top; }}
  th {{ background:#f7f9fc; font-weight:600; }}
  .num {{ text-align:right; }}
  .mono {{ font-family: Consolas, monospace; font-size:11.5px; color:#4b5563; }}
  .sev {{ display:inline-block; padding:1px 7px; border-radius:9px; font-size:11px; font-weight:600; }}
  .sev.p1 {{ background:#fde8e8; color:#b42318; }}
  .sev.p2 {{ background:#fdf1e3; color:#b45309; }}
  .sev.p3 {{ background:#fff7d6; color:#8a6100; }}
  .sev.p4 {{ background:#eef2f7; color:#52606d; }}
  .fix {{ color:#2f6fed; font-size:11.5px; margin-top:2px; }}
  img {{ max-width:100%; border:1px solid #e3e8ef; border-radius:8px; }}
  .foot {{ margin-top:28px; color:#98a2b3; font-size:11px; }}
  @media print {{ body {{ margin:12mm; }} h2 {{ break-after:avoid; }} table {{ break-inside:auto; }} }}
</style></head><body>
<h1>智能运维巡检报告</h1>
<div class="meta">拓扑：{_e(data['topoName'] or '—')} · 生成时间：{_e(data['generatedAt'])} ·
数据来源：{'设备巡检 ' + _e(data.get('runFinishedAt') or '') if data['dataSource'] == 'inspection' else '拓扑信息（尚无巡检数据）'}</div>

<div class="cards">
  <div class="card"><b>{data['overallScore'] if data['overallScore'] is not None else '—'}</b><span>综合健康分 {data.get('overallGrade') or ''}</span></div>
  <div class="card"><b>{counts['p1']}</b><span>P1 事件</span></div>
  <div class="card"><b>{counts['p2']}</b><span>P2 事件</span></div>
  <div class="card"><b>{counts['online']}/{counts['reachableChecked']}</b><span>在线设备</span></div>
</div>

<div class="summary">{_e(data['summary'])}</div>
{mismatch_html}

<h2>设备健康评分</h2>
<table><thead><tr><th>设备</th><th>型号</th><th class="num">评分</th><th>等级</th><th>主要问题</th></tr></thead>
<tbody>{''.join(rows) or '<tr><td colspan="5">无数据</td></tr>'}</tbody></table>

<h2>事件与处置建议</h2>
<table><thead><tr><th>级别</th><th>类型</th><th>事件</th><th>影响范围</th><th>证据与建议</th></tr></thead>
<tbody>{''.join(event_rows) or '<tr><td colspan="5">没有需要处理的事件</td></tr>'}</tbody></table>

<h2>趋势预测</h2>
<table><thead><tr><th>设备</th><th>指标</th><th class="num">当前</th><th class="num">斜率</th><th>预计到达阈值</th><th>最近样本</th></tr></thead>
<tbody>{''.join(trend_rows) or trend_note or '<tr><td colspan="6">历史样本不足（至少 3 次巡检）</td></tr>'}</tbody></table>

<h2>本次 vs 上次</h2>
<table><thead><tr><th>设备</th><th>指标</th><th class="num">上次</th><th class="num">本次</th><th class="num">变化</th></tr></thead>
<tbody>{comparison_rows or '<tr><td colspan="5">没有跨批次的明显变化（或历史不足两次）</td></tr>'}</tbody></table>

<h2>配置漂移</h2>
<div class="meta">{_e(drift.get('prev') or '—')} → {_e(drift.get('cur') or '—')}</div>
<table><thead><tr><th>设备</th><th class="num">新增</th><th class="num">删除</th><th>变更样例</th></tr></thead>
<tbody>{drift_rows or '<tr><td colspan="4">没有两次可对比的配置备份</td></tr>'}</tbody></table>

<h2>配置合规</h2>
<table><thead><tr><th>设备</th><th>级别</th><th>问题</th><th>配置行</th><th>建议</th></tr></thead>
<tbody>{''.join(compliance_rows) or '<tr><td colspan="5">没有配置备份，或不涉及风险项</td></tr>'}</tbody></table>

{f'<h2>拓扑</h2><img src="{img}" alt="拓扑">' if img else ''}

<div class="foot">由 eNSP 拓扑控制台生成 · 评分为加权扣分模型，趋势为最小二乘外推，仅供实验环境参考。</div>
</body></html>"""


def _e(value: Any) -> str:
    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
