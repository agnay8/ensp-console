"""eNSP 拓扑控制台 — 后端

直接复用 ensp-mcp 的实现（topo_inspect / topo_validate / topo_render /
environment_check / device_exec / device_batch），不重造解析逻辑。
"""

from __future__ import annotations

import csv
import io
import json
import re
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool

from ensp_mcp.server import (
    device_batch,
    device_exec,
    environment_check,
    topo_inspect,
    topo_render,
    topo_validate,
)

from brief import analyse, build_skeleton, extract_text
from aiops import build_overview, build_report, load_rules, save_ack, save_rules
from nettools import (
    PRESETS,
    analyze_pcap,
    parse_port_spec,
    run_dns_query,
    run_ping,
    run_port_scan,
    run_speed_test,
    run_traceroute,
    subnet_calc,
    subnet_split,
)
from ops import diff_configs, list_backups, read_config, run_backup, run_matrix
from patrol import SUMMARY_COLUMNS, run_inspection, to_detail_rows, to_summary_rows
from probe import probe_devices

import persistence

ROOT = Path(__file__).resolve().parent
UPLOADS = ROOT / "data" / "uploads"
RENDERS = ROOT / "data" / "renders"
LOGS_DIR = ROOT / "data" / "logs"
for d in (UPLOADS, RENDERS):
    d.mkdir(parents=True, exist_ok=True)

MAX_UPLOAD = 30 * 1024 * 1024

app = FastAPI(title="eNSP 拓扑控制台", version="0.1.0")


@app.middleware("http")
async def no_cache_static(request, call_next):
    """前端文件不缓存，避免改了 JS/CSS 后浏览器还在跑旧版本。"""
    response = await call_next(request)
    path = request.url.path
    if path == "/" or path.endswith((".html", ".js", ".css")):
        response.headers["Cache-Control"] = "no-cache, must-revalidate"
        response.headers["Pragma"] = "no-cache"
    return response

STATE: dict[str, Any] = {
    "topo": "",
    "topoName": "",
    "inspect": None,
    "excel": None,
    "brief": None,
    "env": None,
    "envAt": 0.0,
    "lastRunId": "",
    "backupFolder": "",
    "logEntries": [],
    "logFiltered": [],
    "logMeta": {},
    "logAudit": None,
}
STATE.update(persistence.load())


def _on_scheduled_run(result: dict) -> None:
    """定时巡检完成后，把结果并入内存状态，页面无需刷新即可看到。"""
    run_id = result.get("runId")
    if not run_id:
        return
    STATE.setdefault("inspectRuns", {})[run_id] = result
    while len(STATE["inspectRuns"]) > 5:
        STATE["inspectRuns"].pop(next(iter(STATE["inspectRuns"])), None)
    STATE["lastRunId"] = run_id


@app.on_event("startup")
async def _startup_scheduler() -> None:
    import scheduler

    path = LOGS_DIR / "last.json"
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            STATE["logEntries"] = data.get("entries") or []
            STATE["logFiltered"] = STATE["logEntries"]
            STATE["logMeta"] = data.get("meta") or {}
            STATE["logAudit"] = data.get("audit")
        except Exception:
            pass
    scheduler.start(_on_scheduled_run)


def _persist() -> None:
    persistence.save(STATE)


def _persist_logs() -> None:
    try:
        LOGS_DIR.mkdir(parents=True, exist_ok=True)
        payload = {
            "entries": STATE.get("logEntries") or [],
            "meta": STATE.get("logMeta") or {},
            "audit": STATE.get("logAudit"),
        }
        (LOGS_DIR / "last.json").write_text(
            json.dumps(payload, ensure_ascii=False), encoding="utf-8"
        )
    except Exception:
        pass


# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------

def _safe_json(raw: str) -> dict:
    try:
        return json.loads(raw)
    except Exception:
        return {"ok": False, "error": "MCP 返回了非 JSON 内容", "raw": raw[:2000]}


def _prune_uploads(keep: int = 20) -> int:
    """上传目录只保留最近 keep 份，当前使用的拓扑不删。"""
    protected = set()
    for key in ("topo",):
        value = STATE.get(key)
        if value:
            try:
                protected.add(Path(value).resolve())
            except Exception:
                pass

    files = [p for p in UPLOADS.glob("*") if p.is_file()]
    files.sort(key=lambda p: p.stat().st_mtime)
    removed = 0
    for old in files[:-keep] if len(files) > keep else []:
        try:
            if old.resolve() in protected:
                continue
            old.unlink()
            removed += 1
        except Exception:
            pass
    return removed


def _save_upload(file: UploadFile, subdir: Path, suffix: str | tuple[str, ...]) -> tuple[Path, str]:
    suffixes = (suffix,) if isinstance(suffix, str) else tuple(suffix)
    original = Path(file.filename or "upload").name
    if not original.lower().endswith(suffixes):
        raise HTTPException(400, f"只支持 {' / '.join(suffixes)} 文件")
    data = file.file.read()
    if len(data) > MAX_UPLOAD:
        raise HTTPException(413, "文件超过 30MB")
    if not data:
        raise HTTPException(400, "文件是空的")
    dest = subdir / f"{uuid.uuid4().hex[:8]}_{original}"
    dest.write_bytes(data)
    _prune_uploads()
    return dest, original


# ---------------------------------------------------------------------------
# 环境
# ---------------------------------------------------------------------------

@app.get("/api/env")
async def api_env(path: str = "", refresh: int = 0):
    now = time.time()
    cached_ok = STATE["env"] and (now - STATE["envAt"] < 90) and not path and not refresh
    if cached_ok:
        return {**STATE["env"], "cached": True}

    target = path or STATE["topo"]
    try:
        result = _safe_json(
            await run_in_threadpool(lambda: environment_check(path=target))
        )
    except Exception as exc:
        result = {"ok": False, "error": f"预检失败: {exc}"}

    # MCP 把核心状态放在 runtime 里，这里提到顶层，前端只认一套字段
    rt = result.get("runtime") or {}
    if result.get("ok"):
        ready = rt.get("readyForTopology")
        if ready is None:
            ready = result.get("readyForTopology")
        if ready is None:
            ready = rt.get("virtualDeviceRuntimeReady")
        if ready is None:
            ready = (rt.get("virtualBox") or {}).get("coreReady")
        result["readyForTopology"] = ready
        result["errorCount"] = rt.get("errorCount") or 0
        result["warningCount"] = rt.get("warningCount") or 0
        result["issues"] = rt.get("issues") or result.get("issues") or []

    STATE["env"] = result
    STATE["envAt"] = now
    return {**result, "cached": False}


# ---------------------------------------------------------------------------
# 拓扑
# ---------------------------------------------------------------------------

@app.post("/api/topo/upload")
async def api_topo_upload(file: UploadFile = File(...)):
    dest, original = _save_upload(file, UPLOADS, ".topo")
    result = _safe_json(await run_in_threadpool(lambda: topo_inspect(str(dest))))
    if not result.get("ok"):
        raise HTTPException(400, result.get("error", "拓扑解析失败"))

    STATE["topo"] = str(dest)
    STATE["topoName"] = original
    STATE["inspect"] = result
    STATE["env"] = None
    _persist()

    return {"ok": True, "path": str(dest), "name": original, "inspect": result}


@app.post("/api/topo/inspect")
async def api_topo_inspect(payload: dict):
    path = payload.get("path") or STATE["topo"]
    if not path:
        raise HTTPException(400, "还没有拓扑文件")
    if not Path(path).exists():
        raise HTTPException(404, "拓扑文件不存在")

    result = _safe_json(await run_in_threadpool(lambda: topo_inspect(path)))
    if not result.get("ok"):
        raise HTTPException(400, result.get("error", "解析失败"))

    STATE["topo"] = path
    STATE["topoName"] = Path(path).name
    STATE["inspect"] = result
    return result


@app.post("/api/topo/validate")
async def api_topo_validate(payload: dict):
    path = payload.get("path") or STATE["topo"]
    if not path:
        raise HTTPException(400, "还没有拓扑文件")
    return _safe_json(await run_in_threadpool(lambda: topo_validate(path)))


@app.get("/api/topo/preview")
async def api_topo_preview(path: str = "", t: float = 0):
    target = path or STATE["topo"]
    if not target:
        raise HTTPException(400, "还没有拓扑文件")
    if not Path(target).exists():
        raise HTTPException(404, "拓扑文件不存在")

    out = RENDERS / f"{Path(target).stem}.png"
    result = _safe_json(
        await run_in_threadpool(lambda: topo_render(target, str(out), 1.4, True))
    )
    if not result.get("ok"):
        raise HTTPException(400, result.get("error", "渲染失败"))
    return FileResponse(
        str(out),
        media_type="image/png",
        headers={"Cache-Control": "no-store, max-age=0"},
    )


@app.get("/api/state")
async def api_state():
    return {
        "ok": True,
        "topo": STATE["topo"],
        "topoName": STATE["topoName"],
        "inspect": STATE["inspect"],
        "excel": STATE.get("excel"),
        "lastRunId": STATE.get("lastRunId"),
    }


@app.get("/api/topo/export")
async def api_topo_export(path: str = "", format: str = "xlsx"):
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Font, PatternFill

    info = STATE.get("inspect")
    if not info:
        raise HTTPException(400, "还没有解析过拓扑")

    wb = Workbook()
    ws = wb.active
    ws.title = "设备"
    head = ["设备", "型号", "类别", "Console 端口", "接口总数", "已用", "空闲接口", "系统 MAC"]
    ws.append(head)
    for d in info.get("devices") or []:
        ws.append(
            [
                d.get("name"),
                d.get("model"),
                d.get("category", ""),
                d.get("consolePort"),
                d.get("portsTotal"),
                d.get("portsUsed"),
                ", ".join(d.get("portsFree") or []),
                d.get("systemMac", ""),
            ]
        )

    ws2 = wb.create_sheet("链路")
    ws2.append(["本端设备", "本端接口", "对端设备", "对端接口", "线型"])
    for link in info.get("links") or []:
        ws2.append(
            [
                link.get("from"),
                link.get("fromPort"),
                link.get("to"),
                link.get("toPort"),
                link.get("lineType", ""),
            ]
        )

    fill = PatternFill("solid", fgColor="EAF0FE")
    for sheet in (ws, ws2):
        for cell in sheet[1]:
            cell.fill = fill
            cell.font = Font(bold=True, color="1D4ED8")
            cell.alignment = Alignment(horizontal="center")
        sheet.freeze_panes = "A2"
    for column, width in zip("ABCDEFGH", (14, 14, 10, 14, 10, 8, 42, 20)):
        ws.column_dimensions[column].width = width
    for column, width in zip("ABCDE", (14, 26, 14, 26, 10)):
        ws2.column_dimensions[column].width = width

    buffer = io.BytesIO()
    wb.save(buffer)
    name = f"topology-{datetime.now().strftime('%Y%m%d-%H%M%S')}.xlsx"
    return Response(
        buffer.getvalue(),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{name}"'},
    )


# ---------------------------------------------------------------------------
# 设备探活
# ---------------------------------------------------------------------------

@app.post("/api/device/probe")
async def api_device_probe(payload: dict):
    inspect = STATE.get("inspect") or {}
    devices = payload.get("devices") or inspect.get("devices") or []
    links = payload.get("links") or inspect.get("links") or []
    timeout = float(payload.get("timeout") or 8)

    result = await probe_devices(devices, links, timeout=timeout)
    return {"ok": True, **result}


# ---------------------------------------------------------------------------
# 命令执行
# ---------------------------------------------------------------------------

@app.post("/api/device/exec")
async def api_device_exec(payload: dict):
    target = payload.get("target")
    commands = payload.get("commands") or []
    if not target or not commands:
        raise HTTPException(400, "target 和 commands 必填")

    topo = payload.get("topo") or STATE["topo"]
    try:
        raw = await device_exec(
            target=target,
            commands=[str(c) for c in commands],
            topo_path=topo,
            view=payload.get("view", "keep"),
            save=bool(payload.get("save", False)),
            stop_on_error=bool(payload.get("stopOnError", True)),
            confirm=payload.get("confirm", "Y"),
        )
    except Exception as exc:
        return JSONResponse({"ok": False, "error": f"执行异常: {exc}"}, status_code=200)
    return _safe_json(raw)


@app.post("/api/device/batch")
async def api_device_batch(payload: dict):
    topo = payload.get("topo") or STATE["topo"]
    if not topo:
        raise HTTPException(400, "还没有拓扑文件")

    configs = payload.get("configs") or None
    commands = payload.get("commands") or None
    if not configs and not commands:
        raise HTTPException(400, "configs 或 commands 至少给一个")

    try:
        raw = await device_batch(
            topo_path=topo,
            devices=payload.get("devices"),
            commands=commands,
            configs=configs,
            concurrency=int(payload.get("concurrency", 4)),
            save=payload.get("save"),
            stop_on_error=bool(payload.get("stopOnError", True)),
            include_results=bool(payload.get("includeResults", True)),
        )
    except Exception as exc:
        return JSONResponse({"ok": False, "error": f"执行异常: {exc}"}, status_code=200)
    return _safe_json(raw)


# ---------------------------------------------------------------------------
# Excel 导入
# ---------------------------------------------------------------------------

DEVICE_KEYS = ("设备", "device", "名称", "name", "主机", "hostname", "主机名")
COMMAND_KEYS = ("命令", "配置", "command", "config", "脚本", "script", "cli")
MODEL_KEYS = ("型号", "model", "类型", "type", "设备类型")
ROLE_KEYS = ("角色", "role", "用途", "备注", "remark")

# 只有名字命中这些词的 sheet 才当作「设备 + 命令」来解析，
# 避免把「地址规划」「验证清单」这类说明表误当成设备
CONFIG_SHEET_HINTS = ("设备", "命令", "配置", "device", "command", "config", "cli")


def _is_config_sheet(title: str) -> bool:
    t = (title or "").lower()
    return any(h in t for h in CONFIG_SHEET_HINTS)


def _pick_columns(header: list[str]) -> dict:
    mapping = {"device": None, "commands": [], "model": None, "role": None}
    used = set()
    for i, raw in enumerate(header):
        h = (raw or "").strip().lower()
        if not h:
            continue
        if mapping["device"] is None and any(k in h for k in DEVICE_KEYS):
            mapping["device"] = i
            used.add(i)
        elif mapping["model"] is None and any(k in h for k in MODEL_KEYS):
            mapping["model"] = i
            used.add(i)
        elif mapping["role"] is None and any(k in h for k in ROLE_KEYS):
            mapping["role"] = i
            used.add(i)
    for i, raw in enumerate(header):
        if i in used:
            continue
        h = (raw or "").strip().lower()
        if any(k in h for k in COMMAND_KEYS):
            mapping["commands"].append(i)
    if mapping["device"] is None:
        mapping["device"] = 0
        used.add(0)
        # 只有「整表没有表头特征」时才把其余列都当命令；
        # 表头明确是设备清单但没有命令列时，保持 commands 为空
        if not mapping["commands"]:
            mapping["commands"] = [i for i in range(len(header)) if i not in used]
    return mapping


def _parse_workbook(path: Path) -> dict:
    from openpyxl import load_workbook

    wb = load_workbook(path, data_only=True, read_only=True)
    devices: dict[str, dict] = {}
    sheets_out: list[dict] = []

    all_sheets = list(wb.worksheets)
    targets = [ws for ws in all_sheets if _is_config_sheet(ws.title)]
    skipped = [ws.title for ws in all_sheets if ws not in targets]
    if not targets:
        # 名字都不像配置表时退回旧行为：所有 sheet 都尝试解析
        targets, skipped = all_sheets, []

    for ws in targets:
        rows: list[list[str]] = []
        for row in ws.iter_rows(values_only=True):
            vals = ["" if c is None else str(c).strip() for c in row]
            while vals and vals[-1] == "":
                vals.pop()
            if any(vals):
                rows.append(vals)
        if not rows:
            continue

        header = rows[0]
        mapping = _pick_columns(header)

        # 判断第一行是表头还是数据
        headerish = any(
            any(k in (c or "").lower() for k in DEVICE_KEYS + COMMAND_KEYS + MODEL_KEYS)
            for c in header
        )
        body = rows[1:] if headerish else rows

        sheet_devices = 0
        for vals in body:
            def cell(idx):
                return vals[idx] if idx is not None and idx < len(vals) else ""

            name = cell(mapping["device"]).strip()
            if not name:
                continue
            entry = devices.setdefault(
                name, {"name": name, "model": "", "role": "", "commands": [], "sheets": []}
            )
            model = cell(mapping["model"]).strip()
            if model and not entry["model"]:
                entry["model"] = model
            role = cell(mapping["role"]).strip()
            if role and not entry["role"]:
                entry["role"] = role

            for idx in mapping["commands"]:
                cmd = cell(idx).strip()
                if cmd:
                    entry["commands"].append(cmd)
            if ws.title not in entry["sheets"]:
                entry["sheets"].append(ws.title)
            sheet_devices += 1

        sheets_out.append(
            {
                "name": ws.title,
                "rowCount": len(rows),
                "headerDetected": headerish,
                "header": header,
                "columns": {
                    "device": mapping["device"],
                    "commands": mapping["commands"],
                    "model": mapping["model"],
                },
                "devices": sheet_devices,
            }
        )

    wb.close()

    total_cmds = sum(len(d["commands"]) for d in devices.values())
    return {
        "ok": True,
        "sheets": sheets_out,
        "skippedSheets": skipped,
        "devices": list(devices.values()),
        "deviceCount": len(devices),
        "commandCount": total_cmds,
    }


def _parse_csv(path: Path) -> dict:
    """CSV 版本：单表，表头识别规则与 xlsx 一致。"""
    import csv as _csv

    raw = path.read_text(encoding="utf-8-sig", errors="replace")
    head = raw[:4096]
    delimiter = ","
    for cand in (",", ";", "\t"):
        if head.count(cand) > head.count(delimiter):
            delimiter = cand

    rows: list[list[str]] = []
    for line in _csv.reader(raw.splitlines(), delimiter=delimiter):
        vals = ["" if c is None else str(c).strip() for c in line]
        while vals and vals[-1] == "":
            vals.pop()
        if any(vals):
            rows.append(vals)

    devices: dict[str, dict] = {}
    sheets_out: list[dict] = []
    if rows:
        header = rows[0]
        mapping = _pick_columns(header)
        headerish = any(
            any(k in (c or "").lower() for k in DEVICE_KEYS + COMMAND_KEYS + MODEL_KEYS)
            for c in header
        )
        body = rows[1:] if headerish else rows
        count = 0
        for vals in body:
            def cell(idx):
                return vals[idx] if idx is not None and idx < len(vals) else ""

            name = cell(mapping["device"]).strip()
            if not name:
                continue
            entry = devices.setdefault(
                name, {"name": name, "model": "", "role": "", "commands": [], "sheets": []}
            )
            model = cell(mapping["model"]).strip()
            if model and not entry["model"]:
                entry["model"] = model
            role = cell(mapping["role"]).strip()
            if role and not entry["role"]:
                entry["role"] = role
            for idx in mapping["commands"]:
                cmd = cell(idx).strip()
                if cmd:
                    entry["commands"].append(cmd)
            if path.stem not in entry["sheets"]:
                entry["sheets"].append(path.stem)
            count += 1

        sheets_out.append(
            {
                "name": path.stem,
                "rowCount": len(rows),
                "headerDetected": headerish,
                "header": header,
                "columns": {
                    "device": mapping["device"],
                    "commands": mapping["commands"],
                    "model": mapping["model"],
                },
                "devices": count,
            }
        )

    total = sum(len(d["commands"]) for d in devices.values())
    return {
        "ok": True,
        "sheets": sheets_out,
        "skippedSheets": [],
        "devices": list(devices.values()),
        "deviceCount": len(devices),
        "commandCount": total,
    }


@app.post("/api/excel/parse")
async def api_excel_parse(file: UploadFile = File(...)):
    dest, original = _save_upload(file, UPLOADS, (".xlsx", ".xlsm", ".csv"))
    try:
        if dest.suffix.lower() == ".csv":
            result = await run_in_threadpool(lambda: _parse_csv(dest))
        else:
            result = await run_in_threadpool(lambda: _parse_workbook(dest))
    except Exception as exc:
        raise HTTPException(400, f"Excel 解析失败: {exc}")
    result["path"] = str(dest)
    result["name"] = original
    STATE["excel"] = result
    _persist()
    return result


@app.get("/api/excel/load")
async def api_excel_load(path: str):
    target = Path(path)
    if not target.exists():
        raise HTTPException(404, f"文件不存在: {path}")
    if target.suffix.lower() not in (".xlsx", ".xlsm"):
        raise HTTPException(400, "只支持 .xlsx / .xlsm 文件")
    try:
        result = await run_in_threadpool(lambda: _parse_workbook(target))
    except Exception as exc:
        raise HTTPException(400, f"Excel 解析失败: {exc}")
    result["path"] = str(target)
    result["name"] = target.name
    return result


@app.get("/api/demo/excel")
async def api_demo_excel():
    sample = ROOT / "samples" / "设备与命令示例.xlsx"
    if not sample.exists():
        raise HTTPException(404, "示例文件不存在，请先运行 samples/make_sample.py")
    result = await run_in_threadpool(lambda: _parse_workbook(sample))
    result["path"] = str(sample)
    result["name"] = sample.name
    return result


# ---------------------------------------------------------------------------
# 任务书
# ---------------------------------------------------------------------------

@app.post("/api/brief/upload")
async def api_brief_upload(file: UploadFile = File(...)):
    dest, original = _save_upload(file, UPLOADS, (".txt", ".md", ".docx", ".pdf"))
    try:
        text, kind = await run_in_threadpool(lambda: extract_text(dest))
    except Exception as exc:
        raise HTTPException(400, f"任务书解析失败: {exc}")

    if not text.strip():
        raise HTTPException(400, "没有提取到文字，可能是扫描件或空文档")

    info = await run_in_threadpool(lambda: analyse(text))
    skeleton = await run_in_threadpool(lambda: build_skeleton(info["devices"], info))

    STATE["brief"] = {
        "name": original,
        "path": str(dest),
        "kind": kind,
        "text": text,
        "analysis": info,
    }
    _persist()

    return {
        "ok": True,
        "name": original,
        "path": str(dest),
        "kind": kind,
        "text": text[:80000],
        "truncated": len(text) > 80000,
        "analysis": info,
        "skeleton": skeleton,
    }


@app.get("/api/brief/state")
async def api_brief_state():
    brief = STATE.get("brief")
    if not brief:
        return {"ok": True, "brief": None}
    info = brief.get("analysis") or {}
    skeleton = await run_in_threadpool(
        lambda: build_skeleton(info.get("devices") or [], info)
    )
    return {
        "ok": True,
        "brief": {
            "name": brief["name"],
            "kind": brief["kind"],
            "text": brief["text"][:80000],
            "analysis": info,
            "skeleton": skeleton,
        },
    }


# ---------------------------------------------------------------------------
# 执行记录
# ---------------------------------------------------------------------------

@app.get("/api/history")
async def api_history(limit: int = 600, device: str = ""):
    from ensp_mcp.commandlog import load as load_log

    entries = await run_in_threadpool(lambda: load_log(limit=limit, device=device))
    if not entries:
        return {"ok": True, "total": 0, "batches": []}

    grouped: dict[str, dict] = {}
    for entry in entries:
        key = str(entry.get("batch") or entry.get("ts") or "")
        bucket = grouped.get(key)
        if bucket is None:
            bucket = grouped[key] = {
                "batch": key,
                "ts": entry.get("ts"),
                "tool": entry.get("tool") or "",
                "topo": entry.get("topo") or "",
                "devices": {},
                "commandCount": 0,
                "okCount": 0,
                "failCount": 0,
            }

        dev_name = str(entry.get("device") or "?")
        dev = bucket["devices"].get(dev_name)
        if dev is None:
            dev = bucket["devices"][dev_name] = {
                "device": dev_name,
                "port": entry.get("port"),
                "commands": [],
                "okCount": 0,
                "failCount": 0,
            }

        ok = bool(entry.get("ok"))
        dev["commands"].append(
            {
                "command": entry.get("command") or "",
                "ok": ok,
                "error": entry.get("error"),
                "view": entry.get("view") or "",
                "output": (entry.get("output") or "")[:4000],
            }
        )
        dev["okCount" if ok else "failCount"] += 1
        bucket["commandCount"] += 1
        bucket["okCount" if ok else "failCount"] += 1

    batches = []
    for bucket in grouped.values():
        bucket["deviceList"] = sorted(
            bucket.pop("devices").values(), key=lambda d: str(d["device"])
        )
        bucket["deviceCount"] = len(bucket["deviceList"])
        batches.append(bucket)

    batches.sort(key=lambda b: str(b.get("ts") or ""), reverse=True)
    batches = batches[:60]

    return {
        "ok": True,
        "total": len(entries),
        "batchCount": len(batches),
        "batches": batches,
    }


# ---------------------------------------------------------------------------
# 设备巡检
# ---------------------------------------------------------------------------

@app.post("/api/inspect/run")
async def api_inspect_run(payload: dict):
    try:
        result = await run_inspection(payload)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    except Exception as exc:
        raise HTTPException(500, f"巡检执行失败: {exc}")

    run_id = uuid.uuid4().hex[:10]
    result["runId"] = run_id
    runs = STATE.setdefault("inspectRuns", {})
    runs[run_id] = result
    while len(runs) > 5:
        runs.pop(next(iter(runs)), None)
    STATE["lastRunId"] = run_id
    persistence.save_run(run_id, result)
    _persist()
    return result


@app.get("/api/inspect/last")
async def api_inspect_last():
    runs = STATE.get("inspectRuns") or {}
    if runs:
        return {"ok": True, "result": list(runs.values())[-1]}
    last = STATE.get("lastRunId")
    if last:
        data = await run_in_threadpool(lambda: persistence.load_run(str(last)))
        if data:
            return {"ok": True, "result": data}
    return {"ok": True, "result": None}


# ---------------------------------------------------------------------------
# 智能运维（AIOps）
# ---------------------------------------------------------------------------

@app.get("/api/aiops/overview")
async def api_aiops_overview():
    data = await run_in_threadpool(lambda: build_overview(STATE.get("inspect"), topo_name=STATE.get("topoName") or ""))
    return data


@app.get("/api/aiops/report")
async def api_aiops_report():
    data = await run_in_threadpool(lambda: build_overview(STATE.get("inspect"), topo_name=STATE.get("topoName") or ""))
    html = build_report(data)
    name = f"aiops-report-{datetime.now().strftime('%Y%m%d-%H%M%S')}.html"
    return Response(
        html,
        media_type="text/html; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{name}"'},
    )


@app.post("/api/aiops/events/ack")
async def api_aiops_ack(payload: dict):
    event_id = payload.get("id")
    status = payload.get("status") or "ack"
    if not event_id:
        raise HTTPException(400, "缺少事件 id")
    if status not in ("open", "ack", "ignored"):
        raise HTTPException(400, "status 只能是 open / ack / ignored")
    save_ack(str(event_id), status, str(payload.get("note") or ""))
    return {"ok": True}


@app.get("/api/aiops/rules")
async def api_aiops_rules_get():
    return {"ok": True, "rules": load_rules()}


@app.put("/api/aiops/rules")
async def api_aiops_rules_put(payload: dict):
    rules = payload.get("rules")
    if not isinstance(rules, list):
        raise HTTPException(400, "rules 必须是数组")
    try:
        cleaned = save_rules(rules)
    except re.error as exc:
        raise HTTPException(400, f"正则表达式不合法: {exc}")
    return {"ok": True, "rules": cleaned}


# ---------------------------------------------------------------------------
# 定时巡检
# ---------------------------------------------------------------------------

@app.get("/api/scheduler")
async def api_scheduler_get():
    import scheduler

    return {"ok": True, **scheduler.status()}


@app.post("/api/scheduler")
async def api_scheduler_set(payload: dict):
    import scheduler

    cfg = scheduler.load()
    for key in ("enabled", "intervalMinutes", "devices", "commands", "concurrency", "timeout"):
        if key in payload:
            cfg[key] = payload[key]
    if int(cfg.get("intervalMinutes") or 0) < 1:
        raise HTTPException(400, "巡检间隔至少 1 分钟")
    scheduler.save(cfg)
    return {"ok": True, **scheduler.status()}


@app.post("/api/scheduler/run")
async def api_scheduler_run():
    import scheduler

    result = await scheduler.run_once("manual")
    if not result.get("ok"):
        raise HTTPException(400, result.get("error") or "执行失败")
    return result


# ---------------------------------------------------------------------------
# 日志审计
# ---------------------------------------------------------------------------

def _log_targets(payload: dict) -> list[dict]:
    devices = payload.get("devices") or []
    if not devices:
        devices = [
            {
                "name": d.get("name"),
                "host": "127.0.0.1",
                "port": d.get("consolePort"),
                "model": d.get("model"),
            }
            for d in ((STATE.get("inspect") or {}).get("devices") or [])
            if d.get("consolePort")
        ]
    return devices


@app.get("/api/logs/state")
async def api_logs_state():
    import logaudit

    entries = STATE.get("logEntries") or []
    return {
        "ok": True,
        "count": len(entries),
        "entries": entries[-800:],
        "summary": logaudit.summarise(entries),
        "meta": STATE.get("logMeta") or {},
        "audit": STATE.get("logAudit"),
    }


@app.post("/api/logs/collect")
async def api_logs_collect(payload: dict):
    import logaudit

    devices = _log_targets(payload)
    if not devices:
        raise HTTPException(400, "没有可采集的设备（先载入拓扑或手动添加）")
    result = await logaudit.collect(
        devices,
        timeout=float(payload.get("timeout") or 20),
        concurrency=int(payload.get("concurrency") or 4),
    )
    STATE["logEntries"] = result["entries"]
    STATE["logFiltered"] = result["entries"]
    STATE["logMeta"] = {
        "source": "在线采集",
        "collectedAt": datetime.now().isoformat(timespec="seconds"),
        "devices": [d["device"] for d in result["devices"] if d.get("ok")],
        "sourceDevices": result["devices"],
    }
    _persist_logs()
    return {
        "ok": True,
        "count": len(result["entries"]),
        "devices": result["devices"],
        "summary": logaudit.summarise(result["entries"]),
        "entries": result["entries"][-800:],
    }


@app.post("/api/logs/filter")
async def api_logs_filter(payload: dict):
    import logaudit

    entries = STATE.get("logEntries") or []
    filtered = logaudit.filter_entries(
        entries,
        device=str(payload.get("device") or ""),
        severity=str(payload.get("severity") or ""),
        keyword=str(payload.get("keyword") or ""),
    )
    STATE["logFiltered"] = filtered
    return {
        "ok": True,
        "count": len(filtered),
        "summary": logaudit.summarise(filtered),
        "entries": filtered[-800:],
    }


@app.get("/api/logs/export")
async def api_logs_export(format: str = "csv", scope: str = "filtered"):
    import logaudit

    entries = STATE.get("logFiltered") if scope == "filtered" else STATE.get("logEntries")
    entries = entries or []
    if not entries:
        raise HTTPException(400, "没有可导出的日志")
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    if format == "txt":
        body = logaudit.to_txt(entries)
        media = "text/plain; charset=utf-8"
        name = f"device-logs-{stamp}.txt"
        payload = body.encode("utf-8")
    elif format == "json":
        body = json.dumps(entries, ensure_ascii=False, indent=1)
        media = "application/json; charset=utf-8"
        name = f"device-logs-{stamp}.json"
        payload = body.encode("utf-8")
    else:
        body = logaudit.to_csv(entries)
        media = "text/csv; charset=utf-8"
        name = f"device-logs-{stamp}.csv"
        payload = ("\ufeff" + body).encode("utf-8")
    return Response(
        payload,
        media_type=media,
        headers={"Content-Disposition": f'attachment; filename="{name}"'},
    )


@app.post("/api/logs/audit")
async def api_logs_audit(payload: dict):
    import logaudit

    scope = payload.get("scope") or "filtered"
    entries = STATE.get("logFiltered") if scope == "filtered" else STATE.get("logEntries")
    if not entries:
        raise HTTPException(400, "没有可审计的日志，先采集或导入")
    meta = dict(STATE.get("logMeta") or {})
    meta["source"] = meta.get("source") or "在线采集"
    result = logaudit.audit(entries, meta)
    STATE["logAudit"] = result
    _persist_logs()
    return result


@app.post("/api/logs/audit/upload")
async def api_logs_audit_upload(file: UploadFile = File(...)):
    import logaudit

    raw = file.file.read()
    if not raw:
        raise HTTPException(400, "文件是空的")
    if len(raw) > MAX_UPLOAD:
        raise HTTPException(413, "文件超过 30MB")
    text = None
    for encoding in ("utf-8-sig", "utf-8", "gbk"):
        try:
            text = raw.decode(encoding)
            break
        except Exception:
            continue
    if text is None:
        raise HTTPException(400, "无法识别文件编码，请用 UTF-8 或 GBK 保存")

    original = Path(file.filename or "upload.csv").name
    entries = logaudit.from_file(original, text)
    if not entries:
        raise HTTPException(400, "没有从文件里解析出日志，请确认是导出文件或 logbuffer 原始文本")
    meta = {
        "source": "文件导入",
        "fileName": original,
        "devices": sorted({e.get("device") for e in entries if e.get("device")}),
    }
    result = logaudit.audit(entries, meta)
    STATE["logEntries"] = entries
    STATE["logFiltered"] = entries
    STATE["logMeta"] = meta
    STATE["logAudit"] = result
    _persist_logs()
    return result


@app.get("/api/logs/report")
async def api_logs_report():
    import logaudit

    data = STATE.get("logAudit")
    if not data:
        raise HTTPException(400, "还没有审计结果")
    html = logaudit.build_report(data)
    name = f"log-audit-{datetime.now().strftime('%Y%m%d-%H%M%S')}.html"
    return Response(
        html,
        media_type="text/html; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{name}"'},
    )


@app.get("/api/inspect/export")
async def api_inspect_export(runId: str, format: str = "csv", detail: int = 0):
    result = (STATE.get("inspectRuns") or {}).get(runId)
    if not result:
        raise HTTPException(404, "巡检结果不存在或已过期，请重新巡检")

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")

    if format == "json":
        body = json.dumps(result, ensure_ascii=False, indent=2)
        return Response(
            body,
            media_type="application/json; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="inspection-{stamp}.json"'},
        )

    if detail:
        rows = to_detail_rows(result)
        header = ["设备", "地址", "指标", "值", "单位", "状态"]
        suffix = "detail"
    else:
        rows = to_summary_rows(result)
        header = [label for _, label in SUMMARY_COLUMNS]
        suffix = "summary"

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(header)
    writer.writerows(rows)
    content = "\ufeff" + buffer.getvalue()  # BOM，Excel 打开中文不乱码

    return Response(
        content,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="inspection-{stamp}-{suffix}.csv"'},
    )


# ---------------------------------------------------------------------------
# 网络工具
# ---------------------------------------------------------------------------

def _tool_error(exc: Exception) -> HTTPException:
    if isinstance(exc, ValueError):
        return HTTPException(400, str(exc))
    return HTTPException(500, f"执行失败: {exc}")


@app.post("/api/tools/ping")
async def api_tools_ping(payload: dict):
    try:
        return await run_in_threadpool(
            lambda: run_ping(
                payload.get("host", ""),
                int(payload.get("count") or 4),
                int(payload.get("timeoutMs") or 1000),
                int(payload.get("size") or 32),
            )
        )
    except Exception as exc:
        raise _tool_error(exc)


@app.post("/api/tools/traceroute")
async def api_tools_traceroute(payload: dict):
    try:
        return await run_in_threadpool(
            lambda: run_traceroute(
                payload.get("host", ""),
                int(payload.get("maxHops") or 16),
                int(payload.get("timeoutMs") or 1000),
            )
        )
    except Exception as exc:
        raise _tool_error(exc)


@app.post("/api/tools/portscan")
async def api_tools_portscan(payload: dict):
    try:
        host = payload.get("host", "")
        preset = payload.get("preset") or ""
        if preset and preset in PRESETS:
            ports = PRESETS[preset]
        else:
            ports = parse_port_spec(payload.get("ports") or "22,80,443")
        return await run_port_scan(
            host,
            ports,
            float(payload.get("timeout") or 1.0),
            int(payload.get("concurrency") or 200),
        )
    except Exception as exc:
        raise _tool_error(exc)


@app.post("/api/tools/dns")
async def api_tools_dns(payload: dict):
    try:
        return await run_in_threadpool(
            lambda: run_dns_query(
                payload.get("name", ""),
                payload.get("type", "A"),
                payload.get("server", ""),
                float(payload.get("timeout") or 5),
            )
        )
    except Exception as exc:
        raise _tool_error(exc)


@app.post("/api/tools/subnet")
async def api_tools_subnet(payload: dict):
    try:
        return await run_in_threadpool(lambda: subnet_calc(payload.get("cidr", "")))
    except Exception as exc:
        raise _tool_error(exc)


@app.post("/api/tools/subnet-split")
async def api_tools_subnet_split(payload: dict):
    try:
        return await run_in_threadpool(
            lambda: subnet_split(
                payload.get("cidr", ""),
                int(payload.get("newPrefix") or 24),
                int(payload.get("limit") or 128),
            )
        )
    except Exception as exc:
        raise _tool_error(exc)


@app.post("/api/tools/speedtest")
async def api_tools_speedtest(payload: dict):
    try:
        return await run_in_threadpool(
            lambda: run_speed_test(
                payload.get("url", ""),
                float(payload.get("duration") or 6),
            )
        )
    except Exception as exc:
        raise _tool_error(exc)


@app.post("/api/tools/pcap")
async def api_tools_pcap(file: UploadFile = File(...)):
    data = file.file.read()
    if not data:
        raise HTTPException(400, "文件是空的")
    if len(data) > 80 * 1024 * 1024:
        raise HTTPException(413, "pcap 超过 80MB")
    try:
        result = await run_in_threadpool(lambda: analyze_pcap(data))
    except Exception as exc:
        raise _tool_error(exc)
    result["name"] = Path(file.filename or "capture.pcap").name
    return result


# ---------------------------------------------------------------------------
# 配置运维
# ---------------------------------------------------------------------------

@app.post("/api/backup/run")
async def api_backup_run(payload: dict):
    devices = payload.get("devices") or []
    try:
        result = await run_backup(
            devices,
            payload.get("username") or "",
            payload.get("password") or "",
            int(payload.get("concurrency") or 4),
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    except Exception as exc:
        raise HTTPException(500, f"备份失败: {exc}")

    if result.get("folder"):
        STATE["backupFolder"] = result["folder"]
        _persist()
    return result


@app.get("/api/backup/list")
async def api_backup_list():
    return await run_in_threadpool(list_backups)


@app.get("/api/backup/file")
async def api_backup_file(path: str):
    try:
        return await run_in_threadpool(lambda: read_config(path))
    except ValueError as exc:
        raise HTTPException(400, str(exc))


@app.get("/api/backup/diff")
async def api_backup_diff(a: str, b: str):
    try:
        return await run_in_threadpool(lambda: diff_configs(a, b))
    except ValueError as exc:
        raise HTTPException(400, str(exc))


@app.post("/api/matrix/ping")
async def api_matrix_ping(payload: dict):
    try:
        return await run_matrix(
            payload.get("devices") or [],
            payload.get("targets") or [],
            payload.get("username") or "",
            payload.get("password") or "",
            int(payload.get("concurrency") or 4),
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    except Exception as exc:
        raise HTTPException(500, f"矩阵执行失败: {exc}")


@app.get("/api/storage")
async def api_storage():
    def stat():
        data_dir = ROOT / "data"
        result = {}
        for name in ("uploads", "renders", "backups", "runs"):
            folder = data_dir / name
            if not folder.exists():
                result[name] = {"count": 0, "bytes": 0}
                continue
            files = [p for p in folder.rglob("*") if p.is_file()]
            result[name] = {
                "count": len(files),
                "bytes": sum(p.stat().st_size for p in files),
            }
        return result

    stats = await run_in_threadpool(stat)
    return {"ok": True, "folders": stats}


@app.post("/api/storage/clean")
async def api_storage_clean(payload: dict):
    keep = max(1, min(50, int(payload.get("keep") or 5)))

    def clean() -> dict:
        protected = set()
        for key in ("topo", "brief"):
            value = STATE.get(key)
            if isinstance(value, dict):
                value = value.get("path")
            if value:
                try:
                    protected.add(Path(value).resolve())
                except Exception:
                    pass

        removed = 0
        freed = 0
        files = sorted(
            [p for p in UPLOADS.glob("*") if p.is_file()], key=lambda p: p.stat().st_mtime
        )
        for old in files[:-keep]:
            try:
                if old.resolve() in protected:
                    continue
                size = old.stat().st_size
                old.unlink()
                removed += 1
                freed += size
            except Exception:
                pass

        renders = sorted(
            [p for p in RENDERS.glob("*") if p.is_file()], key=lambda p: p.stat().st_mtime
        )
        for old in renders[:-keep]:
            try:
                size = old.stat().st_size
                old.unlink()
                removed += 1
                freed += size
            except Exception:
                pass

        return {"removed": removed, "bytesFreed": freed}

    result = await run_in_threadpool(clean)
    return {"ok": True, **result}


# ---------------------------------------------------------------------------
# 静态资源
# ---------------------------------------------------------------------------

app.mount("/", StaticFiles(directory=str(ROOT / "web"), html=True), name="web")
