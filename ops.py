"""配置运维：批量备份配置、配置差异对比、设备间连通性矩阵。"""

from __future__ import annotations

import asyncio
import difflib
import re
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BACKUP_DIR = ROOT / "data" / "backups"


# ---------------------------------------------------------------------------
# 设备连接
# ---------------------------------------------------------------------------

async def _open_console(host: str, port: int, username: str, password: str, timeout: float = 8.0):
    from patrol import open_console

    return await open_console(host, port, username, password, timeout=timeout)


# ---------------------------------------------------------------------------
# 配置备份
# ---------------------------------------------------------------------------

async def _backup_one(device: dict, username: str, password: str, timeout: float) -> dict:
    from patrol import console_send

    started = time.monotonic()
    result = {
        "device": device.get("name"),
        "host": device.get("host"),
        "port": device.get("port"),
        "ok": False,
        "error": None,
        "config": "",
    }
    console = None
    try:
        console = await _open_console(device["host"], device["port"], username, password)
        try:
            await console.to_user_view()
        except Exception:
            pass
        text = await console_send(console, "display current-configuration", timeout)
        result["config"] = text or ""
        result["ok"] = bool(result["config"].strip())
        if not result["ok"]:
            result["error"] = "没有取到配置内容"
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


async def run_backup(
    devices: list[dict], username: str = "", password: str = "", concurrency: int = 4
) -> dict:
    if not devices:
        raise ValueError("没有要备份的设备")

    concurrency = max(1, min(8, int(concurrency)))
    semaphore = asyncio.Semaphore(concurrency)

    async def one(dev: dict):
        async with semaphore:
            return await _backup_one(dev, username, password, 45)

    results = await asyncio.gather(*(one(d) for d in devices))

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    folder = BACKUP_DIR / stamp
    folder.mkdir(parents=True, exist_ok=True)

    saved = []
    for item in results:
        if not item["ok"]:
            continue
        name = re.sub(r"[^\w\-.]+", "_", str(item["device"] or "device"))
        path = folder / f"{name}.cfg"
        try:
            path.write_text(item["config"], encoding="utf-8")
            item["file"] = str(path)
            item["lines"] = len([l for l in item["config"].splitlines() if l.strip()])
            item["bytes"] = path.stat().st_size
            saved.append({"device": item["device"], "file": str(path), "lines": item["lines"]})
        except Exception as exc:
            item["ok"] = False
            item["error"] = f"写入文件失败: {exc}"

    succeeded = len(saved)
    return {
        "ok": succeeded > 0,
        "stamp": stamp,
        "folder": str(folder),
        "deviceCount": len(results),
        "succeeded": succeeded,
        "failed": len(results) - succeeded,
        "saved": saved,
        "devices": [
            {k: v for k, v in item.items() if k != "config"} for item in results
        ],
        "error": None if succeeded else "所有设备都没取到配置",
    }


def list_backups() -> dict:
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    folders = []
    for folder in sorted(BACKUP_DIR.iterdir(), key=lambda p: p.name, reverse=True):
        if not folder.is_dir():
            continue
        files = []
        for cfg in sorted(folder.glob("*.cfg")):
            stat = cfg.stat()
            files.append(
                {
                    "name": cfg.name,
                    "device": cfg.stem,
                    "path": str(cfg),
                    "bytes": stat.st_size,
                    "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                }
            )
        if files:
            folders.append({"stamp": folder.name, "path": str(folder), "files": files})
    return {"ok": True, "folders": folders, "folderCount": len(folders)}


def _safe_file(raw: str) -> Path:
    path = Path(raw).resolve()
    root = BACKUP_DIR.resolve()
    if root not in path.parents:
        raise ValueError("只能读取备份目录内的文件")
    if not path.exists():
        raise ValueError("备份文件不存在")
    return path


def read_config(raw: str, limit: int = 200_000) -> dict:
    path = _safe_file(raw)
    text = path.read_text(encoding="utf-8", errors="replace")
    truncated = len(text) > limit
    return {
        "ok": True,
        "name": path.name,
        "device": path.stem,
        "path": str(path),
        "text": text[:limit],
        "truncated": truncated,
        "lines": len(text.splitlines()),
    }


def diff_configs(path_a: str, path_b: str, context: int = 2) -> dict:
    file_a = _safe_file(path_a)
    file_b = _safe_file(path_b)

    lines_a = file_a.read_text(encoding="utf-8", errors="replace").splitlines()
    lines_b = file_b.read_text(encoding="utf-8", errors="replace").splitlines()

    diff = list(
        difflib.unified_diff(
            lines_a, lines_b, fromfile=file_a.name, tofile=file_b.name, lineterm="", n=context
        )
    )

    rows = []
    added = removed = 0
    for line in diff:
        if line.startswith("+++") or line.startswith("---"):
            rows.append({"type": "meta", "text": line})
        elif line.startswith("@@"):
            rows.append({"type": "hunk", "text": line})
        elif line.startswith("+"):
            added += 1
            rows.append({"type": "add", "text": line[1:]})
        elif line.startswith("-"):
            removed += 1
            rows.append({"type": "del", "text": line[1:]})
        else:
            rows.append({"type": "ctx", "text": line[1:] if line.startswith(" ") else line})

    return {
        "ok": True,
        "a": {"name": file_a.name, "path": str(file_a), "lines": len(lines_a)},
        "b": {"name": file_b.name, "path": str(file_b), "lines": len(lines_b)},
        "added": added,
        "removed": removed,
        "same": added == 0 and removed == 0,
        "rows": rows[:4000],
        "truncated": len(rows) > 4000,
    }


# ---------------------------------------------------------------------------
# 连通性矩阵
# ---------------------------------------------------------------------------

PING_RECEIVED = re.compile(r"(\d+)\s+packet\(s\)\s+received", re.I)
PING_LOSS = re.compile(r"([\d.]+)%\s*packet\s*loss", re.I)


def _ping_ok(output: str) -> bool | None:
    m = PING_RECEIVED.search(output or "")
    if m:
        return int(m.group(1)) > 0
    m = PING_LOSS.search(output or "")
    if m:
        return float(m.group(1)) < 100
    return None


async def _ping_from(device: dict, target: str, username: str, password: str) -> dict:
    started = time.monotonic()
    console = None
    row = {"device": device.get("name"), "target": target, "ok": None, "error": None}
    try:
        console = await _open_console(device["host"], device["port"], username, password, timeout=8)
        text = await console.send(f"ping -c 1 -w 1000 {target}", timeout=12)
        row["ok"] = _ping_ok(text)
        if row["ok"] is None:
            row["error"] = "无法解析 ping 结果"
        row["output"] = (text or "")[:800]
    except Exception as exc:
        row["error"] = str(exc)
    finally:
        if console is not None:
            try:
                await console.close()
            except Exception:
                pass
        row["elapsedMs"] = max(1, int((time.monotonic() - started) * 1000))
    return row


async def run_matrix(
    devices: list[dict],
    targets: list[dict],
    username: str = "",
    password: str = "",
    concurrency: int = 4,
) -> dict:
    if not devices or not targets:
        raise ValueError("设备列表和目标地址都不能为空")
    if len(devices) * len(targets) > 64:
        raise ValueError(f"设备 × 目标 = {len(devices) * len(targets)}，超过 64 次上限，请减少数量")

    concurrency = max(1, min(8, int(concurrency)))
    semaphore = asyncio.Semaphore(concurrency)

    async def one(dev: dict, target: dict):
        async with semaphore:
            return await _ping_from(dev, target["ip"], username, password)

    tasks = [one(dev, target) for dev in devices for target in targets]
    results = await asyncio.gather(*tasks)

    lookup = {(r["device"], r["target"]): r for r in results}
    rows = []
    reachable = 0
    total = 0
    for dev in devices:
        cells = []
        for target in targets:
            item = lookup.get((dev.get("name"), target["ip"])) or {}
            ok = item.get("ok")
            cells.append(
                {
                    "target": target["label"],
                    "ip": target["ip"],
                    "ok": ok,
                    "error": item.get("error"),
                    "elapsedMs": item.get("elapsedMs"),
                }
            )
            if ok is True:
                reachable += 1
            if ok is not None:
                total += 1
        rows.append({"device": dev.get("name"), "cells": cells})

    return {
        "ok": True,
        "rows": rows,
        "targets": targets,
        "reachable": reachable,
        "total": total,
        "deviceCount": len(devices),
        "targetCount": len(targets),
    }
