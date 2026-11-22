"""定时巡检调度器。

服务进程内常驻一个轻量循环：每隔 10 秒检查一次配置，到点就复用巡检引擎跑一轮，
结果写入 data/runs，并回调通知 app 更新内存状态。服务没开就不会执行——这是本地
控制台，不引入额外的系统服务或计划任务。
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parent
CONFIG_FILE = ROOT / "data" / "scheduler.json"

DEFAULT_COMMANDS = [
    "display version",
    "display cpu-usage",
    "display memory-usage",
    "display interface brief",
    "display transceiver diagnosis interface",
]

_state: dict[str, Any] = {"task": None, "running": False, "on_run": None}


def defaults() -> dict:
    return {
        "enabled": False,
        "intervalMinutes": 60,
        "devices": [],
        "commands": DEFAULT_COMMANDS,
        "concurrency": 5,
        "timeout": 20,
        "lastRunAt": None,
        "lastRunAtTs": 0,
        "lastRunId": None,
        "lastSummary": None,
        "lastError": None,
    }


def load() -> dict:
    cfg = defaults()
    if CONFIG_FILE.exists():
        try:
            data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                cfg.update({k: v for k, v in data.items() if k in cfg})
        except Exception:
            pass
    return cfg


def save(cfg: dict) -> dict:
    merged = defaults()
    merged.update({k: v for k, v in cfg.items() if k in merged})
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(merged, ensure_ascii=False, indent=1), encoding="utf-8")
    return merged


def status() -> dict:
    cfg = load()
    interval = max(1, int(cfg.get("intervalMinutes") or 60))
    last = float(cfg.get("lastRunAtTs") or 0)
    due = last + interval * 60
    remain = max(0, int(due - time.time())) if cfg.get("enabled") else None
    return {
        "config": cfg,
        "running": _state["running"],
        "nextRunAt": (
            datetime.fromtimestamp(due).isoformat(timespec="seconds") if cfg.get("enabled") else None
        ),
        "nextInSeconds": remain,
    }


async def run_once(reason: str = "manual") -> dict:
    """跑一轮巡检；reason 只用于日志/返回标识。"""
    if _state["running"]:
        return {"ok": False, "error": "上一轮巡检还在执行"}
    from patrol import run_inspection

    import persistence

    cfg = load()
    devices = cfg.get("devices") or []
    if not devices:
        cfg["lastError"] = "没有配置巡检设备"
        save(cfg)
        return {"ok": False, "error": cfg["lastError"]}

    _state["running"] = True
    started = time.time()
    try:
        result = await run_inspection(
            {
                "devices": devices,
                "commands": cfg.get("commands") or DEFAULT_COMMANDS,
                "concurrency": int(cfg.get("concurrency") or 5),
                "timeout": float(cfg.get("timeout") or 20),
            }
        )
        run_id = uuid.uuid4().hex[:10]
        result["runId"] = run_id
        result["trigger"] = reason
        persistence.save_run(run_id, result)

        cfg["lastRunAt"] = datetime.now().isoformat(timespec="seconds")
        cfg["lastRunAtTs"] = time.time()
        cfg["lastRunId"] = run_id
        cfg["lastSummary"] = result.get("summary")
        cfg["lastError"] = None
        save(cfg)

        callback = _state.get("on_run")
        if callback:
            try:
                callback(result)
            except Exception:
                pass
        return {"ok": True, "runId": run_id, "summary": result.get("summary"), "elapsed": round(time.time() - started, 1)}
    except Exception as exc:
        cfg["lastError"] = str(exc)
        save(cfg)
        return {"ok": False, "error": str(exc)}
    finally:
        _state["running"] = False


async def _loop() -> None:
    while True:
        await asyncio.sleep(10)
        try:
            cfg = load()
            if not cfg.get("enabled") or _state["running"]:
                continue
            interval = max(1, int(cfg.get("intervalMinutes") or 60))
            last = float(cfg.get("lastRunAtTs") or 0)
            if time.time() - last >= interval * 60:
                await run_once("scheduled")
        except asyncio.CancelledError:
            return
        except Exception:
            continue


def start(on_run: Callable[[dict], None] | None = None) -> None:
    _state["on_run"] = on_run
    if _state["task"] and not _state["task"].done():
        return
    try:
        _state["task"] = asyncio.get_running_loop().create_task(_loop())
    except RuntimeError:
        _state["task"] = None
