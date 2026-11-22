"""状态持久化：关键状态存到 data/state.json，重启后自动恢复。"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"
STATE_FILE = DATA / "state.json"
RUNS_DIR = DATA / "runs"

# 只持久化这些键，避免把临时对象写进去
PERSIST_KEYS = ("topo", "topoName", "inspect", "excel", "brief", "lastRunId", "backupFolder")


def load() -> dict:
    if not STATE_FILE.exists():
        return {}
    try:
        data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save(state: dict) -> None:
    DATA.mkdir(parents=True, exist_ok=True)
    payload = {k: state.get(k) for k in PERSIST_KEYS if state.get(k) is not None}
    tmp = STATE_FILE.with_suffix(".tmp")
    try:
        tmp.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        tmp.replace(STATE_FILE)
    except Exception:
        pass


def save_run(run_id: str, result: dict) -> None:
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    try:
        (RUNS_DIR / f"{run_id}.json").write_text(
            json.dumps(result, ensure_ascii=False), encoding="utf-8"
        )
        _prune_runs()
    except Exception:
        pass


def load_run(run_id: str) -> dict | None:
    path = RUNS_DIR / f"{run_id}.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _prune_runs(keep: int = 40) -> None:
    if not RUNS_DIR.exists():
        return
    files = sorted(RUNS_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime)
    for old in files[:-keep]:
        try:
            old.unlink()
        except Exception:
            pass
