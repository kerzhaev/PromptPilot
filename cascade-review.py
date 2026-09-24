#!/usr/bin/env python3
"""Cascade Review Engine — цепочка ревью-ступеней поверх REST API PromptPilot.

Спека: CASCADE_UI_PROTOTYPE.md §1.3 (утверждена 2026-09-24).

Автомат фаз на воркфлоу с config.review_chain:
    EXEC → GATE → REV-1 →(PASS)→ REV-2 →(PASS)→ ... → этап закрыт
                       │            │
                       └ REVISION: чинит указанный в слоте фиксер
                         (executor | self | provider id)

Слоты (из config.review_chain.steps):
  provider, fixer, blocking, max_rounds, on_exhaust,
  window {from,to,tz,outside: skip|always}

Движок агностичен к именам агентов — слоты заполняет пользователь.

Политики исчерпания лимита слота (on_exhaust):
  arbitrate_planner — планер получает оба ревью и выносит вердикт (v1: эскалация)
  accept_if_gate_green — принять этап, если последний гейт зелёный
  human — awaiting_human (штатно)

Запуск:  python cascade-review.py [workflow_id]
Без аргумента — обслуживает все воркфлоу с review_chain.enabled.
"""

import json
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

BASE_URL = "http://127.0.0.1:8420"
LOG_PATH = None  # задаётся в main
STATE_PATH = None

try:
    import os
    HOME = os.path.expanduser("~")
    LOG_PATH = os.path.join(HOME, ".promptpilot", "cascade-review.log")
    STATE_PATH = os.path.join(HOME, ".promptpilot", "cascade-review-state.json")
except Exception:
    pass

RESUME_TEXT = "Продолжить работу с учётом сохранённого состояния"


def log(message: str) -> None:
    line = f"{datetime.now().isoformat(timespec='seconds')} {message}"
    print(line, flush=True)
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError:
        pass


def load_state() -> dict:
    try:
        with open(STATE_PATH, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}


def save_state(state: dict) -> None:
    try:
        with open(STATE_PATH, "w", encoding="utf-8") as f:
            json.dump(state, f, ensure_ascii=False)
    except OSError:
        pass


def api(path: str, method: str = "GET", body: dict | None = None, timeout: int = 25):
    req = urllib.request.Request(
        BASE_URL + path,
        method=method,
        data=json.dumps(body).encode("utf-8") if body is not None else None,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def in_window(slot: dict, now_utc: datetime | None = None) -> bool:
    """Проверка ⏰-окна слота. Окна нет → всегда True (крыжик не стоит)."""
    window = slot.get("window")
    if not window:
        return True
    if now_utc is None:
        now_utc = datetime.now(timezone.utc)
    tz_offset = window.get("tz_offset_hours", 3)  # Europe/Moscow = UTC+3
    local_hour = (now_utc.hour + tz_offset) % 24
    frm, to = window.get("from", "22:00"), window.get("to", "04:00")
    fh, th = int(frm.split(":")[0]), int(to.split(":")[0])
    if fh <= th:
        return fh <= local_hour < th
    return local_hour >= fh or local_hour < th  # окно через полночь


def patch_role(workflow_id: str, role: str, provider: str, version: int) -> int:
    w = api(f"/api/workflows/{workflow_id}")
    cfg = w["config"]
    cfg.setdefault("roles", {}).setdefault(role, {})["provider"] = provider
    updated = api(f"/api/workflows/{workflow_id}", "PATCH",
                  {"config": cfg, "expected_version": version})
    return updated["state_version"]


def resume(workflow_id: str, version: int, note: str) -> bool:
    try:
        api(f"/api/workflows/{workflow_id}/human-input", "POST",
            {"expected_version": version, "text": RESUME_TEXT + "\n\n" + note,
             "resume": True})
        return True
    except urllib.error.HTTPError as e:
        if e.code != 409:
            log(f"  resume HTTP {e.code}")
        return False


def gate_green(workflow_id: str) -> bool:
    conn = None
    try:
        import sqlite3
        db = __import__("os").path.expanduser("~/.promptpilot/promptpilot.db")
        conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=5)
        row = conn.execute(
            "SELECT payload_json FROM workflow_events WHERE workflow_id=? "
            "AND event_type IN ('gate.passed','gate.failed') ORDER BY seq DESC LIMIT 1",
            (workflow_id,)).fetchone()
        return bool(row) and "gate.passed" in row[0]
    except Exception:
        return False
    finally:
        if conn:
            conn.close()


def last_review_event(workflow_id: str) -> tuple[str, str]:
    """(event_type, verdict) последнего ревью-события."""
    conn = None
    try:
        import sqlite3
        db = __import__("os").path.expanduser("~/.promptpilot/promptpilot.db")
        conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=5)
        row = conn.execute(
            "SELECT event_type, substr(payload_json,1,400) FROM workflow_events "
            "WHERE workflow_id=? AND event_type IN "
            "('review.revision_required','review.approved','review.awaiting_decision') "
            "ORDER BY seq DESC LIMIT 1", (workflow_id,)).fetchone()
        if not row:
            return "", ""
        verdict = ""
        if "PASS" in row[1].upper():
            verdict = "PASS"
        elif "REVISION_REQUIRED" in row[1].upper():
            verdict = "REVISION_REQUIRED"
        return row[0], verdict
    except Exception:
        return "", ""
    finally:
        if conn:
            conn.close()


def serve_workflow(wf_id: str, state: dict) -> None:
    wf = api(f"/api/workflows/{wf_id}")
    chain = (wf.get("config") or {}).get("review_chain") or {}
    if not chain.get("enabled"):
        return
    steps = chain.get("steps") or []
    if not steps:
        return
    status = wf.get("status")
    if status not in ("reviewing", "awaiting_human", "queued"):
        return

    key = wf_id
    pos = state.setdefault("chain_pos", {}).get(key, 0)  # индекс текущей ступени
    if pos >= len(steps):
        return
    slot = steps[pos]

    # ⏰ окно: вне окна ступень пропускается (не блокирует каскад)
    if not in_window(slot):
        log(f"{wf['slug']}: ступень {pos+1} вне окна — пропуск")
        state["chain_pos"][key] = pos + 1
        save_state(state)
        return

    event, verdict = last_review_event(wf_id)

    if status == "awaiting_human":
        # Ожидаем решения: REVISION → фикс по слоту; PASS → следующая ступень
        if verdict == "REVISION_REQUIRED" or event == "review.revision_required":
            rounds = state.setdefault("slot_rounds", {})
            rk = f"{key}:{pos}"
            rounds[rk] = rounds.get(rk, 0) + 1
            if rounds[rk] > slot.get("max_rounds", 2):
                policy = slot.get("on_exhaust", "arbitrate_planner")
                log(f"{wf['slug']}: слот {pos+1} лимит исчерпан → {policy}")
                if policy == "accept_if_gate_green" and gate_green(wf_id):
                    state["chain_pos"][key] = pos + 1
                    save_state(state)
                    return
                # arbitrate_planner / human → оставляем awaiting_human
                return
            fixer = slot.get("fixer", "executor")
            provider = (wf["config"]["roles"]["executor"]["provider"]
                        if fixer == "executor"
                        else slot["provider"] if fixer == "self"
                        else fixer)
            version = patch_role(wf_id, "executor", provider, wf["state_version"])
            if resume(wf_id, version,
                      f"(каскад: находки Ревью-{pos+1} чинит {provider})"):
                log(f"{wf['slug']}: Ревью-{pos+1} REVISION → фикс {provider} "
                    f"(раунд {rounds[rk]}/{slot.get('max_rounds', 2)})")
        elif verdict == "PASS":
            nxt = pos + 1
            if nxt >= len(steps):
                state["chain_pos"][key] = nxt
                save_state(state)
                log(f"{wf['slug']}: каскад пройден (все {len(steps)} ступеней PASS)")
                return
            nxt_slot = steps[nxt]
            version = patch_role(wf_id, "reviewer", nxt_slot["provider"], wf["state_version"])
            if resume(wf_id, version,
                      f"(каскад: Ревью-{pos+1} PASS → Ревью-{nxt+1} [{nxt_slot['provider']}])"):
                state["chain_pos"][key] = nxt
                save_state(state)
                log(f"{wf['slug']}: Ревью-{pos+1} PASS → Ревью-{nxt+1} "
                    f"[{nxt_slot['provider']}]")
    elif status == "queued":
        # после resume воркер мог не заметить — пинок
        try:
            api(f"/api/workflows/{wf_id}/sync", "POST",
                {"expected_version": wf["state_version"]})
        except Exception:
            pass


def main() -> None:
    target = sys.argv[1] if len(sys.argv) > 1 else None
    state = load_state()
    log(f"cascade-review стартовал ({'workflow ' + target if target else 'все review_chain-воркфлоу'})")
    while True:
        try:
            if target:
                serve_workflow(target, state)
            else:
                wfs = api("/api/workflows", timeout=10)
                for w in wfs:
                    cfg = w.get("config") or {}
                    if (cfg.get("review_chain") or {}).get("enabled"):
                        serve_workflow(w["id"], state)
        except Exception as e:  # noqa: BLE001
            log(f"цикл: {type(e).__name__}: {e}")
        time.sleep(30)


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    main()
