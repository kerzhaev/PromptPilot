"""Run the optional ``review_chain`` as a durable additive controller.

PromptPilot's core workflow has one reviewer slot.  A configured review chain
needs a small coordinator around that slot: the coordinator selects the next
reviewer, records intermediate PASS decisions without closing the workflow,
and routes a revision to the configured fixer.  The core worker still owns all
agent tasks, gates, retries, and ordinary workflow transitions.

The controller deliberately uses the existing SQLite workflow primitives rather
than inventing a second task queue.  All mutations are short transactions and
are represented by ``cascade.*`` events, so a restart can safely resume from
the last durable phase.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import time
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from promptpilot import db, workflows
from promptpilot.models import (
    FindingSeverity,
    FindingStatus,
    ReviewVerdict,
    TaskCreate,
    TaskStatus,
    WorkflowEventCreate,
    WorkflowHumanInput,
    WorkflowInDB,
    WorkflowReviewDecision,
    WorkflowRole,
    WorkflowRunCreate,
    WorkflowStatus,
)

STATE_VERSION = 2
DEFAULT_POLL_SECONDS = 15
_PP_DATA_DIR = Path(os.environ.get("PP_DATA_DIR", str(Path.home() / ".promptpilot")))
DEFAULT_LOG_PATH = _PP_DATA_DIR / "cascade-review.log"
DEFAULT_STATE_PATH = _PP_DATA_DIR / "cascade-review-state.json"

# A review-chain slot may use an explicit budget, or the additive controller
# can derive a conservative budget from the severity of the open findings.
# The derived values are deliberately small: the workflow-level round budget
# remains the final safety cap.
DEFAULT_AUTO_ATTEMPT_POLICY = {
    "mode": "manual",
    "default": 2,
    "max": 3,
    "by_severity": {
        "low": 1,
        "medium": 2,
        "high": 3,
        "blocker": 3,
    },
}
_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "blocker": 4}


def _json_copy(value: Any) -> Any:
    return json.loads(json.dumps(value, ensure_ascii=False))


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _minutes(value: str) -> int:
    try:
        hour, minute = (int(part) for part in str(value).split(":", 1))
        return max(0, min(23, hour)) * 60 + max(0, min(59, minute))
    except (TypeError, ValueError):
        return 0


def in_window(slot: dict[str, Any], now_utc: datetime | None = None) -> bool:
    """Return whether a configured slot may run now.

    The UI stores Moscow as ``tz_offset_hours=3``.  A named ``tz`` is accepted
    for hand-written configs and currently maps the supported Moscow value to
    the same fixed offset.

    Tariff windows v2: ``window.days`` restricts the slot to specific weekdays
    ("weekdays" / "weekend" / "all" / ["mon".."sun"]).  An overnight window
    belongs to its START day: the early-morning tail (time < ``to``) counts
    when YESTERDAY is listed.
    """

    window = slot.get("window") or {}
    if not window:
        return True
    now_utc = now_utc or datetime.now(timezone.utc)
    offset = window.get("tz_offset_hours")
    if offset is None:
        offset = 3 if str(window.get("tz", "")).lower() in {
            "europe/moscow", "msk", "мск"
        } else 0
    try:
        local = now_utc + timedelta(hours=float(offset))
    except (TypeError, ValueError):
        local = now_utc
    current = local.hour * 60 + local.minute
    start = _minutes(window.get("from", "22:00"))
    end = _minutes(window.get("to", "04:00"))
    day_names = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
    today = day_names[local.weekday()]
    yesterday = day_names[(local.weekday() - 1) % 7]
    allowed = _slot_days(window.get("days"))
    if start <= end:
        return start <= current < end and today in allowed
    return ((today in allowed and current >= start)
            or (yesterday in allowed and current < end))


def _slot_days(raw: Any) -> set[str]:
    """Weekday filter for a cascade slot window; absent/all = every day."""
    all_days = {"mon", "tue", "wed", "thu", "fri", "sat", "sun"}
    if raw is None:
        return all_days
    if isinstance(raw, str):
        s = raw.strip().lower()
        if s in ("weekdays", "будни"):
            return {"mon", "tue", "wed", "thu", "fri"}
        if s in ("weekend", "выходные"):
            return {"sat", "sun"}
        return all_days
    if isinstance(raw, (list, tuple, set)):
        allowed = {str(d).strip().lower()[:3] for d in raw} & all_days
        return allowed or all_days
    return all_days


def load_state(path: Path = DEFAULT_STATE_PATH) -> dict[str, Any]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("state is not an object")
    except (OSError, ValueError, json.JSONDecodeError):
        raw = {}
    # Older prototype state used top-level chain_pos/slot_rounds.  Do not
    # silently reinterpret it as a new state machine; durable DB events rebuild
    # the current slot on the first pass.
    if not isinstance(raw.get("workflows"), dict):
        raw = {"version": STATE_VERSION, "workflows": {}}
    raw["version"] = STATE_VERSION
    return raw


def save_state(state: dict[str, Any], path: Path = DEFAULT_STATE_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(state, ensure_ascii=False, indent=2, sort_keys=True)
    fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(payload)
        os.replace(tmp_name, path)
    finally:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass


class CascadeController:
    """One-process controller for all workflows with ``review_chain``."""

    def __init__(
        self,
        *,
        state_path: Path = DEFAULT_STATE_PATH,
        log_path: Path = DEFAULT_LOG_PATH,
        logger: Callable[[str], None] | None = None,
    ) -> None:
        self.state_path = Path(state_path)
        self.log_path = Path(log_path)
        self.state = load_state(self.state_path)
        self._external_logger = logger

    def log(self, message: str) -> None:
        line = f"{_now_iso()} {message}"
        if self._external_logger:
            self._external_logger(line)
        else:
            print(line, flush=True)
        try:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            with self.log_path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
        except OSError:
            pass

    @staticmethod
    def _chain(workflow: WorkflowInDB) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        chain = workflow.config.get("review_chain") or {}
        if not isinstance(chain, dict) or not chain.get("enabled"):
            return {}, []
        steps = [
            _json_copy(step)
            for step in (chain.get("steps") or [])
            if isinstance(step, dict) and str(step.get("provider") or "").strip()
        ]
        for index, step in enumerate(steps):
            step["slot"] = index + 1
            step.setdefault("fixer", "executor")
            step.setdefault("blocking", True)
            step.setdefault("max_rounds", 2)
            step.setdefault("on_exhaust", "human")
        return chain, steps

    @staticmethod
    def _attempt_policy(chain: dict[str, Any]) -> dict[str, Any]:
        """Return a bounded attempt policy without changing the stored config."""
        raw = chain.get("attempt_policy")
        raw = raw if isinstance(raw, dict) else {}
        policy = _json_copy(DEFAULT_AUTO_ATTEMPT_POLICY)
        policy.update({key: value for key, value in raw.items()
                       if key in {"mode", "default", "max", "by_severity"}})
        try:
            policy["default"] = max(1, min(10, int(policy["default"])))
        except (TypeError, ValueError):
            policy["default"] = DEFAULT_AUTO_ATTEMPT_POLICY["default"]
        try:
            policy["max"] = max(1, min(10, int(policy["max"])))
        except (TypeError, ValueError):
            policy["max"] = DEFAULT_AUTO_ATTEMPT_POLICY["max"]
        policy["max"] = max(policy["max"], policy["default"])
        if not isinstance(policy.get("by_severity"), dict):
            policy["by_severity"] = {}
        cleaned = {}
        for severity, fallback in DEFAULT_AUTO_ATTEMPT_POLICY["by_severity"].items():
            value = policy["by_severity"].get(severity, fallback)
            try:
                cleaned[severity] = max(1, min(policy["max"], int(value)))
            except (TypeError, ValueError):
                cleaned[severity] = min(policy["max"], fallback)
        policy["by_severity"] = cleaned
        policy["mode"] = "auto" if str(policy.get("mode", "manual")).lower() == "auto" else "manual"
        return policy

    @staticmethod
    def _finding_value(finding: Any, name: str) -> str:
        value = getattr(finding, name, "")
        return str(getattr(value, "value", value) or "").lower()

    def _max_rounds_for_slot(
        self,
        workflow: WorkflowInDB,
        chain: dict[str, Any],
        slot: dict[str, Any],
        decision: WorkflowReviewDecision | None = None,
    ) -> tuple[int, str]:
        """Resolve the retry budget and expose why that value was selected."""
        policy = self._attempt_policy(chain)
        mode = str(slot.get("attempts_mode") or policy["mode"]).lower()
        if mode != "auto":
            try:
                value = max(1, min(10, int(slot.get("max_rounds") or 2)))
            except (TypeError, ValueError):
                value = 2
            return value, "manual"

        findings: list[Any] = []
        try:
            current_round_no = int(workflow.current_round or 0)
            findings.extend(
                finding for finding in db.list_workflow_findings(workflow.id)
                if int(getattr(finding, "last_seen_round", 0) or 0) == current_round_no
            )
        except Exception:  # noqa: BLE001 - a policy fallback must not stop routing
            pass
        if decision is not None:
            findings.extend(decision.findings)
        open_severities = {
            self._finding_value(item, "severity")
            for item in findings
            if self._finding_value(item, "status") in {"open", "reopened"}
        }
        selected = max(open_severities, key=lambda item: _SEVERITY_RANK.get(item, 0), default="")
        value = policy["by_severity"].get(selected, policy["default"])
        value = max(1, min(policy["max"], int(value)))
        return value, f"auto:{selected or 'default'}"

    @staticmethod
    def _current_round(workflow: WorkflowInDB):
        rounds = db.list_workflow_rounds(workflow.id)
        return next(
            (item for item in rounds if item.round_no == workflow.current_round),
            None,
        )

    @staticmethod
    def _completed_reviewer(workflow: WorkflowInDB):
        current = CascadeController._current_round(workflow)
        if not current:
            return None
        runs = [
            item for item in db.list_workflow_runs(current.id)
            if item.role is WorkflowRole.REVIEWER and item.status.value == "completed"
        ]
        return max(runs, key=lambda item: item.attempt_no) if runs else None

    @staticmethod
    def _superseded_by_executor(workflow: WorkflowInDB, reviewer_run) -> bool:
        """Устарело ли завершённое ревью: после него в том же раунде снова
        работал исполнитель (resume-цикл). Верdict того ревью уже был
        спроецирован в awaiting_human — блокировать новый диспетч нельзя,
        иначе воркфлоу зависает в reviewing навсегда (лайвлок #248).
        """
        current = CascadeController._current_round(workflow)
        if not current:
            return False
        reviewer_started = str(reviewer_run.started_at or "")
        for item in db.list_workflow_runs(current.id):
            if (item.role is WorkflowRole.EXECUTOR
                    and item.status.value == "completed"
                    and str(item.started_at or "") > reviewer_started):
                return True
        return False

    @staticmethod
    def _pending_reviewer(workflow: WorkflowInDB) -> bool:
        current = CascadeController._current_round(workflow)
        if not current:
            return False
        return any(
            item.role is WorkflowRole.REVIEWER
            and item.status.value in {"pending", "running"}
            for item in db.list_workflow_runs(current.id)
        )

    @staticmethod
    def _events(workflow_id: str):
        """Хвост журнала, а не первые 5000 (ASC): на длинной миссии свежие
        cascade-маркеры не попадают в голову выборки (P1-3). ``tail=True``
        возвращает последние ``limit`` событий в хронологическом порядке,
        поэтому все «latest-first»-обходы через reversed() сохраняются."""
        return db.list_workflow_events(workflow_id, limit=5000, tail=True)

    @staticmethod
    def _event_for_run(events, event_type: str | None, run_id: str) -> bool:
        for event in events:
            if event_type and event.event_type != event_type:
                continue
            if not event.event_type.startswith("cascade."):
                continue
            if event.run_id == run_id or event.payload.get("run_id") == run_id:
                return True
        return False

    def _workflow_state(
        self,
        workflow: WorkflowInDB,
        steps: list[dict[str, Any]],
    ) -> dict[str, Any]:
        records = self.state.setdefault("workflows", {})
        current_stage = workflow.current_stage_id or "planless"
        existing = records.get(workflow.id)
        if not isinstance(existing, dict) or existing.get("stage_id") != current_stage:
            slot = 0
            # Rebuild after a controller restart from durable cascade events.
            for event in reversed(self._events(workflow.id)):
                if event.payload.get("stage_id", current_stage) != current_stage:
                    continue
                if event.event_type in {"cascade.slot_passed", "cascade.slot_skipped"}:
                    slot = int(event.payload.get("next_slot", slot))
                    if (event.event_type == "cascade.slot_skipped"
                            and slot >= len(steps)):
                        # P0-1: пропуск последней ступени без раннего PASS —
                        # это холд «все ступени вне окна», а не продвижение.
                        # Рестарт контроллера не должен выталкивать slot за
                        # пределы цепочки по маркеру slot_skipped: после
                        # ручного резюма диспетчер обязан снова попробовать
                        # эту ступень, а не выйти по index >= len(steps).
                        slot = len(steps) - 1
                    break
            existing = {
                "stage_id": current_stage,
                "slot": max(0, min(slot, len(steps))),
                "attempts": {},
                "last_run_id": None,
            }
            records[workflow.id] = existing
        # P0-1.2: цепочка могла СЖАТЬСЯ при живом state (лестница смен
        # восстановила одно-слотовый снимок — slot=1 при len=1 молча
        # выходил по index >= len(steps) каждый тик, конвейер стоял).
        # Клэмпим в ГРАНИЦЫ цепочки, а не в len: за последней ступенью
        # легитимных состояний у диспетчера нет.
        existing["slot"] = max(0, min(int(existing.get("slot", 0)), len(steps) - 1))
        existing.setdefault("attempts", {})
        existing.setdefault("last_run_id", None)

        # The JSON state is only a cache.  Reconcile the fields that affect
        # routing from SQLite events on every pass so a process termination
        # between two controller transactions cannot send the next task to an
        # old reviewer slot or reset its configured retry count.
        stage_events = [
            event for event in self._events(workflow.id)
            if event.payload.get("stage_id", current_stage) == current_stage
        ]
        latest_slot_boundary = max(
            (
                event.seq for event in stage_events
                if event.event_type in {"cascade.slot_passed", "cascade.slot_skipped"}
            ),
            default=0,
        )
        for event in stage_events:
            if event.seq < latest_slot_boundary:
                continue
            if event.event_type != "cascade.revision_requested":
                continue
            slot_index = max(0, int(event.payload.get("slot", 1)) - 1)
            existing["slot"] = min(slot_index, len(steps))
            attempt = int(event.payload.get("attempt", 0) or 0)
            existing["attempts"][str(slot_index)] = max(
                int(existing["attempts"].get(str(slot_index), 0) or 0),
                attempt,
            )
            existing["last_run_id"] = event.payload.get("run_id") or existing.get(
                "last_run_id"
            )
        existing["round"] = workflow.current_round
        return existing

    @staticmethod
    def _base_executor(chain: dict[str, Any], workflow: WorkflowInDB) -> str | None:
        value = chain.get("base_executor_provider")
        if value is not None:
            return value or None
        return (workflow.config.get("roles", {}).get("executor", {}) or {}).get("provider")

    @staticmethod
    def _resolve_fixer(
        slot: dict[str, Any],
        chain: dict[str, Any],
        workflow: WorkflowInDB,
    ) -> str | None:
        fixer = str(slot.get("fixer") or "executor")
        if fixer == "executor":
            return CascadeController._base_executor(chain, workflow)
        if fixer == "self":
            provider = str(slot.get("provider") or "") or None
            if provider and CascadeController._should_fallback_read_only_self(
                provider, workflow
            ):
                # A reviewer configured as ``self`` is allowed to keep its
                # own fixer only when the provider is actually a coding
                # executor.  qwen-review (and similarly named review lanes)
                # are intentionally read-only in this installation.  Sending
                # their revision round back to themselves creates the exact
                # capability question that used to stop the cascade.
                return CascadeController._base_executor(chain, workflow)
            return provider
        return fixer or None

    @staticmethod
    def _should_fallback_read_only_self(
        provider: str, workflow: WorkflowInDB
    ) -> bool:
        """Route a read-only self-fixer to the writable base executor.

        This fallback is opt-in through the workflow's autonomous executor
        settings.  Manual workflows preserve the explicit ``self`` choice and
        therefore preserve their human gate.  The name check is deliberately
        narrow: ``qwen-review`` is the configured review-only lane, while a
        provider ending in ``-review``/``_review`` follows the same contract.
        """
        automation = (workflow.config.get("automation") or {})
        if automation.get("enabled") is not True:
            return False
        if automation.get("auto_dispatch_executor", True) is False:
            return False
        if automation.get("auto_resolve_capability_questions", True) is False:
            return False
        normalized = provider.strip().lower()
        return (
            normalized in {"qwen-review", "qwen_review"}
            or normalized.endswith("-review")
            or normalized.endswith("_review")
        )

    @staticmethod
    def _review_context(workflow: WorkflowInDB, slot_index: int) -> str:
        current = CascadeController._current_round(workflow)
        if not current or slot_index <= 0:
            return "(это первая ступень каскадного ревью)"
        reports = []
        for run in db.list_workflow_runs(current.id):
            if run.role is not WorkflowRole.REVIEWER or run.status.value != "completed":
                continue
            result = (run.output or {}).get("result") or ""
            if result:
                reports.append(f"Ревьюер task #{run.task_id}:\n{result}")
        return "\n\n".join(reports[-3:])[-14000:] or "(предыдущих отчётов нет)"

    def _update_runtime_config(
        self,
        workflow: WorkflowInDB,
        *,
        slot: dict[str, Any] | None = None,
        executor_provider: str | None = None,
        reviewer_provider: str | None = None,
        extra_context: str | None = None,
        reason: str,
    ) -> WorkflowInDB:
        """Update only additive runtime routing metadata, without auto-advance."""

        with db._connect(immediate=True) as conn:
            row = conn.execute(
                "SELECT * FROM workflows WHERE id = ?", (workflow.id,)
            ).fetchone()
            if not row:
                raise db.WorkflowNotFoundError(workflow.id)
            config = db._json_load(row["config_json"])
            before = db._json_dump(config)
            chain = config.setdefault("review_chain", {})
            roles = config.setdefault("roles", {})
            executor = roles.setdefault("executor", {})
            reviewer = roles.setdefault("reviewer", {})
            automation = config.setdefault("automation", {})

            if "base_executor_provider" not in chain:
                chain["base_executor_provider"] = executor.get("provider")
            if "base_reviewer_provider" not in chain:
                chain["base_reviewer_provider"] = reviewer.get("provider")
            if "base_reviewer_prompt_template" not in chain:
                chain["base_reviewer_prompt_template"] = reviewer.get(
                    "prompt_template", ""
                )

            # The add-on is the owner of reviewer dispatch, review application,
            # and revision resume while a chain is enabled.
            automation["auto_dispatch_reviewer"] = False
            automation["auto_apply_review"] = False
            automation["auto_resume_revision"] = False

            if executor_provider is not None:
                executor["provider"] = executor_provider
            if reviewer_provider is not None:
                reviewer["provider"] = reviewer_provider
            if slot is not None:
                slot_index = int(slot.get("slot", 1)) - 1
                context = self._review_context(workflow, slot_index)
                fixer = self._resolve_fixer(slot, chain, workflow)
                base_prompt = chain.get("base_reviewer_prompt_template") or ""
                if not base_prompt:
                    base_prompt = workflows.DEFAULT_REVIEWER_PROMPT
                reviewer["prompt_template"] = (
                    f"{base_prompt.rstrip()}\n\n"
                    "[КОНТЕКСТ КАСКАДНОГО РЕВЬЮ]\n"
                    f"Ты работаешь на ступени {slot_index + 1}. "
                    f"Твой провайдер: {slot.get('provider')}. "
                    f"При REVISION_REQUIRED исправление будет передано: "
                    f"{fixer or 'не настроено'}.\n"
                    "Не исправляй код в этой задаче ревью.\n"
                    "ФОРМАТ ОТВЕТА (обязателен, без исключений) — заверши отчёт "
                    "строго этими двумя машинными строками:\n"
                    "AUDIT_FINDINGS_JSON: [{{\"fingerprint\":\"...\",\"severity\":"
                    "\"low|medium|high\",\"category\":\"...\",\"title\":\"...\","
                    "\"status\":\"open|resolved|reopened\",\"payload\":{{...}}}}]\n"
                    "AUDIT_VERDICT: PASS | REVISION_REQUIRED | HUMAN_REQUIRED\n"
                    "RESOLVE RULE: каждый прежде открытый fingerprint, чьё "
                    "исправление подтверждено твоей проверкой, выводи с "
                    "status=resolved (слов «подтверждено закрытым» в тексте "
                    "недостаточно — без resolved в JSON апсерт переоткроет "
                    "находку и этап не закроется).\n"
                    "Никаких других форм вердикта (ИТОГ:, PASS/REPAIR_REQUIRED, "
                    "произвольный текст) не допускается — иначе ревью будет "
                    "признано невалидным и workflow остановится.\n"
                    "Предыдущие отчёты каскада:\n"
                    f"{context}"
                    + (f"\n{extra_context}" if extra_context else "")
                )

            after = db._json_dump(config)
            if before == after:
                return db._row_to_workflow(row)
            version = int(row["state_version"]) + 1
            now = db._now()
            conn.execute(
                """UPDATE workflows SET config_json=?, state_version=?, updated_at=?
                   WHERE id=? AND state_version=?""",
                (after, version, now, workflow.id, row["state_version"]),
            )
            db._append_workflow_event(conn, WorkflowEventCreate(
                workflow_id=workflow.id,
                event_type="cascade.runtime_configured",
                idempotency_key=f"cascade.runtime_configured:{workflow.id}:v{version}",
                payload={
                    "reason": reason,
                    "slot": slot.get("slot") if slot else None,
                    "executor_provider": executor_provider,
                    "reviewer_provider": reviewer_provider,
                    "automation": {
                        "auto_dispatch_reviewer": False,
                        "auto_apply_review": False,
                        "auto_resume_revision": False,
                    },
                },
            ))
            updated = conn.execute(
                "SELECT * FROM workflows WHERE id = ?", (workflow.id,)
            ).fetchone()
            return db._row_to_workflow(updated)

    def _transition_to_reviewing(
        self,
        workflow: WorkflowInDB,
        *,
        slot: dict[str, Any],
        next_slot: int,
        previous_run_id: int,
        findings: list[Any],
    ) -> WorkflowInDB:
        with db._connect(immediate=True) as conn:
            row = conn.execute(
                "SELECT * FROM workflows WHERE id = ?", (workflow.id,)
            ).fetchone()
            current = WorkflowStatus(row["status"])
            if current is WorkflowStatus.REVIEWING:
                return db._row_to_workflow(row)
            if current is not WorkflowStatus.AWAITING_HUMAN:
                raise db.WorkflowConflictError(
                    f"cascade expected awaiting_human, got {current.value}"
                )
            round_row = workflows._current_round_row(conn, row)
            for finding in findings:
                workflows._upsert_review_finding(
                    conn, workflow.id, round_row["round_no"], finding
                )
            workflow_row = workflows._transition(
                conn,
                row,
                WorkflowStatus.REVIEWING,
                "cascade.slot_passed",
                {
                    "stage_id": row["current_stage_id"] or "planless",
                    "slot": int(slot.get("slot", 1)),
                    "next_slot": next_slot,
                    "run_id": previous_run_id,
                    "provider": slot.get("provider"),
                    "finding_count": len(findings),
                },
                round_id=round_row["id"],
            )
            return db._row_to_workflow(workflow_row)

    def _advance_to_next_slot(
        self,
        workflow: WorkflowInDB,
        state: dict[str, Any],
        steps: list[dict[str, Any]],
    ) -> WorkflowInDB | None:
        next_index = int(state["slot"]) + 1
        state["slot"] = next_index
        state["attempts"] = {}
        state["last_run_id"] = None
        if next_index >= len(steps):
            return None
        return workflow

    def _live_hot_findings(self, workflow: WorkflowInDB) -> bool:
        """Есть ли в живой базе открытые/переоткрытые blocker|high находки.

        База — источник истины: отчёт ревьюера мог перечислить находки,
        закрытые в более ранних раундах (П2a/П2b, инцидент 06.10)."""
        try:
            findings = db.list_workflow_findings(workflow.id)
        except Exception:  # noqa: BLE001 - не знаем -> не рискуем блоком
            return True
        return any(
            finding.severity in {FindingSeverity.BLOCKER, FindingSeverity.HIGH}
            and finding.status in {FindingStatus.OPEN, FindingStatus.REOPENED}
            for finding in findings
        )

    # ── Чистка долга ревью (владелец 07.10): порог medium-находок ──
    DEBT_PROMPT_TAG = "ЧИСТКА ДОЛГА РЕВЬЮ"
    DEBT_SWEEP_MARKER = "cascade.debt_sweep_dispatched"
    DEBT_SWEEP_COOLDOWN_H = 6
    DEBT_SWEEP_BATCH = 25

    def _maybe_debt_sweep(self, workflow: WorkflowInDB,
                          chain: dict[str, Any]) -> None:
        """Долг medium >= порога (debt_sweep_threshold, 0=выкл) — конвейер
        сам берёт недочёты в работу: задача исполнителю с отпечатками.
        Льготные окна: у исполнителя настроены окна — ждём открытия,
        не настроены — берём сразу (требование владельца 07.10)."""
        try:
            threshold = int((chain or {}).get("debt_sweep_threshold") or 0)
        except (TypeError, ValueError):
            threshold = 0
        if threshold <= 0:
            return
        if workflow.status not in {
            WorkflowStatus.EXECUTING, WorkflowStatus.REVIEWING,
            WorkflowStatus.REVISION_REQUIRED, WorkflowStatus.GATING,
            WorkflowStatus.QUEUED,
        }:
            return
        medium = [
            f for f in db.list_workflow_findings(workflow.id)
            if f.severity == FindingSeverity.MEDIUM
            and f.status in {FindingStatus.OPEN, FindingStatus.REOPENED}
        ]
        if len(medium) < threshold:
            return
        if self._debt_sweep_in_flight(workflow.repository_path):
            return
        tail = self._hold_markers_tail(workflow.id)
        for event in reversed(tail):
            if event.event_type == self.DEBT_SWEEP_MARKER:
                started = event.created_at
                if started:

                    age_h = ((datetime.now(timezone.utc) - started)
                             .total_seconds() / 3600)
                    if age_h < self.DEBT_SWEEP_COOLDOWN_H:
                        return
                break
        executor = workflows.resolve_role_provider(workflow, "executor")
        window_open, why = self._executor_debt_window_open(executor)
        if not window_open:
            self.log(
                f"{workflow.slug}: долг medium={len(medium)} >= {threshold}, "
                f"но {why} — чистка ждёт окна")
            return
        medium.sort(key=lambda f: f.fingerprint)
        picked = medium[:self.DEBT_SWEEP_BATCH]
        listing = "\n".join(
            f"- {f.fingerprint}: "
            f"{str((f.payload or {}).get('title') or f.title)[:90]}"
            for f in picked)
        prompt = (
            f"{self.DEBT_PROMPT_TAG} (авто, порог {threshold}): закрыть "
            f"{len(picked)} открытых medium-находок миссии {workflow.slug}."
            "\n"
            "Для КАЖДОЙ: исправить по существу, либо обосновать устаревшее "
            "(файл переписан/требование изменилось) в отчёте. Тесты "
            "затронутых модулей обязаны остаться зелёными; текущую стадию "
            "не ломать.\n\nСПИСОК:\n" + listing +
            "\n\nОтчёт: по каждой строке — фикс или причина снятия. "
            "ИТОГ: ГОТОВО когда все закрыты или обоснованно сняты.")
        sweep_task = db.create_task(TaskCreate(
            prompt=prompt,
            provider=executor or "mmx-m3",
            working_dir=workflow.repository_path,
            priority=6,
            worktree=True,  # параллельно с основным этапом (свой каталог)
        ))
        try:
            # P1-5: ключ маркера уникален task_id'ом задачи чистки. Раньше
            # ключ был фиксированным (round/run = none): первый повтор после
            # кулдауна с изменившимся payload падал WorkflowConflictError'ом
            # ПОСЛЕ create_task — задача жила без маркера, кулдаун не
            # продлевался, и поток чисток шёл за каждым завершением.
            self._append_marker(
                workflow.id,
                event_type=self.DEBT_SWEEP_MARKER,
                run_id=None, round_id=None,
                key_extra=f"task-{sweep_task.id}",
                payload={"open_medium": len(medium), "batch": len(picked),
                         "executor": executor, "threshold": threshold,
                         "task_id": sweep_task.id},
            )
        except db.WorkflowConflictError:
            # Конфликт идемпотентности трактуем как «уже dispatched»:
            # задача уже создана, повторной чистки в этом тике не нужно.
            self.log(
                f"{workflow.slug}: маркер чистки уже записан — чистка "
                "считается назначенной")
        self.log(
            f"{workflow.slug}: ДОЛГ-ЧИСТКА — medium {len(medium)} >= "
            f"{threshold}, задача исполнителю {executor} на {len(picked)} "
            f"находок ({why})")


    DEBT_REVIEW_TAG = "МИНИ-РЕВЬЮ ДОЛГА"
    DEBT_REVIEW_DISPATCHED_MARKER = "cascade.debt_review_dispatched"
    DEBT_REVIEW_APPLIED_MARKER = "cascade.debt_review_applied"
    DEBT_MERGED_MARKER = "cascade.debt_merged"
    DEBT_MERGE_CONFLICT_MARKER = "cascade.debt_merge_conflict"

    def _merge_debt_worktree(self, workflow: WorkflowInDB) -> None:
        """P0-3 (аудит 09.10): ветки чистки долга pp/t<id> НИКТО не мержил —
        правки жили в worktree-призраках, «ГОТОВО» фиксировалось, продукт
        фиксы не получал. Мержим каждую завершённую чистку этой миссии в
        текущую ветку репозитория — только МЕЖДУ задачами (не под руками
        у работающего в том же репо агента) и идемпотентно."""
        import subprocess

        repo = workflow.repository_path or ""
        if not repo:
            return
        # работающий агент в этом же репо — мержим в следующий тик
        for status in (TaskStatus.PENDING, TaskStatus.RUNNING):
            for t in db.list_tasks(status=status):
                if (t.working_dir or "") == repo and not t.worktree:
                    return
        tail = self._hold_markers_tail(workflow.id)
        merged = {
            int((event.payload or {}).get("sweep_task_id") or 0)
            for event in tail
            if event.event_type == self.DEBT_MERGED_MARKER
        }
        conflicted = {
            int((event.payload or {}).get("sweep_task_id") or 0)
            for event in tail
            if event.event_type == self.DEBT_MERGE_CONFLICT_MARKER
        }

        def _git(*args: str) -> subprocess.CompletedProcess:
            # P0-3.1: DEVNULL-stdin (хуки не ждут ввода скрытой консоли) и
            # ДЕРЕВО-килл по таймауту: subprocess.run убивает только прямого
            # ребёнка, а его внуки (git-хуки) держат пайпы открытыми —
            # communicate() висит вечно. Так повис каскад 09.10 19:55:
            # живой процесс, молчащий лог, конвейер стоял ~час.
            proc = subprocess.Popen(
                ["git", "-C", repo, *args], stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, stdin=subprocess.DEVNULL,
                text=True)
            try:
                out, err = proc.communicate(timeout=60)
                return subprocess.CompletedProcess(
                    proc.args, proc.returncode, out, err)
            except subprocess.TimeoutExpired:
                subprocess.run(
                    ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                    capture_output=True, check=False)
                try:
                    proc.communicate(timeout=15)
                except subprocess.TimeoutExpired:
                    pass
                return subprocess.CompletedProcess(
                    proc.args, -1, "",
                    "git timeout after 60s (tree killed)")

        deadline = time.time() + 150.0   # P0-3.1: бюджет тика на мержи
        for task in db.list_tasks(limit=20):
            if time.time() > deadline:
                self.log("debt-merge: бюджет тика исчерпан — продолжу следующим тиком")
                break
            if (self.DEBT_PROMPT_TAG not in (task.prompt or "")
                    or task.status.value != "completed"
                    or (task.working_dir or "") != repo
                    or not task.worktree_branch
                    or task.id in merged
                    or task.id in conflicted):
                continue
            branch = task.worktree_branch
            exists = _git("rev-parse", "--verify", branch)
            if exists.returncode != 0:
                # ветки нет — нечего мержить, считаем закрытым
                self._append_marker(
                    workflow.id, event_type=self.DEBT_MERGED_MARKER,
                    run_id=None, round_id=None,
                    key_extra=f"task-{task.id}",
                    payload={"sweep_task_id": task.id, "branch": branch,
                             "note": "branch missing, nothing to merge"})
                continue
            ancestor = _git("merge-base", "--is-ancestor", branch, "HEAD")
            if ancestor.returncode == 0:
                self._append_marker(
                    workflow.id, event_type=self.DEBT_MERGED_MARKER,
                    run_id=None, round_id=None,
                    key_extra=f"task-{task.id}",
                    payload={"sweep_task_id": task.id, "branch": branch,
                             "note": "already in HEAD"})
                continue
            merge = _git("merge", "--no-edit", branch)
            if merge.returncode == 0:
                self._append_marker(
                    workflow.id, event_type=self.DEBT_MERGED_MARKER,
                    run_id=None, round_id=None,
                    key_extra=f"task-{task.id}",
                    payload={"sweep_task_id": task.id, "branch": branch})
                self.log(
                    f"{workflow.slug}: ветка чистки {branch} (задача "
                    f"#{task.id}) смержена в рабочую ветку миссии")
            else:
                _git("merge", "--abort")
                self._append_marker(
                    workflow.id, event_type=self.DEBT_MERGE_CONFLICT_MARKER,
                    run_id=None, round_id=None,
                    key_extra=f"task-{task.id}",
                    payload={"sweep_task_id": task.id, "branch": branch,
                             "error": (merge.stderr or "")[:200]})
                self.log(
                    f"{workflow.slug}: КОНФЛИКТ мержа чистки {branch} "
                    f"(задача #{task.id}) — merge --abort, ветка жива, "
                    "нужно ручное слияние или повторная чистка")

    def _maybe_debt_review(self, workflow: WorkflowInDB,
                           chain: dict[str, Any]) -> None:
        """Цикл мини-ревью долга: (1) применить завершённые мини-ревью —
        их AUDIT-контракт апсертится в реестр находок (P1-6c); (2) найти
        завершённую чистку без мини-ревью и назначить его (P1-6a). Все
        выборки задач фильтруются по working_dir этой миссии (P1-6b):
        раньше фильтр list_tasks был глобальным и чужая миссия
        перехватывала чужие чистки/мини-ревью."""
        repo = workflow.repository_path or ""
        if not repo:
            return
        # P0-3: сначала влить ветки завершённых чисток в ветку миссии —
        # мини-ревью проверяет код именно в этом репозитории
        try:
            self._merge_debt_worktree(workflow)
        except Exception as exc:  # noqa: BLE001 - мерж не роняет каскад
            self.log(f"{workflow.slug}: debt-merge: "
                     f"{type(exc).__name__}: {exc}")
        tail = self._hold_markers_tail(workflow.id)
        applied_ids = {
            int((event.payload or {}).get("task_id") or 0)
            for event in tail
            if event.event_type == self.DEBT_REVIEW_APPLIED_MARKER
        }
        dispatched_sweeps = {
            int((event.payload or {}).get("sweep_task_id") or 0)
            for event in tail
            if event.event_type == self.DEBT_REVIEW_DISPATCHED_MARKER
        }

        # (1) результаты завершённых мини-ревью этой миссии — в реестр
        for task in db.list_tasks(limit=50):
            if task.status.value != "completed":
                continue
            if self.DEBT_REVIEW_TAG not in (task.prompt or ""):
                continue
            if (task.working_dir or "") != repo:
                continue
            if task.id in applied_ids:
                continue
            self._apply_debt_review_result(workflow, task)
            self._append_marker(
                workflow.id,
                event_type=self.DEBT_REVIEW_APPLIED_MARKER,
                run_id=None, round_id=None,
                key_extra=f"task-{task.id}",
                payload={"task_id": task.id},
            )

        # (2) завершённая чистка без своего мини-ревью — диспатчим его
        sweep_done = None
        for task in db.list_tasks(limit=20):
            if (self.DEBT_PROMPT_TAG in (task.prompt or "")
                    and task.status.value == "completed"
                    and (task.working_dir or "") == repo
                    and task.id not in dispatched_sweeps
                    and not task.verdict == "ГОТОВО"):
                sweep_done = task
                break
        if sweep_done is None:
            return
        # уже есть мини-ревью этой миссии в полёте?
        for status in (TaskStatus.PENDING, TaskStatus.RUNNING):
            for t in db.list_tasks(status=status):
                if (self.DEBT_REVIEW_TAG in (t.prompt or "")
                        and (t.working_dir or "") == repo):
                    return
        # извлечь отпечатки из задачи чистки
        import re as _re

        fingerprints = _re.findall(
            r"- ([A-Za-z0-9_-]{3,80}):", sweep_done.prompt or "")
        if not fingerprints:
            return
        reviewer_provider = (chain.get("steps") or [{}])[0].get(
            "provider") or "goose-zai"
        prompt = (
            f"{self.DEBT_REVIEW_TAG} (авто): проверить и закрыть "
            f"{len(fingerprints)} находок, исправленных чисткой долга "
            f"(задача #{sweep_done.id}).\n\n"
            "Для КАЖДОГО отпечатка: проверь код в репо (файл/строка из "
            "оригинальной находки) — если исправление подтверждено, "
            "выведи его со status resolved; если нет — open.\n"
            "Формат ответа — стандартный AUDIT-контракт.\n\n"
            "ОТПЕЧАТКИ:\n" + "\n".join(f"- {f}" for f in fingerprints))
        db.create_task(TaskCreate(
            prompt=prompt, provider=reviewer_provider,
            working_dir=workflow.repository_path, priority=5,
            worktree=True))
        # P1-6a: маркер «для этой чистки мини-ревью уже назначено» — без
        # него каждый цикл контроллера отправлял повторное мини-ревью той
        # же чистки (дубль до 20 раз), пока фильтр задач был глобальным.
        self._append_marker(
            workflow.id,
            event_type=self.DEBT_REVIEW_DISPATCHED_MARKER,
            run_id=None, round_id=None,
            key_extra=f"sweep-{sweep_done.id}",
            payload={"sweep_task_id": sweep_done.id,
                     "fingerprints": fingerprints[:50]},
        )
        self.log(
            f"{workflow.slug}: МИНИ-РЕВЬЮ ДОЛГА — {len(fingerprints)} "
            f"находок на проверку {reviewer_provider} (чистка "
            f"#{sweep_done.id} завершена)")

    def _apply_debt_review_result(self, workflow: WorkflowInDB,
                                  review_task) -> None:
        """P1-6c: результат мини-ревью долга — полноценный AUDIT-контракт;
        апсертим находки в реестр (resolved закрываются, open/reopened
        переоткрываются). ``record_review`` тут нельзя — он требует раунд
        в awaiting_human; апсертим напрямую, как каскад в
        ``_transition_to_reviewing``."""
        report = str(review_task.result or "")
        decision = workflows.parse_reviewer_report(report)
        if decision is None:
            self.log(
                f"{workflow.slug}: мини-ревью долга #{review_task.id} без "
                "валидного AUDIT-контракта — находки не тронуты")
            return
        try:
            with db._connect(immediate=True) as conn:
                row = conn.execute(
                    "SELECT * FROM workflows WHERE id = ?", (workflow.id,)
                ).fetchone()
                if not row:
                    return
                round_row = workflows._current_round_row(conn, row)
                for finding in decision.findings:
                    workflows._upsert_review_finding(
                        conn, workflow.id, round_row["round_no"], finding)
        except Exception as exc:  # noqa: BLE001 - реестр важнее тика
            self.log(f"{workflow.slug}: применение мини-ревью долга "
                     f"#{review_task.id} не удалось: {exc}")
            return
        resolved = sum(
            1 for item in decision.findings
            if item.status == FindingStatus.RESOLVED)
        self.log(
            f"{workflow.slug}: мини-ревью долга #{review_task.id} применено "
            f"— {resolved}/{len(decision.findings)} находок закрыто")

    def _debt_sweep_in_flight(self, working_dir: str | None = None) -> bool:
        for status in (TaskStatus.PENDING, TaskStatus.RUNNING):
            for task in db.list_tasks(status=status):
                if self.DEBT_PROMPT_TAG not in (task.prompt or ""):
                    continue
                if working_dir and (task.working_dir or "") != working_dir:
                    continue
                return True
        return False

    def _executor_debt_window_open(self, executor: str) -> tuple[bool, str]:
        """Льготные окна исполнителя из лестницы смен: окон нет — сразу;
        есть — ждать открытия (долг не горит, платим дешёвыми часами)."""
        if not executor:
            return True, "исполнитель не задан"
        try:
            from promptpilot.config import DB_DIR

            config_path = DB_DIR / "quota-failover.json"
            config = json.loads(config_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return True, "лестница смен недоступна — сразу"
        rung = next((r for r in (config.get("ladder") or [])
                     if r.get("executor") == executor), None)
        windows = (rung or {}).get("windows") or []
        if not windows:
            return True, "у исполнителя нет льготных окон"
        module = self._qfw_module()
        if module is None:
            return True, "проверка окон недоступна — сразу"
        if module.rung_in_window({"windows": windows}):
            return True, "льготное окно открыто"
        return False, "вне льготного окна исполнителя"

    _qfw_cache = None

    def _qfw_module(self):
        """quota-failover-watcher как библиотека окон (один раз)."""
        if CascadeController._qfw_cache is not None:
            return CascadeController._qfw_cache
        import importlib.util

        path = (Path(workflows.__file__).parent.parent
                / "quota-failover-watcher.py")
        if not path.is_file():
            return None
        spec = importlib.util.spec_from_file_location("qfw_windows", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        CascadeController._qfw_cache = module
        return module

    def _drop_resolved_from_report(self, workflow, findings):
        """Квен-H2: из списка находок отчёта убрать те, что в живой базе
        уже закрыты (resolved/accepted) — апсерт перехода ступени не должен
        их переоткрывать."""
        closed = {
            f.fingerprint for f in db.list_workflow_findings(workflow.id)
            if f.status in {FindingStatus.RESOLVED, FindingStatus.ACCEPTED_RISK}
        }
        return [f for f in findings if f.fingerprint not in closed]

    def _hold_markers_tail(self, workflow_id: str) -> list:
        """Квен-M6: последние события стойки — из ХВОСТА журнала (tail=True),
        а не из первых 5000 (на длинной миссии свежие маркеры туда
        не попадают)."""
        return list(db.list_workflow_events(
            workflow_id, limit=200, tail=True))

    def _clear_stale_blocker(self, workflow: WorkflowInDB) -> WorkflowInDB | None:
        """П2b: стойка «PASS + открытый blocker/high», которых в базе уже
        нет — каскад снимает её сам адресным резюмом (раньше это делал
        дежурный руками: час простоя на устаревшем списке находок)."""
        tail = self._hold_markers_tail(workflow.id)
        # Квен-H1: снимаем ТОЛЬКО если последний маркер стойки — именно
        # этот блокер; свежий awaiting_decision/gate.human_required и
        # прочие причины стойки неприкосновенны
        HOLD_EVENTS = {
            "cascade.open_blocker", "cascade.exhausted",
            "cascade.stale_blocker_cleared",
            "review.awaiting_decision", "cascade.human_required",
            "cascade.no_fixer", "cascade.invalid_review_output",
        }
        marker = next(
            (event for event in reversed(tail)
             if event.event_type in HOLD_EVENTS),
            None,
        )
        if marker is None or marker.event_type != "cascade.open_blocker":
            return None
        if "blocker/high" not in str((marker.payload or {}).get("reason") or ""):
            return None
        if self._live_hot_findings(workflow):
            return None
        cleared_marker = next(
            (event for event in reversed(tail)
             if event.event_type == "cascade.stale_blocker_cleared"),
            None,
        )
        if cleared_marker is not None and cleared_marker.seq > marker.seq:
            return None  # уже снимали после этого блокера — не зацикливаемся
        self.log(
            f"{workflow.slug}: устаревший блокер — открытых blocker/high "
            f"в базе нет, продолжаю конвейер (П2b)"
        )
        fresh = db.get_workflow(workflow.id) or workflow
        try:
            result = workflows.human_input(
                workflow.id,
                WorkflowHumanInput(
                    expected_version=fresh.state_version,
                    text=("Авто-снятие устаревшего блокера каскада: открытых "
                          "blocker/high находок в живой базе нет. Продолжай "
                          "текущий раунд по плану; новые находки — по канону."),
                    resume=True,
                ),
            )
        except Exception as exc:  # noqa: BLE001 - снимем на следующем цикле
            self.log(f"{workflow.slug}: авто-снятие не удалось: {exc}")
            return None
        # Квен-M5+M6: маркер только ПОСЛЕ успешного резюма и с уникальным
        # payload (seq маркера) — контентная дедупликация событий не съест
        # повтор и не заблокирует следующую попытку
        self._append_marker(
            workflow.id,
            event_type="cascade.stale_blocker_cleared",
            run_id=str(marker.payload.get("run_id") or "") or None,
            round_id=None,
            payload={"reason": "живая база не содержит открытых blocker/high",
                     "cleared_after_seq": int(marker.seq)},
        )
        return result

    def _append_marker(
        self,
        workflow_id: str,
        *,
        event_type: str,
        run_id: str | None,
        round_id: str | None,
        payload: dict[str, Any],
        key_extra: str | None = None,
    ) -> None:
        """``key_extra`` делает ключ идемпотентности уникальным для
        повторяющихся маркеров без рана/раунда (P1-5): иначе первый же
        повтор с изменившимся payload падает в WorkflowConflictError, а
        журнал событий append-only — переписать ключ нельзя."""
        key_run = run_id or "none"
        key_round = round_id or "none"
        idempotency_key = f"{event_type}:{workflow_id}:{key_round}:{key_run}"
        if key_extra:
            idempotency_key += f":{key_extra}"
        db.append_workflow_event(WorkflowEventCreate(
            workflow_id=workflow_id,
            round_id=round_id,
            run_id=run_id,
            event_type=event_type,
            idempotency_key=idempotency_key,
            payload={"run_id": run_id, **payload},
        ))

    def _record_review_once(
        self,
        workflow: WorkflowInDB,
        decision: WorkflowReviewDecision,
    ) -> WorkflowInDB:
        """Record a verdict, reusing a durable core verdict after a takeover.

        The core may have parsed the reviewer output just before the cascade
        controller disabled the core review flags. Replaying the same report
        then collides on the strict finding idempotency key. If the durable
        round already contains the same revision verdict, continue from that
        projection instead of treating the collision as a new failure.
        """
        try:
            return workflows.record_review(
                workflow.id,
                decision.model_copy(update={"expected_version": workflow.state_version}),
            )
        except db.WorkflowConflictError as exc:
            if "idempotency key" not in str(exc):
                raise
            if decision.verdict is not ReviewVerdict.REVISION_REQUIRED:
                raise
            refreshed = db.get_workflow(workflow.id)
            if not refreshed:
                raise
            current = self._current_round(refreshed)
            if not current:
                raise
            already_applied = any(
                event.event_type == "review.revision_required"
                and event.round_id == current.id
                for event in self._events(refreshed.id)
            )
            if not already_applied:
                raise
            self.log(
                f"{workflow.slug}: повторный verdict уже записан core; "
                "продолжаю каскад без повторной записи findings"
            )
            return refreshed

    def _hold_for_human(
        self,
        workflow: WorkflowInDB,
        *,
        slot: dict[str, Any],
        event_type: str,
        reason: str,
        run_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> WorkflowInDB:
        with db._connect(immediate=True) as conn:
            row = conn.execute(
                "SELECT * FROM workflows WHERE id = ?", (workflow.id,)
            ).fetchone()
            state = WorkflowStatus(row["status"])
            round_row = workflows._current_round_row(conn, row)
            payload = {
                "stage_id": row["current_stage_id"] or "planless",
                "slot": int(slot.get("slot", 1)),
                "reason": reason,
            }
            if run_id:
                # U20: маркер обработанного ревью - без него _event_for_run
                # не находил событие, и каскад переоткрывал блокер каждый
                # тик (8+ событий подряд, инцидент 2026-10-04 04:1x).
                payload["run_id"] = run_id
            if metadata:
                payload.update(metadata)
            if state in {WorkflowStatus.REVISION_REQUIRED, WorkflowStatus.REVIEWING}:
                row = workflows._transition(
                    conn, row, WorkflowStatus.AWAITING_HUMAN,
                    event_type, payload, round_id=round_row["id"],
                )
            elif state is WorkflowStatus.AWAITING_HUMAN:
                row = workflows._touch(
                    conn, row, event_type, payload, round_id=round_row["id"],
                )
            if run_id:
                db._append_workflow_event(conn, WorkflowEventCreate(
                    workflow_id=workflow.id,
                    round_id=round_row["id"],
                    run_id=run_id,
                    event_type="cascade.review_processed",
                    idempotency_key=(
                        f"cascade.review_processed:{workflow.id}:"
                        f"{round_row['id']}:{run_id}"
                    ),
                    payload={
                        "run_id": run_id,
                        "slot": int(slot.get("slot", 1)),
                        "reason": reason,
                    },
                ))
            return db._row_to_workflow(row)

    def _resume_chain_revision(
        self,
        workflow: WorkflowInDB,
        *,
        chain: dict[str, Any],
        slot: dict[str, Any],
        attempt: int,
        max_rounds: int | None,
        budget_source: str | None,
        fixer: str,
        text: str,
    ) -> WorkflowInDB:
        """Create the next executor round for a chain revision.

        ``workflows.human_input(resume=True)`` also applies the core's
        per-stage revision budget.  That budget is a single-reviewer policy;
        applying it here would make a visually configured cascade stop before
        its later slots or retries.  The add-on owns the slot budget, while
        the core still owns the global workflow round budget and lifecycle
        transitions.
        """

        with db._connect(immediate=True) as conn:
            row = conn.execute(
                "SELECT * FROM workflows WHERE id = ?", (workflow.id,)
            ).fetchone()
            if not row:
                raise db.WorkflowNotFoundError(workflow.id)
            state = WorkflowStatus(row["status"])
            if state is WorkflowStatus.QUEUED:
                return db._row_to_workflow(row)
            round_row = workflows._current_round_row(conn, row)
            if state not in {
                WorkflowStatus.REVISION_REQUIRED,
                WorkflowStatus.AWAITING_HUMAN,
            } or round_row["status"] != "revision_required":
                raise db.WorkflowConflictError(
                    "cascade revision expected revision_required, "
                    f"got workflow={state.value}, round={round_row['status']}"
                )
            if max_rounds is None:
                max_rounds, budget_source = self._max_rounds_for_slot(
                    workflow, chain, slot
                )
            next_round = int(row["current_round"]) + 1
            if not workflows._check_round_budget(conn, row, next_round):
                payload = {
                    "stage_id": row["current_stage_id"] or "planless",
                    "slot": int(slot.get("slot", 1)),
                    "attempt": attempt,
                    "max_rounds": workflows._max_automated_rounds(row),
                    "refused_round": next_round,
                    "text": text,
                    "fixer": fixer,
                    "attempt_budget": max_rounds,
                    "attempt_budget_source": budget_source,
                }
                if state is WorkflowStatus.AWAITING_HUMAN:
                    row = workflows._touch(
                        conn,
                        row,
                        "cascade.max_rounds",
                        payload,
                        round_id=round_row["id"],
                    )
                else:
                    row = workflows._transition(
                        conn,
                        row,
                        WorkflowStatus.AWAITING_HUMAN,
                        "cascade.max_rounds",
                        payload,
                        round_id=round_row["id"],
                    )
                return db._row_to_workflow(row)

            new_round = workflows._insert_round(
                conn,
                workflow.id,
                next_round,
                base_sha=round_row["candidate_sha"],
                stage_id=row["current_stage_id"],
            )
            row = workflows._workflow_row(conn, workflow.id)
            row = workflows._transition(
                conn,
                row,
                WorkflowStatus.QUEUED,
                "cascade.revision_resumed",
                {
                    "stage_id": row["current_stage_id"] or "planless",
                    "slot": int(slot.get("slot", 1)),
                    "attempt": attempt,
                    "max_rounds": max_rounds,
                    "attempt_budget": max_rounds,
                    "attempt_budget_source": budget_source,
                    "fixer": fixer,
                    "text": text,
                    "previous_round": round_row["round_no"],
                    "new_round": next_round,
                    "stage_revision_budget": "owned_by_cascade",
                },
                round_id=new_round["id"],
            )
            return db._row_to_workflow(row)

    def _resume_recorded_revision(
        self,
        workflow: WorkflowInDB,
        *,
        chain: dict[str, Any],
        state: dict[str, Any],
        slot: dict[str, Any],
        attempt: int,
        fixer: str,
        reason: str,
        max_rounds: int | None = None,
        budget_source: str | None = None,
    ) -> WorkflowInDB:
        if max_rounds is None:
            max_rounds, budget_source = self._max_rounds_for_slot(
                workflow, chain, slot
            )
        index = int(slot.get("slot", 1)) - 1
        resume_text = (
            f"Каскад: исправить замечания ревью-ступени {index + 1} "
            f"провайдером {fixer}. Раунд {attempt}/{max_rounds} "
            f"({budget_source or 'manual'})."
        )
        configured = self._update_runtime_config(
            workflow,
            slot=slot,
            executor_provider=fixer,
            reviewer_provider=str(slot["provider"]),
            reason=reason,
        )
        resumed = self._resume_chain_revision(
            configured,
            chain=chain,
            slot=slot,
            attempt=attempt,
            max_rounds=max_rounds,
            budget_source=budget_source,
            fixer=fixer,
            text=resume_text,
        )
        if resumed.status is WorkflowStatus.AWAITING_HUMAN:
            save_state(self.state, self.state_path)
            return resumed
        advanced = workflows.advance_workflow(resumed.id)
        self.log(
            f"{workflow.slug}: ступень {index + 1} REVISION_REQUIRED → "
            f"исправление provider={fixer}, раунд {attempt}/{max_rounds} "
            f"({budget_source or 'manual'})"
        )
        return advanced

    def _dispatch_reviewer(
        self,
        workflow: WorkflowInDB,
        state: dict[str, Any],
        steps: list[dict[str, Any]],
    ) -> WorkflowInDB:
        index = int(state["slot"])
        if index >= len(steps):
            return workflow
        slot = steps[index]
        if not in_window(slot):
            window = slot.get("window") or {}
            outside_policy = str(window.get("outside") or "wait").lower()
            if outside_policy == "skip":
                self.log(
                    f"{workflow.slug}: ступень {index + 1} вне окна — пропускаю"
                )
                with db._connect(immediate=True) as conn:
                    row = conn.execute(
                        "SELECT * FROM workflows WHERE id = ?", (workflow.id,)
                    ).fetchone()
                    round_row = workflows._current_round_row(conn, row)
                    next_slot = index + 1
                    row = workflows._touch(
                        conn, row, "cascade.slot_skipped",
                        {
                            "stage_id": row["current_stage_id"] or "planless",
                            "slot": index + 1,
                            "next_slot": next_slot,
                            "reason": "outside_window",
                            "provider": slot.get("provider"),
                        },
                        round_id=round_row["id"],
                    )
                    workflow = db._row_to_workflow(row)
                state["attempts"] = {}
                state["last_run_id"] = None
                if next_slot >= len(steps):
                    # Пропущена последняя ступень. Если более ранняя ступень
                    # в этом раунде уже дала PASS — этап закрываем PASS'ом
                    # (окно ночное задумано как «днём дешевле пропустить», а
                    # не «стоять до ночи»). Иначе — честная пауза человеку.
                    current_round = self._current_round(workflow)
                    already_passed = any(
                        event.event_type == "cascade.slot_passed"
                        and (current_round is None
                             or event.round_id == current_round.id)
                        for event in self._events(workflow.id)
                    )
                    if already_passed:
                        chain = self._chain(workflow)[0]
                        # record_review применяется только из awaiting_human:
                        # кратко переводим воркфлоу туда (проекция «финальный
                        # вердикт готов»), сразу ниже запишем PASS.
                        if workflow.status is WorkflowStatus.REVIEWING:
                            workflow = self._hold_for_human(
                                workflow,
                                slot=slot,
                                event_type="cascade.final_skip_ready",
                                reason=("Финальная ступень пропущена вне окна; "
                                        "применяю PASS предыдущей ступени."),
                            )
                        configured = self._update_runtime_config(
                            workflow,
                            executor_provider=self._base_executor(chain, workflow),
                            reviewer_provider=str(slot.get("provider") or ""),
                            reason="restore executor after skipped final slot",
                        )
                        decision = WorkflowReviewDecision(
                            verdict=ReviewVerdict.PASS,
                            expected_version=0,  # перезапишется в _record_review_once
                            summary=("Каскад завершён: финальная ступень "
                                     "пропущена (вне окна); предыдущая "
                                     "ступень уже PASS."),
                        )
                        completed = self._record_review_once(configured, decision)
                        state["slot"] = 0
                        if completed.status is WorkflowStatus.QUEUED:
                            completed = workflows.advance_workflow(completed.id)
                        self.log(
                            f"{workflow.slug}: каскад завершён — финальная "
                            f"ступень пропущена вне окна (PASS предыдущей)"
                        )
                        return completed
                    # P0-1: пауза «все ступени вне окна» НЕ продвигает slot
                    # за пределы цепочки. Раньше здесь оставался
                    # slot == len(steps), и после ручного резюма
                    # process_workflow молча выходил по «index >= len(steps)»
                    # — конвейер навсегда замирал без ревью. Держим индекс
                    # текущей (пропущенной) ступени: резюм в открывшемся окне
                    # диспатчит её заново.
                    return self._hold_for_human(
                        workflow,
                        slot=slot,
                        event_type="cascade.all_slots_skipped",
                        reason="Все ступени каскада сейчас вне разрешённого окна.",
                    )
                state["slot"] = next_slot
                return self._dispatch_reviewer(workflow, state, steps)

            # A checked "only in window" option means wait for the next poll;
            # silently dispatching now would contradict the UI, while
            # stopping for a human would defeat the unattended pipeline.
            if state.get("window_wait_slot") != index:
                self.log(
                    f"{workflow.slug}: ступень {index + 1} вне окна — жду "
                    f"{window.get('from', '22:00')}–{window.get('to', '04:00')}"
                )
                state["window_wait_slot"] = index
            return workflow
        state.pop("window_wait_slot", None)

        cadence_note = None
        cadence = self._cadence(self._chain(workflow)[0])
        if cadence in {"window", "mission_final"}:
            # P1-7: mission_final строит тот же catch-up контекст на первом
            # ревью финального этапа — иначе диапазон diff промежуточных
            # этапов, закрытых гейтами, вообще никем не аудируется. Полоса
            # _defer_streak сама обнуляется после первого не-дефер раунда
            # (фикс-раунды финального этапа ревьюаются как обычно).
            checkpoint, stage_codes = self._defer_streak(workflow)
            if checkpoint:
                header = (
                    "[КАДЕНС: ЛЬГОТНОЕ ОКНО — КАТЧ-АП]"
                    if cadence == "window"
                    else "[КАДЕНС: ТОЛЬКО ФИНАЛ МИССИИ — КАТЧ-АП]"
                )
                cadence_note = (
                    f"{header}\n"
                    "Это ревью покрытия накопленного: этапы "
                    f"{', '.join(stage_codes) or '— '} закрывались гейтами без "
                    f"ревью. Аудируй диапазон ОТ commit {checkpoint} ДО "
                    "текущего HEAD ветки (git diff доступен в воркдерее); "
                    "находки помечай fingerprint'ами с префиксами этих этапов."
                )
        workflow = self._update_runtime_config(
            workflow,
            slot=slot,
            reviewer_provider=str(slot["provider"]),
            extra_context=cadence_note,
            reason="select reviewer slot",
        )
        current = db.get_workflow(workflow.id)
        if not current or current.status is not WorkflowStatus.REVIEWING:
            return current or workflow
        if self._pending_reviewer(current):
            return current
        result = workflows._dispatch_configured_role(current, WorkflowRole.REVIEWER)
        task_id = result.task.id
        state["last_run_id"] = result.run.id
        self.log(
            f"{current.slug}: запущен ревью-слот {index + 1}/{len(steps)} "
            f"provider={slot['provider']} task=#{task_id}"
        )
        return result.workflow

    def _gate_is_green(self, workflow: WorkflowInDB) -> bool:
        current = self._current_round(workflow)
        if not current:
            return False
        return any(
            event.event_type == "gate.passed"
            and event.round_id == current.id
            for event in self._events(workflow.id)
        )

    @staticmethod
    def _cadence(chain: dict[str, Any]) -> str:
        """Каденс ревью: every_round (дефолт) | stage_final | mission_final."""
        value = str((chain or {}).get("review_cadence") or "").lower()
        allowed = {"every_round", "stage_final", "mission_final", "window"}
        return value if value in allowed else "every_round"

    def _is_final_stage(self, workflow: WorkflowInDB) -> bool:
        stage_id = workflow.current_stage_id
        if not stage_id:
            return True
        with db._connect() as conn:
            rows = conn.execute(
                "SELECT id FROM workflow_stages WHERE workflow_id = ? "
                "ORDER BY position ASC",
                (workflow.id,),
            ).fetchall()
        return bool(rows) and rows[-1]["id"] == stage_id

    def _defer_streak(self, workflow: WorkflowInDB) -> tuple[str | None, list[str]]:
        """Полоса непроверенных каденсом раундов: (base_sha первого раунда
        полосы, коды этапов). Идём от предпоследнего раунда назад, пока
        раунды несут маркер cascade.cadence_deferred."""
        rounds = db.list_workflow_rounds(workflow.id)
        deferred = {
            event.round_id for event in self._events(workflow.id)
            if event.event_type == "cascade.cadence_deferred"
        }
        streak = []
        for row in reversed(rounds[:-1] if len(rounds) > 1 else []):
            if row.id in deferred:
                streak.append(row)
            else:
                break
        if not streak:
            return None, []
        streak.reverse()
        stage_ids = {row.stage_id for row in streak if row.stage_id}
        codes: list[str] = []
        with db._connect() as conn:
            for stage_id in stage_ids:
                code = conn.execute(
                    "SELECT code FROM workflow_stages WHERE id = ?",
                    (stage_id,)).fetchone()
                if code:
                    codes.append(str(code["code"]))
        return streak[0].base_sha, sorted(codes)

    @staticmethod
    def _cadence_windows(chain: dict[str, Any]) -> list[dict[str, Any]]:
        """Окна каденса «window»: список review_windows (дни+часы) либо
        одиночное review_window для старых конфигов."""
        chain = chain or {}
        windows = chain.get("review_windows")
        if isinstance(windows, list) and windows:
            return [w for w in windows if isinstance(w, dict)]
        single = chain.get("review_window")
        return [single] if isinstance(single, dict) and single else []

    @classmethod
    def _cadence_window_open(
        cls, chain: dict[str, Any], now_utc=None,
    ) -> bool:
        windows = cls._cadence_windows(chain)
        if not windows:
            return False
        return any(in_window({"window": w}, now_utc) for w in windows)

    def _stage_had_revision(self, workflow: WorkflowInDB) -> bool:
        stage_id = workflow.current_stage_id or "planless"
        for event in self._events(workflow.id):
            if event.event_type != "cascade.revision_requested":
                continue
            if (event.payload or {}).get("stage_id", "planless") == stage_id:
                return True
        return False

    def _apply_revision(
        self,
        workflow: WorkflowInDB,
        state: dict[str, Any],
        slot: dict[str, Any],
        decision: WorkflowReviewDecision,
        chain: dict[str, Any],
    ) -> WorkflowInDB:
        index = int(state["slot"])
        attempts = int(state["attempts"].get(str(index), 0)) + 1
        state["attempts"][str(index)] = attempts
        max_rounds, budget_source = self._max_rounds_for_slot(
            workflow, chain, slot, decision
        )
        if attempts > max_rounds:
            policy = str(slot.get("on_exhaust") or "human")
            if policy == "accept_if_gate_green" and self._gate_is_green(workflow):
                if index + 1 < len(self._chain(workflow)[1]):
                    passed = decision.model_copy(update={"verdict": ReviewVerdict.PASS})
                    return self._apply_pass(workflow, state, passed, chain)
                try:
                    return self._record_review_once(
                        workflow,
                        decision.model_copy(update={"verdict": ReviewVerdict.PASS}),
                    )
                except db.WorkflowConflictError:
                    pass
            return self._hold_for_human(
                workflow,
                slot=slot,
                event_type="cascade.exhausted",
                reason=(
                    f"Лимит попыток исчерпан ({attempts - 1}/{max_rounds}); "
                    f"бюджет {budget_source}; политика: {policy}."
                ),
                run_id=str(state.get("last_run_id") or "") or None,
                metadata={
                    "attempt": attempts - 1,
                    "attempt_budget": max_rounds,
                    "attempt_budget_source": budget_source,
                    "on_exhaust": policy,
                },
            )

        recorded = self._record_review_once(workflow, decision)
        current_round = self._current_round(recorded)
        self._append_marker(
            recorded.id,
            event_type="cascade.revision_requested",
            run_id=str(state.get("last_run_id") or "") or None,
            round_id=current_round.id if current_round else None,
            payload={
                "stage_id": recorded.current_stage_id or "planless",
                "slot": index + 1,
                "attempt": attempts,
                "attempt_budget": max_rounds,
                "attempt_budget_source": budget_source,
            },
        )
        fixer = self._resolve_fixer(slot, chain, recorded)
        if not fixer:
            return self._hold_for_human(
                recorded,
                slot=slot,
                event_type="cascade.no_fixer",
                reason="Для ступени не выбран провайдер исправления.",
                run_id=str(state.get("last_run_id") or "") or None,
            )
        return self._resume_recorded_revision(
            recorded,
            chain=chain,
            state=state,
            slot=slot,
            attempt=attempts,
            fixer=fixer,
            reason="route revision to configured fixer",
            max_rounds=max_rounds,
            budget_source=budget_source,
        )

    def _apply_pass(
        self,
        workflow: WorkflowInDB,
        state: dict[str, Any],
        decision: WorkflowReviewDecision,
        chain: dict[str, Any],
    ) -> WorkflowInDB:
        index = int(state["slot"])
        steps = self._chain(workflow)[1]
        slot = steps[index]
        reviewer = self._completed_reviewer(workflow)
        if not reviewer:
            return workflow
        if (
            index + 1 < len(steps)
            and self._cadence(chain) == "stage_final"
            and self._stage_had_revision(workflow)
        ):
            # Каденс «один раз на этап»: цепочка уже прошла этот этап,
            # ступень-автор вернула REVISION, фикс-раунд перепроверен этой же
            # ступенью — оставшиеся ступени повторно не гоняем, этап принят.
            self.log(
                f"{workflow.slug}: каденс stage_final — перепроверка ступени "
                f"{index + 1} прошла, этап принимается без повтора цепочки"
            )
            return self._record_final_pass(workflow, state, decision, chain, slot)
        if index + 1 < len(steps):
            if any(
                finding.severity in {FindingSeverity.BLOCKER, FindingSeverity.HIGH}
                and finding.status in {FindingStatus.OPEN, FindingStatus.REOPENED}
                for finding in decision.findings
            ):
                # П2a: текст отчёта мог перечислить уже закрытые находки —
                # блок ставим только по живой базе (инцидент 06.10: час
                # стойки из-за устаревшего списка в отчёте ревьюера)
                if self._live_hot_findings(workflow):
                    return self._hold_for_human(
                        workflow,
                        slot=slot,
                        event_type="cascade.open_blocker",
                        reason="Ревью вернул PASS, но оставил открытый blocker/high finding.",
                        run_id=str(reviewer.id),
                    )
                self.log(
                    f"{workflow.slug}: отчёт обещал открытый blocker/high, "
                    f"в живой базе они закрыты — блок не ставится (П2a)"
                )
                # квен-H2: устаревший отчёт не должен переоткрывать закрытые
                # находки при переходе ступени — иначе следующий слот увидит
                # «открытую» hot и встанет уже навсегда
                decision = decision.model_copy(update={
                    "findings": self._drop_resolved_from_report(
                        workflow, decision.findings),
                })
            transitioned = self._transition_to_reviewing(
                workflow,
                slot=slot,
                next_slot=index + 2,
                previous_run_id=reviewer.id,
                findings=decision.findings,
            )
            state["slot"] = index + 1
            state["attempts"] = {}
            state["last_run_id"] = None
            state["round"] = transitioned.current_round
            return self._dispatch_reviewer(transitioned, state, steps)

        return self._record_final_pass(workflow, state, decision, chain, slot)

    def _record_final_pass(
        self,
        workflow: WorkflowInDB,
        state: dict[str, Any],
        decision: WorkflowReviewDecision,
        chain: dict[str, Any],
        slot: dict[str, Any],
    ) -> WorkflowInDB:
        """Принять этап PASS'ом текущей ступени (нормальный финал или каденс)."""
        base_executor = self._base_executor(chain, workflow)
        configured = self._update_runtime_config(
            workflow,
            executor_provider=base_executor,
            reviewer_provider=str(slot["provider"]),
            reason="restore executor after final review slot",
        )
        completed = self._record_review_once(configured, decision)
        state["slot"] = 0
        state["attempts"] = {}
        state["last_run_id"] = None
        if completed.status is WorkflowStatus.QUEUED:
            completed = workflows.advance_workflow(completed.id)
        self.log(f"{workflow.slug}: каскад завершён — финальная ступень PASS")
        return completed

    # P0-2: маркер input_sha256 синтетического рана каденс-дефера — по нему
    # восстановление отличает «ревью отложено» от настоящего отчёта ревьюера.
    CADENCE_DEFER_INPUT_SHA = "cadence-mission-final-defer"

    def _cadence_defer_pass(
        self,
        workflow: WorkflowInDB,
        state: dict[str, Any],
        chain: dict[str, Any],
        cadence: str = "mission_final",
    ) -> WorkflowInDB:
        """Каденс mission_final: промежуточный этап закрывается зелёным
        гейтом без ревью; полная цепочка прогонится на финальном этапе."""
        steps = self._chain(workflow)[1]
        current = self._current_round(workflow)
        if not current:
            return workflow
        events = self._events(workflow.id)
        already_deferred = any(
            event.event_type == "cascade.cadence_deferred"
            and event.round_id == current.id
            for event in events
        )
        if already_deferred:
            return workflow  # рестарт контроллера: отсрочка уже применена
        # record_review требует завершённый ревью-ран на раунде — каденс
        # пишет синтетический ран-маркер «ревью отложено» (task_id нет,
        # результат помечен) и валидирует этап как обычный PASS.
        attempt = 1
        with db._connect() as conn:
            row = conn.execute(
                """SELECT MAX(attempt_no) AS m FROM workflow_runs
                   WHERE round_id = ? AND role = 'reviewer'""",
                (current.id,),
            ).fetchone()
            attempt = int(row["m"] or 0) + 1
        marker_run = db.create_workflow_run(WorkflowRunCreate(
            workflow_id=workflow.id,
            round_id=current.id,
            role=WorkflowRole.REVIEWER,
            attempt_no=attempt,
            input_sha256=self.CADENCE_DEFER_INPUT_SHA,
        ))
        with db._connect(immediate=True) as conn:
            conn.execute(
                """UPDATE workflow_runs SET status='completed',
                   started_at=?, completed_at=?, output_json=?
                   WHERE id = ?""",
                (db._now(), db._now(),
                 db._json_dump({"result": (
                     "Каденс «только финал миссии»: ревью этапа отложено, "
                     "этап закрыт зелёным гейтом."
                 )}),
                 marker_run.id),
            )
        # record_review применяется только из awaiting_human — краткий
        # перевод туда (та же проекция, что у финального пропуска окна).
        held = self._hold_for_human(
            workflow,
            slot=steps[0] if steps else {},
            event_type="cascade.cadence_deferred",
            reason=f"Каденс «{cadence}»: ревью этапа отложено.",
            run_id=None,
            metadata={"cadence": cadence},
        )
        return self._finish_cadence_defer(held, state, chain, cadence)

    def _finish_cadence_defer(
        self,
        workflow: WorkflowInDB,
        state: dict[str, Any],
        chain: dict[str, Any],
        cadence: str,
    ) -> WorkflowInDB:
        """Дозапись дефер-PASS (первый проход или восстановление P0-2).

        Вызывается и сразу после холда, и из ``_process_completed_review``,
        если контроллер упал между холдом и ``record_review``: workflow
        остаётся в awaiting_human с синтетическим completed-раном, и без
        этой ветки его текст парсился бы как отчёт ревьюера."""
        decision = WorkflowReviewDecision(
            verdict=ReviewVerdict.PASS,
            expected_version=0,  # перезапишется в _record_review_once
            summary=(
                f"Каденс «{cadence}»: ревью этапа отложено, "
                "этап закрыт зелёным гейтом."
            ),
        )
        base_executor = self._base_executor(chain, workflow)
        configured = self._update_runtime_config(
            workflow,
            executor_provider=base_executor,
            reviewer_provider=str(chain.get("base_reviewer_provider") or ""),
            reason="restore executor (review deferred by cadence)",
        )
        completed = self._record_review_once(configured, decision)
        state["slot"] = 0
        state["attempts"] = {}
        state["last_run_id"] = None
        if completed.status is WorkflowStatus.QUEUED:
            completed = workflows.advance_workflow(completed.id)
        self.log(
            f"{workflow.slug}: каденс {cadence} — этап закрыт гейтом, "
            "ревью отложено"
        )
        return completed

    def _process_completed_review(
        self,
        workflow: WorkflowInDB,
        state: dict[str, Any],
        chain: dict[str, Any],
        steps: list[dict[str, Any]],
    ) -> WorkflowInDB:
        reviewer = self._completed_reviewer(workflow)
        if not reviewer:
            return workflow
        events = self._events(workflow.id)
        if self._event_for_run(events, None, str(reviewer.id)):
            return workflow
        if str(reviewer.input_sha256 or "") == self.CADENCE_DEFER_INPUT_SHA:
            # P0-2: это синтетический ран каденса-дефера («Каденс… отложено»),
            # а не отчёт ревьюера — парсить его текст нельзя: parse -> None
            # порождал ложную стойку cascade.invalid_review_output. Если
            # контроллер упал между холдом и record_review, дозаписываем
            # дефер-PASS тем же путём, что и первый проход.
            cadence = "mission_final"
            for event in reversed(events):
                if (event.event_type == "cascade.cadence_deferred"
                        and event.round_id == reviewer.round_id):
                    cadence = str((event.payload or {}).get("cadence")
                                  or cadence)
                    break
            return self._finish_cadence_defer(workflow, state, chain, cadence)
        index = int(state["slot"])
        slot = steps[index]
        report = (reviewer.output or {}).get("result") or ""
        decision = workflows.parse_reviewer_report(report)
        if not decision:
            # Let the existing Jev/verdict watcher repair invalid output, but
            # leave the chain paused instead of guessing a PASS.
            state["last_run_id"] = reviewer.id
            return self._hold_for_human(
                workflow,
                slot=slot,
                event_type="cascade.invalid_review_output",
                reason="Ревьюер не вернул валидные AUDIT_FINDINGS_JSON/AUDIT_VERDICT.",
                run_id=str(reviewer.id),
            )
        state["last_run_id"] = reviewer.id
        if decision.verdict is ReviewVerdict.HUMAN_REQUIRED:
            if slot.get("blocking", True) is False:
                # P19: advisory-слот не имеет права вето и через HUMAN_REQUIRED;
                # его вопрос фиксируется отчётом и логом, но конвейер продолжает.
                self.log(
                    f"{workflow.slug}: слот {index + 1} non-blocking просит "
                    "человека ({}) — фиксирую как advisory, конвейер продолжает"
                    .format((decision.summary or "")[-160:])
                )
                advisory = decision.model_copy(update={"verdict": ReviewVerdict.PASS})
                return self._apply_pass(workflow, state, advisory, chain)
            recorded = self._record_review_once(workflow, decision)
            return self._hold_for_human(
                recorded,
                slot=slot,
                event_type="cascade.human_required",
                reason="Ревьюер явно запросил решение человека.",
                run_id=str(reviewer.id),
            )
        if decision.verdict is ReviewVerdict.REVISION_REQUIRED:
            if slot.get("blocking", True) is False:
                advisory = decision.model_copy(update={"verdict": ReviewVerdict.PASS})
                return self._apply_pass(workflow, state, advisory, chain)
            current = self._current_round(workflow)
            already_recorded = any(
                event.event_type == "review.revision_required"
                and event.round_id == (current.id if current else None)
                for event in self._events(workflow.id)
            )
            if already_recorded:
                # Core automation may have projected an old chain review to
                # ``awaiting_human`` before this controller took ownership.
                # Do not call record_review a second time: its finding event
                # is already durable and would collide on the idempotency key.
                attempts = int(state["attempts"].get(str(state["slot"]), 0) or 0) + 1
                state["attempts"][str(state["slot"])] = attempts
                self._append_marker(
                    workflow.id,
                    event_type="cascade.revision_requested",
                    run_id=str(reviewer.id),
                    round_id=current.id if current else None,
                    payload={
                        "stage_id": workflow.current_stage_id or "planless",
                        "slot": int(state["slot"]) + 1,
                        "attempt": attempts,
                        "recovered_existing_review": True,
                    },
                )
                fixer = self._resolve_fixer(slot, chain, workflow)
                if not fixer:
                    return self._hold_for_human(
                        workflow,
                        slot=slot,
                        event_type="cascade.no_fixer",
                        reason="Для ступени не выбран провайдер исправления.",
                        run_id=str(reviewer.id),
                    )
                return self._resume_recorded_revision(
                    workflow,
                    chain=chain,
                    state=state,
                    slot=slot,
                    attempt=attempts,
                    fixer=fixer,
                    reason="recover review already applied by core automation",
                )
            return self._apply_revision(workflow, state, slot, decision, chain)
        return self._apply_pass(workflow, state, decision, chain)

    def _handle_reviewer_failure(
        self,
        workflow: WorkflowInDB,
        state: dict[str, Any],
        chain: dict[str, Any],
        steps: list[dict[str, Any]],
    ) -> WorkflowInDB:
        """U25: ревью-ран УПАЛ (провайдер умер, 401, таймаут CLI).

        sync_task проецирует падение ревьюера в awaiting_human
        (reviewer.failed), но политика ступени (blocking/on_exhaust) к
        авариям не применялась — конвейер ждал ручного клика владельца
        (инцидент 09.10 17:35: codex 401, владелец нажимал «Принять
        вручную» сам). Неблокирующая ступень не имеет права вето и
        падением (принцип P19); блокирующая с on_exhaust=
        accept_if_gate_green при зелёном гейте принимается; остальные
        честно ждут человека.
        """
        current_round = self._current_round(workflow)
        if not current_round:
            return workflow
        runs = [
            item for item in db.list_workflow_runs(current_round.id)
            if item.role is WorkflowRole.REVIEWER
        ]
        if not runs:
            return workflow
        run = max(runs, key=lambda item: item.attempt_no)
        if run.status.value != "failed":
            return workflow
        index = int(state["slot"])
        if index >= len(steps):
            return workflow
        slot = steps[index]
        run_id = str(run.id)
        events = self._events(workflow.id)
        if self._event_for_run(
            events, "cascade.reviewer_failed_advisory", run_id
        ):
            return workflow
        if self._event_for_run(events, "cascade.reviewer_failed", run_id):
            return workflow
        error = str((run.output or {}).get("error") or "reviewer run failed")
        blocking = slot.get("blocking", True) is not False
        exhaust = str(slot.get("on_exhaust") or "human").lower()
        gate_green = self._gate_is_green(workflow)
        accept = (not blocking) or (exhaust == "accept_if_gate_green"
                                    and gate_green)
        if not accept:
            return self._hold_for_human(
                workflow,
                slot=slot,
                event_type="cascade.reviewer_failed",
                reason=(f"Ревьюер ступени упал: {error[:180]}"),
                run_id=run_id,
            )
        self.log(
            f"{workflow.slug}: слот {index + 1} ({slot.get('provider')}) "
            f"упал ({'advisory' if not blocking else 'accept_if_gate_green'}) "
            f"— конвейер продолжает: {error[-140:]}"
        )
        self._append_marker(
            workflow.id,
            event_type="cascade.reviewer_failed_advisory",
            run_id=run_id,
            round_id=current_round.id,
            payload={
                "slot": index + 1,
                "provider": slot.get("provider"),
                "error": error[-300:],
                "gate_green": gate_green,
                "policy": "advisory" if not blocking else exhaust,
            },
        )
        next_slot = index + 1
        state["slot"] = next_slot
        state["attempts"] = {}
        state["last_run_id"] = None
        if next_slot >= len(steps):
            # Последняя ступень: синтез финального PASS, если более ранняя
            # ступень этого раунда уже PASS (зеркалит пропуск вне окна).
            already_passed = any(
                event.event_type == "cascade.slot_passed"
                and event.round_id == current_round.id
                for event in self._events(workflow.id)
            )
            if not already_passed:
                return self._hold_for_human(
                    workflow,
                    slot=slot,
                    event_type="cascade.reviewer_failed",
                    reason=(
                        "Финальная ступень упала, раннего PASS в раунде нет — "
                        "нужно ручное решение."
                    ),
                    run_id=run_id,
                )
            if workflow.status is WorkflowStatus.REVIEWING:
                workflow = self._hold_for_human(
                    workflow,
                    slot=slot,
                    event_type="cascade.final_failover_ready",
                    reason=(
                        "Финальная ступень упала; применяю PASS предыдущей "
                        "ступени (политика ступени)."
                    ),
                )
            configured = self._update_runtime_config(
                workflow,
                executor_provider=self._base_executor(chain, workflow),
                reviewer_provider=str(slot.get("provider") or ""),
                reason="restore executor after failed final slot",
            )
            decision = WorkflowReviewDecision(
                verdict=ReviewVerdict.PASS,
                expected_version=0,  # перезапишется в _record_review_once
                summary=(
                    "Каскад завершён: финальная ступень упала "
                    f"({error[:120]}); предыдущая ступень уже PASS, "
                    "политика ступени принимает этап."
                ),
            )
            try:
                completed = self._record_review_once(configured, decision)
            except Exception as exc:  # noqa: BLE001 - например, открытые blocker
                return self._hold_for_human(
                    configured,
                    slot=slot,
                    event_type="cascade.reviewer_failed",
                    reason=f"PASS после падения ступени не записан: {exc}",
                    run_id=run_id,
                )
            state["slot"] = 0
            if completed.status is WorkflowStatus.QUEUED:
                completed = workflows.advance_workflow(completed.id)
            return completed
        workflow = self._transition_to_reviewing(
            workflow,
            slot=slot,
            next_slot=next_slot,
            previous_run_id=run.id,
            findings=[],
        )
        return self._dispatch_reviewer(workflow, state, steps)

    def process_workflow(self, workflow_id: str) -> WorkflowInDB | None:
        workflow = db.get_workflow(workflow_id)
        if not workflow:
            return None
        chain, steps = self._chain(workflow)
        if not steps or workflow.status in {
            WorkflowStatus.COMPLETED,
            WorkflowStatus.FAILED,
            WorkflowStatus.CANCELLED,
        }:
            return workflow

        automation = workflow.config.get("automation") or {}
        if (
            automation.get("auto_dispatch_reviewer", True)
            or automation.get("auto_apply_review", True)
            or automation.get("auto_resume_revision", True)
        ):
            # Repair configs written by the prototype or by an older UI before
            # the next executor reaches the reviewer boundary.  This is an
            # additive config normalization, not a core state transition.
            workflow = self._update_runtime_config(
                workflow,
                reason="enable cascade controller ownership",
            )

        # Reconcile a task that finished between worker ticks before deciding
        # which slot owns the next action.
        try:
            workflows.sync_all_tasks(workflow.id)
        except Exception as exc:  # noqa: BLE001
            self.log(f"{workflow.slug}: sync перед каскадом: {type(exc).__name__}: {exc}")
        workflow = db.get_workflow(workflow.id) or workflow
        state = self._workflow_state(workflow, steps)
        # долг-ревью: порог medium превышен и окно исполнителя позволяет —
        # конвейер сам берёт недочёты в работу (владелец 07.10)
        try:
            self._maybe_debt_sweep(workflow, chain)
            self._maybe_debt_review(workflow, chain)
        except Exception as exc:  # noqa: BLE001 - долг не роняет каскад
            import traceback as _tb

            self.log(f"{workflow.slug}: debt-sweep: " + ''.join(
                _tb.format_exception(type(exc), exc, exc.__traceback__))[-400:].replace(chr(10), ' | '))
        index = int(state["slot"])
        if index >= len(steps):
            return workflow

        if workflow.status is WorkflowStatus.REVIEWING:
            if self._pending_reviewer(workflow):
                return workflow
            done = self._completed_reviewer(workflow)
            if (done and not self._superseded_by_executor(workflow, done)
                    and str(done.input_sha256 or "")
                    != self.CADENCE_DEFER_INPUT_SHA):
                # The worker normally projects this to awaiting_human. Do not
                # dispatch another reviewer until that projection is durable —
                # НО если каскад уже принял решение по этому ревью
                # (slot_passed/skipped/revision), проекция давно случилась:
                # ждать нечего, проваливаемся к диспетчеру следующей ступени.
                # P0-2: у синтетического дефер-рана нет task_id — воркер его
                # НЕ спроецирует никогда; ждать его в reviewing — дедлок.
                if not self._event_for_run(self._events(workflow.id), None, done.id):
                    return workflow
            cadence = self._cadence(chain)
            if cadence == "mission_final" and not self._is_final_stage(workflow):
                result = self._cadence_defer_pass(workflow, state, chain,
                                                  cadence="mission_final")
                save_state(self.state, self.state_path)
                return result
            if cadence == "window":
                if not self._cadence_window_open(chain):
                    result = self._cadence_defer_pass(workflow, state, chain,
                                                      cadence="window")
                    save_state(self.state, self.state_path)
                    return result
            result = self._dispatch_reviewer(workflow, state, steps)
            save_state(self.state, self.state_path)
            return result

        if workflow.status is WorkflowStatus.AWAITING_HUMAN:
            cleared = self._clear_stale_blocker(workflow)
            if cleared is not None:
                save_state(self.state, self.state_path)
                return cleared
            result = self._process_completed_review(workflow, state, chain, steps)
            if result.status is WorkflowStatus.AWAITING_HUMAN:
                # U25: пауза может быть падением ревьюера (reviewer.failed),
                # а не человеческим вердиктом — применить политику ступени
                result = self._handle_reviewer_failure(result, state, chain, steps)
            save_state(self.state, self.state_path)
            return result

        if workflow.status is WorkflowStatus.REVISION_REQUIRED:
            current = self._current_round(workflow)
            events = self._events(workflow.id)
            stage_id = workflow.current_stage_id or "planless"

            # Normal path after a review decision.  If the controller was
            # restarted after ``record_review`` but before the next round was
            # created, this durable marker lets it continue with the same
            # configured fixer instead of leaving the workflow stuck.
            marker = next(
                (
                    event for event in reversed(events)
                    if event.event_type == "cascade.revision_requested"
                    and event.round_id == (current.id if current else None)
                    and event.payload.get("stage_id", stage_id) == stage_id
                ),
                None,
            )
            if marker:
                slot_index = max(0, int(marker.payload.get("slot", 1)) - 1)
                if slot_index < len(steps):
                    state["slot"] = slot_index
                    attempt = max(
                        int(marker.payload.get("attempt", 1) or 1),
                        int(state["attempts"].get(str(slot_index), 0) or 0),
                    )
                    state["attempts"][str(slot_index)] = attempt
                    slot = steps[slot_index]
                    fixer = self._resolve_fixer(slot, chain, workflow)
                    if fixer:
                        result = self._resume_recorded_revision(
                            workflow,
                            chain=chain,
                            state=state,
                            slot=slot,
                            attempt=attempt,
                            fixer=fixer,
                            reason="recover cascade revision after controller restart",
                        )
                        save_state(self.state, self.state_path)
                        return result

            # A crash can occur in the small gap after core
            # ``record_review`` commits and before the marker above is saved.
            # A reviewer revision is still identifiable from the core event
            # and its completed report; deterministic gate revisions have no
            # reviewer run and therefore cannot enter this branch.
            review_event = next(
                (
                    event for event in reversed(events)
                    if event.event_type == "review.revision_required"
                    and event.round_id == (current.id if current else None)
                ),
                None,
            )
            reviewer = self._completed_reviewer(workflow)
            reviewer_decision = workflows.parse_reviewer_report(
                (reviewer.output or {}).get("result") or ""
            ) if reviewer else None
            if (
                review_event
                and reviewer
                and reviewer_decision
                and reviewer_decision.verdict is ReviewVerdict.REVISION_REQUIRED
            ):
                slot = steps[index]
                attempt = int(state["attempts"].get(str(index), 0) or 0) + 1
                state["attempts"][str(index)] = attempt
                self._append_marker(
                    workflow.id,
                    event_type="cascade.revision_requested",
                    run_id=str(reviewer.id),
                    round_id=current.id if current else None,
                    payload={
                        "stage_id": stage_id,
                        "slot": index + 1,
                        "attempt": attempt,
                        "recovered_without_marker": True,
                    },
                )
                fixer = self._resolve_fixer(slot, chain, workflow)
                if fixer:
                    result = self._resume_recorded_revision(
                        workflow,
                        chain=chain,
                        state=state,
                        slot=slot,
                        attempt=attempt,
                        fixer=fixer,
                        reason="recover markerless cascade revision",
                    )
                    save_state(self.state, self.state_path)
                    return result

            # Deterministic gate failure: the chain does not invent a review
            # verdict, but it can resume the base executor through the core's
            # ordinary gate-retry path.
            recent = events[-1:] if workflow.id else []
            if recent and recent[0].event_type == "gate.failed":
                base = self._base_executor(chain, workflow)
                configured = self._update_runtime_config(
                    workflow,
                    executor_provider=base,
                    reviewer_provider=str(steps[index]["provider"]),
                    reason="resume deterministic gate revision",
                )
                resumed = workflows.human_input(
                    configured.id,
                    WorkflowHumanInput(
                        expected_version=configured.state_version,
                        text="Каскад: повторить этап после неуспешного deterministic gate.",
                        resume=True,
                    ),
                )
                result = workflows.advance_workflow(resumed.id)
                save_state(self.state, self.state_path)
                return result
        return workflow

    def process_all(self) -> int:
        count = 0
        for workflow in db.list_workflows(limit=500):
            chain, steps = self._chain(workflow)
            if not steps:
                continue
            count += 1
            try:
                self.process_workflow(workflow.id)
            except Exception as exc:  # noqa: BLE001
                self.log(
                    f"{workflow.slug}: цикл каскада: {type(exc).__name__}: {exc}"
                )
        save_state(self.state, self.state_path)
        return count

    def run_forever(self, *, workflow_id: str | None = None, poll_seconds: int = DEFAULT_POLL_SECONDS) -> None:
        self.log(
            "cascade-review запущен "
            f"({'workflow ' + workflow_id if workflow_id else 'все review_chain-воркфлоу'})"
        )
        tick = 0
        while True:
            tick += 1
            try:
                if workflow_id:
                    self.process_workflow(workflow_id)
                else:
                    self.process_all()
            except Exception as exc:  # noqa: BLE001
                self.log(f"цикл: {type(exc).__name__}: {exc}")
            # P0-3.1: сердцебиение каждые 12 тиков — повисший/умерший цикл
            # виден по свежести лога (гипервизор ловит молчание)
            if tick % 12 == 0:
                self.log(f"тик {tick}: жив (heartbeat)")
            time.sleep(max(1, poll_seconds))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="PromptPilot additive review-chain controller")
    parser.add_argument("workflow_id", nargs="?", help="workflow id/slug, or all workflows")
    parser.add_argument("--once", action="store_true", help="process once and exit")
    parser.add_argument("--poll-seconds", type=int, default=DEFAULT_POLL_SECONDS)
    parser.add_argument("--state-file", type=Path, default=DEFAULT_STATE_PATH)
    parser.add_argument("--log-file", type=Path, default=DEFAULT_LOG_PATH)
    args = parser.parse_args(argv)
    controller = CascadeController(state_path=args.state_file, log_path=args.log_file)
    if args.once:
        if args.workflow_id:
            controller.process_workflow(args.workflow_id)
        else:
            controller.process_all()
        return 0
    controller.run_forever(
        workflow_id=args.workflow_id,
        poll_seconds=args.poll_seconds,
    )
    return 0


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass
    raise SystemExit(main())
