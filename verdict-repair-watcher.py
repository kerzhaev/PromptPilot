#!/usr/bin/env python3
"""Verdict-repair watcher для PromptPilot.

Ловит события `executor.invalid_output` (исполнитель потерял строку вердикта
«ИТОГ:» — главная причина остановок пайплайна) и автоматически продолжает
локальный автономный workflow, если остановка носит только технический
протокольный характер. Для неоднозначных случаев остаётся резервная проверка
через TypeSafe Jev (System One: https://docs.typesafe.ai).

В автономном локальном workflow watcher также автоматически разрешает узкий
класс capability-вопросов: когда агент уже подготовил дифф, но не может писать
файлы/запускать shell, выбирается вариант helper-agent и раунд продолжается.
Обычные вопросы о продуктовых решениях, внешних системах и удалённых машинах
по-прежнему остаются за человеком.

Политика безопасности:
  - протокольные остановки (потерянный ИТОГ/машинные строки аудита) в локальном
    workflow проходят автоматически, но ограничены пятью продолжениями на
    раунд;
  - merge/push/deploy/release, production/main, удалённые/внешние ресурсы,
    удаление/перезапись, секреты, безопасность, owner-решения и неоднозначные
    вопросы остаются за человеком;
  - каждое решение пишется в ~/.promptpilot/verdict-repair.log (аудит).

Запуск:  python verdict-repair-watcher.py
Ключ:    env TYPESAFE_API_KEY или файл C:\\Users\\Nachfin\\Desktop\\TypeSafe.txt
Стоп:    Ctrl+C
"""

import json
import os
import re
import sqlite3
import sys
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime

HOME = os.path.expanduser("~")
# The portable remote launcher supplies PP_DATA_DIR so the watcher follows the
# same isolated database as core instead of silently attaching to the host
# user's unrelated ~/.promptpilot database.
DATA_DIR = os.environ.get("PP_DATA_DIR", os.path.join(HOME, ".promptpilot"))
DB_PATH = os.path.join(DATA_DIR, "promptpilot.db")
LOG_PATH = os.path.join(DATA_DIR, "verdict-repair.log")
STATE_PATH = os.path.join(DATA_DIR, "verdict-repair-state.json")
# U11: путь к ключу TypeSafe берём из профиля ТЕКУЩЕГО пользователя — раньше
# был жёстко вшит чужой профиль (C:\Users\Nachfin\...), UI сохранял ключ в
# Path.home()/Desktop, вотчер читал мимо: ключ «не сохранялся» (инцидент
# 2026-10-03). Совпадает с путём записи в api.py (_typesafe_key_file).
KEY_FILE = os.path.join(os.path.expanduser("~"), "Desktop", "TypeSafe.txt")
BASE_URL = "http://127.0.0.1:8420"
TYPESAFE_URL = "https://api.typesafe.ai/v1/systemone"
POLL_SECONDS = 20
MIN_CHOICE_CONF = 0.85
MIN_NOUL_DONE = 0.70
AUTO_VERDICTS = {"done", "already"}
RESUME_TEXT = "Продолжить работу с учётом сохранённого состояния"

# ELICIT auto-resolution is intentionally narrow.  Do not match every question
# mentioning an agent: only a local autonomous workflow may automatically choose
# a helper for a missing write/shell capability.
CAPABILITY_MARKERS = (
    "write_file", "run_shell_command", "edit/write_file", "shell",
    "write access", "file write", "запис", "правк", "дифф", "diff",
    "permission",
)
HELPER_MARKERS = (
    "помощник-агент", "помощник агента", "helper-agent", "helper agent",
    "helper", "agent", "агент",
)
MANUAL_MARKERS = (
    "ничего не давать", "не давать", "вручную", "ручн", "manual",
)
AUTO_CAPABILITY_ENV = "PP_AUTO_ELICIT_CAPABILITY"
AUTO_NONCRITICAL_ENV = "PP_AUTO_RESUME_NONCRITICAL"
MAX_NONCRITICAL_RESUMES_PER_WORKFLOW_ROUND = 5

# These are intentionally high-signal markers.  A generic ``НУЖЕН ЧЕЛОВЕК``
# is not enough to classify a stop as critical: technical reports often use
# that verdict after losing the machine-readable closing line.  Conversely,
# mentioning one of these high-impact operations keeps the human gate.
CRITICAL_MARKERS = (
    "production", "prod environment", "продакш", "merge", "push", "deploy",
    "release", "publish", "публиков", "слияни", "выкат",
    "delete repository", "delete data", "удалить репозитор", "удалить данн",
    "перезаписать данн", "перезаписать репозитор", "уничтожить данн",
    "wipe storage", "destruct", "selectel", "s3", "ssh",
    "remote host", "удалённая машина", "удаленная машина", "внешнее хранилище",
    "external storage", "secret", "credential", "api key", "access token",
    "парол", "секрет", "owner decision", "решение владельца", "владелец",
    "security gate", "security blocker", "security decision", "безопасност gate",
    "blocker decision", "критичн решение", "critical decision",
)
CRITICAL_BRANCH_RE = re.compile(
    r"(?:\b(?:main|master)\b.{0,48}(?:branch|ветк|merge|push|deploy|release|"
    r"слияни|публиков|переключ)|"
    r"(?:branch|ветк|merge|push|deploy|release|слияни|публиков|переключ).{0,48}"
    r"\b(?:main|master)\b)",
    re.I,
)

# Only these event/reason combinations are technical protocol stops.  An
# arbitrary human-required report must not become an unconditional retry.
NONCRITICAL_STOP_MARKERS = (
    "missing successful workflow verdict", "missing workflow verdict",
    "without the required closing", "invalid output", "invalid workflow output",
    "без успешного вердикта", "потерял строку", "потеряна строка",
    "не вернул валидн", "не вернул обязательн", "не содержит обязательн",
    "stage-plan-v1", "audit_verdict", "audit_findings_json", "машинн",
)
NONCRITICAL_QUESTION_MARKERS = (
    "техническ", "некритич", "ошибк", "сбой", "таймаут", "повтор",
    "перезапуск", "продолж", "не хватает прав", "доступ к файлам",
    "shell", "write_file", "run_shell_command", "diff", "патч", "тест",
    "test", "итог", "вердикт", "audit", "аудит", "missing", "invalid",
    "protocol", "протокол",
)
SAFE_CHOICE_MARKERS = (
    "продолж", "continue", "авто", "auto", "повтор", "retry", "перезапуск",
    "helper", "помощ", "исполн", "безопасн", "safe", "восстанов",
)

# U12: панель «Права». Вопрос, попадающий в правовой класс, автовыбором не
# закрывается, если в глобальной политике этот класс ask/deny — решает человек.
PERMISSION_KEYWORDS = {
    "install_tools": ("установ", "sdk", "jdk", "инструмент", "докачать", "android studio"),
    "environments": ("окружени", "venv", "виртуальн", "контейнер", "docker", "зависимост"),
    "git_push": ("push", "пуш", "pull request", "публиков", "merge", "мерж", "слияни"),
    "deploy": ("deploy", "деплой", "ssh", "на сервер", "домен", "vps", "выкат", "vps"),
    "real_sends": ("отправ", "email", "sms", "telegram", "рассыл", "письм"),
    "secrets": ("секрет", "парол", "токен", "api key", "api-ключ", "credential", "ключ"),
    "device_ops": ("устройств", "adb", "apk", "телефон", "эмулятор", "avd"),
    "payments": ("покуп", "оплат", "платн"),
}


def _permissions_gate(question_text: str, context_text: str) -> str | None:
    """Класс прав из текста вопроса; None = обычный технический вопрос."""
    full = f"{question_text} {context_text}"
    for key, words in PERMISSION_KEYWORDS.items():
        if any(word in full for word in words):
            return key
    return None


def _permissions_mode(action_key: str) -> str:
    """Режим класса из панели «Права» через API (allow по умолчанию)."""
    try:
        data = api("/api/permissions", "GET")
        for action in data.get("actions", []):
            if action.get("key") == action_key:
                return str(action.get("mode") or "allow")
    except Exception:  # noqa: BLE001 - панель недоступна = не блокируем автовыбор
        pass
    return "allow"


def log(message: str) -> None:
    line = f"{datetime.now().isoformat(timespec='seconds')} {message}"
    print(line, flush=True)
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError:
        pass


def load_key() -> str:
    env = os.environ.get("TYPESAFE_API_KEY", "").strip()
    if env:
        return env
    with open(KEY_FILE, encoding="utf-8") as f:
        return f.read().strip()


def load_state() -> dict:
    try:
        with open(STATE_PATH, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {"last_seq": 0}


def save_state(state: dict) -> None:
    with open(STATE_PATH, "w", encoding="utf-8") as f:
        json.dump(state, f)


def db_connect():
    conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True, timeout=5)
    conn.execute("PRAGMA busy_timeout = 4000")
    return conn


def api(path: str, method: str = "GET", body: dict | None = None):
    req = urllib.request.Request(
        BASE_URL + path,
        method=method,
        data=json.dumps(body).encode("utf-8") if body is not None else None,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read().decode("utf-8"))


def _row_dict(row, names: tuple[str, ...]) -> dict:
    """Convert a sqlite tuple/Row or an existing mapping to a small dict."""
    if isinstance(row, dict):
        return row
    return {name: row[index] for index, name in enumerate(names)}


def _automation_config(workflow: dict) -> dict | None:
    try:
        config = json.loads(workflow.get("config_json") or "{}")
    except (TypeError, json.JSONDecodeError):
        return None
    automation = config.get("automation") if isinstance(config, dict) else None
    return automation if isinstance(automation, dict) else None


def _protected_branch(branch: str) -> bool:
    normalized = branch.replace("\\", "/").strip().lower()
    for prefix in ("refs/heads/", "origin/", "upstream/"):
        if normalized.startswith(prefix):
            normalized = normalized[len(prefix):]
    return normalized in {"main", "master", "production", "prod"}


def _local_autonomous_enabled(
    workflow: dict,
    task: dict,
    *,
    config_flag: str,
    env_name: str,
) -> bool:
    """Shared safety fence for watcher-owned local automatic actions."""
    if os.environ.get(env_name, "1").strip().lower() in {
        "0", "false", "no", "off",
    }:
        return False
    if str(workflow.get("status") or "") != "awaiting_human":
        return False
    automation = _automation_config(workflow)
    if automation is None:
        return False
    if automation.get("enabled") is not True:
        return False
    if automation.get("auto_dispatch_executor", True) is False:
        return False
    # Legacy workflow rows do not have the newer flag.  Their omission is
    # intentionally treated as enabled so an already-running local workflow
    # receives the fix without a manual migration; an explicit false remains
    # an opt-out.
    if automation.get(config_flag, True) is False:
        return False
    if str(task.get("machine") or "").strip():
        return False
    checkout = str(
        task.get("working_dir") or workflow.get("repository_path") or ""
    ).strip()
    if not os.path.isabs(checkout) or checkout.startswith(("\\\\", "//")):
        return False
    branch = str(workflow.get("candidate_branch") or "").strip().lower()
    if not branch or _protected_branch(branch):
        return False
    return True


def _auto_capability_enabled(workflow: dict, task: dict) -> bool:
    """Whether a capability question is safe to answer automatically."""
    return _local_autonomous_enabled(
        workflow,
        task,
        config_flag="auto_resolve_capability_questions",
        env_name=AUTO_CAPABILITY_ENV,
    )


def _auto_noncritical_enabled(workflow: dict, task: dict) -> bool:
    """Whether a technical stop may be resumed without an owner."""
    return _local_autonomous_enabled(
        workflow,
        task,
        config_flag="auto_resume_noncritical_gates",
        env_name=AUTO_NONCRITICAL_ENV,
    )


def _contains_critical_marker(*texts: str) -> bool:
    blob = " ".join(str(text or "") for text in texts).lower()
    if any(marker in blob for marker in CRITICAL_MARKERS):
        return True
    return bool(CRITICAL_BRANCH_RE.search(blob))


def _verdict_zone(report: str) -> str:
    """P14: зона явных заявлений агента — строки ИТОГ* и ELICIT-блок.

    Технический стоп (потерян вердикт и т.п.) не несёт просьбы к человеку по
    определению: реальные просьбы приходят событиями executor.human_required
    и ELICIT-вопросами (см. auto_capability_choice). Сканирование всего тела
    отчёта давало ложные «критические» стопы: агенты цитируют env/документацию
    со словами «пароль», «владелец», «ssh» в безобидных заметках.
    """
    text = str(report or "")
    parts = [
        line for line in text.splitlines()
        if line.strip().upper().startswith("ИТОГ")
    ]
    elic = ELICIT_RE.search(text)
    if elic:
        parts.append(elic.group(0)[:1500])
    return " ".join(parts)


def _report_has_open_severe_findings(report: str) -> bool:
    """U19: в отчёте ревью есть ОТКРЫТЫЕ blocker/high-находки.

    Такая остановка — не «потерянный ИТОГ»: каскад специально открыл
    блокер (например, «PASS, но открытый blocker/high»), и решение
    должно остаться человеку. Ищем severity в AUDIT_FINDINGS_JSON."""
    text = str(report or "")
    i = text.find("AUDIT_FINDINGS_JSON:")
    if i < 0:
        return False
    tail = text[i: i + 20000]
    for needle in ('"severity": "blocker"', '"severity":"blocker"',
                   '"severity": "high"', '"severity":"high"'):
        j = tail.find(needle)
        if j < 0:
            continue
        window = tail[max(0, j - 200): j + 400]
        if '"status": "resolved"' in window or '"status":"resolved"' in window:
            continue
        return True
    return False


CASCADE_ESCALATION_EVENTS = (
    "cascade.open_blocker",
    "cascade.human_required",
    "review.human_required",
)


def _cascade_escalated_after(seq, events) -> bool:
    """U19d: после обрабатываемого события каскад эскалировал стоп.

    Инцидент 2026-10-04 03:49: вотчер среагировал на СТАРОЕ
    executor.invalid_output (task#299), хотя ПОЗЖЕ каскад открыл блокер
    (task#301) — резюм по старому событию съел человеческую остановку.
    Эскалация каскада новее события = стоп уже передан человеку."""
    try:
        seq = int(seq or 0)
    except (TypeError, ValueError):
        return False
    for e in events or []:
        try:
            if int(e.get("seq", 0)) > seq and e.get("event_type") in CASCADE_ESCALATION_EVENTS:
                return True
        except (TypeError, ValueError):
            continue
    return False


def _jev_autoresume_allowed(mode: str, report: str) -> bool:
    """U19b: Jev-резюм разрешён, только если в отчёте ревью нет ОТКРЫТЫХ
    blocker/high-находок. Jev-путь включается при сломанном машинном
    разборе вердикта - и именно тогда серьёзные находки должны решаться
    человеком, а не распознанной по косвенным признакам «valid_revision»
    (инцидент 2026-10-04 02:33: каскадный блокер съеден Jev-резюмом)."""
    if mode == "reviewer" and _report_has_open_severe_findings(report):
        return False
    return True


def _stop_is_critical(reason: str, report: str) -> bool:
    """Критичность технического стопа: причина + зона явных заявлений."""
    if _report_has_open_severe_findings(report):
        return True
    return _contains_critical_marker(reason, _verdict_zone(report))


def auto_capability_choice(question: dict, workflow: dict, task: dict) -> dict | None:
    """Return the helper-agent option for a safe capability question.

    This deliberately returns ``None`` for ordinary human decisions.  The
    caller can then persist the question unchanged and the existing UI remains
    the fallback.
    """
    if not isinstance(question, dict) or not _auto_capability_enabled(workflow, task):
        return None
    question_text = str(question.get("question") or "").lower()
    context_text = str(question.get("context") or "").lower()
    # The capability signal must be in the actual question.  A context note
    # such as "helper-agent is available" is not enough by itself; this keeps
    # ordinary product/agent questions on the human path.
    if not any(marker in question_text for marker in CAPABILITY_MARKERS):
        return None
    if not any(marker in f"{question_text} {context_text}" for marker in HELPER_MARKERS):
        return None
    options = question.get("options")
    if not isinstance(options, list):
        return None
    for option in options:
        if not isinstance(option, dict) or not option.get("id"):
            continue
        label = str(option.get("label") or "")
        option_text = f"{option.get('id')} {label}".lower()
        if any(marker in option_text for marker in MANUAL_MARKERS):
            continue
        if any(marker in option_text for marker in HELPER_MARKERS):
            return {
                "id": str(option["id"]),
                "label": label or str(option["id"]),
            }
    return None


def auto_answer_capability_question(
    elicit_id: str, question: dict, workflow: dict, task: dict,
) -> bool:
    """Answer one eligible capability question and resume the workflow.

    The local API remains the single writer for elicit/workflow state.  If the
    API is unavailable or rejects the resume, the pending question is left
    intact so the operator still has a recoverable fallback.
    """
    choice = auto_capability_choice(question, workflow, task)
    if choice is None:
        return False
    body = {
        "choice": choice["id"],
        "comment": (
            "Автовыбор PromptPilot: локальный автономный workflow не имеет "
            "write/shell в текущей сессии; запускаю helper-agent."
        ),
    }
    try:
        api(f"/api/elicit/{elicit_id}/answer", "POST", body)
    except Exception as exc:  # noqa: BLE001 - pending UI fallback is intentional
        log(
            f"  ELICIT auto-resolve не прошёл для {elicit_id}: "
            f"{type(exc).__name__}: {exc}"
        )
        return False
    log(
        f"  >>> ELICIT auto-resolve: {elicit_id} → "
        f"helper-agent ({choice['id']}) — локальный автономный workflow продолжен"
    )
    return True


def auto_noncritical_choice(
    question: dict, workflow: dict, task: dict,
) -> dict | None:
    """Choose only an explicit safe/default answer to a technical question.

    A default alone is not sufficient: product choices and owner decisions
    also carry defaults.  The question must look technical, must not mention
    a protected operation, and the selected option must either be the declared
    safe/default path or have an unmistakable continue/retry/helper marker.
    """
    if not isinstance(question, dict) or not _auto_noncritical_enabled(workflow, task):
        return None
    question_text = str(question.get("question") or "").lower()
    context_text = str(question.get("context") or "").lower()
    options = question.get("options")
    if not isinstance(options, list):
        return None
    option_rows = [
        option for option in options
        if isinstance(option, dict) and str(option.get("id") or "").strip()
    ]
    if not option_rows:
        return None
    if _contains_critical_marker(question_text, context_text, *(
        f"{item.get('id')} {item.get('label') or ''}" for item in option_rows
    )):
        return None
    # U12: панель «Права» — правовой класс в режиме ask/deny не автовыбирается
    gate = _permissions_gate(question_text, context_text)
    if gate is not None and _permissions_mode(gate) != "allow":
        log(
            f"  ELICIT {gate}=ask/deny в панели «Права» — вопрос оставлен человеку"
        )
        return None
    full_text = f"{question_text} {context_text}"
    if not any(marker in full_text for marker in NONCRITICAL_QUESTION_MARKERS):
        return None

    default_id = str(question.get("default") or "").strip()
    by_id = {str(item["id"]): item for item in option_rows}
    default = by_id.get(default_id)
    if default:
        option_text = f"{default.get('id')} {default.get('label') or ''}".lower()
        if not any(marker in option_text for marker in MANUAL_MARKERS):
            return {
                "id": str(default["id"]),
                "label": str(default.get("label") or default["id"]),
            }

    safe = []
    for option in option_rows:
        option_text = f"{option.get('id')} {option.get('label') or ''}".lower()
        if any(marker in option_text for marker in MANUAL_MARKERS):
            continue
        if any(marker in option_text for marker in SAFE_CHOICE_MARKERS):
            safe.append(option)
    if len(safe) != 1:
        return None
    return {
        "id": str(safe[0]["id"]),
        "label": str(safe[0].get("label") or safe[0]["id"]),
    }


def auto_answer_noncritical_question(
    elicit_id: str, question: dict, workflow: dict, task: dict,
) -> bool:
    choice = auto_noncritical_choice(question, workflow, task)
    if choice is None:
        return False
    body = {
        "choice": choice["id"],
        "comment": (
            "Автовыбор PromptPilot: вопрос технический и некритичный; "
            "применяю безопасный default и продолжаю."
        ),
    }
    try:
        api(f"/api/elicit/{elicit_id}/answer", "POST", body)
    except Exception as exc:  # noqa: BLE001 - pending UI fallback is intentional
        log(
            f"  ELICIT auto-resolve некритичного вопроса не прошёл для "
            f"{elicit_id}: {type(exc).__name__}: {exc}"
        )
        return False
    log(
        f"  >>> ELICIT auto-resolve: {elicit_id} → "
        f"{choice['id']} — технический вопрос закрыт автоматически"
    )
    return True


def ask_jev(key: str, report_tail: str, mode: str) -> dict | None:
    """Спросить Jev, что подразумевает отчёт. mode: 'executor' | 'reviewer'.
    None = сервис недоступен."""
    if not key:
        return None
    if mode == "reviewer":
        questions = {
            "done": {
                "type": "noul",
                "instructions": (
                    "Отчёт является валидным аудитом: содержит вердикт "
                    "(PASS/REVISION_REQUIRED/HUMAN_REQUIRED) и конкретные "
                    "замечания либо явное отсутствие замечаний?"
                ),
            },
            "verdict": {
                "type": "choice",
                "criteria": {
                    "valid_revision": "аудит валиден, требуются исправления работы",
                    "valid_pass": "аудит валиден, замечаний нет — работа принята",
                    "human": "аудит требует решения человека",
                    "garbage": "текст не является валидным аудитом",
                },
            },
        }
    else:
        questions = {
            "done": {
                "type": "noul",
                "instructions": (
                    "Отчёт агента-исполнителя однозначно заявляет, что "
                    "поставленная задача выполнена успешно (сборка/тесты "
                    "прошли, изменения сделаны)?"
                ),
            },
            "verdict": {
                "type": "choice",
                "criteria": {
                    "done": "работа выполнена успешно в этом запуске",
                    "already": "работа уже была сделана ранее, отчёт это подтверждает",
                    "human": "исполнитель просит вмешательства человека или задаёт вопрос",
                    "fail": "работа не удалась или не завершена",
                },
            },
        }
    body = json.dumps(
        {"state": report_tail, "model": "jev-latest", "questions": questions},
        ensure_ascii=False,
    ).encode("utf-8")
    req = urllib.request.Request(
        TYPESAFE_URL,
        data=body,
        method="POST",
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.loads(r.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as e:
        log(f"  TypeSafe недоступен: {e}")
        return None


MAX_TIMEOUT_RESUMES_PER_TASK = 2


def timeout_resume_cap_reached(workflow_id: str, task_id: str) -> bool:
    """Не более 2 авто-resume на одну задачу: если таймаут повторяется —
    провайдер виснет системно, дальше только человек."""
    state = load_state()
    return state.get("timeout_resumes", {}).get(f"{workflow_id}:{task_id}", 0) >= MAX_TIMEOUT_RESUMES_PER_TASK


def bump_timeout_resume(workflow_id: str, task_id: str) -> None:
    state = load_state()
    counts = state.setdefault("timeout_resumes", {})
    counts[f"{workflow_id}:{task_id}"] = counts.get(f"{workflow_id}:{task_id}", 0) + 1
    if len(counts) > 100:  # не растём бесконечно
        for k in sorted(counts)[:-50]:
            counts.pop(k, None)
    save_state(state)


def resume_timeout(workflow_id: str, task_id: str) -> None:
    conn = db_connect()
    try:
        wf = conn.execute(
            "SELECT status, current_round, state_version FROM workflows WHERE id = ?",
            (workflow_id,),
        ).fetchone()
    finally:
        conn.close()
    if not wf:
        return
    wf_status, wf_round, wf_version = wf
    if wf_status != "awaiting_human":
        log(f"  task#{task_id}: воркфлоу {wf_status} — timeout-resume не нужен")
        return
    body = {
        "expected_version": wf_version,
        "text": (
            "Продолжить работу с учётом сохранённого состояния\n\n"
            f"(авто-resume: задача #{task_id} убита воркером по 4-часовому таймауту; "
            "продолжаем с сохранённого состояния — при повторном таймауте будет "
            "эскалация человеку)"
        ),
        "resume": True,
    }
    for attempt in (1, 2):
        try:
            api(f"/api/workflows/{workflow_id}/human-input", "POST", body)
            break
        except urllib.error.HTTPError as e:
            if e.code == 409 and attempt == 1:
                conn = db_connect()
                try:
                    wf_version = conn.execute(
                        "SELECT state_version FROM workflows WHERE id = ?", (workflow_id,)
                    ).fetchone()[0]
                    body["expected_version"] = wf_version
                finally:
                    conn.close()
                continue
            log(f"  timeout-resume не прошёл: HTTP {e.code}")
            return
    bump_timeout_resume(workflow_id, task_id)
    log(f"  >>> TIMEOUT-RESUME отправлен: задача #{task_id} продолжена без человека (раунд {wf_round})")


def noncritical_resume_cap_reached(workflow_id: str, wf_round: int) -> bool:
    state = load_state()
    key = f"{workflow_id}:{wf_round}"
    return state.get("noncritical_resumes", {}).get(key, 0) >= (
        MAX_NONCRITICAL_RESUMES_PER_WORKFLOW_ROUND
    )


def bump_noncritical_resume(workflow_id: str, wf_round: int) -> None:
    state = load_state()
    counts = state.setdefault("noncritical_resumes", {})
    key = f"{workflow_id}:{wf_round}"
    counts[key] = counts.get(key, 0) + 1
    if len(counts) > 100:
        for old_key in sorted(counts)[:-50]:
            counts.pop(old_key, None)
    save_state(state)


def _is_noncritical_protocol_stop(
    event_type: str,
    reason: str,
    report: str,
) -> bool:
    if event_type not in {
        "executor.invalid_output",
        "reviewer.invalid_output",
        "automation.paused",
    }:
        return False
    reason_text = str(reason or "").lower()
    if any(marker in reason_text for marker in NONCRITICAL_STOP_MARKERS):
        return True
    # Events normally carry a precise reason.  Use the report only as a
    # fallback for old event rows that did not persist it.
    if reason_text:
        return False
    report_text = str(report or "").lower()
    return any(marker in report_text for marker in (
        "without the required closing",
        "missing successful workflow verdict",
        "без успешного вердикта",
        "потерял строку",
        "не вернул обязательн",
    ))


def resume_noncritical_stop(
    *,
    event_type: str,
    reason: str,
    report: str,
    workflow: dict,
    task: dict,
    workflow_id: str,
    task_id: int | str,
    wf_round: int,
    wf_version: int,
    mode: str,
) -> bool:
    """Resume a bounded, local protocol retry without asking the owner."""
    if not _auto_noncritical_enabled(workflow, task):
        return False
    if not _is_noncritical_protocol_stop(event_type, reason, report):
        return False
    if _stop_is_critical(reason, report):
        log(
            f"  task#{task_id}: зона вердикта содержит критический "
            "маркер — оставляю человеку"
        )
        return False
    if noncritical_resume_cap_reached(workflow_id, int(wf_round or 0)):
        log(
            f"  task#{task_id}: лимит некритичных авто-продолжений "
            f"({MAX_NONCRITICAL_RESUMES_PER_WORKFLOW_ROUND}) исчерпан — человеку"
        )
        return False

    if mode == "reviewer":
        text = (
            "Продолжить ревью автоматически: предыдущая остановка была "
            "технической — не хватило машинно-читаемой строки аудита. "
            "Проверь сохранённое состояние и верни строгие строки "
            "AUDIT_FINDINGS_JSON и AUDIT_VERDICT. Не запрашивай владельца "
            "из-за потери формата отчёта."
        )
    else:
        text = (
            "Продолжить работу автоматически с учётом сохранённого состояния. "
            "Предыдущая остановка была технической: потерян машинный ИТОГ. "
            "Проверь изменения и тесты и заверши точной строкой "
            "«ИТОГ: ГОТОВО» или «ИТОГ: НЕ СМОГ». Если не хватает локальных "
            "прав на запись/shell, передай применение изменений helper-agent; "
            "не останавливайся на повторном обсуждении уже выбранного пути."
        )
    body = {
        "expected_version": wf_version,
        "text": text,
        "resume": True,
    }
    for attempt in (1, 2):
        try:
            api(f"/api/workflows/{workflow_id}/human-input", "POST", body)
            break
        except urllib.error.HTTPError as exc:
            if exc.code == 409 and attempt == 1:
                try:
                    conn = db_connect()
                    try:
                        fresh = conn.execute(
                            "SELECT state_version FROM workflows WHERE id = ?",
                            (workflow_id,),
                        ).fetchone()
                    finally:
                        conn.close()
                    if not fresh:
                        return False
                    body["expected_version"] = fresh[0]
                except sqlite3.Error as refresh_exc:
                    log(
                        f"  task#{task_id}: не обновил state_version после 409: "
                        f"{refresh_exc}"
                    )
                    return False
                continue
            log(f"  task#{task_id}: noncritical-resume не прошёл: HTTP {exc.code}")
            return False
        except Exception as exc:  # noqa: BLE001 - pending human fallback
            log(
                f"  task#{task_id}: noncritical-resume не прошёл: "
                f"{type(exc).__name__}: {exc}"
            )
            return False
    else:
        return False

    bump_noncritical_resume(workflow_id, int(wf_round or 0))
    log(
        f"  >>> NONCRITICAL-RESUME отправлен: task#{task_id}, "
        f"event={event_type}, раунд {wf_round} продолжен без человека"
    )
    return True


DEAD_WORKFLOWS = {
    'wf_874980f3fc3f40868777032da8f6bea1',  # pkg-reverso-m2 (слит в main)
    'wf_84c029c14a82473c9b05876968819f19',  # pkg-backup-m3 (слит в main)
}


# ── ELICIT: разбор вопросов оператору из отчётов ─────────────────────
ELICIT_RE = re.compile(
    r"ELICIT_QUESTION_JSON:\s*(\{.*?\})\s*(?:\n|$)", re.S)


def db_connect_rw():
    """Read-write соединение (для записи elicit-вопросов)."""
    conn = sqlite3.connect(DB_PATH, timeout=5)
    conn.execute("PRAGMA busy_timeout = 4000")
    return conn


def extract_elicit(event: dict) -> None:
    """Если отчёт задачи содержит ELICIT_QUESTION_JSON — сохранить вопрос.

    Вопрос попадает в workflow_elicits (pending) и рисуется формой в UI;
    ответ оператора вернётся в промпт следующей попытки того же раунда.
    Узкий capability-вопрос и однозначный технический default локального
    автономного workflow могут быть отвечены здесь автоматически; продуктовые,
    опасные и неоднозначные вопросы остаются pending.
    """
    payload = event.get("payload") or {}
    task_id = payload.get("task_id")
    workflow_id = event.get("workflow_id", "")
    if not task_id or not workflow_id:
        return
    conn = db_connect()
    try:
        row = conn.execute(
            """SELECT result, working_dir, machine FROM tasks
               WHERE id = ?""", (task_id,)).fetchone()
        wf = conn.execute(
            """SELECT current_round, config_json, repository_path,
                      candidate_branch, status
               FROM workflows WHERE id = ?""",
            (workflow_id,)).fetchone()
    finally:
        conn.close()
    if not row or not wf or not row[0]:
        return
    m = ELICIT_RE.search(row[0])
    if not m:
        return
    try:
        q = json.loads(m.group(1), strict=False)
    except json.JSONDecodeError:
        log(f"  task#{task_id}: ELICIT-блок не распарсился — пропуск")
        return
    if not isinstance(q.get("question"), str) or not isinstance(q.get("options"), list):
        log(f"  task#{task_id}: ELICIT-блок без question/options — пропуск")
        return
    task = _row_dict(row, ("result", "working_dir", "machine"))
    workflow = _row_dict(
        wf,
        ("current_round", "config_json", "repository_path",
         "candidate_branch", "status"),
    )
    elicit_id = None
    pending = False
    conn = db_connect_rw()
    try:
        conn.execute(
            """CREATE TABLE IF NOT EXISTS workflow_elicits (
                id TEXT PRIMARY KEY,
                workflow_id TEXT NOT NULL,
                round_no INTEGER NOT NULL,
                task_id INTEGER,
                question_json TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                answer_json TEXT,
                answer_text TEXT,
                created_at TEXT NOT NULL,
                answered_at TEXT,
                injected_at TEXT
            )""")
        dup = conn.execute(
            """SELECT id, status FROM workflow_elicits
               WHERE workflow_id = ? AND task_id = ?""",
            (workflow_id, task_id)).fetchone()
        if dup:
            elicit_id, status = dup[0], dup[1]
            pending = status == "pending"
        else:
            elicit_id = f"elicit_{uuid.uuid4().hex[:20]}"
            conn.execute(
                """INSERT INTO workflow_elicits
                   (id, workflow_id, round_no, task_id, question_json, status, created_at)
                   VALUES (?, ?, ?, ?, ?, 'pending', ?)""",
                (elicit_id, workflow_id, workflow["current_round"], task_id,
                 m.group(1), datetime.now().isoformat(timespec="seconds")))
            conn.commit()
            pending = True
    finally:
        conn.close()
    if pending and auto_answer_capability_question(
        str(elicit_id), q, workflow, task
    ):
        return
    if pending and auto_answer_noncritical_question(
        str(elicit_id), q, workflow, task
    ):
        return
    if pending:
        log(f"  >>> ELICIT: вопрос от task#{task_id} "
            f"(раунд {workflow['current_round']}) сохранён — "
            "ждёт ответа оператора в UI")


def reconcile_pending_elicits() -> None:
    """Apply the new policy to pending questions left by an older watcher."""
    conn = db_connect()
    try:
        try:
            rows = conn.execute(
                """SELECT id, workflow_id, task_id, question_json
                   FROM workflow_elicits
                   WHERE status = 'pending'
                   ORDER BY created_at
                   LIMIT 200"""
            ).fetchall()
        except sqlite3.OperationalError:
            # The table is created lazily by extract_elicit.
            return
    finally:
        conn.close()

    for elicit_id, workflow_id, task_id, question_raw in rows:
        if not task_id:
            continue
        try:
            question = json.loads(question_raw or "{}")
        except json.JSONDecodeError:
            continue
        conn = db_connect()
        try:
            task_row = conn.execute(
                """SELECT result, working_dir, machine FROM tasks
                   WHERE id = ?""", (task_id,)
            ).fetchone()
            workflow_row = conn.execute(
                """SELECT current_round, config_json, repository_path,
                          candidate_branch, status
                   FROM workflows WHERE id = ?""", (workflow_id,)
            ).fetchone()
        finally:
            conn.close()
        if not task_row or not workflow_row:
            continue
        task = _row_dict(task_row, ("result", "working_dir", "machine"))
        workflow = _row_dict(
            workflow_row,
            ("current_round", "config_json", "repository_path",
             "candidate_branch", "status"),
        )
        if auto_answer_capability_question(
            str(elicit_id), question, workflow, task
        ):
            continue
        auto_answer_noncritical_question(
            str(elicit_id), question, workflow, task
        )


# ── Память воркфлоу: разбор MEMORY_SAVE_JSON из отчётов ──────────────
MEMORY_RE = re.compile(
    r"MEMORY_SAVE_JSON:\s*(\{.*?\})\s*(?:\n|$)", re.S)
MEMORY_MAX_BYTES = 16 * 1024


def extract_memory(event: dict) -> None:
    """Применить заметки MEMORY_SAVE_JSON из завершившейся задачи.

    Семантика save (замена целиком), лимит 16КБ — ОТКАЗ, не обрезка: при
    превышении пишем в журнал, агент увидит актуальную память в следующем
    промпте и ужмёт сам.
    """
    payload = event.get("payload") or {}
    task_id = payload.get("task_id")
    workflow_id = event.get("workflow_id", "")
    if not task_id or not workflow_id:
        return
    conn = db_connect()
    try:
        row = conn.execute(
            "SELECT result FROM tasks WHERE id = ?", (task_id,)).fetchone()
    finally:
        conn.close()
    if not row or not row[0]:
        return
    for m in MEMORY_RE.finditer(row[0]):
        try:
            # strict=False: агенты порой пишут многострочный content с
            # реальными переводами строк внутри строки JSON — это валидно
            # для нашего блока, строгий парсер зря ругается.
            note = json.loads(m.group(1), strict=False)
        except json.JSONDecodeError:
            log(f"  task#{task_id}: MEMORY_SAVE_JSON не распарсился — пропуск")
            continue
        name = str(note.get("name") or "memory.md").strip().lower()[:64]
        content = note.get("content")
        if not isinstance(content, str) or not content.strip():
            continue
        if len(content.encode("utf-8")) > MEMORY_MAX_BYTES:
            log(f"  task#{task_id}: заметка {name} > {MEMORY_MAX_BYTES} байт — "
                f"ОТКАЗАНО (не обрезаем); агент ужмёт в следующей попытке")
            continue
        conn = db_connect_rw()
        try:
            conn.execute(
                """CREATE TABLE IF NOT EXISTS workflow_memory (
                    workflow_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    content TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    updated_by_task INTEGER,
                    PRIMARY KEY (workflow_id, name)
                )""")
            conn.execute(
                """INSERT INTO workflow_memory
                   (workflow_id, name, content, updated_at, updated_by_task)
                   VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(workflow_id, name) DO UPDATE SET
                       content = excluded.content,
                       updated_at = excluded.updated_at,
                       updated_by_task = excluded.updated_by_task""",
                (workflow_id, name, content,
                 datetime.now().isoformat(timespec="seconds"), task_id))
            conn.commit()
        finally:
            conn.close()
        log(f"  >>> MEMORY: заметка «{name}» обновлена из task#{task_id} "
            f"({len(content.encode('utf-8'))} байт)")


def try_repair(
    key: str,
    event: dict,
    *,
    protocol_only: bool = False,
) -> None:
    """Обработать событие: потеря вердикта исполнителем/аудитором или таймаут.

    Режим protocol_only используется для стартового reconciliation уже
    обработанных событий: он может поднять только локальный технический
    retry и не вызывает внешний Jev повторно.
    """
    payload = event.get("payload") or {}
    event_type = event.get("event_type", "")
    task_id = payload.get("task_id")
    reason = str(payload.get("reason") or "")
    error = str(payload.get("error") or "")
    workflow_id = event.get("workflow_id", "")

    mode = "executor"
    if event_type in ("reviewer.invalid_output", "automation.paused"):
        mode = "reviewer"

    # automation.paused интересует только в аудит-варианте; прочие причины
    # (конфликты версий и т.п.) — не наша епархия.
    if event_type == "automation.paused" and "AUDIT" not in reason.upper() and "аудитор" not in reason.lower():
        return
    if workflow_id in DEAD_WORKFLOWS:
        return  # мёртвый воркфлоу: работа слита в main
    if task_id is None:
        return

    # executor.failed: авто-resume ТОЛЬКО на таймауте (задача частично
    # выполнена, продолжение с сохранённого состояния осмысленно). Прочие
    # фейлы (CLI not found, повторный краш провайдера) — человеку.
    if event_type == "executor.failed":
        if "timed out" not in error.lower() and "timeout" not in error.lower():
            log(f"  task#{task_id}: executor.failed не по таймауту ({error[:80]}) — человеку")
            return
        if timeout_resume_cap_reached(workflow_id, str(task_id)):
            return
        resume_timeout(workflow_id, str(task_id))
        return

    conn = db_connect()
    try:
        row = conn.execute(
            """SELECT provider, status, result, working_dir, machine
               FROM tasks WHERE id = ?""", (task_id,)
        ).fetchone()
        wf = conn.execute(
            """SELECT status, current_round, state_version, config_json,
                      repository_path, candidate_branch
               FROM workflows WHERE id = ?""",
            (workflow_id,),
        ).fetchone()
    finally:
        conn.close()

    if not row or not wf:
        log(f"  task#{task_id}: нет записи — пропуск")
        return
    provider, task_status, result, working_dir, machine = row
    wf_status, wf_round, wf_version, config_json, repository_path, candidate_branch = wf
    task = {
        "provider": provider,
        "status": task_status,
        "result": result,
        "working_dir": working_dir,
        "machine": machine,
    }
    workflow = {
        "status": wf_status,
        "current_round": wf_round,
        "state_version": wf_version,
        "config_json": config_json,
        "repository_path": repository_path,
        "candidate_branch": candidate_branch,
    }

    if wf_status != "awaiting_human":
        log(f"  task#{task_id}: воркфлоу уже {wf_status} — resume не нужен")
        return

    # U19d: каскад эскалировал стоп ПОСЛЕ нашего события — человек решает.
    # Отсутствие таблицы/ошибка чтения = «эскалаций нет»: гвард не должен
    # останавливать штатное восстановление при деградации наблюдения.
    try:
        conn2 = db_connect()
        try:
            rows2 = conn2.execute(
                """SELECT seq, event_type FROM workflow_events
                   WHERE workflow_id = ? AND seq > ? ORDER BY seq DESC LIMIT 50""",
                (workflow_id, int(event.get("seq") or 0)),
            ).fetchall()
        finally:
            conn2.close()
        if _cascade_escalated_after(event.get("seq"), [
                {"seq": r[0], "event_type": r[1]} for r in rows2]):
            log(f"  task#{task_id}: каскад эскалировал остановку новее события — человеку")
            return
    except Exception as exc:  # noqa: BLE001 - гвард деградировал: лечим как «эскалаций нет»
        log(f"  task#{task_id}: проверка эскалации каскада не удалась ({type(exc).__name__}) — трактую как отсутствие эскалаций")

    report = result or ""
    if resume_noncritical_stop(
        event_type=event_type,
        reason=reason,
        report=report,
        workflow=workflow,
        task=task,
        workflow_id=workflow_id,
        task_id=task_id,
        wf_round=wf_round,
        wf_version=wf_version,
        mode=mode,
    ):
        return
    if protocol_only:
        return
    if not _jev_autoresume_allowed(mode, report):
        log(f"  task#{task_id}: Jev-путь закрыт — открытые blocker/high-находки, решение человеку")
        return
    if len(report) < 80:
        log(f"  task#{task_id}: отчёт слишком короткий ({len(report)} симв) — не рискую")
        return
    tail = report[-4000:]

    answer = ask_jev(key, tail, mode)
    if answer is None:
        return
    answers = answer.get("answers", {})
    done = (answers.get("done") or {}).get("noul", 0.0)
    verdict = (answers.get("verdict") or {})
    choice = verdict.get("choice", "")
    conf = verdict.get("confidence", 0.0)
    usage = answer.get("usage", {})
    auto_ok = choice in (AUTO_VERDICTS if mode == "executor"
                         else {"valid_revision", "valid_pass"})
    log(
        f"  Jev[{mode}] по task#{task_id} ({provider}): choice={choice} conf={conf:.2f} "
        f"noul_done={done:.2f} tokens={usage.get('input_tokens', '?')}/{usage.get('output_tokens', '?')}"
    )

    if auto_ok and conf >= MIN_CHOICE_CONF and done >= MIN_NOUL_DONE:
        body = {
            "expected_version": wf_version,
            "text": (
                f"{RESUME_TEXT}\n\n"
                f"(авто-верdict: исполнитель {provider} потерял строку «ИТОГ», "
                f"но TypeSafe Jev распознал по отчёту задачи #{task_id} вердикт "
                f"«{choice}» с уверенностью {conf:.2f}; noul-выполнено={done:.2f})"
            ),
            "resume": True,
        }
        for attempt in (1, 2):
            try:
                api(f"/api/workflows/{workflow_id}/human-input", "POST", body)
                break
            except urllib.error.HTTPError as e:
                if e.code == 409 and attempt == 1:
                    conn = db_connect()
                    try:
                        wf_version = conn.execute(
                            "SELECT state_version FROM workflows WHERE id = ?", (workflow_id,)
                        ).fetchone()[0]
                        body["expected_version"] = wf_version
                    finally:
                        conn.close()
                    continue
                log(f"  resume не прошёл: HTTP {e.code}")
                return
        log(f"  >>> AUTO-RESUME отправлен: вердикт «{choice}» (conf {conf:.2f}) — раунд {wf_round} продолжен без человека")
    else:
        log(f"  >>> без действий: вердикт «{choice}»/уверенность недостаточна — решение за человеком")


def reconcile_pending_protocol_stops(key: str) -> None:
    """Recover a technical stop that the previous watcher already consumed.

    The normal event cursor is intentionally not rewound.  On restart, look
    only at the newest technical stop per workflow; the current workflow can
    therefore recover even when the old watcher has already advanced last_seq.
    """
    conn = db_connect()
    try:
        rows = conn.execute(
            """SELECT e.seq, e.workflow_id, e.event_type, e.payload_json
               FROM workflow_events e
               JOIN workflows w ON w.id = e.workflow_id
               WHERE e.event_type IN (
                   'executor.invalid_output',
                   'reviewer.invalid_output',
                   'automation.paused'
               )
                 AND w.status = 'awaiting_human'
               ORDER BY e.seq DESC
               LIMIT 500"""
        ).fetchall()
    finally:
        conn.close()

    latest: dict[str, tuple] = {}
    for row in rows:
        workflow_id = row[1]
        if workflow_id in latest:
            continue
        try:
            payload = json.loads(row[3] or "{}")
        except json.JSONDecodeError:
            continue
        reason = str(payload.get("reason") or "")
        if not any(marker in reason.lower() for marker in NONCRITICAL_STOP_MARKERS):
            continue
        latest[workflow_id] = row

    for seq, workflow_id, event_type, payload_raw in reversed(list(latest.values())):
        try:
            payload = json.loads(payload_raw or "{}")
        except json.JSONDecodeError:
            continue
        try:
            try_repair(
                key,
                {
                    "seq": seq,
                    "workflow_id": workflow_id,
                    "event_type": event_type,
                    "payload": payload,
                },
                protocol_only=True,
            )
        except Exception as exc:  # noqa: BLE001 - reconciliation must not kill watcher
            log(
                f"  reconciliation seq={seq}: {type(exc).__name__}: {exc}"
            )




SILENCE_LIMIT_SEC = 15 * 60
GUARD_KILLS: dict[str, int] = {}
MAX_GUARD_KILLS_PER_TASK = 2


def silence_guard(state: dict) -> None:
    """Задача running на codex-harness (mmx-m3), а rollout-сессия не пишет
    ≥15 минут → процесс ждёт мёртвый сетевой ответ. Добиваем процесс:
    воркер закроет задачу failed, вотчер авто-resume'ит (лимит 2/задача)."""
    import glob
    conn = db_connect()
    try:
        rows = conn.execute(
            "SELECT id FROM tasks WHERE status='running' AND provider='mmx-m3'"
        ).fetchall()
    finally:
        conn.close()
    if not rows:
        return
    files = sorted(
        glob.glob("C:/Tools/codex-minimax/sessions/**/rollout-*.jsonl",
                  recursive=True),
        key=lambda p: os.path.getmtime(p))
    if not files:
        return
    newest = files[-1]
    age = time.time() - os.path.getmtime(newest)
    if age < SILENCE_LIMIT_SEC:
        return
    for (task_id,) in rows:
        guard_key = f"{task_id}"
        if GUARD_KILLS.get(guard_key, 0) >= MAX_GUARD_KILLS_PER_TASK:
            continue
        import subprocess
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "Get-CimInstance Win32_Process -Filter \"Name='codex.exe'\" | "
             "ForEach-Object { Stop-Process -Id $_.ProcessId -Force; $_.ProcessId }"],
            capture_output=True, text=True, timeout=30)
        killed = [x for x in out.stdout.split() if x.strip().isdigit()]
        GUARD_KILLS[guard_key] = GUARD_KILLS.get(guard_key, 0) + 1
        log(f"СТРАЖ: задача #{task_id} mmx-m3 молчит {int(age)//60} мин "
            f"(сессия {os.path.basename(newest)[:40]}) → codex убит ({','.join(killed)})")
        # Воркер пометит failed через пару секунд; сами делаем resume (как
        # timeout-resume), чтобы петля замкнулась без человека.
        time.sleep(12)
        wf_rows = None
        conn2 = db_connect()
        try:
            wf_rows = [r for r in conn2.execute(
                "SELECT id, status, state_version FROM workflows WHERE status='awaiting_human'"
            ).fetchall() if r[0] not in DEAD_WORKFLOWS]
        finally:
            conn2.close()
        for wf_id, wf_status, wf_version in wf_rows:
            note = (f"(авто-resume: страж убил зависший mmx-m3 процесса задачи #{task_id}; "
                    f"молчание {int(age)//60} мин)")
            body = {"expected_version": wf_version,
                    "text": RESUME_TEXT + "\n\n" + note,
                    "resume": True}
            for attempt in (1, 2):
                try:
                    api(f"/api/workflows/{wf_id}/human-input", "POST", body)
                    log(f"  >>> GUARD-RESUME отправлен: {wf_id} продолжен")
                    break
                except urllib.error.HTTPError as e:
                    if e.code == 409 and attempt == 1:
                        try:
                            w2 = api(f"/api/workflows/{wf_id}")
                            body["expected_version"] = w2["state_version"]
                        except Exception:
                            pass
                        continue
                    log(f"  guard-resume не прошёл: HTTP {e.code}")


def main() -> None:
    try:
        key = load_key()
    except OSError as exc:
        # Deterministic local protocol stops do not need Jev.  The watcher
        # must still start without a TypeSafe key and leave only ambiguous
        # cases pending for the UI.
        key = ""
        log(f"TypeSafe key недоступен ({exc}); локальная авто-политика работает")
    state = load_state()
    log(
        f"watcher стартовал; last_seq={state.get('last_seq', 0)}; "
        f"key: {'env' if os.environ.get('TYPESAFE_API_KEY') else (KEY_FILE if key else 'нет')}"
    )
    while True:
        try:
            conn = db_connect()
            try:
                rows = conn.execute(
                    "SELECT seq, workflow_id, event_type, payload_json, created_at "
                    "FROM workflow_events WHERE seq > ? AND event_type IN "
                    "('executor.invalid_output', 'reviewer.invalid_output', "
                    "'automation.paused', 'executor.failed', 'run.completed') "
                    "ORDER BY seq",
                    (state.get("last_seq", 0),),
                ).fetchall()
                max_row = conn.execute("SELECT MAX(seq) FROM workflow_events").fetchone()[0]
            finally:
                conn.close()

            for seq, workflow_id, event_type, payload_raw, created_at in rows:
                # automation.paused бывает и с другими причинами — фильтруем
                # на аудитора внутри try_repair по reason.
                log(f"событие seq={seq} {event_type} ({created_at[:19]})")
                try:
                    payload = json.loads(payload_raw or "{}")
                except json.JSONDecodeError:
                    payload = {}
                if event_type == "run.completed":
                    try:
                        extract_memory({"workflow_id": workflow_id,
                                        "payload": payload})
                    except Exception as e:
                        log(f"  memory-разбор: {type(e).__name__}: {e}")
                else:
                    if event_type in ("executor.invalid_output", "automation.paused",
                                      "reviewer.invalid_output"):
                        try:
                            extract_elicit({"seq": seq, "workflow_id": workflow_id,
                                            "payload": payload, "event_type": event_type})
                        except Exception as e:
                            log(f"  elicit-разбор: {type(e).__name__}: {e}")
                    try_repair(key, {"seq": seq, "workflow_id": workflow_id,
                                     "payload": payload, "event_type": event_type})
                state["last_seq"] = seq
                save_state(state)

            if max_row is not None and max_row > state.get("last_seq", 0):
                # продвигаем курсор и по неинтересным событиям
                state["last_seq"] = max_row
                save_state(state)

            # Recover a stop that an older watcher version already processed
            # before the deterministic local auto-policy existed.
            try:
                reconcile_pending_protocol_stops(key)
            except Exception as e:
                log(f"reconciliation: {type(e).__name__}: {e}")
            try:
                reconcile_pending_elicits()
            except Exception as e:
                log(f"pending ELICIT reconciliation: {type(e).__name__}: {e}")
        except sqlite3.Error as e:
            log(f"DB: {e}")
        except Exception as e:  # noqa: BLE001 — вотчер не должен умирать
            log(f"цикл: {type(e).__name__}: {e}")

        # ── Страж тишины: codex-harness задача running, а сессия молчит ≥15 мин ──
        try:
            silence_guard(state)
        except Exception as e:
            log(f"страж: {type(e).__name__}: {e}")

        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    # Под pythonw (без консоли) stdout/stderr == None — печатать некуда.
    # Весь вывод всё равно дублируется в лог-файл, мусор отправляем в devnull.
    if sys.stdout is None:
        sys.stdout = open(os.devnull, "w", encoding="utf-8")
    else:
        sys.stdout.reconfigure(encoding="utf-8")
    if sys.stderr is None:
        sys.stderr = open(os.devnull, "w", encoding="utf-8")
    else:
        sys.stderr.reconfigure(encoding="utf-8")
    main()
