"""Muse 注册任务执行器：连接 WebUI SSE 实时日志流、SQLite 存储与 MuseFlow 协议核心。"""
from __future__ import annotations

import json
import logging
import queue
import random
import sys
import threading
import traceback
import uuid
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from auth_flow import MuseFlow, MuseFlowError, MuseRegisterResult  # noqa: E402
from fingerprint import generate_fingerprint  # noqa: E402
from mail_providers import (  # noqa: E402
    MailProviderError,
    create_mail_provider,
    get_provider_class,
)

from . import db  # noqa: E402

_run_queues: dict[str, queue.Queue] = {}
_lock = threading.Lock()
_current_run = threading.local()

LOG_DIR = Path(__file__).resolve().parent / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)


class QueueLogHandler(logging.Handler):
    """线程隔离的日志采集器：只捕获当前 run 线程产生的日志写入文件与 SSE 队列。"""

    def __init__(self, run_id: str, log_file: Path):
        super().__init__()
        self.run_id = run_id
        self._fh = open(log_file, "a", encoding="utf-8")
        self.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%H:%M:%S",
        ))

    def emit(self, record: logging.LogRecord):
        try:
            rid = getattr(_current_run, "run_id", None)
            if rid is not None and rid != self.run_id:
                return
            msg = self.format(record)
            self._fh.write(msg + "\n")
            self._fh.flush()
            q = _run_queues.get(self.run_id)
            if q is not None:
                q.put(msg)
        except Exception:
            pass

    def close(self):
        try:
            self._fh.close()
        except Exception:
            pass
        super().close()


def _emit_status(run_id: str, kind: str, payload: dict | str = ""):
    q = _run_queues.get(run_id)
    if q is None:
        return
    body = dict(payload) if isinstance(payload, dict) else {"message": str(payload)}
    body["kind"] = kind
    q.put("__EVENT__:" + json.dumps(body, ensure_ascii=False))


def _do_register(
    run_id: str,
    account: dict,
    options: dict,
    log_file: Path,
):
    _current_run.run_id = run_id

    handler = QueueLogHandler(run_id, log_file)
    handler.setLevel(logging.INFO)
    root_logger = logging.getLogger()
    root_logger.addHandler(handler)
    if root_logger.level > logging.INFO or root_logger.level == 0:
        root_logger.setLevel(logging.INFO)

    log = logging.getLogger("registrar")
    email = account["email"]
    mail_source = db.get_setting("mail_source", db.DEFAULT_MAIL_SOURCE)
    try:
        is_pooled = get_provider_class(mail_source).pooled
    except MailProviderError:
        is_pooled = True

    flow: Optional[MuseFlow] = None
    try:
        mail = create_mail_provider(mail_source, db.get_mail_settings(), account)
        log.info(f"[register] 邮箱来源: {mail_source} ({mail.display_name})")

        auto_pool_own = bool(options.get("auto_pool_own_code", True))

        # 指纹轮换：默认（chrome142 / 空 / auto / random）不再用固定指纹，
        # 每单现生成一套 Chrome 家族指纹（TLS impersonate / UA / Client Hints /
        # Accept-Language / 屏幕全部同源，JP 画像），避免同一指纹连续注册被风控关联。
        # 显式指定了其他 impersonate 的单子保持原样，不强制轮换。
        fingerprint = None
        impersonate_opt = (options.get("impersonate") or "chrome142").strip()
        if impersonate_opt in ("", "chrome142", "auto", "random"):
            rng = random.Random()
            for _ in range(20):
                cand = generate_fingerprint(rng, country_code="JP")
                if cand.get("browser_type") == "chrome":
                    fingerprint = cand
                    break
            if fingerprint is None:
                fingerprint = generate_fingerprint(random.Random(), country_code="JP")
            impersonate_opt = fingerprint["impersonate"]
            log.info(
                f"[register] 本单指纹: {fingerprint.get('browser_type')}/{fingerprint['impersonate']} "
                f"屏幕={fingerprint.get('screen')} 语言={fingerprint.get('lang_full')}"
            )

        def _on_phase(stage: str, info: dict) -> None:
            _emit_status(run_id, "phase", {
                "phase": stage,
                "email": info.get("email") or email,
                "message": info.get("message") or "",
            })

        def _on_early_save(res: MuseRegisterResult) -> None:
            db.save_registered(res.to_db_dict())
            log.info(f"[register] 账号核心凭证已早落盘: {res.email}")

        def _on_own_code(own_code: str, owner_email: str) -> None:
            if auto_pool_own and own_code:
                added = db.import_invite_codes([own_code], max_uses=30, source=f"auto:{owner_email}")
                if added.get("inserted"):
                    log.info(f"[register] ✨ 自有邀请码 {own_code} 已自动回流至邀请码池 (可用 30 次)")

        flow = MuseFlow(
            proxy=options.get("proxy"),
            impersonate=impersonate_opt,
            fingerprint=fingerprint,
            lang=options.get("lang") or "ja",
            otp_timeout=int(options.get("otp_timeout") or 45),
            first_name=options.get("first_name") or "",
            last_name=options.get("last_name") or "",
            date_of_birth=options.get("date_of_birth") or "",
            send_caa=bool(options.get("send_caa", True)),
            send_falco=bool(options.get("send_falco", True)),
            resolve_ip=bool(options.get("resolve_ip", True)),
            redeem_mode=options.get("redeem_mode") or "pool",
            invite_code=options.get("invite_code") or "",
            on_phase=_on_phase,
            on_early_save=_on_early_save,
            claim_pool_code=db.claim_invite_code,
            finish_pool_code=db.finish_invite_code,
            on_own_code=_on_own_code,
        )

        _emit_status(run_id, "phase", {"phase": "starting", "email": email})
        log.info(f"[register] 开始 Muse 注册流程: {email}")

        result = flow.run_register(mail)
        d = result.to_db_dict()
        db.save_registered(d)
        if is_pooled:
            db.mark_done(email)

        summary = {
            "email": d["email"],
            "status": d["status"],
            "stage": d["stage"],
            "account_id": d["account_id"],
            "own_code": d["own_code"],
            "used_invite_code": d["used_invite_code"],
            "session_token_len": len(d.get("session_token") or ""),
            "access_token_len": len(d.get("access_token") or ""),
            "ip": d.get("ip") or "",
            "last_error": d.get("last_error") or "",
        }
        _emit_status(run_id, "done", summary)
        log.info(
            f"[register] ✅ 完成 email={d['email']} status={d['status']} "
            f"uid={d['account_id']} own_code={d['own_code'] or '(无)'} "
            f"hatch_sess={summary['session_token_len']}"
        )

        category = "pending_redemption" if d.get("last_error") else ""
        db.finish_run(
            run_id,
            "done",
            error=d.get("last_error") or "",
            category=category,
            stage=d["stage"],
            email=d["email"],
        )

    except MuseFlowError as exc:
        err = str(exc)
        stage = exc.stage
        category = exc.category
        real_email = (flow.result.email if flow and flow.result.email else email)

        if exc.registered and flow is not None:
            d = flow.result.to_db_dict()
            db.save_registered(d)
            if is_pooled:
                db.mark_done(email)
            log.warning(
                f"[register] ⚠️ 账号已注册保留但后续受限 (status={d['status']}, stage={stage}): {err}"
            )
        else:
            log.error(f"[register] ❌ 失败 (stage={stage}, category={category}): {err}")
            if is_pooled:
                if category == "pre_send_network":
                    db.release_unused(email)
                    log.warning(f"[register] {email} 为发码前网络异常，已释放回 available")
                else:
                    db.mark_failed(email, f"[{stage}/{category}] {err}")

        db.finish_run(run_id, "failed", err, category=category, stage=stage, email=real_email)
        _emit_status(run_id, "error", {
            "email": real_email,
            "message": err,
            "category": category,
            "stage": stage,
            "registered": exc.registered,
            "status": flow.result.status if flow else "failed",
        })

    except MailProviderError as exc:
        err = str(exc)
        category = "account" if exc.fatal else "pre_send_network"
        log.error(f"[register] 邮箱 Provider 错误 ({category}): {err}")
        if is_pooled:
            if exc.fatal:
                db.mark_failed(email, f"[mail] {err}")
            else:
                db.release_unused(email)
        db.finish_run(run_id, "failed", err, category=category, stage="initialized", email=email)
        _emit_status(run_id, "error", {"email": email, "message": err, "category": category, "stage": "initialized"})

    except Exception as exc:
        err = str(exc)
        log.error(f"[register] 未预期异常: {err}\n{traceback.format_exc()}")
        if is_pooled:
            db.mark_failed(email, f"[unknown] {err}")
        db.finish_run(run_id, "failed", err, category="unknown", stage="unknown", email=email)
        _emit_status(run_id, "error", {"email": email, "message": err, "category": "unknown"})

    finally:
        try:
            root_logger.removeHandler(handler)
            handler.close()
        except Exception:
            pass
        q = _run_queues.get(run_id)
        if q is not None:
            q.put(None)
        _current_run.run_id = None


def start_registration(account: dict, options: dict) -> str:
    run_id = uuid.uuid4().hex[:12]
    log_file = LOG_DIR / f"{run_id}.log"
    db.create_run(run_id, account["email"], str(log_file))

    q: queue.Queue = queue.Queue()
    with _lock:
        _run_queues[run_id] = q

    th = threading.Thread(
        target=_do_register,
        args=(run_id, account, options, log_file),
        daemon=True,
        name=f"register-{run_id}",
    )
    th.start()
    return run_id


def get_run_queue(run_id: str) -> Optional[queue.Queue]:
    return _run_queues.get(run_id)


def remove_run_queue(run_id: str) -> None:
    with _lock:
        _run_queues.pop(run_id, None)
