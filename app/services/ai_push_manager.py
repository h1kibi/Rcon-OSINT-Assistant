"""AI Push Manager: background report generation, alert tracking, cooldown."""
import hashlib
import json
from datetime import timedelta
from PySide6.QtCore import QObject, Signal
from loguru import logger

from app.db import repositories as repo
from app.db.models import _utcnow
from app.services.ai_push_service import (
    get_ai_push_candidates,
    build_vuln_push_payload,
    build_rule_based_push,
    build_ai_push_prompt,
)
from app.ui.ai_push_window import AIPushWorker

MIN_REPORT_INTERVAL_MINUTES = 60


class AIPushManager(QObject):
    report_ready = Signal(int)
    generation_started = Signal()
    generation_failed = Signal(str)
    alert_count_changed = Signal(int)

    def __init__(self, session_factory, get_config, request_sync, parent=None):
        super().__init__(parent)
        self.session_factory = session_factory
        self.get_config = get_config
        self.request_sync = request_sync
        self._worker = None
        self._status = "idle"
        self._startup_pending = True

    @property
    def status(self):
        return self._status

    def is_generating(self):
        return self._status in {"queued", "generating_rule", "generating_ai"}

    def start_on_boot(self):
        self._startup_pending = True
        self._status = "queued"
        self.generation_started.emit()
        self.request_sync()

    def on_sync_done(self):
        if self.is_generating():
            return

        triggered = self._startup_pending
        if not triggered:
            session = self.session_factory()
            try:
                latest = repo.get_latest_ai_push_report(session)
                if not latest:
                    triggered = True
                elif repo.count_unalerted_high_risk_candidates(session) > 0:
                    triggered = True
                elif latest.updated_at and _utcnow() - latest.updated_at >= timedelta(minutes=MIN_REPORT_INTERVAL_MINUTES):
                    triggered = True
            except Exception:
                triggered = True
            finally:
                session.close()

        if triggered:
            self._start_generation("hourly" if not self._startup_pending else "startup")

    def _start_generation(self, trigger_type: str):
        self._startup_pending = False
        self._status = "generating_rule"
        self.generation_started.emit()

        session = self.session_factory()
        try:
            report = repo.create_ai_push_report(session, trigger_type=trigger_type)
            candidates = get_ai_push_candidates(session, limit=5, days=14)
            items = [build_vuln_push_payload(session, v) for v in candidates]

            if not items:
                report.status = "ready_rule"
                report.final_content = "# AI推送\n暂无符合条件的高危漏洞。"
                session.add(report)
                session.commit()
                self._status = "idle"
                self.report_ready.emit(report.id)
                return

            rule_md = build_rule_based_push(items)
            prompt = build_ai_push_prompt(items)
            context_json = json.dumps(items, ensure_ascii=False, default=str)
            content_hash = hashlib.sha256(rule_md.encode("utf-8")).hexdigest()

            repo.add_ai_push_report_items(session, report.id, items)
            new_count = repo.upsert_high_risk_alerts(session, report.id, items)

            agent_cfg = getattr(self.get_config(), "agent", None)
            has_ai = bool(agent_cfg and getattr(agent_cfg, "api_key", ""))

            if not has_ai:
                repo.save_ai_push_report_ready(
                    session, report.id,
                    rule_content=rule_md, ai_content="",
                    final_content=rule_md, prompt=prompt,
                    context_json=context_json, content_hash=content_hash,
                    model="rule-based", candidate_count=len(items),
                    high_risk_count=len(items),
                    new_high_risk_count=new_count, status="ready_rule",
                )
                repo.add_personal_library_report_entry(session, report.id, report.title)
                self._status = "idle"
                self.report_ready.emit(report.id)
                self._emit_alert_count(session)
                return

            self._status = "generating_ai"
            self._start_worker(
                report.id, agent_cfg, prompt, rule_md,
                context_json, items, new_count,
            )
        except Exception as e:
            logger.exception("AI push generation failed")
            self._status = "idle"
            self.generation_failed.emit(str(e))
        finally:
            session.close()

    def _start_worker(self, report_id, agent_cfg, prompt, rule_md, context_json, items, new_count):
        self._worker = AIPushWorker(agent_cfg, prompt, self)
        self._worker.response_ready.connect(
            lambda text: self._on_ai_ok(report_id, text, rule_md, prompt, context_json, items, new_count)
        )
        self._worker.error_occurred.connect(
            lambda err: self._on_ai_err(report_id, err, rule_md, prompt, context_json, items, new_count)
        )
        self._worker.start()

    def _on_ai_ok(self, report_id, text, rule_md, prompt, context_json, items, new_count):
        session = self.session_factory()
        try:
            content_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
            cfg = self.get_config()
            model = getattr(cfg.agent, "model", "unknown") if hasattr(cfg, "agent") else "unknown"
            repo.save_ai_push_report_ready(
                session, report_id,
                rule_content=rule_md, ai_content=text,
                final_content=text, prompt=prompt,
                context_json=context_json, content_hash=content_hash,
                model=model, candidate_count=len(items),
                high_risk_count=len(items),
                new_high_risk_count=new_count, status="ready_ai",
            )
            repo.add_personal_library_report_entry(session, report_id, "AI推送：最新高危漏洞简报")
            self._status = "idle"
            self.report_ready.emit(report_id)
            self._emit_alert_count(session)
        finally:
            session.close()

    def _on_ai_err(self, report_id, err, rule_md, prompt, context_json, items, new_count):
        session = self.session_factory()
        try:
            content_hash = hashlib.sha256(rule_md.encode("utf-8")).hexdigest()
            repo.save_ai_push_report_ready(
                session, report_id,
                rule_content=rule_md, ai_content="",
                final_content=rule_md, prompt=prompt,
                context_json=context_json, content_hash=content_hash,
                model="rule-based", candidate_count=len(items),
                high_risk_count=len(items),
                new_high_risk_count=new_count, status="ready_rule",
            )
            repo.add_personal_library_report_entry(session, report_id, "AI推送：最新高危漏洞简报")
            self._status = "idle"
            self.report_ready.emit(report_id)
            self._emit_alert_count(session)
        finally:
            session.close()

    def _emit_alert_count(self, session):
        try:
            count = repo.count_unread_high_risk_alerts(session)
            self.alert_count_changed.emit(count)
        except Exception as e:
            logger.warning(f"Alert count query failed: {e}")

    def get_latest_report_id(self):
        session = self.session_factory()
        try:
            r = repo.get_latest_ready_ai_push_report(session)
            return r.id if r else None
        finally:
            session.close()

    def mark_report_viewed(self, report_id):
        session = self.session_factory()
        try:
            repo.mark_report_alerts_read(session, report_id)
            self._emit_alert_count(session)
        finally:
            session.close()
