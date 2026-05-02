"""Agent tool service — database queries for Rcon AI panel."""

from sqlmodel import select, func
from app.db.models import Vulnerability
from app.db.repositories import get_vulnerabilities


class AgentToolService:
    def __init__(self, session_factory):
        self.session_factory = session_factory

    def stats(self) -> dict:
        session = self.session_factory()
        try:
            return {
                "total": session.exec(select(func.count(Vulnerability.id))).one(),
                "kev": session.exec(
                    select(func.count(Vulnerability.id)).where(Vulnerability.is_kev == True)
                ).one(),
                "unread": session.exec(
                    select(func.count(Vulnerability.id)).where(Vulnerability.status == "unread")
                ).one(),
                "high": session.exec(
                    select(func.count(Vulnerability.id)).where(Vulnerability.action_value_score >= 80)
                ).one(),
            }
        finally:
            session.close()

    def recent(self, limit: int = 8) -> list[dict]:
        session = self.session_factory()
        try:
            vulns = get_vulnerabilities(session, sort="date_desc", limit=limit)
            return [self._brief(v) for v in vulns]
        finally:
            session.close()

    def top_risk(self, limit: int = 8) -> list[dict]:
        session = self.session_factory()
        try:
            vulns = get_vulnerabilities(session, sort="score_desc", limit=limit)
            return [self._brief(v) for v in vulns]
        finally:
            session.close()

    def search(self, keyword: str, limit: int = 10) -> list[dict]:
        session = self.session_factory()
        try:
            vulns = get_vulnerabilities(session, keyword=keyword.strip(), limit=limit)
            return [self._brief(v) for v in vulns]
        finally:
            session.close()

    def cve(self, cve_id: str) -> dict | None:
        session = self.session_factory()
        try:
            vuln = session.exec(
                select(Vulnerability).where(Vulnerability.cve_id == cve_id)
            ).first()
            if not vuln:
                return None
            return {
                "id": vuln.id,
                "cve_id": vuln.cve_id,
                "title": vuln.title,
                "severity": vuln.severity,
                "cvss": vuln.cvss_score,
                "epss": vuln.epss_score,
                "epss_percentile": vuln.epss_percentile,
                "is_kev": vuln.is_kev,
                "has_poc": vuln.has_poc_signal,
                "has_patch": vuln.has_patch,
                "score": vuln.action_value_score,
                "description": vuln.description,
            }
        finally:
            session.close()

    def _brief(self, v) -> dict:
        return {
            "cve_id": v.cve_id or v.ghsa_id or v.osv_id,
            "title": v.title,
            "severity": v.severity,
            "cvss": v.cvss_score,
            "epss": v.epss_percentile,
            "score": v.action_value_score,
            "is_kev": v.is_kev,
            "has_poc": v.has_poc_signal,
            "has_patch": v.has_patch,
        }
