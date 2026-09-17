"""应用门面：组装存储、规则与各领域服务。"""

from __future__ import annotations

from pathlib import Path

from safety.config import SignalCriteria, default_rules
from safety.ingest import IngestionService
from safety.linkage import LinkageService
from safety.reports import ReportService
from safety.repository import Repository
from safety.seriousness import SeriousnessService
from safety.signals import SignalService


class SafetyApp:
    def __init__(
        self,
        *,
        criteria: SignalCriteria | None = None,
        salt: str = "pv-fixture-salt",
    ) -> None:
        self.criteria = criteria or SignalCriteria()
        rules = default_rules()
        self.repo = Repository()
        self.ingestion = IngestionService(self.repo, salt=salt)
        self.linkage = LinkageService(self.repo, self.criteria)
        self.seriousness = SeriousnessService(
            self.repo, rules=rules, rule_version=self.criteria.rule_version
        )
        self.signals = SignalService(self.repo, self.criteria)
        self.reports = ReportService(self.repo)

    def load(self, fixture_path: str | Path):
        return self.ingestion.load_fixture(fixture_path)
