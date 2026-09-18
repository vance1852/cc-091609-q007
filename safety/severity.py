"""病例严重性重新判定。

重新判定必须说明两件事：依据哪条规则、由谁复核。判定结果只追加审计，
不修改原始报告；首报与随访的事件术语分别映射后取最高严重等级。
"""

from dataclasses import dataclass
from datetime import datetime

from .config import SEVERITY_RULES
from .store import CaseRecord, ReportStore

SEVERITY_RANK = {"非严重": 1, "严重": 2}
RANK_TO_SEVERITY = {v: k for k, v in SEVERITY_RANK.items()}

# 术语 -> (等级, 规则号)
TERM_SEVERITY: dict[str, tuple[str, str]] = {
    "肝功能异常": ("非严重", "S-EV03"),
    "肝功能异常随访": ("非严重", "S-EV03"),
    "黄疸": ("严重", "S-EV02"),
    "急性肝损伤": ("严重", "S-EV01"),
    "急性肝损伤随访": ("严重", "S-EV01"),
}


@dataclass(frozen=True)
class SeverityAssessment:
    case_id: str
    severity: str
    applied_rules: tuple[str, ...]
    evidence_terms: tuple[str, ...]
    assessed_by: str
    assessed_at: str
    note: str | None = None


class SeverityService:
    def __init__(self, store: ReportStore):
        self._store = store
        self._assessments: dict[str, list[SeverityAssessment]] = {}

    def reassess(
        self, case_id: str, assessed_by: str, note: str | None = None
    ) -> SeverityAssessment:
        case: CaseRecord = self._store.get_case(case_id)
        terms = [term for v in case.versions for term in v.event_terms]

        best_rank = 1
        applied: list[str] = []
        for term in terms:
            if term in TERM_SEVERITY:
                level, rule_id = TERM_SEVERITY[term]
                rank = SEVERITY_RANK[level]
                best_rank = max(best_rank, rank)
                rule_text = SEVERITY_RULES[
                    {
                        "S-EV01": "acute-liver-injury",
                        "S-EV02": "jaundice",
                        "S-EV03": "liver-dysfunction",
                    }[rule_id]
                ]
                entry = f"{rule_id}（{term} → {level}）：{rule_text}"
                if entry not in applied:
                    applied.append(entry)

        assessment = SeverityAssessment(
            case_id=case_id,
            severity=RANK_TO_SEVERITY[best_rank],
            applied_rules=tuple(applied),
            evidence_terms=tuple(terms),
            assessed_by=assessed_by,
            assessed_at=datetime.now().isoformat(timespec="seconds"),
            note=note,
        )
        self._assessments.setdefault(case_id, []).append(assessment)
        return assessment

    def history(self, case_id: str) -> list[SeverityAssessment]:
        """同一病例可多次复核，历史全部保留。"""
        return list(self._assessments.get(case_id, []))

    def latest(self, case_id: str) -> SeverityAssessment | None:
        history = self._assessments.get(case_id, [])
        return history[-1] if history else None
