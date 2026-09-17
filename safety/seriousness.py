"""严重性重新判定：规则匹配 + 复核人审计。

每次重新判定都生成一条不可变记录，写明：
- 使用了哪条规则及规则版本；
- 命中了哪些事件术语；
- 判定前后的严重性级别；
- 复核人与判定理由。

随访使病情进展（如"肝功能异常"进展为"肝衰竭"）时可上调级别；
规则只给出建议级别，留痕后供信号流程与人工复核使用。
"""

from __future__ import annotations

from datetime import datetime

from safety.access import Permission, authorize
from safety.access import Principal
from safety.config import SeriousnessRule
from safety.contracts import SeriousnessAssessment, SeriousnessLevel
from safety.repository import Repository


class SeriousnessService:
    def __init__(self, repo: Repository, rules: tuple[SeriousnessRule, ...], rule_version: str) -> None:
        self.repo = repo
        self.rules = rules
        self.rule_version = rule_version

    def current_level(self, case_id: str) -> SeriousnessLevel:
        assessments = self.repo.assessments_of(case_id)
        if assessments:
            return assessments[-1].current_level
        return SeriousnessLevel.UNKNOWN

    def reassess(
        self,
        principal: Principal,
        case_id: str,
        *,
        rationale: str = "",
        assessed_at: datetime | None = None,
        override_level: SeriousnessLevel | None = None,
    ) -> SeriousnessAssessment:
        """依据病例全部版本的事件术语重新判定严重性。

        override_level 允许授权复核人基于规则之外的临床判断调整，
        但同样必须留痕（规则字段记为人工复核）。
        """

        authorize(principal, Permission.ASSESS_SERIOUSNESS)
        case_id = self.repo.effective_case(case_id)
        previous = self.current_level(case_id)

        all_terms: list[str] = []
        for version in self.repo.versions_of(case_id):
            for term in version.event_terms:
                if term not in all_terms:
                    all_terms.append(term)
        term_blob = " ".join(all_terms)

        matched_rule: SeriousnessRule | None = None
        matched_terms: tuple[str, ...] = ()
        for rule in self.rules:  # 规则按严重程度优先排序
            hits = tuple(t for t in rule.any_terms if t in term_blob)
            if hits:
                matched_rule, matched_terms = rule, hits
                break

        if override_level is not None:
            level = override_level
            rule_id, rule_summary = "MANUAL", "授权复核人基于临床判断的人工复核"
            if matched_rule is not None:
                rule_summary = f"{rule_summary}；规则建议参考 {matched_rule.rule_id}"
        elif matched_rule is not None:
            level = matched_rule.level
            rule_id = matched_rule.rule_id
            rule_summary = matched_rule.summary
        else:
            level = SeriousnessLevel.UNKNOWN
            rule_id = "SR-NONE"
            rule_summary = "无规则命中，严重性未知，待补充信息"

        assessment = SeriousnessAssessment(
            assessment_id=f"asm-{case_id}-{len(self.repo.assessments_of(case_id)) + 1}",
            case_id=case_id,
            rule_id=rule_id,
            rule_version=self.rule_version,
            rule_summary=rule_summary,
            previous_level=previous,
            current_level=level,
            matched_terms=matched_terms,
            rationale=rationale or rule_summary,
            reviewer=principal.user_id,
            assessed_at=assessed_at or datetime.now(),
        )
        self.repo.add_assessment(assessment)
        return assessment
