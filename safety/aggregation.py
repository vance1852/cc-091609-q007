"""产品维度聚合与趋势。

聚合身份 = 药名 + 厂家 + 批准信息。同名中成药只要厂家或批准信息不同，
就视为不同产品身份分别聚合——不允许仅按药名合并信号。

- 病例计数使用人工确认后的**有效病例**（合并组只计主病例，判独立的
  分别计数）；
- 批号维度保留 ``未知``，缺失批号既不猜测也不与任何已知批号合并；
- 原料批次沿暴露记录上卷，用于把质量调查落实到具体批次。
"""

from dataclasses import dataclass, field

from .matching import MatchingService
from .privacy import UNKNOWN_TOKEN
from .store import ReportStore


@dataclass(frozen=True)
class ProductIdentity:
    product_name: str
    manufacturer_id: str | None
    approval_code: str | None

    def key(self) -> str:
        return f"{self.product_name}|厂家={self.manufacturer_id or UNKNOWN_TOKEN}|批准={self.approval_code or UNKNOWN_TOKEN}"

    @classmethod
    def unknown_manufacturer(cls, name: str) -> "ProductIdentity":
        return cls(name, None, None)


@dataclass
class ProductTrend:
    identity: ProductIdentity
    case_ids: list[str] = field(default_factory=list)
    report_ids: list[str] = field(default_factory=list)
    product_lot_counts: dict[str, set[str]] = field(default_factory=dict)
    ingredient_lot_cases: dict[str, set[str]] = field(default_factory=dict)
    institutions: set[str] = field(default_factory=set)

    @property
    def distinct_cases(self) -> int:
        return len(self.case_ids)

    def describe(self) -> dict:
        return {
            "product_identity": self.identity.key(),
            "distinct_cases": self.distinct_cases,
            "report_count": len(self.report_ids),
            "institutions": sorted(self.institutions),
            "product_lots": {
                lot: sorted(cases) for lot, cases in sorted(self.product_lot_counts.items())
            },
            "ingredient_lots": {
                lot: sorted(cases)
                for lot, cases in sorted(self.ingredient_lot_cases.items())
            },
            "case_ids": sorted(self.case_ids),
            "report_ids": sorted(self.report_ids),
        }


class AggregationService:
    def __init__(self, store: ReportStore, matching: MatchingService):
        self._store = store
        self._matching = matching

    def product_trends(self) -> list[ProductTrend]:
        case_mapping = self._matching.effective_case_mapping()
        trends: dict[str, ProductTrend] = {}

        for case in self._store.cases:
            effective_id = case_mapping.get(case.case_id, case.case_id)
            # 聚合身份以首报暴露为准；随访不改变产品身份
            first = self._store.first_report_of_case(case.case_id)
            identity = ProductIdentity(
                product_name=first.product_name,
                manufacturer_id=first.manufacturer_id,
                approval_code=first.approval_code,
            )
            trend = trends.setdefault(identity.key(), ProductTrend(identity=identity))
            if effective_id not in trend.case_ids:
                trend.case_ids.append(effective_id)
            trend.institutions.add(first.institution_id)

            # 批号：同一有效病例的所有版本暴露都计入，但 None 归入“未知”
            for report_id in case.report_ids:
                report = self._store.get_report(report_id)
                trend.report_ids.append(report_id)
                lot = report.product_lot or UNKNOWN_TOKEN
                trend.product_lot_counts.setdefault(lot, set()).add(effective_id)
                for ing in report.ingredient_lots:
                    trend.ingredient_lot_cases.setdefault(ing, set()).add(effective_id)

        return sorted(trends.values(), key=lambda t: (-t.distinct_cases, t.identity.key()))
