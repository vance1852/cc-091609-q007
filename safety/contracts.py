"""病例版本、暴露信息、产品身份与安全信号契约。

这些结构贯穿整条核查链路。版本对象全部为不可变类型：
首报与随访只能追加新版本，任何"补充"都不会改写历史版本。
"""

from dataclasses import dataclass, field
from datetime import date, datetime
from enum import StrEnum


class SignalState(StrEnum):
    """信号调查流程：验证 → 病例补充 → 质量调查 → 关闭。"""

    VALIDATING = "validating"
    FOLLOW_UP = "follow-up"
    QUALITY_REVIEW = "quality-review"
    CLOSED = "closed"


class ClusterDecision(StrEnum):
    """疑似重复组的人工判定结果。"""

    PENDING = "pending"
    MERGED = "merged"
    KEEP_INDEPENDENT = "keep-independent"


class SeriousnessLevel(StrEnum):
    UNKNOWN = "unknown"
    NON_SERIOUS = "non-serious"
    SERIOUS = "serious"


@dataclass(frozen=True)
class CaseVersion:
    case_id: str
    version: int
    report_id: str
    institution_id: str
    privacy_match_key: str | None
    event_terms: tuple[str, ...]
    onset_date: date | None
    recorded_at: datetime
    follows_version: int | None = None
    note: str = ""


@dataclass(frozen=True)
class ProductExposure:
    case_id: str
    report_id: str
    product_name: str
    manufacturer_id: str | None
    approval_code: str | None
    product_lot: str | None
    ingredient_lots: tuple[str, ...] = ()


@dataclass(frozen=True)
class ProductIdentity:
    """同名药品按"名称 + 厂家 + 批准文号"区分身份；缺失值保持显式未知。"""

    product_name: str
    manufacturer_id: str
    approval_code: str

    @property
    def key(self) -> str:
        return f"{self.product_name}|manufacturer={self.manufacturer_id}|approval={self.approval_code}"

    def describe(self) -> str:
        return (
            f"{self.product_name}（厂家：{self.manufacturer_id}，"
            f"批准文号：{self.approval_code}）"
        )


@dataclass(frozen=True)
class SafetySignal:
    signal_id: str
    product_identity: str
    case_ids: tuple[str, ...]
    rule_version: str
    state: SignalState
    started_at: datetime


@dataclass(frozen=True)
class DuplicateCluster:
    """可能重复组：只提供线索与判定依据，合并与否由人工决定。"""

    cluster_id: str
    member_report_ids: tuple[str, ...]
    reasons: tuple[str, ...]
    created_at: datetime
    decision: ClusterDecision = ClusterDecision.PENDING
    decided_by: str | None = None
    decided_at: datetime | None = None
    rationale: str | None = None
    primary_report_id: str | None = None


@dataclass(frozen=True)
class SeriousnessAssessment:
    """严重性重新判定的审计记录：依据哪条规则、谁复核、前后结论。"""

    assessment_id: str
    case_id: str
    rule_id: str
    rule_version: str
    rule_summary: str
    previous_level: SeriousnessLevel
    current_level: SeriousnessLevel
    matched_terms: tuple[str, ...]
    rationale: str
    reviewer: str
    assessed_at: datetime


@dataclass(frozen=True)
class TimelineEvent:
    event_id: str
    signal_id: str
    at: datetime
    actor: str
    kind: str
    summary: str
    detail: dict = field(default_factory=dict)


@dataclass(frozen=True)
class Investigation:
    investigation_id: str
    signal_id: str
    idempotency_key: str | None
    created_at: datetime
    created_by: str
    events: tuple[TimelineEvent, ...] = ()
