"""病例版本、暴露信息与安全信号。"""

from dataclasses import dataclass
from datetime import date, datetime
from enum import StrEnum


class SignalState(StrEnum):
    VALIDATING = "validating"
    FOLLOW_UP = "follow-up"
    QUALITY_REVIEW = "quality-review"
    CLOSED = "closed"


@dataclass(frozen=True)
class CaseVersion:
    case_id: str
    version: int
    institution_id: str
    privacy_match_key: str
    event_terms: tuple[str, ...]
    onset_date: date | None
    recorded_at: datetime
    follows_version: int | None = None


@dataclass(frozen=True)
class ProductExposure:
    case_id: str
    product_name: str
    manufacturer_id: str | None
    approval_code: str | None
    product_lot: str | None
    ingredient_lots: tuple[str, ...] = ()


@dataclass(frozen=True)
class SafetySignal:
    signal_id: str
    product_identity: str
    case_ids: tuple[str, ...]
    rule_version: str
    state: SignalState
    started_at: datetime
