"""可配置的核查规则与角色权限。

阈值、规则版本、匹配权重与角色集中在此处，严重性重新判定时记录的
``rule_version`` 与信号所引用的规则版本均来自这里，保证可追溯。
"""

from dataclasses import dataclass, field
from enum import StrEnum


RULE_VERSION = "pv-rules-2026.09"


class Role(StrEnum):
    """系统角色。只有 ``CASE_INVESTIGATOR`` 与 ``ADMIN`` 可查看可识别信息。"""

    CASE_INVESTIGATOR = "case-investigator"
    QUALITY_INVESTIGATOR = "quality-investigator"
    ANALYST = "analyst"
    ADMIN = "admin"


# 可查看可识别信息（原始隐私标识、机构下的病例对应关系）的角色
IDENTIFIABLE_ACCESS_ROLES = frozenset({Role.CASE_INVESTIGATOR, Role.ADMIN})


@dataclass(frozen=True)
class SignalThreshold:
    """信号触发条件：同一产品身份下达到指定独立病例数。"""

    min_distinct_cases: int = 3


@dataclass(frozen=True)
class MatchingWeights:
    """疑似重复评分权重，合计 1.0。"""

    privacy_match_key: float = 0.7
    event_family: float = 0.15
    institution: float = 0.05
    time_proximity: float = 0.10
    # 发病日期在该天数内视为时间接近
    time_window_days: int = 30
    # 达到该分数才生成疑似重复组线索
    candidate_threshold: float = 0.5


@dataclass(frozen=True)
class PrivacyConfig:
    # HMAC 盐值应来自部署环境（环境变量/密钥管理），禁止写死在代码里
    match_key_salt: str
    # 匹配标识截断长度，只用于比对，不暴露原文
    digest_hex_length: int = 16


@dataclass(frozen=True)
class PvConfig:
    rule_version: str = RULE_VERSION
    threshold: SignalThreshold = field(default_factory=SignalThreshold)
    matching: MatchingWeights = field(default_factory=MatchingWeights)
    privacy: PrivacyConfig | None = None


# 严重性判定规则（按肝损伤相关术语归类），规则号写入审计记录
SEVERITY_RULES: dict[str, str] = {
    "acute-liver-injury": "S-EV01 术语映射：急性肝损伤/急性肝损伤随访 => 严重",
    "jaundice": "S-EV02 术语映射：黄疸 => 严重",
    "liver-dysfunction": "S-EV03 术语映射：肝功能异常及其随访 => 非严重（需结合实验室指标复核）",
}

# 事件术语归族：随访术语与其首报术语归为同一事件族，用于重复匹配
EVENT_FAMILIES: dict[str, str] = {
    "肝功能异常": "hepatic",
    "肝功能异常随访": "hepatic",
    "急性肝损伤": "hepatic",
    "急性肝损伤随访": "hepatic",
    "黄疸": "hepatic",
}
