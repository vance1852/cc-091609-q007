"""可配置的核查规则与信号阈值。

阈值与规则都可以按部署环境调整；规则带版本号，严重性判定与信号
都会记录使用的规则版本，保证结论可回溯。
"""

from dataclasses import dataclass

from safety.contracts import SeriousnessLevel


@dataclass(frozen=True)
class SeriousnessRule:
    rule_id: str
    summary: str
    any_terms: tuple[str, ...]
    level: SeriousnessLevel


@dataclass(frozen=True)
class SignalCriteria:
    """信号触发与重复匹配的配置条件。"""

    rule_version: str = "hepato-v1"
    # 同一产品身份下，窗口内去重后的独立病例达到该数量才触发信号。
    min_distinct_cases: int = 2
    window_days: int = 30
    # 无隐私标识时的软匹配时间窗。
    dedup_window_days: int = 30
    # 是否允许仅凭时间/机构/事件特征（无共同匹配标识）提出疑似组。
    soft_linkage_enabled: bool = True


def default_rules() -> tuple[SeriousnessRule, ...]:
    """肝功能异常相关默认严重性规则，顺序即优先级，严重规则在前。"""

    return (
        SeriousnessRule(
            rule_id="SR-HEP-001",
            summary="出现肝衰竭或死亡等危及生命的结局术语",
            any_terms=("肝衰竭", "急性肝衰竭", "死亡"),
            level=SeriousnessLevel.SERIOUS,
        ),
        SeriousnessRule(
            rule_id="SR-HEP-002",
            summary="事件导致住院或住院时间延长",
            any_terms=("住院",),
            level=SeriousnessLevel.SERIOUS,
        ),
        SeriousnessRule(
            rule_id="SR-HEP-003",
            summary="仅报告肝功能异常（含随访异常），未见严重结局术语，暂判非严重",
            any_terms=("肝功能异常",),
            level=SeriousnessLevel.NON_SERIOUS,
        ),
    )
