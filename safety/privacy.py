"""隐私保护工具：匹配标识派生与事件术语规范化。"""

from __future__ import annotations

import hashlib

# 转院随访等常见后缀，剥离后得到事件核心术语用于相似性比较。
_FOLLOW_UP_SUFFIXES = ("随访", "复诊", "复查")
# 规则词典中需要识别的肝功能相关术语（包含匹配）。
_EVENT_LEXICON = (
    "肝功能异常",
    "肝衰竭",
    "急性肝衰竭",
    "死亡",
    "住院",
)


def derive_match_key(raw_key: str | None, *, salt: str) -> str | None:
    """把机构提交的伪标识再做一次带盐哈希，链路上只保存派生值。

    原始 privacyKey 不落库；同一患者跨机构提交相同伪标识时，
    派生出的哈希一致，可用于隐私保护下的匹配。
    缺失标识时返回 None，由上层保持"未知"，绝不猜测补齐。
    """

    if raw_key is None:
        return None
    digest = hashlib.sha256(f"{salt}:{raw_key}".encode("utf-8")).hexdigest()
    return f"pmk:{digest[:16]}"


def normalize_event_terms(event: str) -> tuple[str, ...]:
    """从事件文本抽取术语：原文 + 词典命中项，保持顺序去重。"""

    terms: list[str] = []
    if event:
        terms.append(event)
    for word in _EVENT_LEXICON:
        if word in event and word not in terms:
            terms.append(word)
    return tuple(terms)


def core_event(event: str) -> str:
    """事件核心术语：去掉随访/复诊等后缀。"""

    text = event.strip()
    for suffix in _FOLLOW_UP_SUFFIXES:
        if text.endswith(suffix) and len(text) > len(suffix):
            return text[: -len(suffix)]
    return text
