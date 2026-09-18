"""安全信号的验证与调查流程。

流程状态：``validating``（验证）→ ``follow-up``（病例补充）
→ ``quality-review``（质量调查）→ ``closed``（关闭）。

保障：
- **幂等启动**：以（产品身份键, 规则版本）为请求键，重复请求返回既有
  信号，绝不启动第二次调查；
- 状态转移受控，只能前进，不可跳跃/回退；
- 质量调查必须落实到具体的产品批号与原料批号（未知批号如实记录为
  “未知”，不猜测）；
- 每个动作写入调查时间线（操作人、时间、说明、批次对象）；
- 可识别视图（病例对应原始报告、机构明细）只对授权角色开放，
  信号本身可由分析角色查看脱敏内容。
"""

from dataclasses import dataclass, field
from datetime import datetime

from .aggregation import AggregationService, ProductTrend
from .config import PvConfig
from .contracts import SafetySignal, SignalState
from .privacy import AccessContext
from .store import ReportStore

# 允许的状态转移
TRANSITIONS: dict[SignalState, SignalState | None] = {
    SignalState.VALIDATING: SignalState.FOLLOW_UP,
    SignalState.FOLLOW_UP: SignalState.QUALITY_REVIEW,
    SignalState.QUALITY_REVIEW: SignalState.CLOSED,
    SignalState.CLOSED: None,
}

STAGE_LABEL = {
    SignalState.VALIDATING: "验证",
    SignalState.FOLLOW_UP: "病例补充",
    SignalState.QUALITY_REVIEW: "质量调查",
    SignalState.CLOSED: "关闭",
}


class WorkflowError(RuntimeError):
    pass


@dataclass(frozen=True)
class TimelineEvent:
    at: str
    actor: str
    stage: str
    action: str
    detail: str
    product_lots: tuple[str, ...] = ()
    ingredient_lots: tuple[str, ...] = ()


@dataclass
class Investigation:
    signal: SafetySignal
    timeline: list[TimelineEvent] = field(default_factory=list)
    quality_targets: dict[str, list[str]] = field(default_factory=dict)  # 产品批号 -> 原料批号
    closure_reason: str | None = None

    @property
    def product_identity(self) -> str:
        return self.signal.product_identity


class SignalWorkflow:
    def __init__(
        self,
        store: ReportStore,
        aggregation: AggregationService,
        config: PvConfig,
    ):
        self._store = store
        self._aggregation = aggregation
        self._config = config
        self._investigations: dict[str, Investigation] = {}
        self._request_index: dict[str, str] = {}  # (身份键, 规则版本) -> signal_id

    # ------------------------------------------------------------------ 启动
    def evaluate(self, actor: AccessContext) -> list[Investigation]:
        """按配置阈值评估全部产品趋势，达标的进入验证阶段；重复调用幂等。"""
        started: list[Investigation] = []
        for trend in self._aggregation.product_trends():
            if trend.distinct_cases >= self._config.threshold.min_distinct_cases:
                started.append(
                    self.request_investigation(
                        identity_key=trend.identity.key(),
                        trend=trend,
                        actor=actor,
                    )
                )
        return started

    def request_investigation(
        self,
        identity_key: str,
        actor: AccessContext,
        trend: ProductTrend | None = None,
    ) -> Investigation:
        """重复请求不会启动两次调查——既有信号直接返回。"""
        request_key = f"{identity_key}@{self._config.rule_version}"
        existing_id = self._request_index.get(request_key)
        if existing_id is not None:
            return self._investigations[existing_id]

        if trend is None:
            trend = next(
                (t for t in self._aggregation.product_trends() if t.identity.key() == identity_key),
                None,
            )
        if trend is None:
            raise WorkflowError(f"产品身份 {identity_key} 暂无聚合数据")
        if trend.distinct_cases < self._config.threshold.min_distinct_cases:
            raise WorkflowError(
                f"独立病例 {trend.distinct_cases} 例，"
                f"未达阈值 {self._config.threshold.min_distinct_cases} 例"
            )

        signal_id = f"sig-{len(self._investigations) + 1:03d}"
        signal = SafetySignal(
            signal_id=signal_id,
            product_identity=identity_key,
            case_ids=tuple(sorted(trend.case_ids)),
            rule_version=self._config.rule_version,
            state=SignalState.VALIDATING,
            started_at=datetime.now(),
        )
        inv = Investigation(signal=signal)
        inv.timeline.append(
            TimelineEvent(
                at=signal.started_at.isoformat(timespec="seconds"),
                actor=actor.user_id,
                stage=STAGE_LABEL[signal.state],
                action="open-investigation",
                detail=(
                    f"独立病例 {trend.distinct_cases} 例达到阈值 "
                    f"{self._config.threshold.min_distinct_cases} 例，进入验证"
                ),
            )
        )
        self._investigations[signal_id] = inv
        self._request_index[request_key] = signal_id
        return inv

    # ------------------------------------------------------------------ 流转
    def advance(
        self,
        signal_id: str,
        actor: AccessContext,
        detail: str,
        product_lots: tuple[str, ...] = (),
        ingredient_lots: tuple[str, ...] = (),
        closure_reason: str | None = None,
    ) -> Investigation:
        inv = self._investigations.get(signal_id)
        if inv is None:
            raise KeyError(f"信号 {signal_id} 不存在")
        current = inv.signal.state
        nxt = TRANSITIONS[current]
        if nxt is None:
            raise WorkflowError(f"信号 {signal_id} 已关闭，不可继续流转")

        if nxt == SignalState.QUALITY_REVIEW:
            if not product_lots:
                raise WorkflowError("进入质量调查必须指明受调查的产品批号（未知批号请显式填“未知”）")
            for lot in product_lots:
                inv.quality_targets.setdefault(lot, [])
                for ing in ingredient_lots:
                    if ing not in inv.quality_targets[lot]:
                        inv.quality_targets[lot].append(ing)

        if nxt == SignalState.CLOSED:
            if not closure_reason:
                raise WorkflowError("关闭信号必须填写关闭理由")
            inv.closure_reason = closure_reason

        object.__setattr__(inv.signal, "state", nxt)
        inv.timeline.append(
            TimelineEvent(
                at=datetime.now().isoformat(timespec="seconds"),
                actor=actor.user_id,
                stage=STAGE_LABEL[nxt],
                action=f"enter-{nxt.value}",
                detail=detail,
                product_lots=product_lots,
                ingredient_lots=ingredient_lots,
            )
        )
        return inv

    def note(self, signal_id: str, actor: AccessContext, detail: str) -> TimelineEvent:
        """在当前阶段补充调查动作（如病例补充、留样检验），不改变状态。"""
        inv = self._investigations.get(signal_id)
        if inv is None:
            raise KeyError(f"信号 {signal_id} 不存在")
        event = TimelineEvent(
            at=datetime.now().isoformat(timespec="seconds"),
            actor=actor.user_id,
            stage=STAGE_LABEL[inv.signal.state],
            action="note",
            detail=detail,
        )
        inv.timeline.append(event)
        return event

    # ------------------------------------------------------------------ 溯源
    def _cases_under_signal(self, inv: Investigation) -> list:
        """信号病例经人工合并后，展开为实际归并到它的全部病例。"""
        case_mapping = self._aggregation._matching.effective_case_mapping()
        targets = set(inv.signal.case_ids)
        return [
            self._store.get_case(cid)
            for cid, effective in case_mapping.items()
            if effective in targets
        ]

    def trace_reports(
        self, signal_id: str, actor: AccessContext
    ) -> list[dict]:
        """从信号返回每份原始报告（含合并组保留的各版本）。可识别信息仅授权角色可见。"""
        inv = self._investigations.get(signal_id)
        if inv is None:
            raise KeyError(f"信号 {signal_id} 不存在")

        result: list[dict] = []
        for case in self._cases_under_signal(inv):
            case_id = case.case_id
            for report_id in case.report_ids:
                report = self._store.get_report(report_id)
                if actor.may_view_identifiable:
                    result.append(
                        {
                            "report_id": report.report_id,
                            "case_id": case_id,
                            "institution": report.institution_id,
                            "match_key": case.first_version.privacy_match_key,
                            "raw": report.payload,
                            "source_hash": report.source_hash,
                        }
                    )
                else:
                    result.append(
                        {
                            "report_id": report.report_id,
                            "case_id": case_id,
                            "institution": "***未授权***",
                            "match_key": "***未授权***",
                            "raw": {
                                k: ("***未授权***" if k in ("privacyKey", "institution") else v)
                                for k, v in report.payload.items()
                            },
                            "source_hash": report.source_hash,
                        }
                    )
        return result

    def export_identifiable_detail(self, signal_id: str, actor: AccessContext) -> dict:
        """导出信号下病例-机构-原始隐私标识对照；仅授权角色，否则拒绝。"""
        actor.require_identifiable()
        inv = self._investigations.get(signal_id)
        if inv is None:
            raise KeyError(f"信号 {signal_id} 不存在")
        detail = {}
        for case in self._cases_under_signal(inv):
            case_id = case.case_id
            detail[case_id] = {
                "privacy_match_key": case.first_version.privacy_match_key,
                "institutions": [v.institution_id for v in case.versions],
                "report_ids": list(case.report_ids),
            }
        return detail

    @property
    def investigations(self) -> list[Investigation]:
        return list(self._investigations.values())

    def get(self, signal_id: str) -> Investigation:
        return self._investigations[signal_id]
