"""信号检测与调查流程。

- 信号按"产品身份"（名称+厂家+批准文号）分开聚合，同名药不混算；
- 触发条件可配置（窗口内独立病例数阈值），重复组人工判定为
  "保持独立"的病例分别计数，"已合并"的只计一次，避免夸大；
- 调查启动幂等：重复请求（含相同幂等键）不会启动第二次；
- 流程：validating → follow-up → quality-review → closed，
  每次流转写入调查时间线。
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta

from safety.access import Permission, authorize
from safety.access import Principal
from safety.config import SignalCriteria
from safety.contracts import (
    Investigation,
    ProductIdentity,
    SafetySignal,
    SignalState,
    TimelineEvent,
)
from safety.errors import DuplicateInvestigationError, InvalidTransitionError
from safety.repository import Repository, product_identity_of

_FLOW = {
    SignalState.VALIDATING: SignalState.FOLLOW_UP,
    SignalState.FOLLOW_UP: SignalState.QUALITY_REVIEW,
    SignalState.QUALITY_REVIEW: SignalState.CLOSED,
    SignalState.CLOSED: None,
}

_ACTIONS = {
    SignalState.VALIDATING: "验证信号：核对病例、暴露与产品身份",
    SignalState.FOLLOW_UP: "病例补充：收集随访与缺失批号信息",
    SignalState.QUALITY_REVIEW: "质量调查：追溯产品批号与原料批次",
    SignalState.CLOSED: "关闭：完成处置并归档",
}


class SignalService:
    def __init__(self, repo: Repository, criteria: SignalCriteria) -> None:
        self.repo = repo
        self.criteria = criteria

    # ---- 信号检测 -----------------------------------------------------

    def detect_signals(self, *, now: datetime | None = None) -> list[SafetySignal]:
        """按产品身份聚合独立病例，达到阈值则生成信号。

        病例去重口径：人工已合并的重复组按主病例计一次；
        判定保持独立的成员分别计数；尚未判定的疑似组分别计数，
        但在解释信息中标注待核查，提示信号可能被高估。
        """

        anchor = now or datetime.now()
        window_start = anchor - timedelta(days=self.criteria.window_days)

        # 未人工判定的疑似重复组：组内病例在计数时保守地折为 1 个
        # "待核病例"单位，避免在结论明确前夸大信号；
        # 判定"保持独立"后下次检测即分别计数。
        pending_members: dict[str, frozenset[str]] = {
            c.cluster_id: frozenset(self.repo.case_of_report(rid) for rid in c.member_report_ids)
            for c in self.repo.list_clusters()
            if c.decision.value == "pending"
        }

        def counting_units(case_set: set[str]) -> set[str]:
            units: set[str] = set(case_set)
            for cluster_id, members in pending_members.items():
                # 仅当整组都落在同一产品身份桶内才折算，跨身份的组各自计数。
                if members <= case_set:
                    units.difference_update(members)
                    units.add(f"pending-cluster:{cluster_id}")
            return units

        # 产品身份 -> 有效病例集合
        buckets: dict[str, set[str]] = {}
        identities: dict[str, ProductIdentity] = {}
        for exposure in self.repo.exposures.values():
            effective = self.repo.effective_case(exposure.case_id)
            versions = self.repo.versions_of(effective)
            if not versions:
                continue
            first = versions[0]
            if first.recorded_at < window_start:
                continue
            identity = product_identity_of(exposure)
            buckets.setdefault(identity.key, set()).add(effective)
            identities[identity.key] = identity

        signals: list[SafetySignal] = []
        for identity_key, cases in sorted(buckets.items()):
            units = counting_units(cases)
            if len(units) < self.criteria.min_distinct_cases:
                continue
            signal = self._build_signal(identities[identity_key], cases, anchor)
            if signal is not None:
                self.repo.put_signal(signal)
                signals.append(signal)
        return signals

    def _build_signal(
        self, identity: ProductIdentity, cases: set[str], now: datetime
    ) -> SafetySignal | None:
        ordered = tuple(sorted(cases))
        digest = hashlib.sha256(identity.key.encode("utf-8")).hexdigest()[:10]
        signal_id = f"signal-{digest}"
        existing = next(
            (s for s in self.repo.list_signals() if s.product_identity == identity.key),
            None,
        )
        if existing is not None:
            # 已存在信号则刷新病例口径，保持状态与启动时间不变。
            refreshed = SafetySignal(
                signal_id=existing.signal_id,
                product_identity=existing.product_identity,
                case_ids=ordered,
                rule_version=existing.rule_version,
                state=existing.state,
                started_at=existing.started_at,
            )
            self.repo.put_signal(refreshed)
            return refreshed
        return SafetySignal(
            signal_id=signal_id,
            product_identity=identity.key,
            case_ids=ordered,
            rule_version=self.criteria.rule_version,
            state=SignalState.VALIDATING,
            started_at=now,
        )

    # ---- 调查生命周期（幂等） ----------------------------------------

    def start_investigation(
        self,
        principal: Principal,
        signal_id: str,
        *,
        idempotency_key: str | None = None,
        now: datetime | None = None,
    ) -> Investigation:
        """启动调查。重复请求不会启动两次：

        - 相同 idempotency_key 返回同一调查；
        - 即便没有幂等键，同一信号也只允许一条调查。
        """

        authorize(principal, Permission.MANAGE_INVESTIGATION)
        signal = self.repo.get_signal(signal_id)
        stamp = now or datetime.now()

        if idempotency_key is not None:
            existing_id = self.repo.idempotency_lookup(idempotency_key)
            if existing_id is not None:
                return self.repo.investigations[existing_id]  # 重复请求，原样返回

        if self.repo.has_investigation_for_signal(signal_id):
            raise DuplicateInvestigationError(f"信号 {signal_id} 已存在调查，不得重复启动")

        investigation = Investigation(
            investigation_id=f"inv-{signal_id}",
            signal_id=signal_id,
            idempotency_key=idempotency_key,
            created_at=stamp,
            created_by=principal.user_id,
        )
        self.repo.start_investigation(investigation, idempotency_key)
        self.repo.append_timeline(
            investigation.investigation_id,
            TimelineEvent(
                event_id=f"evt-{signal_id}-start",
                signal_id=signal_id,
                at=stamp,
                actor=principal.user_id,
                kind="investigation-started",
                summary=f"调查启动，进入{SignalState.VALIDATING.value}（{_ACTIONS[SignalState.VALIDATING]}）",
                detail={"state": SignalState.VALIDATING.value},
            ),
        )
        return investigation

    def advance(
        self,
        principal: Principal,
        signal_id: str,
        *,
        note: str = "",
        now: datetime | None = None,
    ) -> SignalState:
        """沿状态机推进一步，并记录时间线。"""

        authorize(principal, Permission.MANAGE_INVESTIGATION)
        signal = self.repo.get_signal(signal_id)
        investigation = self.repo.investigation_of_signal(signal_id)
        if investigation is None:
            raise InvalidTransitionError(f"信号 {signal_id} 尚未启动调查")

        target = _FLOW[signal.state]
        if target is None:
            raise InvalidTransitionError(f"信号 {signal_id} 已关闭，不能继续流转")

        stamp = now or datetime.now()
        self.repo.put_signal(
            SafetySignal(
                signal_id=signal.signal_id,
                product_identity=signal.product_identity,
                case_ids=signal.case_ids,
                rule_version=signal.rule_version,
                state=target,
                started_at=signal.started_at,
            )
        )
        seq = len(investigation.events) + 1
        self.repo.append_timeline(
            investigation.investigation_id,
            TimelineEvent(
                event_id=f"evt-{signal_id}-{seq}",
                signal_id=signal_id,
                at=stamp,
                actor=principal.user_id,
                kind=f"state->{target.value}",
                summary=f"流转至 {target.value}：{_ACTIONS[target]}"
                + (f"；备注：{note}" if note else ""),
                detail={"from": signal.state.value, "to": target.value, "note": note},
            ),
        )
        return target
