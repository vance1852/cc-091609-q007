"""疑似重复组检测与人工判定。

风险背景：直接去重会漏掉病程进展，贸然合并会夸大/缩小信号。
因此系统只生成"可能重复组"并给出可解释依据，合并或保持独立
一律由获授权人员确认，并永久记录判定人、理由与时间。
"""

from __future__ import annotations

from datetime import datetime

from safety.access import Permission, authorize
from safety.access import Principal
from safety.config import SignalCriteria
from safety.contracts import (
    ClusterDecision,
    DuplicateCluster,
)
from safety.privacy import core_event
from safety.repository import Repository

_TRANSITIONS = {
    ClusterDecision.PENDING: {ClusterDecision.MERGED, ClusterDecision.KEEP_INDEPENDENT},
    # 判定结论终局，防止对同一组反复改判导致信号口径漂移。
    ClusterDecision.MERGED: set(),
    ClusterDecision.KEEP_INDEPENDENT: set(),
}


class LinkageService:
    def __init__(self, repo: Repository, criteria: SignalCriteria | None = None) -> None:
        self.repo = repo
        self.criteria = criteria or SignalCriteria()

    def detect_clusters(self, *, now: datetime | None = None) -> list[DuplicateCluster]:
        """扫描全部首报病例，生成可能重复组（仅新增，已建组不重复建）。

        匹配依据（隐私保护）：
        1. 强线索：派生匹配标识一致（同一伪标识，跨机构可见）；
        2. 软线索：无标识或标识不一致时，事件核心术语相同且时间接近，
           且暴露的是同一产品身份 —— 只提示，不自动成立。
        """

        cases = self.repo.all_case_ids()
        already = {rid for c in self.repo.list_clusters() for rid in c.member_report_ids}
        created: list[DuplicateCluster] = []

        for i, cid_a in enumerate(cases):
            va = self.repo.versions_of(cid_a)[0]
            for cid_b in cases[i + 1 :]:
                vb = self.repo.versions_of(cid_b)[0]
                ra, rb = va.report_id, vb.report_id
                if ra in already or rb in already:
                    continue

                reasons = self._match_reasons(va, vb)
                if not reasons:
                    continue
                # 双方都有派生标识且不一致 → 明确是不同患者，
                # 事件/产品等软线索不得翻案，避免把不同患者误并成一组。
                if (
                    va.privacy_match_key
                    and vb.privacy_match_key
                    and va.privacy_match_key != vb.privacy_match_key
                ):
                    continue
                if self.criteria.soft_linkage_enabled is False and not reasons[0].startswith(
                    "强线索"
                ):
                    continue

                cluster = DuplicateCluster(
                    cluster_id=f"cluster-{ra.removeprefix('report-')}-{rb.removeprefix('report-')}",
                    member_report_ids=(ra, rb),
                    reasons=tuple(reasons),
                    created_at=now or max(va.recorded_at, vb.recorded_at),
                )
                self.repo.add_cluster(cluster)
                already.update((ra, rb))
                created.append(cluster)
        return created

    def _match_reasons(self, va, vb) -> list[str]:
        reasons: list[str] = []
        if va.privacy_match_key and va.privacy_match_key == vb.privacy_match_key:
            reasons.append("强线索：隐私匹配标识一致（疑同一患者跨机构上报）")

        same_event = core_event(va.event_terms[0]) == core_event(vb.event_terms[0])
        if same_event:
            reasons.append("事件特征一致：核心事件术语相同")
        gap = abs(va.recorded_at - vb.recorded_at)
        delta = gap.days
        if delta <= self.criteria.dedup_window_days:
            reasons.append(f"时间接近：首报时间相差 {delta} 天（≤ {self.criteria.dedup_window_days} 天）")

        ea = self.repo.exposure_of_report(va.report_id)
        eb = self.repo.exposure_of_report(vb.report_id)
        same_product = False
        cross_institution = va.institution_id != vb.institution_id
        if ea and eb:
            from safety.repository import product_identity_of

            same_product = product_identity_of(ea).key == product_identity_of(eb).key
            if same_product:
                reasons.append("暴露产品身份一致（同名同厂家同批准文号）")
            if cross_institution:
                reasons.append(
                    f"跨机构上报：{va.institution_id} → {vb.institution_id}"
                    + ("（符合转院重复特征）" if same_product else "（但产品身份不同）")
                )

        has_strong = bool(reasons and reasons[0].startswith("强线索"))
        if not has_strong:
            # 软成立条件：事件特征 + 时间接近 + 同一产品身份，三者缺一不可。
            # 跨机构差异仅作背景，不参与计数，避免同名异厂家被误判为重复。
            soft_hits = sum(
                1
                for r in reasons
                if r.startswith(("事件特征一致", "时间接近", "暴露产品身份一致"))
            )
            if soft_hits < 3:
                return []
        return reasons

    def decide(
        self,
        principal: Principal,
        cluster_id: str,
        decision: ClusterDecision,
        *,
        rationale: str,
        primary_report_id: str | None = None,
        decided_at: datetime | None = None,
    ) -> DuplicateCluster:
        """人工确认合并或保持独立。只有授权角色可判定。"""

        authorize(principal, Permission.CONFIRM_CLUSTER)
        cluster = self.repo.get_cluster(cluster_id)
        allowed = _TRANSITIONS[cluster.decision]
        if decision not in allowed:
            from safety.errors import ClusterStateError

            raise ClusterStateError(
                f"重复组 {cluster_id} 当前状态 {cluster.decision} 不允许判定为 {decision}"
            )

        chosen_primary = primary_report_id
        if decision is ClusterDecision.MERGED:
            if chosen_primary is None:
                # 默认保留首报时间最早者为主病例，确保首报不被覆盖。
                chosen_primary = self._earliest_report(cluster.member_report_ids)
            if chosen_primary not in cluster.member_report_ids:
                raise ValueError("主报告必须是重复组成员")
            self._apply_merge(cluster, chosen_primary)

        updated = DuplicateCluster(
            cluster_id=cluster.cluster_id,
            member_report_ids=cluster.member_report_ids,
            reasons=cluster.reasons,
            created_at=cluster.created_at,
            decision=decision,
            decided_by=principal.user_id,
            decided_at=decided_at or datetime.now(),
            rationale=rationale,
            primary_report_id=chosen_primary,
        )
        self.repo.update_cluster(updated)
        return updated

    def _earliest_report(self, report_ids: tuple[str, ...]) -> str:
        def first_time(rid: str) -> datetime:
            cid = self.repo.report_case[rid]
            return self.repo.versions_of(cid)[0].recorded_at

        return min(report_ids, key=first_time)

    def _apply_merge(self, cluster: DuplicateCluster, primary_report_id: str) -> None:
        primary_case = self.repo.report_case[primary_report_id]
        for rid in cluster.member_report_ids:
            if rid == primary_report_id:
                continue
            member_case = self.repo.report_case[rid]
            if self.repo.effective_case(member_case) != self.repo.effective_case(primary_case):
                self.repo.merge_case(member_case, primary_case)
