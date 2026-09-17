"""核查后端测试：覆盖隐私匹配、人工去重、首报保护、产品身份、
批号未知、严重性审计、信号阈值、调查幂等与 RBAC。

运行：python3 -m unittest -v
"""

from __future__ import annotations

import unittest
from datetime import datetime

from safety.access import Permission, Principal
from safety.app import SafetyApp
from safety.config import SignalCriteria
from safety.contracts import (
    ClusterDecision,
    SeriousnessLevel,
    SignalState,
)
from safety.errors import (
    AccessDeniedError,
    ClusterStateError,
    DuplicateInvestigationError,
    InvalidTransitionError,
    UnknownReportError,
)

T0 = datetime(2026, 9, 10, 9, 0)


def rpt(rid, institution, key, product="中成药甲", **kw):
    item = {"id": rid, "institution": institution, "privacyKey": key, "product": product}
    item.update(kw)
    return item


class SafetyBackendTests(unittest.TestCase):
    def setUp(self):
        self.app = SafetyApp(criteria=SignalCriteria(min_distinct_cases=2, window_days=30))
        self.specialist = Principal("pv-zhang", ("pv-specialist",))
        self.physician = Principal("dr-li", ("pv-physician",))
        self.reviewer = Principal("pv-liu", ("pv-reviewer",))
        self.auditor = Principal("auditor-wang", ("auditor",))

    def ingest_fixture(self):
        self.app.ingestion.ingest(
            rpt("report-a", "hospital-east", "p-71", lot="lot-8", event="肝功能异常"),
            received_at=T0,
        )
        self.app.ingestion.ingest(
            rpt("report-b", "hospital-west", "p-71", lot=None, event="肝功能异常随访"),
            received_at=T0.replace(minute=1),
        )
        self.app.ingestion.ingest(
            rpt("report-c", "clinic-2", "p-92", manufacturer="maker-b", event="肝功能异常"),
            received_at=T0.replace(minute=2),
        )

    # ---- 原始报告与隐私 ------------------------------------------------

    def test_raw_report_frozen_and_key_not_in_business_view(self):
        self.ingest_fixture()
        raw = self.app.reports.raw_report("report-a")
        self.assertNotIn("privacyKey", raw["payload"])
        # 原始快照逐字保留机构字段
        self.assertEqual(raw["payload"]["lot"], "lot-8")
        with self.assertRaises(UnknownReportError):
            self.app.reports.raw_report("nope")

    def test_privacy_match_key_is_hashed_and_stable(self):
        self.ingest_fixture()
        va = self.app.repo.versions_of("case-a")[0]
        vb = self.app.repo.versions_of("case-b")[0]
        self.assertTrue(va.privacy_match_key.startswith("pmk:"))
        self.assertNotIn("p-71", va.privacy_match_key)
        self.assertEqual(va.privacy_match_key, vb.privacy_match_key)
        self.assertNotEqual(
            va.privacy_match_key, self.app.repo.versions_of("case-c")[0].privacy_match_key
        )

    # ---- 疑似重复与人工判定 --------------------------------------------

    def test_duplicate_cluster_only_for_same_patient(self):
        self.ingest_fixture()
        clusters = self.app.linkage.detect_clusters()
        self.assertEqual(len(clusters), 1)
        members = clusters[0].member_report_ids
        self.assertEqual(set(members), {"report-a", "report-b"})
        self.assertTrue(any(r.startswith("强线索") for r in clusters[0].reasons))

    def test_different_privacy_keys_never_cluster_even_if_features_match(self):
        self.ingest_fixture()
        # 不同患者、同产品同事件同时间窗：不得被聚成重复组
        self.app.ingestion.ingest(
            rpt("report-d", "hospital-north", "p-33", lot="lot-9", event="肝功能异常"),
            received_at=T0.replace(day=11),
        )
        clusters = self.app.linkage.detect_clusters()
        all_members = {m for c in clusters for m in c.member_report_ids}
        self.assertNotIn("report-d", all_members)

    def test_manual_merge_preserves_first_report_and_appends(self):
        self.ingest_fixture()
        (cluster,) = self.app.linkage.detect_clusters()
        self.app.linkage.decide(
            self.specialist, cluster.cluster_id, ClusterDecision.MERGED,
            rationale="转院重复，确认同一患者", decided_at=T0.replace(day=11),
        )
        detail = self.app.reports.case_cluster("case-a")
        self.assertTrue(detail["first_report_preserved"])
        versions = detail["versions"]
        self.assertEqual(versions[0]["report_id"], "report-a")
        self.assertEqual(versions[0]["note"], "首报")
        self.assertEqual(versions[1]["report_id"], "report-b")
        self.assertEqual(versions[1]["follows_version"], 1)
        self.assertIn("case-b", detail["merged_from"])
        # 原始 report-b 快照仍可回溯
        self.assertEqual(self.app.reports.raw_report("report-b")["report_id"], "report-b")

    def test_keep_independent_kept_separate_for_signal_count(self):
        self.ingest_fixture()
        (cluster,) = self.app.linkage.detect_clusters()
        self.app.linkage.decide(
            self.specialist, cluster.cluster_id, ClusterDecision.KEEP_INDEPENDENT,
            rationale="虽标识相同但实为两例，保持独立", decided_at=T0.replace(day=11),
        )
        self.app.linkage.detect_clusters()  # 不应重建已判定的组
        self.assertEqual(len(self.app.repo.list_clusters()), 1)
        self.assertNotEqual(
            self.app.repo.effective_case("case-a"),
            self.app.repo.effective_case("case-b"),
        )

    def test_cluster_decision_is_terminal(self):
        self.ingest_fixture()
        (cluster,) = self.app.linkage.detect_clusters()
        self.app.linkage.decide(
            self.specialist, cluster.cluster_id, ClusterDecision.MERGED, rationale="x"
        )
        with self.assertRaises(ClusterStateError):
            self.app.linkage.decide(
                self.specialist, cluster.cluster_id, ClusterDecision.KEEP_INDEPENDENT,
                rationale="改判",
            )

    def test_followup_never_overwrites_first_report(self):
        self.ingest_fixture()
        before = self.app.repo.versions_of("case-a")[0]
        self.app.ingestion.add_follow_up(
            "case-a", report_id="report-a-fu", institution_id="hospital-east",
            event="肝功能异常随访", recorded_at=T0.replace(day=12),
            raw_privacy_key="p-71",
        )
        after = self.app.repo.versions_of("case-a")[0]
        self.assertEqual(before, after)  # 首报对象不可变
        self.assertEqual(len(self.app.repo.versions_of("case-a")), 2)
        self.assertEqual(self.app.repo.versions_of("case-a")[1].follows_version, 1)

    # ---- 产品身份与批号 ------------------------------------------------

    def test_same_name_different_manufacturer_aggregated_separately(self):
        self.ingest_fixture()
        trends = {t["manufacturer"]: t for t in self.app.reports.product_trends()}
        self.assertIn("maker-b", trends)
        self.assertIn("未知", trends)
        self.assertEqual(trends["maker-b"]["distinct_cases"], ["case-c"])
        self.assertEqual(trends["未知"]["distinct_cases"], ["case-a", "case-b"])

    def test_unknown_lot_preserved_not_guessed(self):
        self.ingest_fixture()
        unknown_trend = next(
            t for t in self.app.reports.product_trends() if t["manufacturer"] == "未知"
        )
        self.assertIn("report-b", unknown_trend["unknown_lot_reports"])
        self.assertEqual(unknown_trend["known_product_lots"], ["lot-8"])
        # 绝不能凭空给 report-b 编一个批号
        exposure_b = self.app.repo.exposure_of_report("report-b")
        self.assertIsNone(exposure_b.product_lot)

    # ---- 严重性判定 ----------------------------------------------------

    def test_seriousness_reassess_records_rule_and_reviewer(self):
        self.ingest_fixture()
        a1 = self.app.seriousness.reassess(self.specialist, "case-a", rationale="初判")
        self.assertEqual(a1.current_level, SeriousnessLevel.NON_SERIOUS)
        self.assertEqual(a1.rule_id, "SR-HEP-003")
        self.assertEqual(a1.reviewer, "pv-zhang")
        self.assertEqual(a1.rule_version, "hepato-v1")
        self.assertEqual(a1.previous_level, SeriousnessLevel.UNKNOWN)

        self.app.ingestion.add_follow_up(
            "case-a", report_id="fu2", institution_id="hospital-west",
            event="急性肝衰竭 住院", recorded_at=T0.replace(day=14), raw_privacy_key="p-71",
        )
        a2 = self.app.seriousness.reassess(self.physician, "case-a", rationale="进展上调")
        self.assertEqual(a2.current_level, SeriousnessLevel.SERIOUS)
        self.assertEqual(a2.rule_id, "SR-HEP-001")
        self.assertIn("急性肝衰竭", a2.matched_terms)
        self.assertEqual(a2.previous_level, SeriousnessLevel.NON_SERIOUS)
        # 历史判定全部保留
        self.assertEqual(len(self.app.repo.assessments_of("case-a")), 2)

    def test_manual_override_is_audited(self):
        self.ingest_fixture()
        a = self.app.seriousness.reassess(
            self.reviewer, "case-a", override_level=SeriousnessLevel.SERIOUS, rationale="临床判断"
        )
        self.assertEqual(a.rule_id, "MANUAL")
        self.assertEqual(a.current_level, SeriousnessLevel.SERIOUS)

    # ---- 信号阈值与流程 ------------------------------------------------

    def _reach_threshold(self):
        self.ingest_fixture()
        (cluster,) = self.app.linkage.detect_clusters()
        self.app.linkage.decide(
            self.specialist, cluster.cluster_id, ClusterDecision.MERGED, rationale="同患者"
        )
        # 另两名不同患者，同产品身份（厂家/批准均缺失）
        self.app.ingestion.ingest(
            rpt("report-d", "hospital-north", "p-33", lot="lot-8",
                ingredientLots=["ing-huangqin-22"], event="肝功能异常"),
            received_at=T0.replace(day=11),
        )
        self.app.ingestion.ingest(
            rpt("report-e", "community-south", "p-44", lot="lot-8",
                ingredientLots=["ing-huangqin-22"], event="肝功能异常"),
            received_at=T0.replace(day=12),
        )

    def test_signal_triggered_by_distinct_cases_not_duplicate_count(self):
        self._reach_threshold()
        signals = self.app.signals.detect_signals(now=T0.replace(day=13))
        # 只有"未知厂家"身份达标；maker-b 仅 1 例不触发
        self.assertEqual(len(signals), 1)
        cases = set(signals[0].case_ids)
        self.assertEqual(cases, {"case-a", "case-d", "case-e"})  # b 已并入 a，不重复计数

    def test_below_threshold_no_signal(self):
        self.ingest_fixture()
        self.app.linkage.detect_clusters()
        signals = self.app.signals.detect_signals(now=T0.replace(day=13))
        self.assertEqual(signals, [])

    def test_pending_cluster_counts_conservative_until_kept_independent(self):
        # 仅 a/b 两例，处于未判定疑似组：保守折为 1 例，不达阈值 2
        self.app.ingestion.ingest(
            rpt("report-a", "hospital-east", "p-71", lot="lot-8", event="肝功能异常"),
            received_at=T0,
        )
        self.app.ingestion.ingest(
            rpt("report-b", "hospital-west", "p-71", lot=None, event="肝功能异常随访"),
            received_at=T0.replace(minute=1),
        )
        (cluster,) = self.app.linkage.detect_clusters()
        self.assertEqual(self.app.signals.detect_signals(now=T0.replace(day=13)), [])

        # 人工判定保持独立（确为两例病程）：分别计数，信号成立
        self.app.linkage.decide(
            self.specialist, cluster.cluster_id, ClusterDecision.KEEP_INDEPENDENT,
            rationale="实为两例独立病程", decided_at=T0.replace(day=11),
        )
        signals = self.app.signals.detect_signals(now=T0.replace(day=13))
        self.assertEqual(len(signals), 1)
        self.assertEqual(set(signals[0].case_ids), {"case-a", "case-b"})

    def test_investigation_idempotent_and_single_per_signal(self):
        self._reach_threshold()
        (signal,) = self.app.signals.detect_signals(now=T0.replace(day=13))
        i1 = self.app.signals.start_investigation(
            self.specialist, signal.signal_id, idempotency_key="req-1", now=T0.replace(day=13)
        )
        i2 = self.app.signals.start_investigation(
            self.specialist, signal.signal_id, idempotency_key="req-1", now=T0.replace(day=13)
        )
        self.assertEqual(i1.investigation_id, i2.investigation_id)
        with self.assertRaises(DuplicateInvestigationError):
            self.app.signals.start_investigation(
                self.specialist, signal.signal_id, idempotency_key="req-2"
            )
        # 无幂等键同样不得二次启动
        with self.assertRaises(DuplicateInvestigationError):
            self.app.signals.start_investigation(self.specialist, signal.signal_id)

    def test_state_machine_flow_and_timeline(self):
        self._reach_threshold()
        (signal,) = self.app.signals.detect_signals(now=T0.replace(day=13))
        self.app.signals.start_investigation(self.specialist, signal.signal_id, now=T0.replace(day=13))
        self.assertEqual(self.app.signals.advance(self.specialist, signal.signal_id), SignalState.FOLLOW_UP)
        self.assertEqual(self.app.signals.advance(self.specialist, signal.signal_id), SignalState.QUALITY_REVIEW)
        self.assertEqual(self.app.signals.advance(self.specialist, signal.signal_id), SignalState.CLOSED)
        with self.assertRaises(InvalidTransitionError):
            self.app.signals.advance(self.specialist, signal.signal_id)
        detail = self.app.reports.signal_detail(signal.signal_id)
        # 启动 + 3 次流转
        self.assertEqual(len(detail["timeline"]), 4)
        actors = {e["actor"] for e in detail["timeline"]}
        self.assertIn("pv-zhang", actors)

    def test_cannot_advance_without_investigation(self):
        self._reach_threshold()
        (signal,) = self.app.signals.detect_signals(now=T0.replace(day=13))
        with self.assertRaises(InvalidTransitionError):
            self.app.signals.advance(self.specialist, signal.signal_id)

    def test_signal_traces_back_to_every_raw_report(self):
        self._reach_threshold()
        (signal,) = self.app.signals.detect_signals(now=T0.replace(day=13))
        self.app.signals.start_investigation(self.specialist, signal.signal_id)
        refs = {r["report_id"] for r in self.app.reports.signal_detail(signal.signal_id)["raw_report_refs"]}
        self.assertIn("report-b", refs)  # 被合并的转院报告仍可回溯
        for rid in refs:
            self.assertEqual(self.app.reports.raw_report(rid)["report_id"], rid)

    # ---- RBAC ----------------------------------------------------------

    def test_only_authorized_role_sees_identifiable_info(self):
        self.ingest_fixture()
        with self.assertRaises(AccessDeniedError):
            self.app.reports.identifiable_key(self.specialist, "report-a")
        with self.assertRaises(AccessDeniedError):
            self.app.reports.identifiable_key(self.auditor, "report-a")
        view = self.app.reports.identifiable_key(self.physician, "report-a")
        self.assertEqual(view["raw_privacy_key"], "p-71")
        log = self.app.reports.access_log()
        self.assertEqual([e["granted"] for e in log], [False, False, True])

    def test_specialist_cannot_confirm_without_permission_role_check(self):
        # auditor 无任何处置权限
        self.ingest_fixture()
        (cluster,) = self.app.linkage.detect_clusters()
        with self.assertRaises(AccessDeniedError):
            self.app.linkage.decide(
                self.auditor, cluster.cluster_id, ClusterDecision.MERGED, rationale="x"
            )

    def test_permission_matrix(self):
        self.assertTrue(self.physician.can(Permission.VIEW_IDENTIFIABLE))
        self.assertFalse(self.specialist.can(Permission.VIEW_IDENTIFIABLE))
        self.assertTrue(self.specialist.can(Permission.MANAGE_INVESTIGATION))
        self.assertFalse(self.auditor.can(Permission.MANAGE_INVESTIGATION))

    def test_raw_report_identity_requires_principal(self):
        self.ingest_fixture()
        # 默认脱敏
        self.assertNotIn("privacyKey", self.app.reports.raw_report("report-a")["payload"])
        # 要求可识别字段却不给主体 → 拒绝，而非静默泄出
        with self.assertRaises(AccessDeniedError):
            self.app.reports.raw_report("report-a", include_identity=True)
        # 无权限角色 → 拒绝
        with self.assertRaises(AccessDeniedError):
            self.app.reports.raw_report("report-a", include_identity=True, principal=self.specialist)
        # 授权角色可取到原始伪标识
        view = self.app.reports.raw_report("report-a", include_identity=True, principal=self.physician)
        self.assertEqual(view["payload"]["privacyKey"], "p-71")


if __name__ == "__main__":
    unittest.main()
