"""关键业务不变量测试（仅标准库）：python3 -m unittest discover -s tests -v"""

import tempfile
import unittest
from datetime import date
from pathlib import Path

from safety.aggregation import AggregationService, ProductIdentity
from safety.config import MatchingWeights, PrivacyConfig, PvConfig, SignalThreshold
from safety.contracts import SignalState
from safety.matching import MatchingService
from safety.privacy import AccessContext, AccessDeniedError, UNKNOWN_TOKEN
from safety.severity import SeverityService
from safety.store import ReportStore
from safety.workflow import SignalWorkflow, WorkflowError

PRIV = PrivacyConfig(match_key_salt="unit-test-salt")
FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "adverse_reports.json"

PV = AccessContext("pv-1", "case-investigator")
ANALYST = AccessContext("an-1", "analyst")


def build(ledger: Path | None = None, threshold: int = 3):
    store = ReportStore(PRIV, ledger_path=ledger)
    store.load_fixture(FIXTURE)
    matching = MatchingService(store, MatchingWeights())
    agg = AggregationService(store, matching)
    cfg = PvConfig(privacy=PRIV, threshold=SignalThreshold(min_distinct_cases=threshold))
    wf = SignalWorkflow(store, agg, cfg)
    return store, matching, agg, cfg, wf


class TestStore(unittest.TestCase):
    def test_duplicate_report_rejected(self):
        store, *_ = build()
        with self.assertRaises(ValueError):
            store.ingest(store.reports[0].payload)

    def test_followup_does_not_overwrite_first(self):
        store, *_ = build()
        case5 = store.get_case("case-0005")
        self.assertEqual(len(case5.versions), 2)
        self.assertEqual(case5.versions[0].version, 1)
        self.assertEqual(case5.versions[1].follows_version, 1)
        # 首报事件术语不被随访覆盖
        self.assertEqual(store.first_report_of_case("case-0005").event, "黄疸")
        self.assertEqual(case5.versions[0].event_terms, ("黄疸",))
        self.assertEqual(case5.versions[1].event_terms, ("急性肝损伤随访",))

    def test_unknown_lot_preserved(self):
        store, *_ = build()
        self.assertIsNone(store.get_report("report-b").product_lot)
        self.assertEqual(store.lot_view("case-0002"), UNKNOWN_TOKEN)

    def test_ledger_replay_and_tamper_detection(self):
        with tempfile.TemporaryDirectory() as tmp:
            ledger = Path(tmp) / "l.jsonl"
            build(ledger=ledger)
            store2 = ReportStore(PRIV, ledger_path=ledger)
            self.assertEqual(len(store2.reports), 6)
            # 篡改台账 -> 哈希链断裂
            lines = ledger.read_text(encoding="utf-8").splitlines()
            import json

            entry = json.loads(lines[0])
            entry["payload"]["event"] = "被篡改"
            lines[0] = json.dumps(entry, ensure_ascii=False, sort_keys=True)
            ledger.write_text("\n".join(lines), encoding="utf-8")
            with self.assertRaises(RuntimeError):
                ReportStore(PRIV, ledger_path=ledger)


class TestMatching(unittest.TestCase):
    def test_transfer_duplicate_detected(self):
        store, matching, *_ = build()
        cands = matching.find_candidates()
        self.assertEqual(len(cands), 1)
        self.assertEqual(set(cands[0].case_ids), {"case-0001", "case-0002"})
        self.assertGreaterEqual(cands[0].min_score(), 0.5)

    def test_no_automatic_merge(self):
        store, matching, agg, *_ = build()
        # 未确认前：两个病例分别计数（共 4 个未知厂家病例中的 a/b/d/e）
        unknown = [t for t in agg.product_trends() if t.identity.manufacturer_id is None][0]
        self.assertEqual(unknown.distinct_cases, 4)

    def test_manual_merge_then_counts_once_but_reports_remain(self):
        store, matching, agg, *_ = build()
        cand = matching.find_candidates()[0]
        matching.decide(cand.candidate_id, "merged", "pv-1", "2026-09-10T09:00:00", "case-0001")
        unknown = [t for t in agg.product_trends() if t.identity.manufacturer_id is None][0]
        self.assertEqual(unknown.distinct_cases, 3)
        # 病程进展不丢：两份原始报告仍可追溯
        self.assertIn("report-a", unknown.report_ids)
        self.assertIn("report-b", unknown.report_ids)

    def test_keep_separate_preserved(self):
        store, matching, agg, *_ = build()
        cand = matching.find_candidates()[0]
        matching.decide(cand.candidate_id, "kept-separate", "pv-1", "2026-09-10T09:00:00")
        unknown = [t for t in agg.product_trends() if t.identity.manufacturer_id is None][0]
        self.assertEqual(unknown.distinct_cases, 4)
        # 已决定的组不可重复决定
        with self.assertRaises(ValueError):
            matching.decide(cand.candidate_id, "merged", "pv-1", "2026-09-11T09:00:00", "case-0001")


class TestAggregation(unittest.TestCase):
    def test_same_name_different_manufacturer_split(self):
        _, _, agg, *_ = build()
        identities = {t.identity.key() for t in agg.product_trends()}
        self.assertIn(ProductIdentity("中成药甲", None, None).key(), identities)
        self.assertIn(ProductIdentity("中成药甲", "maker-b", None).key(), identities)
        self.assertEqual(len(identities), 2)


class TestSeverity(unittest.TestCase):
    def test_reassess_records_rule_and_reviewer(self):
        store, *_ = build()
        svc = SeverityService(store)
        a = svc.reassess("case-0005", assessed_by="reviewer-q")
        self.assertEqual(a.severity, "严重")
        self.assertTrue(all(r.startswith(("S-EV01", "S-EV02")) for r in a.applied_rules))
        self.assertEqual(a.assessed_by, "reviewer-q")
        # 重复复核保留历史
        svc.reassess("case-0005", assessed_by="reviewer-r")
        self.assertEqual(len(svc.history("case-0005")), 2)


class TestWorkflow(unittest.TestCase):
    def test_threshold_gate(self):
        *_, wf = build(threshold=5)
        self.assertEqual(wf.evaluate(PV), [])

    def test_idempotent_start(self):
        _, _, agg, cfg, wf = build()
        key = ProductIdentity("中成药甲", None, None).key()
        first = wf.request_investigation(key, PV)
        second = wf.request_investigation(key, PV)
        self.assertIs(first, second)
        self.assertEqual(len(wf.investigations), 1)
        wf.evaluate(PV)
        self.assertEqual(len(wf.investigations), 1)

    def test_state_machine_and_lot_requirement(self):
        _, _, _, _, wf = build()
        inv = wf.evaluate(PV)[0]
        sid = inv.signal.signal_id
        wf.advance(sid, PV, "验证完成")
        # 进入质量调查必须指定批号
        with self.assertRaises(WorkflowError):
            wf.advance(sid, PV, "补充完成")
        wf.advance(sid, PV, "补充完成", product_lots=("lot-8",), ingredient_lots=("raw-angelica-5",))
        self.assertEqual(inv.signal.state, SignalState.QUALITY_REVIEW)
        # 关闭必须给理由
        with self.assertRaises(WorkflowError):
            wf.advance(sid, PV, "关闭")
        wf.advance(sid, PV, "关闭", closure_reason="处置完成")
        self.assertEqual(inv.signal.state, SignalState.CLOSED)
        with self.assertRaises(WorkflowError):
            wf.advance(sid, PV, "再次操作")

    def test_trace_includes_merged_duplicate_reports(self):
        _, matching, _, _, wf = build()
        cand = matching.find_candidates()[0]
        matching.decide(cand.candidate_id, "merged", "pv-1", "2026-09-10T09:00:00", "case-0001")
        inv = wf.evaluate(PV)[0]
        report_ids = {r["report_id"] for r in wf.trace_reports(inv.signal.signal_id, PV)}
        self.assertIn("report-b", report_ids)

    def test_rbac(self):
        *_, wf = build()
        sid = wf.evaluate(PV)[0].signal.signal_id
        with self.assertRaises(AccessDeniedError):
            wf.export_identifiable_detail(sid, ANALYST)
        redacted = wf.trace_reports(sid, ANALYST)
        self.assertTrue(all(r["institution"] == "***未授权***" for r in redacted))
        # 授权角色可看
        detail = wf.export_identifiable_detail(sid, PV)
        self.assertIn("case-0001", detail)


if __name__ == "__main__":
    unittest.main()
