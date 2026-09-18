"""端到端样例：从原始报告到可解释的病例簇、产品趋势与调查时间线。

运行：``python -m safety.demo``（工作区根目录）
"""

import json
import tempfile
from pathlib import Path

from .aggregation import AggregationService
from .config import MatchingWeights, PrivacyConfig, PvConfig
from .matching import MatchingService
from .privacy import AccessContext
from .severity import SeverityService
from .store import ReportStore
from .workflow import SignalWorkflow

FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "adverse_reports.json"

PV_OFFICER = AccessContext("pv-zhang", "case-investigator")
QA_STAFF = AccessContext("qa-li", "quality-investigator")
ANALYST = AccessContext("analyst-wang", "analyst")
REVIEWER = AccessContext("pv-zhang", "case-investigator")


def banner(title: str) -> None:
    print(f"\n{'=' * 72}\n{title}\n{'=' * 72}")


def main() -> None:
    config = PvConfig(privacy=PrivacyConfig(match_key_salt="demo-salt-change-in-prod"))

    with tempfile.TemporaryDirectory() as tmp:
        ledger = Path(tmp) / "ledger.jsonl"
        store = ReportStore(config.privacy, ledger_path=ledger)
        reports = store.load_fixture(FIXTURE)

        # 1) 原始报告保存（只追加、哈希链）
        banner("1. 原始报告台账（不可变；随访不覆盖首报）")
        for r in reports:
            print(
                f"#{r.ledger_seq} {r.report_id} | {r.institution_id} | "
                f"{r.event} | 批号={r.product_lot or '未知'} | hash={r.source_hash[:12]}…"
            )

        # 2) 疑似重复组（只给线索，人工确认）
        matching = MatchingService(store, config.matching)
        candidates = matching.find_candidates()
        banner("2. 疑似重复病例组（系统建议，等待人工确认）")
        for cand in candidates:
            print(f"[{cand.candidate_id}] 病例 {list(cand.case_ids)}")
            for p in cand.pair_evidence:
                print(f"   {p.case_a}↔{p.case_b} 评分={p.score} 依据：{'、'.join(p.reasons)}")

        # 人工确认：a 与 b 为同一患者转院重报，合并；其余保持独立
        for cand in candidates:
            if set(cand.case_ids) == {"case-0001", "case-0002"}:
                matching.decide(
                    cand.candidate_id,
                    action="merged",
                    decided_by="pv-zhang",
                    decided_at="2026-09-10T09:00:00",
                    merged_into="case-0001",
                    note="同一隐私标识、同事件族、转院跨机构，判定为重复上报，保留两版本病程",
                )

        # 3) 严重性重新判定（规则 + 复核人）
        severity = SeverityService(store)
        banner("3. 严重性重新判定（记录规则与复核人）")
        for case in store.cases:
            a = severity.reassess(case.case_id, assessed_by="pv-zhang")
            print(f"{case.case_id}: {a.severity} | 规则：{'；'.join(a.applied_rules)} | 复核人：{a.assessed_by}")

        # 4) 产品趋势
        aggregation = AggregationService(store, matching)
        trends = aggregation.product_trends()
        banner("4. 产品趋势（同名药按厂家/批准信息分开；批号未知保留）")
        for t in trends:
            print(json.dumps(t.describe(), ensure_ascii=False, indent=2))

        # 5) 信号启动（阈值）+ 幂等
        workflow = SignalWorkflow(store, aggregation, config)
        started = workflow.evaluate(PV_OFFICER)
        again = workflow.evaluate(PV_OFFICER)
        banner("5. 信号触发与幂等启动")
        print(f"首次评估启动 {len(started)} 个信号；重复评估启动 {len(again) - len(started)} 个（应为 0）")
        for inv in workflow.investigations:
            print(
                f"{inv.signal.signal_id} | {inv.signal.product_identity} | "
                f"病例={list(inv.signal.case_ids)} | 状态={inv.signal.state}"
            )

        # 6) 调查流程：验证 -> 病例补充 -> 质量调查（绑定批次）-> 关闭
        sig = started[0].signal.signal_id
        banner("6. 调查流程推进")
        workflow.advance(sig, PV_OFFICER, "完成因果关系评估：时间合理、肝损伤事件族一致")
        workflow.note(sig, PV_OFFICER, "向 hospital-west 补充实验室随访数据（不改动首报）")
        workflow.advance(
            sig,
            PV_OFFICER,
            "病例材料补充完毕，移交质量调查；锁定涉事成品批与共有原料批",
            product_lots=("lot-8",),
            ingredient_lots=("raw-angelica-5", "raw-licorice-9"),
        )
        workflow.note(sig, QA_STAFF, "原料 raw-licorice-9 黄曲霉毒素检测异常，启动供应商调查")
        workflow.note(
            sig,
            QA_STAFF,
            "成品批 lot-8 与原料批 raw-licorice-9 关联确认，已采取封存与召回控制措施",
        )
        workflow.advance(sig, QA_STAFF, "风险已控制，监测期内无新发病例", closure_reason="批次质量问题确认并完成处置")

        inv = workflow.get(sig)
        print(f"信号 {sig} 最终状态：{inv.signal.state}")
        print("质量调查对象：", json.dumps(inv.quality_targets, ensure_ascii=False))

        # 7) 调查时间线
        banner("7. 调查时间线（可解释）")
        for e in inv.timeline:
            lots = f" | 产品批={list(e.product_lots)} 原料批={list(e.ingredient_lots)}" if e.product_lots else ""
            print(f"[{e.at}] {e.stage} | {e.actor} | {e.action} | {e.detail}{lots}")

        # 8) 从信号返回每份原始报告 + RBAC
        banner("8. 从信号溯源每份原始报告（角色差异化）")
        print("-- 授权药物警戒专员视图 --")
        for item in workflow.trace_reports(sig, PV_OFFICER):
            print(f"{item['case_id']} <- {item['report_id']} | {item['institution']} | hash={item['source_hash'][:12]}…")
        print("-- 分析角色视图（可识别信息脱敏）--")
        redacted = workflow.trace_reports(sig, ANALYST)[0]
        print(json.dumps(redacted, ensure_ascii=False))
        print("-- 分析角色尝试导出可识别对照 --")
        try:
            workflow.export_identifiable_detail(sig, ANALYST)
        except PermissionError as exc:
            print(f"已拒绝：{exc}")
        print("-- 授权角色导出可识别对照 --")
        print(json.dumps(workflow.export_identifiable_detail(sig, REVIEWER), ensure_ascii=False, indent=2))

        # 9) 台账续建校验
        banner("9. 台账哈希链与重启校验")
        store2 = ReportStore(config.privacy, ledger_path=ledger)
        print(f"从台账重建 {len(store2.reports)} 份报告、{len(store2.cases)} 个病例（哈希链校验通过）")
        print("首报保持不变：", store2.first_report_of_case("case-0001").event)


if __name__ == "__main__":
    main()
