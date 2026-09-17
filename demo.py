"""端到端演示：从脱敏报告到可解释病例簇、产品趋势与调查时间线。

运行：python -m demo  （在仓库根目录）
"""

from __future__ import annotations

import json
from datetime import datetime

from safety.access import Principal
from safety.app import SafetyApp
from safety.config import SignalCriteria
from safety.contracts import ClusterDecision
from safety.errors import (
    AccessDeniedError,
    DuplicateInvestigationError,
    InvalidTransitionError,
)

FIXTURE = "fixtures/adverse_reports.json"


def banner(title: str) -> None:
    print("\n" + "=" * 72)
    print(title)
    print("=" * 72)


def show(obj) -> None:
    print(json.dumps(obj, ensure_ascii=False, indent=2, default=str))


def main() -> None:
    app = SafetyApp(criteria=SignalCriteria(min_distinct_cases=2, window_days=30))
    specialist = Principal("pv-zhang", ("pv-specialist",), display_name="张专员")
    physician = Principal("dr-li", ("pv-physician",), display_name="李医师")
    auditor = Principal("auditor-wang", ("auditor",), display_name="王审计")

    # 1) 接收报告：原始快照冻结，每份先独立建案 -------------------------
    app.load(FIXTURE)
    # 在夹具之外追加同产品身份（同名、厂家/批准信息同样缺失）的其他患者
    # 报告，用于验证：不同患者不会被并成重复组，但会计入同一信号口径。
    app.ingestion.ingest(
        {
            "id": "report-d",
            "institution": "hospital-north",
            "privacyKey": "p-33",
            "product": "中成药甲",
            "lot": "lot-8",
            "ingredientLots": ["ing-huangqin-22", "ing-gancao-17"],
            "event": "肝功能异常 住院",
        },
        received_at=datetime(2026, 9, 11, 9, 0),
    )
    app.ingestion.ingest(
        {
            "id": "report-e",
            "institution": "community-south",
            "privacyKey": "p-44",
            "product": "中成药甲",
            "lot": "lot-8",
            "ingredientLots": ["ing-huangqin-22"],
            "event": "肝功能异常",
        },
        received_at=datetime(2026, 9, 12, 9, 0),
    )
    banner("1. 原始报告（脱敏，privacyKey 不出现在业务侧）")
    for rid in ("report-a", "report-b", "report-c"):
        show(app.reports.raw_report(rid))

    # 2) 疑似重复组 -----------------------------------------------------
    clusters = app.linkage.detect_clusters()
    banner("2. 系统生成的可能重复组（仅线索，待人工判定）")
    show(
        [
            {
                "cluster_id": c.cluster_id,
                "members": list(c.member_report_ids),
                "reasons": list(c.reasons),
                "decision": c.decision.value,
            }
            for c in clusters
        ]
    )

    cluster_id = clusters[0].cluster_id

    # 3) 人工确认 a/b 为同一患者转院重复，合并；保留 report-a 为首报 ----
    decision = app.linkage.decide(
        specialist,
        cluster_id,
        ClusterDecision.MERGED,
        rationale="同一隐私匹配标识、事件连续（肝功能异常→随访异常）、东西两院转院时间衔接，判为同一病例，a 为首报。",
        decided_at=datetime(2026, 9, 11, 10, 0),
    )
    banner("3. 人工判定：合并 a/b（report-b 转为随访版本，首报 report-a 保留）")
    show(
        {
            "decision": decision.decision.value,
            "decided_by": decision.decided_by,
            "primary_report_id": decision.primary_report_id,
            "rationale": decision.rationale,
        }
    )
    show(app.reports.case_cluster("case-a"))

    # 4) 严重性重新判定（记录规则与复核人） -----------------------------
    app.seriousness.reassess(
        specialist, "case-a",
        rationale="首报与随访均为肝功能异常，未见肝衰竭/住院，按 hepato-v1 判非严重，持续观察。",
        assessed_at=datetime(2026, 9, 11, 10, 30),
    )
    # 模拟病情进展的补充随访：追加版本而非改写
    app.ingestion.add_follow_up(
        "case-a",
        report_id="report-a-fu2",
        institution_id="hospital-west",
        event="急性肝衰竭 住院",
        recorded_at=datetime(2026, 9, 14, 8, 0),
        raw_privacy_key="p-71",
        note="病情进展随访",
    )
    progressed = app.seriousness.reassess(
        physician, "case-a",
        rationale="随访进展为急性肝衰竭并住院，按 SR-HEP-001 上调为严重。",
        assessed_at=datetime(2026, 9, 14, 9, 0),
    )
    banner("4. 严重性重新判定（规则版本 + 命中术语 + 复核人全程留痕）")
    show(
        {
            "rule_id": progressed.rule_id,
            "rule_version": progressed.rule_version,
            "matched_terms": list(progressed.matched_terms),
            "previous": progressed.previous_level.value,
            "current": progressed.current_level.value,
            "reviewer": progressed.reviewer,
            "rationale": progressed.rationale,
        }
    )
    show(
        {
            "case_cluster": app.reports.case_cluster("case-a")["case_id"],
            "version_count": len(app.reports.case_cluster("case-a")["versions"]),
            "first_report_preserved": app.reports.case_cluster("case-a")["first_report_preserved"],
        }
    )

    # 5) 产品趋势：同名药厂家不同，分开聚合；批号未知如实保留 -----------
    banner("5. 产品趋势（中成药甲：未知厂家 vs maker-b 分开；lot 未知不猜测）")
    show(app.reports.product_trends())

    # 6) 信号检测 -------------------------------------------------------
    signals = app.signals.detect_signals(now=datetime(2026, 9, 14, 12, 0))
    banner("6. 达到配置条件的信号（按产品身份分别触发）")
    show([{"signal_id": s.signal_id, "cases": list(s.case_ids), "state": s.state.value} for s in signals])

    # 7) 调查流程 + 幂等启动 -------------------------------------------
    target = next(s for s in signals if "maker-b" not in s.product_identity)
    inv1 = app.signals.start_investigation(
        specialist, target.signal_id,
        idempotency_key="request-001", now=datetime(2026, 9, 14, 13, 0),
    )
    # 重复请求：相同幂等键返回同一调查，不启动第二次
    inv2 = app.signals.start_investigation(
        specialist, target.signal_id,
        idempotency_key="request-001", now=datetime(2026, 9, 14, 13, 5),
    )
    idempotent = inv1.investigation_id == inv2.investigation_id
    # 即使换幂等键，同一信号也不得二次启动
    blocked = False
    try:
        app.signals.start_investigation(
            specialist, target.signal_id, idempotency_key="request-002",
            now=datetime(2026, 9, 14, 13, 10),
        )
    except DuplicateInvestigationError:
        blocked = True

    app.signals.advance(specialist, target.signal_id, note="完成病例与暴露核对", now=datetime(2026, 9, 15, 9, 0))
    app.signals.advance(specialist, target.signal_id, note="向 hospital-west 追查 report-b 缺失批号", now=datetime(2026, 9, 18, 9, 0))
    app.signals.advance(physician, target.signal_id, note="原料批次抽样检验中，未知批号继续挂账；处置完成关闭", now=datetime(2026, 9, 25, 9, 0))
    closed_again = False
    try:
        app.signals.advance(specialist, target.signal_id)
    except InvalidTransitionError:
        closed_again = True

    banner("7. 调查幂等性与完整时间线")
    show(
        {
            "idempotent_same_key": idempotent,
            "second_start_blocked": blocked,
            "cannot_advance_after_close": closed_again,
            "detail": app.reports.signal_detail(target.signal_id),
        }
    )

    # 8) 从信号回溯每份原始报告 ----------------------------------------
    banner("8. 从信号回溯每份原始报告（含转院与进展随访）")
    refs = app.reports.signal_detail(target.signal_id)["raw_report_refs"]
    show(refs)
    show(app.reports.raw_report("report-b"))

    # 9) 权限：仅授权角色可查看可识别信息 ------------------------------
    banner("9. 访问控制：可识别信息仅授权角色可见，访问留痕")
    denied = False
    try:
        app.reports.identifiable_key(specialist, "report-a")
    except AccessDeniedError:
        denied = True
    physician_view = app.reports.identifiable_key(physician, "report-a")
    show(
        {
            "specialist_denied": denied,
            "physician_view": physician_view,
            "auditor_denied": _auditor_check(app, auditor),
            "access_log": list(app.reports.access_log()),
        }
    )


def _auditor_check(app: SafetyApp, auditor: Principal) -> bool:
    try:
        app.reports.identifiable_key(auditor, "report-a")
    except AccessDeniedError:
        return True
    return False


if __name__ == "__main__":
    main()
