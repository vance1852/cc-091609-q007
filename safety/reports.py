"""可解释输出：病例簇、产品趋势、调查时间线、信号→原始报告回溯。

默认输出全部为脱敏数据。可识别信息（机构提交的原始伪标识）只有
获得 view-identifiable 权限的角色才能在显式调用受控接口时获取，
且每次访问都会留痕。
"""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime

from safety.access import Permission, authorize
from safety.access import Principal
from safety.contracts import ClusterDecision
from safety.errors import AccessDeniedError, UnknownReportError
from safety.repository import Repository, product_identity_of


def _iso(value) -> str | None:
    return value.isoformat() if value else None


class ReportService:
    def __init__(self, repo: Repository) -> None:
        self.repo = repo
        self._access_log: list[dict] = []

    # ---- 身份访问审计 -------------------------------------------------

    def identifiable_key(self, principal: Principal, report_id: str) -> dict:
        """受控读取原始匹配标识；无权限直接拒绝并记录尝试。"""

        allowed = principal.can(Permission.VIEW_IDENTIFIABLE)
        self._access_log.append(
            {
                "at": datetime.now().isoformat(),
                "user": principal.user_id,
                "report_id": report_id,
                "granted": allowed,
            }
        )
        authorize(principal, Permission.VIEW_IDENTIFIABLE)
        record = self.repo.get_identity(report_id)
        return {
            "report_id": report_id,
            "raw_privacy_key": record.raw_privacy_key if record else None,
        }

    def access_log(self) -> tuple[dict, ...]:
        return tuple(self._access_log)

    # ---- 病例簇 -------------------------------------------------------

    def case_cluster(self, case_id: str) -> dict:
        """以一个有效病例为中心的可解释病例簇。

        含全部历史版本（首报 + 随访 + 合并转入）、原始报告引用、
        所属重复组及人工判定结论、严重性判定轨迹。
        """

        primary = self.repo.effective_case(case_id)
        versions = [
            {
                "version": v.version,
                "report_id": v.report_id,
                "institution": v.institution_id,
                "privacy_match_key": v.privacy_match_key,  # 派生伪标识，非可识别信息
                "event_terms": list(v.event_terms),
                "recorded_at": _iso(v.recorded_at),
                "follows_version": v.follows_version,
                "note": v.note,
            }
            for v in self.repo.versions_of(primary)
        ]
        report_ids = [v["report_id"] for v in versions]

        clusters = []
        for cluster in self.repo.list_clusters():
            if any(rid in report_ids for rid in cluster.member_report_ids):
                clusters.append(
                    {
                        "cluster_id": cluster.cluster_id,
                        "members": list(cluster.member_report_ids),
                        "reasons": list(cluster.reasons),
                        "decision": cluster.decision.value,
                        "decided_by": cluster.decided_by,
                        "decided_at": _iso(cluster.decided_at),
                        "rationale": cluster.rationale,
                        "primary_report_id": cluster.primary_report_id,
                    }
                )

        return {
            "case_id": primary,
            "merged_from": sorted(
                {alias for alias, target in self.repo.case_alias.items() if target == primary}
            ),
            "first_report_preserved": versions[0]["version"] == 1 and versions[0]["note"] == "首报",
            "versions": versions,
            "report_ids": report_ids,
            "duplicate_clusters": clusters,
            "seriousness_assessments": [
                asdict(a) for a in self.repo.assessments_of(primary)
            ],
        }

    # ---- 产品趋势 -----------------------------------------------------

    def product_trends(self) -> list[dict]:
        """按产品身份聚合的趋势。同名药厂家/批准不同则分开展示。"""

        trends: dict[str, dict] = {}
        for exposure in self.repo.exposures.values():
            identity = product_identity_of(exposure)
            case_id = self.repo.effective_case(exposure.case_id)
            bucket = trends.setdefault(
                identity.key,
                {
                    "product_identity": identity.key,
                    "product_name": identity.product_name,
                    "manufacturer": identity.manufacturer_id,
                    "approval_code": identity.approval_code,
                    "distinct_cases": set(),
                    "product_lots": set(),
                    "ingredient_lots": set(),
                    "unknown_lot_reports": [],
                    "reports": [],
                },
            )
            bucket["distinct_cases"].add(case_id)
            bucket["reports"].append(exposure.report_id)
            if exposure.product_lot:
                bucket["product_lots"].add(exposure.product_lot)
            else:
                bucket["unknown_lot_reports"].append(exposure.report_id)
            bucket["ingredient_lots"].update(exposure.ingredient_lots)

        result = []
        for key in sorted(trends):
            b = trends[key]
            signals = [
                s.signal_id for s in self.repo.list_signals() if s.product_identity == key
            ]
            result.append(
                {
                    "product_identity": b["product_identity"],
                    "product_name": b["product_name"],
                    "manufacturer": b["manufacturer"],
                    "approval_code": b["approval_code"],
                    "distinct_case_count": len(b["distinct_cases"]),
                    "distinct_cases": sorted(b["distinct_cases"]),
                    "known_product_lots": sorted(b["product_lots"]),
                    "ingredient_lots": sorted(b["ingredient_lots"]),
                    # 批号取不到时如实保留未知，不猜测、不与已知批号混算。
                    "unknown_lot_reports": b["unknown_lot_reports"],
                    "lot_status": (
                        "部分未知" if b["unknown_lot_reports"] else "全部已知"
                    ),
                    "signals": signals,
                }
            )
        return result

    # ---- 信号 → 原始报告 ----------------------------------------------

    def signal_detail(self, signal_id: str) -> dict:
        signal = self.repo.get_signal(signal_id)
        cases = list(signal.case_ids)
        raw_refs = []
        for case_id in cases:
            for version in self.repo.versions_of(case_id):
                raw_refs.append(
                    {
                        "case_id": case_id,
                        "report_id": version.report_id,
                        "version": version.version,
                        "institution": version.institution_id,
                    }
                )
        # 标注仍待人工核查的疑似组：信号计数时这些病例被保守折算，
        # 结论明确（合并/独立）后口径才最终确定。
        case_set = set(cases)
        pending_clusters = []
        for cluster in self.repo.list_clusters():
            member_cases = {self.repo.case_of_report(rid) for rid in cluster.member_report_ids}
            if member_cases & case_set and cluster.decision == ClusterDecision.PENDING:
                pending_clusters.append(
                    {
                        "cluster_id": cluster.cluster_id,
                        "members": list(cluster.member_report_ids),
                        "counting_note": "待人工判定，信号计数时组内暂折为 1 例",
                    }
                )
        investigation = self.repo.investigation_of_signal(signal_id)
        return {
            "signal_id": signal.signal_id,
            "product_identity": signal.product_identity,
            "rule_version": signal.rule_version,
            "state": signal.state.value,
            "started_at": _iso(signal.started_at),
            "case_ids": cases,
            "raw_report_refs": raw_refs,
            "pending_duplicate_clusters": pending_clusters,
            "timeline": (
                [
                    {
                        "event_id": e.event_id,
                        "at": _iso(e.at),
                        "actor": e.actor,
                        "kind": e.kind,
                        "summary": e.summary,
                        "detail": e.detail,
                    }
                    for e in investigation.events
                ]
                if investigation
                else []
            ),
        }

    def raw_report(
        self,
        report_id: str,
        *,
        include_identity: bool = False,
        principal: Principal | None = None,
    ) -> dict:
        """取原始报告快照。默认脱敏；include_identity 必须提供授权主体。"""

        raw = self.repo.raw_reports.get(report_id)
        if raw is None:
            raise UnknownReportError(f"原始报告不存在: {report_id}")
        payload = dict(raw.payload)
        if include_identity:
            if principal is None:
                # 不允许在无主体、无授权的情况下带出可识别字段。
                raise AccessDeniedError("读取含可识别信息的原始报告必须指定授权主体")
            self.identifiable_key(principal, report_id)  # 校验并留痕
        else:
            payload.pop("privacyKey", None)
        return {
            "report_id": raw.report_id,
            "institution": raw.institution_id,
            "received_at": _iso(raw.received_at),
            "payload": payload,
        }
