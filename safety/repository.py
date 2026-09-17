"""内存存储层：原始报告不可变、身份分区隔离、版本只追加。

生产环境可把本模块的 Repository 替换为数据库实现，接口约定：
- 原始报告一经接收即冻结，任何随访只追加，不改写；
- 可识别信息（原始匹配标识）单独分区，查询层默认不可见；
- 病例合并通过别名与版本追加实现，首报版本永远保留。
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from threading import Lock

from safety.contracts import (
    CaseVersion,
    DuplicateCluster,
    Investigation,
    ProductExposure,
    ProductIdentity,
    SafetySignal,
    SeriousnessAssessment,
    TimelineEvent,
)

UNKNOWN = "未知"


@dataclass(frozen=True)
class RawReport:
    """接收到的原始报告快照（不可变）。"""

    report_id: str
    institution_id: str
    payload: dict
    received_at: datetime
    payload_version: int = 1


@dataclass(frozen=True)
class IdentityRecord:
    """身份分区：仅保存提交方给的原始伪标识，与业务数据分开存放。"""

    report_id: str
    raw_privacy_key: str | None


class Repository:
    def __init__(self) -> None:
        self._lock = Lock()
        self.raw_reports: dict[str, RawReport] = {}
        self.identity: dict[str, IdentityRecord] = {}
        self.report_case: dict[str, str] = {}
        self.versions: dict[str, list[CaseVersion]] = {}
        self.exposures: dict[str, ProductExposure] = {}
        self.case_alias: dict[str, str] = {}
        self.clusters: dict[str, DuplicateCluster] = {}
        self.assessments: dict[str, list[SeriousnessAssessment]] = {}
        self.signals: dict[str, SafetySignal] = {}
        self.investigations: dict[str, Investigation] = {}
        self._idem: dict[str, str] = {}

    # ---- 原始报告 -----------------------------------------------------

    def add_raw_report(self, report: RawReport) -> None:
        with self._lock:
            if report.report_id in self.raw_reports:
                raise ValueError(f"原始报告已存在: {report.report_id}")
            self.raw_reports[report.report_id] = report

    def get_raw_report(self, report_id: str) -> RawReport:
        return self.raw_reports[report_id]

    def list_raw_reports(self) -> list[RawReport]:
        return [self.raw_reports[k] for k in sorted(self.raw_reports)]

    # ---- 身份分区 -----------------------------------------------------

    def put_identity(self, record: IdentityRecord) -> None:
        self.identity[record.report_id] = record

    def get_identity(self, report_id: str) -> IdentityRecord | None:
        return self.identity.get(report_id)

    # ---- 病例与版本 ---------------------------------------------------

    def register_case(self, case_id: str, version: CaseVersion) -> None:
        with self._lock:
            self.versions.setdefault(case_id, []).append(version)
            self.report_case[version.report_id] = case_id

    def bind_report_case(self, report_id: str, case_id: str) -> None:
        self.report_case[report_id] = case_id

    def append_version(self, case_id: str, version: CaseVersion) -> None:
        with self._lock:
            self.versions.setdefault(case_id, []).append(version)
            self.report_case[version.report_id] = case_id

    def versions_of(self, case_id: str) -> list[CaseVersion]:
        return sorted(self.versions.get(case_id, []), key=lambda v: v.version)

    def all_case_ids(self) -> list[str]:
        return sorted(self.versions)

    def effective_case(self, case_id: str) -> str:
        """沿别名链找到人工合并后的主病例。"""

        seen: set[str] = set()
        current = case_id
        while current in self.case_alias and current not in seen:
            seen.add(current)
            current = self.case_alias[current]
        return current

    def merge_case(self, member: str, primary: str) -> None:
        """把成员病例并入主病例：其版本按时间追加为主病例的后续版本。

        首报（主病例 v1）原样保留；成员首报转为主病例的随访版本，
        原始报告快照不受影响，仍可从 signal 回溯到 report-b。
        """

        with self._lock:
            if member == primary:
                return
            member_versions = self.versions.pop(member, [])
            base = self.versions.setdefault(primary, [])
            next_no = max((v.version for v in base), default=0)
            last_no = next_no
            for mv in sorted(member_versions, key=lambda v: (v.recorded_at, v.version)):
                next_no += 1
                base.append(
                    CaseVersion(
                        case_id=primary,
                        version=next_no,
                        report_id=mv.report_id,
                        institution_id=mv.institution_id,
                        privacy_match_key=mv.privacy_match_key,
                        event_terms=mv.event_terms,
                        onset_date=mv.onset_date,
                        recorded_at=mv.recorded_at,
                        follows_version=last_no,
                        note="由人工合并转入（转院重复报告），原始报告保留",
                    )
                )
                self.report_case[mv.report_id] = primary
                last_no = next_no
            self.case_alias[member] = primary

    # ---- 暴露 / 产品身份 ----------------------------------------------

    def add_exposure(self, exposure: ProductExposure) -> None:
        self.exposures[exposure.report_id] = exposure

    def exposure_of_report(self, report_id: str) -> ProductExposure | None:
        return self.exposures.get(report_id)

    def reports_of_case(self, case_id: str) -> list[str]:
        primary = self.effective_case(case_id)
        return sorted(
            rid for rid, cid in self.report_case.items() if self.effective_case(cid) == primary
        )

    def case_of_report(self, report_id: str) -> str:
        return self.effective_case(self.report_case[report_id])

    # ---- 疑似重复组 ---------------------------------------------------

    def add_cluster(self, cluster: DuplicateCluster) -> None:
        with self._lock:
            self.clusters[cluster.cluster_id] = cluster

    def update_cluster(self, cluster: DuplicateCluster) -> None:
        self.clusters[cluster.cluster_id] = cluster

    def get_cluster(self, cluster_id: str) -> DuplicateCluster:
        return self.clusters[cluster_id]

    def list_clusters(self) -> list[DuplicateCluster]:
        return [self.clusters[k] for k in sorted(self.clusters)]

    # ---- 严重性判定 ---------------------------------------------------

    def add_assessment(self, assessment: SeriousnessAssessment) -> None:
        with self._lock:
            self.assessments.setdefault(assessment.case_id, []).append(assessment)

    def assessments_of(self, case_id: str) -> list[SeriousnessAssessment]:
        return list(self.assessments.get(self.effective_case(case_id), []))

    # ---- 信号 ---------------------------------------------------------

    def put_signal(self, signal: SafetySignal) -> None:
        with self._lock:
            self.signals[signal.signal_id] = signal

    def get_signal(self, signal_id: str) -> SafetySignal:
        return self.signals[signal_id]

    def list_signals(self) -> list[SafetySignal]:
        return [self.signals[k] for k in sorted(self.signals)]

    # ---- 调查与时间线 -------------------------------------------------

    def start_investigation(self, investigation: Investigation, idem_key: str | None) -> str:
        """幂等启动：返回既有调查 id 或登记新调查。调用方负责状态判断。"""

        with self._lock:
            if idem_key is not None and idem_key in self._idem:
                return self._idem[idem_key]
            self.investigations[investigation.investigation_id] = investigation
            if idem_key is not None:
                self._idem[idem_key] = investigation.investigation_id
            return investigation.investigation_id

    def has_investigation_for_signal(self, signal_id: str) -> bool:
        return any(inv.signal_id == signal_id for inv in self.investigations.values())

    def investigation_of_signal(self, signal_id: str) -> Investigation | None:
        for inv in self.investigations.values():
            if inv.signal_id == signal_id:
                return inv
        return None

    def append_timeline(self, investigation_id: str, event: TimelineEvent) -> None:
        with self._lock:
            inv = self.investigations[investigation_id]
            self.investigations[investigation_id] = Investigation(
                investigation_id=inv.investigation_id,
                signal_id=inv.signal_id,
                idempotency_key=inv.idempotency_key,
                created_at=inv.created_at,
                created_by=inv.created_by,
                events=(*inv.events, event),
            )

    def idempotency_lookup(self, key: str) -> str | None:
        return self._idem.get(key)


def product_identity_of(exposure: ProductExposure) -> ProductIdentity:
    """同名药厂家或批准信息不同则身份不同；缺失保持显式"未知"，不猜测。"""

    return ProductIdentity(
        product_name=exposure.product_name,
        manufacturer_id=exposure.manufacturer_id or UNKNOWN,
        approval_code=exposure.approval_code or UNKNOWN,
    )
