"""原始报告台账与病例版本管理。

关键约束：
- 原始报告按接收顺序**只追加**保存，带 SHA-256 哈希与前序哈希链，
  任何随访都不会改写首报；
- 随访报告（``followsReport``）在同一病例下追加新的 ``CaseVersion``，
  显式 ``follows_version`` 指向被随访版本；
- 无随访关系的报告各自建立新病例，即使隐私匹配标识相同也不自动并案，
  并案判断交给 :mod:`safety.matching` 产出线索、人工确认。
"""

import copy
import hashlib
import json
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path

from .config import PrivacyConfig
from .contracts import CaseVersion, ProductExposure
from .privacy import derive_match_key, lot_or_unknown

GENESIS_HASH = "0" * 64


def _canonical_hash(payload: dict) -> str:
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _entry_hash(entry: dict) -> str:
    return hashlib.sha256(
        json.dumps(entry, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    ).hexdigest()


def _parse_dt(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


def _parse_date(value: str | None) -> date | None:
    return date.fromisoformat(value) if value else None


@dataclass(frozen=True)
class RawReport:
    """一份原始上报的不可变记录（含原文与哈希）。"""

    report_id: str
    institution_id: str
    raw_privacy_key: str
    product_name: str
    manufacturer_id: str | None
    approval_code: str | None
    product_lot: str | None
    ingredient_lots: tuple[str, ...]
    event: str
    onset_date: date | None
    recorded_at: datetime | None
    follows_report_id: str | None
    payload: dict
    source_hash: str
    received_at: datetime
    ledger_seq: int


@dataclass
class CaseRecord:
    """一个病例的全部版本与暴露信息。"""

    case_id: str
    versions: list[CaseVersion] = field(default_factory=list)
    exposures: list[ProductExposure] = field(default_factory=list)
    report_ids: list[str] = field(default_factory=list)

    @property
    def first_version(self) -> CaseVersion:
        return self.versions[0]


class ReportStore:
    def __init__(self, privacy_config: PrivacyConfig, ledger_path: str | Path | None = None):
        self._privacy_config = privacy_config
        self._ledger_path = Path(ledger_path) if ledger_path else None
        self._reports: dict[str, RawReport] = {}
        self._cases: dict[str, CaseRecord] = {}
        self._report_to_case: dict[str, str] = {}
        self._seq = 0
        self._prev_hash = GENESIS_HASH
        if self._ledger_path:
            self._ledger_path.parent.mkdir(parents=True, exist_ok=True)
            if self._ledger_path.exists():
                self._replay_ledger()

    # ------------------------------------------------------------------ 载入
    def load_fixture(self, path: str | Path) -> list[RawReport]:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        return [self.ingest(item) for item in data.get("reports", [])]

    def ingest(self, payload: dict, received_at: datetime | None = None) -> RawReport:
        """接收并保存一份原始报告；重复 report_id 将被拒绝（幂等保护）。"""
        report_id = payload["id"]
        if report_id in self._reports:
            raise ValueError(f"报告 {report_id} 已存在，原始报告不可重复写入")

        self._seq += 1
        report = RawReport(
            report_id=report_id,
            institution_id=payload.get("institution", "未知机构"),
            raw_privacy_key=payload["privacyKey"],
            product_name=payload["product"],
            manufacturer_id=payload.get("manufacturer"),
            approval_code=payload.get("approval"),
            # 批号缺失保留 None（未知），不做任何推断
            product_lot=payload.get("lot"),
            ingredient_lots=tuple(payload.get("ingredientLots", [])),
            event=payload["event"],
            onset_date=_parse_date(payload.get("onsetDate")),
            recorded_at=_parse_dt(payload.get("recordedAt")),
            follows_report_id=payload.get("followsReport"),
            payload=copy.deepcopy(payload),
            source_hash=_canonical_hash(payload),
            received_at=received_at or datetime.now(),
            ledger_seq=self._seq,
        )
        self._persist_entry(report)
        self._reports[report_id] = report
        self._build_case(report)
        return report

    def _persist_entry(self, report: RawReport) -> None:
        entry = {
            "seq": report.ledger_seq,
            "report_id": report.report_id,
            "received_at": report.received_at.isoformat(timespec="seconds"),
            "source_hash": report.source_hash,
            "prev_hash": self._prev_hash,
            "payload": report.payload,
        }
        if self._ledger_path:
            with open(self._ledger_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n")
        self._prev_hash = _entry_hash(entry)

    def _replay_ledger(self) -> None:
        """从只追加台账重放：重建内存对象，不再写盘。"""
        for line in self._ledger_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            entry = json.loads(line)
            if entry["prev_hash"] != self._prev_hash:
                raise RuntimeError(f"台账哈希链在序号 {entry['seq']} 处断裂")
            payload = entry["payload"]
            if _canonical_hash(payload) != entry["source_hash"]:
                raise RuntimeError(f"报告 {entry['report_id']} 原文哈希校验失败")
            self._seq = entry["seq"]
            self._prev_hash = _entry_hash(entry)
            report = RawReport(
                report_id=entry["report_id"],
                institution_id=payload.get("institution", "未知机构"),
                raw_privacy_key=payload["privacyKey"],
                product_name=payload["product"],
                manufacturer_id=payload.get("manufacturer"),
                approval_code=payload.get("approval"),
                product_lot=payload.get("lot"),
                ingredient_lots=tuple(payload.get("ingredientLots", [])),
                event=payload["event"],
                onset_date=_parse_date(payload.get("onsetDate")),
                recorded_at=_parse_dt(payload.get("recordedAt")),
                follows_report_id=payload.get("followsReport"),
                payload=copy.deepcopy(payload),
                source_hash=entry["source_hash"],
                received_at=datetime.fromisoformat(entry["received_at"]),
                ledger_seq=entry["seq"],
            )
            self._reports[report.report_id] = report
            self._build_case(report)

    # ------------------------------------------------------------------ 病例
    def _build_case(self, report: RawReport) -> None:
        match_key = derive_match_key(report.raw_privacy_key, self._privacy_config)
        recorded_at = report.recorded_at or report.received_at

        if report.follows_report_id:
            if report.follows_report_id not in self._reports:
                raise ValueError(
                    f"报告 {report.report_id} 声明随访 {report.follows_report_id}，但首报不存在"
                )
            case_id = self._report_to_case[report.follows_report_id]
            parent = self._cases[case_id]
            follows_version = parent.versions[-1].version
            version_no = follows_version + 1
        else:
            case_id = f"case-{len(self._cases) + 1:04d}"
            follows_version = None
            version_no = 1
            self._cases[case_id] = CaseRecord(case_id=case_id)

        case = self._cases[case_id]
        case.versions.append(
            CaseVersion(
                case_id=case_id,
                version=version_no,
                institution_id=report.institution_id,
                privacy_match_key=match_key,
                event_terms=(report.event,),
                onset_date=report.onset_date,
                recorded_at=recorded_at,
                follows_version=follows_version,
            )
        )
        case.exposures.append(
            ProductExposure(
                case_id=case_id,
                product_name=report.product_name,
                manufacturer_id=report.manufacturer_id,
                approval_code=report.approval_code,
                product_lot=report.product_lot,
                ingredient_lots=report.ingredient_lots,
            )
        )
        case.report_ids.append(report.report_id)
        self._report_to_case[report.report_id] = case_id

    # ------------------------------------------------------------------ 查询
    def get_report(self, report_id: str) -> RawReport:
        return self._reports[report_id]

    def case_of_report(self, report_id: str) -> str:
        return self._report_to_case[report_id]

    @property
    def reports(self) -> list[RawReport]:
        return sorted(self._reports.values(), key=lambda r: r.ledger_seq)

    @property
    def cases(self) -> list[CaseRecord]:
        return sorted(self._cases.values(), key=lambda c: c.case_id)

    def get_case(self, case_id: str) -> CaseRecord:
        return self._cases[case_id]

    def first_report_of_case(self, case_id: str) -> RawReport:
        """始终返回首报原文——随访补充不能覆盖首报。"""
        case = self._cases[case_id]
        return self._reports[case.report_ids[0]]

    def lot_view(self, case_id: str) -> str:
        return lot_or_unknown(self.first_report_of_case(case_id).product_lot)
