"""报告接收：原始快照冻结、隐私标识派生、首报版本与暴露建立。

关键约定：
- 每条进来的报告先原样存入原始分区，之后一切处理都引用快照；
- 每份报告先独立建案（v1 首报），跨机构是否为同一患者由
  "疑似重复组"流程人工判定，系统不擅自合并；
- 随访补充只能追加新版本，绝不覆盖首报内容；
- 批号缺失时存 None，产品身份聚合时显示为"未知"，不做任何猜测。
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path

from safety.contracts import CaseVersion, ProductExposure
from safety.privacy import derive_match_key, normalize_event_terms
from safety.repository import IdentityRecord, RawReport, Repository

# 夹具无时间戳时使用的确定性起点，保证演示与测试可复现。
_DEFAULT_BASE = datetime(2026, 9, 10, 9, 0)


class IngestionService:
    def __init__(self, repo: Repository, *, salt: str = "pv-fixture-salt") -> None:
        self.repo = repo
        self.salt = salt

    def load_fixture(
        self, path: str | Path, *, base: datetime = _DEFAULT_BASE
    ) -> list[str]:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        case_ids: list[str] = []
        for index, item in enumerate(data.get("reports", [])):
            stamp = (
                datetime.fromisoformat(item["recordedAt"])
                if item.get("recordedAt")
                else base + timedelta(minutes=index)
            )
            case_ids.append(self.ingest(item, received_at=stamp))
        return case_ids

    def ingest(self, item: dict, *, received_at: datetime | None = None) -> str:
        report_id = item["id"]
        stamp = received_at or (
            datetime.fromisoformat(item["recordedAt"]) if item.get("recordedAt") else datetime.now()
        )

        # 1) 原始报告冻结保存（逐字保留机构提交的 payload）。
        self.repo.add_raw_report(
            RawReport(
                report_id=report_id,
                institution_id=item.get("institution", "未知机构"),
                payload=dict(item),
                received_at=stamp,
            )
        )
        # 2) 身份分区单独存放原始伪标识，业务链路只持有派生哈希。
        raw_key = item.get("privacyKey")
        self.repo.put_identity(IdentityRecord(report_id=report_id, raw_privacy_key=raw_key))
        match_key = derive_match_key(raw_key, salt=self.salt)

        # 3) 每份报告先独立建案；是否与既有病例为同一患者，
        #    由疑似重复组的人工判定决定，不在摄入阶段擅自合并。
        case_id = f"case-{report_id.removeprefix('report-')}"
        self.repo.register_case(
            case_id,
            CaseVersion(
                case_id=case_id,
                version=1,
                report_id=report_id,
                institution_id=item.get("institution", "未知机构"),
                privacy_match_key=match_key,
                event_terms=normalize_event_terms(item.get("event", "")),
                onset_date=None,
                recorded_at=stamp,
                note="首报",
            ),
        )

        # 4) 暴露信息：批号与原料批次缺失即保留 None / 空，不猜测。
        ingredient_lots = item.get("ingredientLots")
        self.repo.add_exposure(
            ProductExposure(
                case_id=case_id,
                report_id=report_id,
                product_name=item.get("product", "未知药品"),
                manufacturer_id=item.get("manufacturer"),
                approval_code=item.get("approval"),
                product_lot=item.get("lot"),
                ingredient_lots=tuple(ingredient_lots) if ingredient_lots else (),
            )
        )
        return case_id

    def add_follow_up(
        self,
        case_id: str,
        *,
        report_id: str,
        institution_id: str,
        event: str,
        recorded_at: datetime,
        raw_privacy_key: str | None = None,
        note: str = "随访补充",
    ) -> str:
        """向既有病例追加随访版本。

        只允许新增版本号：首报 v1 永不被修改或覆盖。可传新的原始
        报告快照（转院随访），同样冻结保存，可从病例回溯。
        """

        case_id = self.repo.effective_case(case_id)
        prior = self.repo.versions_of(case_id)
        next_version = len(prior) + 1

        if raw_privacy_key is not None:
            self.repo.put_identity(
                IdentityRecord(report_id=report_id, raw_privacy_key=raw_privacy_key)
            )
        match_key = derive_match_key(raw_privacy_key, salt=self.salt)

        self.repo.add_raw_report(
            RawReport(
                report_id=report_id,
                institution_id=institution_id,
                payload={
                    "id": report_id,
                    "institution": institution_id,
                    "event": event,
                    "followUpTo": case_id,
                },
                received_at=recorded_at,
            )
        )
        self.repo.append_version(
            case_id,
            CaseVersion(
                case_id=case_id,
                version=next_version,
                report_id=report_id,
                institution_id=institution_id,
                privacy_match_key=match_key,
                event_terms=normalize_event_terms(event),
                onset_date=None,
                recorded_at=recorded_at,
                follows_version=prior[-1].version,
                note=f"{note}（追加版本，不覆盖首报）",
            ),
        )
        return case_id
