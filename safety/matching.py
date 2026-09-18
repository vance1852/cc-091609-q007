"""疑似重复病例发现与人工确认。

策略：只**生成线索**，绝不自动并案。

- 以隐私保护匹配标识为主、事件族/机构/时间邻近度为辅，对病例两两评分；
- 评分超过配置阈值的病例对组成疑似重复组（并查集聚类），附评分依据，
  供药物警戒专员研判；
- 人工可将一组确认为“合并”（记录主病例）或“保持独立”；两种决定都
  落审计，后续重算时已决组不再重复打扰。

随访版本不参与跨病例匹配（它们已在同一病例内）。
"""

from dataclasses import dataclass, field
from datetime import date

from .config import EVENT_FAMILIES, MatchingWeights
from .store import CaseRecord, ReportStore


@dataclass(frozen=True)
class PairEvidence:
    case_a: str
    case_b: str
    score: float
    reasons: tuple[str, ...]


@dataclass
class DuplicateCandidate:
    """一个疑似重复组：同组病例两两有证据相连。"""

    candidate_id: str
    case_ids: tuple[str, ...]
    pair_evidence: tuple[PairEvidence, ...]
    status: str = "pending"  # pending / merged / kept-separate
    decided_by: str | None = None
    decided_at: str | None = None
    merged_into: str | None = None
    note: str | None = None

    def min_score(self) -> float:
        return min(p.score for p in self.pair_evidence)


@dataclass
class MergeDecision:
    candidate_id: str
    action: str  # merged / kept-separate
    decided_by: str
    decided_at: str
    merged_into: str | None = None
    note: str | None = None


def _event_family(term: str) -> str | None:
    return EVENT_FAMILIES.get(term)


def _time_close(a: date | None, b: date | None, window_days: int) -> bool:
    if a is None or b is None:
        return False
    return abs((a - b).days) <= window_days


def score_pair(a: CaseRecord, b: CaseRecord, weights: MatchingWeights) -> PairEvidence | None:
    fa, fb = a.first_version, b.first_version
    if fa.case_id == fb.case_id:
        return None

    score = 0.0
    reasons: list[str] = []

    if fa.privacy_match_key == fb.privacy_match_key:
        score += weights.privacy_match_key
        reasons.append("隐私匹配标识一致")

    fam_a = _event_family(fa.event_terms[0])
    fam_b = _event_family(fb.event_terms[0])
    if fam_a is not None and fam_a == fam_b:
        score += weights.event_family
        reasons.append(f"事件同族({fam_a})")

    if fa.institution_id == fb.institution_id:
        score += weights.institution
        reasons.append("报告机构相同")
    else:
        reasons.append("跨机构（可能为转院）")

    if _time_close(fa.onset_date, fb.onset_date, weights.time_window_days):
        score += weights.time_proximity
        reasons.append(f"发病日期相距≤{weights.time_window_days}天")

    return PairEvidence(fa.case_id, fb.case_id, round(score, 4), tuple(reasons))


class _UnionFind:
    def __init__(self, items):
        self.parent = {x: x for x in items}

    def find(self, x):
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


class MatchingService:
    def __init__(self, store: ReportStore, weights: MatchingWeights):
        self._store = store
        self._weights = weights
        self._candidates: dict[str, DuplicateCandidate] = {}
        self._decisions: list[MergeDecision] = []

    def find_candidates(self) -> list[DuplicateCandidate]:
        """重新扫描病例并生成疑似重复组；已有决定的组保持原结论。"""
        cases = self._store.cases
        evidence: list[PairEvidence] = []
        for i, a in enumerate(cases):
            for b in cases[i + 1 :]:
                pair = score_pair(a, b, self._weights)
                if pair and pair.score >= self._weights.candidate_threshold:
                    evidence.append(pair)

        if not evidence:
            return []

        uf = _UnionFind([c.case_id for c in cases])
        for p in evidence:
            uf.union(p.case_a, p.case_b)

        groups: dict[str, list[str]] = {}
        for p in evidence:
            root = uf.find(p.case_a)
            groups.setdefault(root, [])
            for cid in (p.case_a, p.case_b):
                if cid not in groups[root]:
                    groups[root].append(cid)

        result: list[DuplicateCandidate] = []
        for members in (tuple(sorted(v)) for _, v in sorted(groups.items())):
            pairs = tuple(
                p for p in evidence if p.case_a in members and p.case_b in members
            )
            existing = next(
                (c for c in self._candidates.values() if c.case_ids == members), None
            )
            if existing:
                existing.pair_evidence = pairs
                result.append(existing)
            else:
                candidate_id = f"dup-{len(self._candidates) + 1:03d}"
                cand = DuplicateCandidate(
                    candidate_id=candidate_id, case_ids=members, pair_evidence=pairs
                )
                self._candidates[candidate_id] = cand
                result.append(cand)
        return result

    def decide(
        self,
        candidate_id: str,
        action: str,
        decided_by: str,
        decided_at: str,
        merged_into: str | None = None,
        note: str | None = None,
    ) -> DuplicateCandidate:
        if action not in ("merged", "kept-separate"):
            raise ValueError("action 必须为 merged 或 kept-separate")
        cand = self._candidates.get(candidate_id)
        if cand is None:
            raise KeyError(f"疑似组 {candidate_id} 不存在")
        if cand.status != "pending":
            raise ValueError(f"疑似组 {candidate_id} 已由 {cand.decided_by} 判定，不可重复决定")

        if action == "merged":
            if merged_into is None or merged_into not in cand.case_ids:
                raise ValueError("合并必须指定组内一个主病例 merged_into")
            cand.merged_into = merged_into
        cand.status = "merged" if action == "merged" else "kept-separate"
        cand.decided_by = decided_by
        cand.decided_at = decided_at
        cand.note = note
        self._decisions.append(
            MergeDecision(
                candidate_id=cand.candidate_id,
                action=action,
                decided_by=decided_by,
                decided_at=decided_at,
                merged_into=merged_into,
                note=note,
            )
        )
        return cand

    @property
    def decisions(self) -> list[MergeDecision]:
        return list(self._decisions)

    def effective_case_mapping(self) -> dict[str, str]:
        """返回病例 -> 归并后主病例 的映射；未合并/判独立的病例映射到自身。"""
        mapping = {c.case_id: c.case_id for c in self._store.cases}
        for cand in self._candidates.values():
            if cand.status == "merged" and cand.merged_into:
                for cid in cand.case_ids:
                    mapping[cid] = cand.merged_into
        return mapping
