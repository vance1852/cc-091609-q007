"""基于角色的访问控制（RBAC）。

只有被显式授予"查看可识别信息"权限的角色才能接触身份分区数据；
匹配标识是脱敏派生出的伪标识，不属于可识别信息。
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from safety.errors import AccessDeniedError


class Permission(StrEnum):
    VIEW_IDENTIFIABLE = "view-identifiable"
    CONFIRM_CLUSTER = "confirm-cluster"
    ASSESS_SERIOUSNESS = "assess-seriousness"
    MANAGE_INVESTIGATION = "manage-investigation"


# 药物警戒专员可处理信号与重复组；可识别信息仅对授权角色开放。
ROLE_PERMISSIONS: dict[str, frozenset[Permission]] = {
    "pv-specialist": frozenset(
        {
            Permission.CONFIRM_CLUSTER,
            Permission.ASSESS_SERIOUSNESS,
            Permission.MANAGE_INVESTIGATION,
        }
    ),
    "pv-reviewer": frozenset(
        {
            Permission.CONFIRM_CLUSTER,
            Permission.ASSESS_SERIOUSNESS,
            Permission.MANAGE_INVESTIGATION,
        }
    ),
    # 药物警戒医师 / 隐私管理员：经授权可查看可识别信息。
    "pv-physician": frozenset(
        {
            Permission.VIEW_IDENTIFIABLE,
            Permission.CONFIRM_CLUSTER,
            Permission.ASSESS_SERIOUSNESS,
            Permission.MANAGE_INVESTIGATION,
        }
    ),
    "privacy-officer": frozenset({Permission.VIEW_IDENTIFIABLE}),
    # 审计角色只读公开信息，无任何处置权限。
    "auditor": frozenset(),
}


@dataclass(frozen=True)
class Principal:
    user_id: str
    roles: tuple[str, ...] = ()
    display_name: str = ""

    def can(self, permission: Permission) -> bool:
        granted: set[Permission] = set()
        for role in self.roles:
            granted.update(ROLE_PERMISSIONS.get(role, frozenset()))
        return permission in granted


def authorize(principal: Principal, permission: Permission) -> None:
    """无权时抛出 AccessDeniedError，不泄露被保护资源是否存在。"""

    if not principal.can(permission):
        raise AccessDeniedError(
            f"用户 {principal.user_id} 的角色 {list(principal.roles)} "
            f"缺少权限 {permission}"
        )
