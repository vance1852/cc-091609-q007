"""隐私保护匹配标识与可识别信息访问控制。

- 上报方的 ``privacyKey`` 不以明文参与聚合；使用 HMAC-SHA256 加盐派生
  不可逆的匹配标识，只用于跨机构记录链接。
- 可识别信息（原始匹配键、机构-病例对应明细）只有授权角色可查看，
  其他角色看到的是脱敏视图。
"""

import hashlib
import hmac
from dataclasses import dataclass

from .config import IDENTIFIABLE_ACCESS_ROLES, PrivacyConfig, Role

UNKNOWN_TOKEN = "未知"


def derive_match_key(raw_privacy_key: str, config: PrivacyConfig) -> str:
    """由原始隐私标识派生不可逆匹配标识（同盐下同一患者稳定）。"""
    digest = hmac.new(
        config.match_key_salt.encode("utf-8"),
        raw_privacy_key.strip().encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"mk-{digest[: config.digest_hex_length]}"


class AccessDeniedError(PermissionError):
    """未获授权角色请求可识别信息。"""


@dataclass(frozen=True)
class AccessContext:
    user_id: str
    role: Role

    @property
    def may_view_identifiable(self) -> bool:
        return self.role in IDENTIFIABLE_ACCESS_ROLES

    def require_identifiable(self) -> None:
        if not self.may_view_identifiable:
            raise AccessDeniedError(
                f"角色 {self.role} 无权查看可识别信息（用户 {self.user_id}）"
            )


def lot_or_unknown(lot: str | None) -> str:
    """批号缺失时保留“未知”，绝不猜测或用其他批号填充。"""
    if lot is None or not lot.strip():
        return UNKNOWN_TOKEN
    return lot.strip()
