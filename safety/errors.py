"""领域错误类型。"""


class SafetyError(Exception):
    """所有信号核查错误的基类。"""


class AccessDeniedError(SafetyError):
    """角色无权执行该操作（例如查看可识别信息）。"""


class UnknownReportError(SafetyError):
    """引用了不存在的原始报告。"""


class DuplicateReportError(SafetyError):
    """同一 report_id 被重复提交。"""


class ClusterStateError(SafetyError):
    """疑似重复组当前状态不允许该判定。"""


class InvalidTransitionError(SafetyError):
    """信号状态机不允许该流转。"""


class DuplicateInvestigationError(SafetyError):
    """同一信号已存在调查，重复请求不得再启动一次。"""
