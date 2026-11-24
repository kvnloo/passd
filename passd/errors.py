INTERNAL_ERROR_MESSAGE = "internal error"


class PassdError(Exception):
    code = "passd_error"


class AuthError(PassdError):
    code = "auth_error"


class PermissionDenied(PassdError):
    code = "permission_denied"


class NotFound(PassdError):
    code = "not_found"


class Conflict(PassdError):
    code = "conflict"


class ValidationError(PassdError):
    code = "validation_error"


class ProtonAgentDenial(PermissionDenied):
    code = "proton_agent_denial"


class ProtonAgentAuthExpired(ProtonAgentDenial):
    code = "proton_agent_auth_expired"


class ProtonAgentAccessDenied(ProtonAgentDenial):
    code = "proton_agent_access_denied"


class ProtonAgentItemNotFound(ProtonAgentDenial):
    code = "proton_agent_item_not_found"


class ProtonAgentReasonRequired(ProtonAgentDenial):
    code = "proton_agent_reason_required"


class ProtonAgentUnavailable(ProtonAgentDenial):
    code = "proton_agent_unavailable"


class ProtonAgentDisabled(ProtonAgentDenial):
    code = "proton_agent_disabled"
