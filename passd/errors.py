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
