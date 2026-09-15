class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str):
        self.status, self.code, self.message = status, code, message


def forbidden():
    return ApiError(403, "forbidden", "Access is not permitted.")


def invalid():
    return ApiError(422, "invalid_input", "Invalid request.")


def unavailable():
    return ApiError(503, "dependency_unavailable", "A required dependency is unavailable.")
