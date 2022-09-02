class APIException(Exception):
    """Class for the APIException exception class that will
    return a JSON response with the error message when raised"""
    def __init__(self, error: str | dict, status_code: int | None = 400):
        """Constructor for the APIException exception class

        Usage Example:
        >>> raise APIException({"error": "invalid request"})
        >>> raise APIException("invalid request") # the error message will be the same as above

        Attributes:
            error (str | dict):
                The error message to be returned to the user.
                If the error message is a str, it will be converted to a dict with the key "error".
            status_code (int | None):
                The status code to be returned to the user. (Default: 400)
        """
        self.error = error if (isinstance(error, dict)) \
                           else {"error": error}
        self.status_code = status_code