# import third-party libraries
from pydantic import BaseModel

class CsrfResponse(BaseModel):
    """The JSON payload schema for the user
    when requesting a CSRF token."""
    csrf_token: str