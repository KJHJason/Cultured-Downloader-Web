# import Python's standard libraries
import re
from dataclasses import dataclass, field

# import local python libraries
if (__name__ == "__main__"):
    from secret_manager import SECRET_MANAGER
else:
    from .secret_manager import SECRET_MANAGER

@dataclass(frozen=True, repr=False)
class AppConstants:
    """This dataclass is used to store all the constants used in the application."""
    DEBUG_MODE: bool = True

    # For encrypting/decrypting user's saved cookies
    # which will retrieve a 256-bit key for AES-256-GCM
    COOKIE_KEY: bytes = SECRET_MANAGER.get_secret_payload(secretID="cookie-encryption-key", decodeSecret=False) 

    # For the Google Drive API
    GDRIVE_API_TOKEN: str = SECRET_MANAGER.get_secret_payload(secretID="gdrive-api-token")
    REQ_HEADERS: dict[str, str] = field(default_factory=lambda : {
        "User-Agent": 
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36",
        "referer": 
            "https://cultureddownloader.com/query"
    })

    # For caching
    BLUEPRINT_ENDPOINT_REGEX: re.Pattern[str] = re.compile(r"^[\w]+(.)[\w]+$")

APP_CONSTANTS = AppConstants()

__all__ = [
    "APP_CONSTANTS"
]