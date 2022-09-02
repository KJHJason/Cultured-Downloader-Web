# import Python's standard libraries
import re
from dataclasses import dataclass, field

@dataclass(frozen=True, repr=False)
class AppConstants:
    """This dataclass is used to store all the constants used in the application."""
    # API constants
    DEBUG_MODE: bool = True # TODO: Change this to False when deploying to production
    FAVICON_URL: str = "/favicon.ico"
    API_RESPONSES: dict = field(
        default_factory=lambda: {
            429: {
                "error_code": 429, 
                "message": "Too many requests"
            }
        }
    )

    # For API documentations
    # https://fastapi.tiangolo.com/advanced/extending-openapi/
    LATEST_VER: str = "v1"
    VER_ONE: str = "v1"
    DOCS_URL: str = "/docs"
    REDOC_URL: str = "/redoc"
    OPENAPI_JSON_URL: str = "/openapi.json"
    VER_ONE_OPENAPI_JSON_URL: str = f"/api/{VER_ONE}{OPENAPI_JSON_URL}"

    # For the API's session middleware
    ISSUER: str = "https://api.cultureddownloader.com/"

    # For encrypting/decrypting the saved user's cookie data
    RSA_SHA256_KEY_ID: str = "user-data-rsa-key-1"
    RSA_SHA512_KEY_ID: str = "user-data-rsa-key-2"
    RSA_SHA256_VERSION_SECRET_ID: str = "user-data-rsa-key-1-ver"
    RSA_SHA512_VERSION_SECRET_ID: str = "user-data-rsa-key-2-ver"
    COOKIE_ENCRYPTION_KEY: str = "cookie-aes-key"

    # For the Google Drive API
    DRIVE_REQ_HEADERS: dict[str, str] = field(
        default_factory=lambda : {
            "User-Agent": 
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36",
            "referer": 
                "https://api.cultureddownloader.com/drive/query"
        }
    )

    # For caching
    BLUEPRINT_ENDPOINT_REGEX: re.Pattern[str] = re.compile(r"^[\w]+(.)[\w]+$")

APP_CONSTANTS = AppConstants()

__all__ = [
    "APP_CONSTANTS"
]