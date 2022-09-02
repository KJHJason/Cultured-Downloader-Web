# import Python's standard libraries
import pathlib
from dataclasses import dataclass

# import third-party libraries
from six import ensure_binary
from google_crc32c import Checksum as g_crc32c

def crc32c(data: bytes | str) -> int:
    """Calculates the CRC32C checksum of the provided data

    Args:
        data (str|bytes): 
            The bytes of the data which the checksum should be calculated.
            If the data is in string format, it will be encoded to bytes.

    Returns:
        An int representing the CRC32C checksum of the provided bytes
    """
    return int(g_crc32c(initial_value=ensure_binary(data, encoding="utf-8")).hexdigest(), 16)

@dataclass(frozen=True, repr=False)
class Constants:
    """This dataclass is used to store all the important constants used 
    during initialisation of the web application.
    """
    # For the web application
    ROOT_DIR_PATH: pathlib.Path = pathlib.Path(__file__).parent.parent.absolute()
    CONFIG_DIR_PATH: pathlib.Path = ROOT_DIR_PATH.joinpath("config_files")
    ICON_PATH: pathlib.Path = ROOT_DIR_PATH.joinpath("static", "images", "icons", "favicon.ico")

    # For GCP-related constants
    GOOGLE_PROJECT_NAME: str = "cultureddownloader"
    GOOGLE_PROJECT_LOCATION: str = "asia-southeast1"

    # For Google API that requires Google OAuth2 authentication
    OAUTH_CLIENT_SECRET_NAME: str = "google-oauth-client"
    OAUTH_TOKEN_SECRET_NAME: str = "google-oauth-token"

    # For Google API scopes:
    # Google Drive API Scopes details: 
    #   https://developers.google.com/identity/protocols/oauth2/scopes#drive
    # WARNING: Editing the scopes below will require the token to be re-generated
    GOOGLE_OAUTH_SCOPES = ["https://www.googleapis.com/auth/drive.readonly"]

CONSTANTS = Constants()

__all__ = [
    "CONSTANTS"
]