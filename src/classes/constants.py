# For Google Cloud API Errors (Third-party libraries)
import google.api_core.exceptions as GoogleErrors

# For Google SM (Secret Manager) API (Third-party libraries)
from google.cloud import secretmanager

# import third-party libraries
from google_crc32c import Checksum as g_crc32c

# import Python's standard libraries
import re
import secrets
import pathlib
from typing import Union
from six import ensure_binary
from dataclasses import dataclass, field

def crc32c(data:Union[bytes, str]) -> int:
    """Calculates the CRC32C checksum of the provided data

    Args:
        data (str|bytes): 
            The bytes of the data which the checksum should be calculated.
            If the data is in string format, it will be encoded to bytes.

    Returns:
        An int representing the CRC32C checksum of the provided bytes
    """
    return int(g_crc32c(initial_value=ensure_binary(data)).hexdigest(), 16)

FILE_PATH = pathlib.Path(__file__).parent.absolute()
GOOGLE_PROJECT_NAME = "cultureddownloader"

class SecretManager:
    """Creates a Secret Manager client that can be used to retrieve secrets from GCP."""
    def __init__(self) -> None:
        self.__GOOGLE_PROJECT_NAME = GOOGLE_PROJECT_NAME
        self.__SM_CLIENT = secretmanager.SecretManagerServiceClient.from_service_account_json(
            filename=FILE_PATH.parent.joinpath("config_files", "google-sm.json")
        )

    @property
    def SM_CLIENT(self) -> secretmanager.SecretManagerServiceClient:
        return self.__SM_CLIENT

    def get_secret_payload(self, secretID: str, 
                           versionID: str = "latest", decodeSecret: bool = True) -> Union[str, bytes]:
        """Get the secret payload from Google Cloud Secret Manager API.

        Args:
            secretID (str): 
                The ID of the secret.
            versionID (str): 
                The version ID of the secret.
            decodeSecret (bool): 
                If true, decode the returned secret bytes payload to string type.

        Returns:
            secretPayload (str|bytes): the secret payload
        """
        # construct the resource name of the secret version
        secretName = self.__SM_CLIENT.secret_version_path(self.__GOOGLE_PROJECT_NAME, secretID, versionID)

        # get the secret version
        try:
            response = self.__SM_CLIENT.access_secret_version(request={"name": secretName})
        except (GoogleErrors.NotFound) as e:
            # secret version not found
            print("Error caught:")
            print(e, end="\n\n")
            return

        # return the secret payload
        secret = response.payload.data
        return secret.decode("utf-8") if (decodeSecret) else secret

    def upload_new_secret_version(self, secretID: Union[str, bytes] = None, secret: str = None, 
                                  destroyPastVer: bool = False, destroyOptimise: bool = False) -> None:
        """Uploads the new secret to Google Cloud Platform's Secret Manager API.

        Args:
            secretID (str): 
                The ID of the secret to upload
            secret (str|bytes): 
                The secret to upload
            destroyPastVer (bool): 
                Whether to destroy the past version of the secret or not
            destroyOptimise (bool): 
                Whether to optimise the process of destroying the past version of the secret
                Note: This should be True if the past versions have consistently been destroyed

        Returns:
            None
        """
        # construct the secret path to the secret key ID
        secretPath = self.__SM_CLIENT.secret_path(self.__GOOGLE_PROJECT_NAME, secretID)

        # encode the secret to bytes if secret is in string format
        if (isinstance(secret, str)):
            secret = secret.encode()

        # calculate the payload crc32c checksum
        crc32cChecksum = crc32c(secret)

        # Add the secret version and send to Google Secret Management API
        response = self.__SM_CLIENT.add_secret_version(parent=secretPath, payload={"data": secret, "data_crc32c": crc32cChecksum})

        # disable all past versions if destroyPastVer is True
        if (destroyPastVer):
            # get the latest secret version
            latestVer = int(response.name.split("/")[-1])
            for version in range(latestVer - 1, 0, -1):
                secretVersionPath = self.__SM_CLIENT.secret_version_path(CONSTANTS.GOOGLE_PROJECT_ID, secretID, version)
                try:
                    self.__SM_CLIENT.destroy_secret_version(request={"name": secretVersionPath})
                except (GoogleErrors.FailedPrecondition):
                    # key is already destroyed
                    if (destroyOptimise):
                        break

SECRET_MANAGER = SecretManager()

@dataclass(frozen=True, repr=False)
class Constants:
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

CONSTANTS = Constants()

__all__ = [
    "CONSTANTS",
    "SECRET_MANAGER"
]