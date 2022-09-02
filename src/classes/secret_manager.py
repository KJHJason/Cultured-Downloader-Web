# For Google Cloud API Errors (Third-party libraries)
import google.api_core.exceptions as GoogleErrors

# For Google SM (Secret Manager) API (Third-party libraries)
from google.cloud import secretmanager
from google.cloud.secretmanager_v1.types import resources

# import Python's standard libraries
import warnings

# import local python libraries
if (__package__ is None or __package__ == ""):
    from initialise import CONSTANTS as C, crc32c
    from cloud_logger import CLOUD_LOGGER
else:
    from .initialise import CONSTANTS as C, crc32c
    from .cloud_logger import CLOUD_LOGGER

class SecretManager:
    """Creates a Secret Manager client that can be used to retrieve secrets from GCP."""
    def __init__(self) -> None:
        self.__SM_CLIENT = secretmanager.SecretManagerServiceClient.from_service_account_json(
            filename=C.CONFIG_DIR_PATH.joinpath("google-sm.json")
        )

    def get_secret_payload(self, secret_id: str, 
                           version_id: str = "latest", decode_secret: bool = True) -> str | bytes:
        """Get the secret payload from Google Cloud Secret Manager API.

        Args:
            secret_id (str): 
                The ID of the secret.
            version_id (str): 
                The version ID of the secret.
            decode_secret (bool): 
                If true, decode the returned secret bytes payload to string type. (Default: True)

        Returns:
            secretPayload (str|bytes): the secret payload
        """
        # construct the resource name of the secret version
        secret_name = self.__SM_CLIENT.secret_version_path(C.GOOGLE_PROJECT_NAME, secret_id, version_id)

        # get the secret version
        try:
            response = self.__SM_CLIENT.access_secret_version(request={"name": secret_name})
        except (GoogleErrors.NotFound) as e:
            # secret version not found
            warnings.warn(
                message=f"Secret {secret_id} (version {version_id}) not found!\n{e}",
                category=RuntimeWarning
            )
            return

        # return the secret payload
        secret = response.payload.data
        return secret.decode("utf-8") if (decode_secret) else secret

    def upload_new_secret_version(self, secret_id: str | bytes = None, secret: str = None, 
                                  destroy_past_ver: bool = False, destroy_optimise: bool = False) -> resources.SecretVersion:
        """Uploads the new secret to Google Cloud Platform's Secret Manager API.

        Args:
            secret_id (str): 
                The ID of the secret to upload
            secret (str|bytes): 
                The secret to upload
            destroy_past_ver (bool): 
                Whether to destroy the past version of the secret or not
            destroy_optimise (bool): 
                Whether to optimise the process of destroying the past version of the secret
                Note: This should be True if the past versions have consistently been destroyed

        Returns:
            secretVersion (resources.SecretVersion): 
                The response from GCP Secret Manager API
        """
        # construct the secret path to the secret key ID
        secret_path = self.__SM_CLIENT.secret_path(C.GOOGLE_PROJECT_NAME, secret_id)

        # encode the secret to bytes if secret is in string format
        if (isinstance(secret, str)):
            secret = secret.encode("utf-8")

        # calculate the payload crc32c checksum
        crc32c_checksum = crc32c(secret)

        # Add the secret version and send to Google Secret Management API
        response = self.__SM_CLIENT.add_secret_version(
            parent=secret_path, payload={"data": secret, "data_crc32c": crc32c_checksum}
        )

        # get the latest secret version and log the action
        latest_ver = int(response.name.rsplit(sep="/", maxsplit=1)[1])
        CLOUD_LOGGER.info(
            content={
                "message": f"Secret {secret_id} (version {latest_ver}) created successfully!",
                "details": {
                    "created": str(response.create_time)
                }
            }
        )

        # disable all past versions if destroy_past_ver is True
        if (destroy_past_ver):
            for version in range(latest_ver - 1, 0, -1):
                secret_version_path = self.__SM_CLIENT.secret_version_path(C.GOOGLE_PROJECT_NAME, secret_id, version)
                try:
                    delete_res = self.__SM_CLIENT.destroy_secret_version(
                        request={"name": secret_version_path}
                    )
                    CLOUD_LOGGER.info(
                        content={
                            "message": f"Secret {secret_id} (version {version}) destroyed successfully!",
                            "details": {
                                "destroyed": str(delete_res.destroy_time)
                            }
                        }
                    )
                except (GoogleErrors.FailedPrecondition):
                    # key is already destroyed
                    if (destroy_optimise):
                        break

            CLOUD_LOGGER.info(
                content=f"Successfully destroyed all past versions of the secret {secret_id}"
            )

        return response

SECRET_MANAGER = SecretManager()

__all__ = [
    "SECRET_MANAGER"
]