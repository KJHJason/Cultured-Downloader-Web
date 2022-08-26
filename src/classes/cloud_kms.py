# For Google Cloud API Errors (Third-party libraries)
import google.api_core.exceptions as GoogleErrors

# For Google Cloud KMS (key management service) API (Third-party libraries)
from google.cloud import kms

# import Python's standard libraries
import json
from typing import Optional
from base64 import urlsafe_b64encode

# import local python libraries
if (__package__ is None or __package__ == ""):
    from exceptions import CRC32ChecksumError, DecryptionError
    from initialise import crc32c
    from secret_manager import SECRET_MANAGER
    from cloud_logger import CLOUD_LOGGER
    from app_constants import APP_CONSTANTS as C
else:
    from .exceptions import CRC32ChecksumError, DecryptionError
    from .initialise import crc32c
    from .secret_manager import SECRET_MANAGER
    from .cloud_logger import CLOUD_LOGGER
    from .app_constants import APP_CONSTANTS as C

class GCPKMS:
    def __init__(self) -> None:
        self.__KMS_CLIENT = kms.KeyManagementServiceClient.from_service_account_info(
            info=json.loads(SECRET_MANAGER.get_secret_payload(secretID="google-kms"))
        )
        self.__KEY_RING_ID = "dev" if (C.DEBUG_MODE) else "web-app"

class AESGCM(GCPKMS):
    def __init__(self) -> None:
        super().__init__()

    def encrypt(self, plaintext: str | bytes, keyID: str, keyRingID: Optional[str] = None) -> bytes:
        """Using AES-256-GCM to encrypt the provided plaintext via GCP KMS.

        Args:
            plaintext (str|bytes): 
                the plaintext to encrypt
            keyRingID (str): 
                the key ring ID (Defaults to KEY_RING_ID attribute of the class)
            keyID (str): 
                the key ID/name of the key

        Returns:
            ciphertext (bytes): the ciphertext in bytes format

        Raises:
            CRC32ChecksumError:
                If the integrity checks failed
        """
        if (keyRingID is None):
            keyRingID = self.__KEY_RING_ID

        if (isinstance(plaintext, str)):
            plaintext = plaintext.encode("utf-8")

        # Compute the plaintext's CRC32C checksum before sending it to Google Cloud KMS API
        plaintextCRC32C = crc32c(plaintext)

        # Construct the key version name
        keyVersionName = self.__KMS_CLIENT.crypto_key_path(
            C.GOOGLE_PROJECT_NAME, C.GOOGLE_PROJECT_LOCATION, keyRingID, keyID
        )

        # Construct and send the request to Google Cloud KMS API to encrypt the plaintext
        response = self.__KMS_CLIENT.encrypt(
            request={"name": keyVersionName, "plaintext": plaintext, "plaintext_crc32c": plaintextCRC32C}
        )

        # Perform some integrity checks on the encrypted data that Google Cloud KMS API returned
        # details: https://cloud.google.com/kms/docs/data-integrity-guidelines
        if (not response.verified_plaintext_crc32c):
            # request sent to Google Cloud KMS API was corrupted in-transit
            raise CRC32ChecksumError("Plaintext CRC32C checksum does not match.")
        if (response.ciphertext_crc32c != crc32c(response.ciphertext)):
            # response received from Google Cloud KMS API was corrupted in-transit
            raise CRC32ChecksumError("Ciphertext CRC32C checksum does not match.")

        return response.ciphertext

    def decrypt(self, ciphertext: bytes, keyID: str, 
                keyRingID: Optional[str] = None, decode: Optional[bool] = False) -> str | bytes:
        """Using AES-256-GCM to decrypt the provided ciphertext via GCP KMS.

        Args:
            ciphertext (bytes): 
                the ciphertext to decrypt
            keyRingID (str): 
                the key ring ID (Defaults to KEY_RING_ID attribute of the class)
            keyID (str): 
                the key ID/name of the key
            decode (bool): 
                whether to decode the decrypted plaintext to string (Defaults to True)

        Returns:
            plaintext (str): the plaintext

        Raises:
            TypeError: 
                If the ciphertext is not bytes
            DecryptionError: 
                If the decryption failed
            CRC32ChecksumError: 
                If the integrity checks failed
        """
        if (isinstance(ciphertext, bytearray)):
            ciphertext = bytes(ciphertext)

        if (not isinstance(ciphertext, bytes)):
            raise TypeError(f"The ciphertext, {ciphertext} is in \"{type(ciphertext)}\" format. Please pass in a bytes type variable.")

        if (keyRingID is None):
            keyRingID = self.__KEY_RING_ID

        # Construct the key version name
        keyVersionName = self.__KMS_CLIENT.crypto_key_path(
            C.GOOGLE_PROJECT_NAME, C.GOOGLE_PROJECT_LOCATION, keyRingID, keyID
        )

        # compute the ciphertext's CRC32C checksum before sending it to Google Cloud KMS API
        cipherTextCRC32C = crc32c(ciphertext)

        # construct and send the request to Google Cloud KMS API to decrypt the ciphertext
        try:
            response = self.__KMS_CLIENT.decrypt(
                request={"name": keyVersionName, "ciphertext": ciphertext, "ciphertext_crc32c": cipherTextCRC32C}
            )
        except (GoogleErrors.InvalidArgument) as e:
            try:
                ciphertextToLog = urlsafe_b64encode(ciphertext).decode("utf-8")
            except:
                ciphertextToLog = "Could not url-safe base64 encode the ciphertext..."
            CLOUD_LOGGER.write_log_entry(
                logMessage={
                    "Decryption Error": str(e),
                    "URL-base64 Encoded Ciphertext": ciphertextToLog
                },
                severity="INFO"
            )
            raise DecryptionError("Symmetric Decryption failed.")

        # Perform a integrity check on the decrypted data that Google Cloud KMS API returned
        # details: https://cloud.google.com/kms/docs/data-integrity-guidelines
        if (response.plaintext_crc32c != crc32c(response.plaintext)):
            # response received from Google Cloud KMS API was corrupted in-transit
            raise CRC32ChecksumError("Plaintext CRC32C checksum does not match.")

        return response.plaintext.decode("utf-8") if (decode) else response.plaintext

AES_GCM = AESGCM()

__all__ = [
    "AES_GCM"
]