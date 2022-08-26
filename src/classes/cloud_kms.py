# For Google Cloud API Errors (Third-party libraries)
import google.api_core.exceptions as GoogleErrors

# For Google Cloud KMS (key management service) API (Third-party libraries)
from google.cloud import kms

# import third-party libraries
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import types

# import Python's standard libraries
import json
from typing import Optional, Callable, Any
from base64 import urlsafe_b64encode

# import local python libraries
if (__package__ is None or __package__ == ""):
    from exceptions import CRC32ChecksumError, DecryptionError
    from utils import rsa_encrypt
    from initialise import crc32c, CONSTANTS as C
    from secret_manager import SECRET_MANAGER
    from cloud_logger import CLOUD_LOGGER
    from app_constants import AppConstants as AC
else:
    from .exceptions import CRC32ChecksumError, DecryptionError
    from .utils import rsa_encrypt
    from .initialise import crc32c, CONSTANTS as C
    from .secret_manager import SECRET_MANAGER
    from .cloud_logger import CLOUD_LOGGER
    from .app_constants import AppConstants as AC

class GCPKMS:
    """Creates an authenticated Cloud KMS client that can be used for cryptographic operations."""
    def __init__(self) -> None:
        self.__KMS_CLIENT = kms.KeyManagementServiceClient.from_service_account_info(
            info=json.loads(SECRET_MANAGER.get_secret_payload(secretID="google-kms"))
        )
        self.__KEY_RING_ID = "dev" if (AC.DEBUG_MODE) else "web-app"

    def get_latest_key_ver(self, keyID: str, keyRingID: Optional[str] = None) -> int | None:
        """Get the latest version of the key from GCP KMS API.

        Args:
            keyID (str):
                The ID of the key.
            keyRingID (str, optional):
                The ID of the key ring. (Defaults to KEY_RING_ID attribute of the object)

        Returns:
            The latest integer version of the key or None if the key is not found.
        """
        if (keyRingID is None):
            keyRingID = self.__KEY_RING_ID

        keyPath = self.KMS_CLIENT.crypto_key_path(
            C.GOOGLE_PROJECT_NAME, C.GOOGLE_PROJECT_LOCATION, keyRingID, keyID
        )
        try:
            metadata = self.__KMS_CLIENT.get_crypto_key(request={"name": keyPath})
        except (GoogleErrors.NotFound):
            return None # key not found
        return int(metadata.primary.name.rsplit(sep="/", maxsplit=1)[1])

    def log_failed_decryption(self, ciphertext: bytes, error: Any) -> None:
        """Logs the failed decryption attempt to the Cloud Logger and raise DecryptionError."""
        try:
            ciphertextToLog = urlsafe_b64encode(ciphertext).decode("utf-8")
        except:
            ciphertextToLog = "Could not url-safe base64 encode the ciphertext..."

        CLOUD_LOGGER.write_log_entry(
            logMessage={
                "Decryption Error": str(error),
                "URL-base64 Encoded Ciphertext": ciphertextToLog
            },
            severity="INFO"
        )
        raise DecryptionError("Asymmetric Decryption failed.")

    @property
    def KMS_CLIENT(self) -> kms.KeyManagementServiceClient:
        """Returns the KMS client."""
        return self.__KMS_CLIENT

    @property
    def KEY_RING_ID(self) -> str:
        """Returns the key ring ID."""
        return self.__KEY_RING_ID

class AESGCM(GCPKMS):
    """Creates an authenticated GCP KMS client that uses AES-256-GCM for cryptographic operations."""
    def __init__(self) -> None:
        super().__init__()

    def encrypt(self, plaintext: str | bytes, keyID: str, keyRingID: Optional[str] = None) -> bytes:
        """Using AES-256-GCM to encrypt the provided plaintext via GCP KMS.

        Args:
            plaintext (str|bytes): 
                the plaintext to encrypt
            keyRingID (str): 
                the key ring ID (Defaults to KEY_RING_ID attribute of the object)
            keyID (str): 
                the key ID/name of the key

        Returns:
            ciphertext (bytes): the ciphertext in bytes format

        Raises:
            CRC32ChecksumError:
                If the integrity checks failed
        """
        if (keyRingID is None):
            keyRingID = self.KEY_RING_ID

        if (isinstance(plaintext, str)):
            plaintext = plaintext.encode("utf-8")

        # Compute the plaintext's CRC32C checksum before sending it to Google Cloud KMS API
        plaintextCRC32C = crc32c(plaintext)

        # Construct the key version name
        keyVersionName = self.KMS_CLIENT.crypto_key_path(
            C.GOOGLE_PROJECT_NAME, C.GOOGLE_PROJECT_LOCATION, keyRingID, keyID
        )

        # Construct and send the request to Google Cloud KMS API to encrypt the plaintext
        response = self.KMS_CLIENT.encrypt(
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
                the key ring ID (Defaults to KEY_RING_ID attribute of the object)
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
            keyRingID = self.KEY_RING_ID

        # Construct the key version name
        keyVersionName = self.KMS_CLIENT.crypto_key_path(
            C.GOOGLE_PROJECT_NAME, C.GOOGLE_PROJECT_LOCATION, keyRingID, keyID
        )

        # compute the ciphertext's CRC32C checksum before sending it to Google Cloud KMS API
        cipherTextCRC32C = crc32c(ciphertext)

        # construct and send the request to Google Cloud KMS API to decrypt the ciphertext
        try:
            response = self.KMS_CLIENT.decrypt(
                request={"name": keyVersionName, "ciphertext": ciphertext, "ciphertext_crc32c": cipherTextCRC32C}
            )
        except (GoogleErrors.InvalidArgument) as e:
            self.log_failed_decryption(ciphertext=ciphertext, error=e)

        # Perform a integrity check on the decrypted data that Google Cloud KMS API returned
        # details: https://cloud.google.com/kms/docs/data-integrity-guidelines
        if (response.plaintext_crc32c != crc32c(response.plaintext)):
            # response received from Google Cloud KMS API was corrupted in-transit
            raise CRC32ChecksumError("Plaintext CRC32C checksum does not match.")

        return response.plaintext.decode("utf-8") if (decode) else response.plaintext

class Asymmetric(GCPKMS):
    """Creates an authenticated GCP KMS client that uses asymmetric cryptography operations."""
    def __init__(self) -> None:
        super().__init__()

    def get_public_key(self, keyID: str, keyRingID: Optional[str] = None, 
                       version: Optional[int] = None) -> types.PUBLIC_KEY_TYPES:
        """Returns the public key of the provided key ID.

        Args:
            keyID (str): 
                the key ID/name of the key
            keyRingID (str): 
                the key ring ID (Defaults to KEY_RING_ID attribute of the object)
            version (int):
                the key version (Defaults to the latest version)

        Returns:
            publicKey (types.PUBLIC_KEY_TYPES): the public key
        """
        if (keyRingID is None):
            keyRingID = self.KEY_RING_ID

        if (version is None):
            version = self.get_latest_key_ver(keyID=keyID, keyRingID=keyRingID)

        # Construct the key version name
        keyVersionName = self.KMS_CLIENT.crypto_key_version_path(
            C.GOOGLE_PROJECT_NAME, C.GOOGLE_PROJECT_LOCATION, keyRingID, keyID, version
        )

        # Get the public key from Google Cloud KMS API
        publicKey = self.KMS_CLIENT.get_public_key(request={"name": keyVersionName})

        # Extract and parse the public key as a PEM-encoded RSA public key
        publicKey = serialization.load_pem_public_key(
            data=publicKey.pem.encode("utf-8"),
            backend=default_backend()
        )
        return publicKey

class RSA(Asymmetric):
    """Creates an authenticated GCP KMS client that uses RSA-OAEP-SHA for cryptographic operations."""
    def __init__(self, digestMethod: Optional[Callable] = hashes.SHA512) -> None:
        if (not issubclass(digestMethod, hashes.HashAlgorithm)):
            raise TypeError("digestMethod must be a subclass of cryptography.hazmat.primitives.hashes.HashAlgorithm")

        self.__DIGEST_METHOD = digestMethod
        super().__init__()

    def encrypt(self, plaintext: str | bytes, keyID: str,
                keyRingID: Optional[str] = None, version: Optional[int] = None) -> bytes:
        if (keyRingID is None):
            keyRingID = self.KEY_RING_ID

        if (version is None):
            version = self.get_latest_key_ver(keyID=keyID, keyRingID=keyRingID)

        if (isinstance(plaintext, str)):
            plaintext = plaintext.encode("utf-8")

        # Encrypt the plaintext with the public key
        publicKey = self.get_public_key(keyID=keyID, keyRingID=keyRingID, version=version)
        return rsa_encrypt(plaintext=plaintext, publicKey=publicKey, digestMethod=self.__DIGEST_METHOD)

    def decrypt(self, ciphertext: bytes, keyID: str,
                keyRingID: Optional[str] = None, version: Optional[int] = None) -> bytes:
        if (keyRingID is None):
            keyRingID = self.KEY_RING_ID

        if (version is None):
            version = self.get_latest_key_ver(keyID=keyID, keyRingID=keyRingID)

        # Construct the key version name
        keyVersionName = self.KMS_CLIENT.crypto_key_version_path(
            C.GOOGLE_PROJECT_NAME, C.GOOGLE_PROJECT_LOCATION, keyRingID, keyID, version
        )

        # Compute the ciphertext's CRC32C checksum before sending it to Google Cloud KMS API
        cipherTextCRC32C = crc32c(ciphertext)

        # send the request to Google Cloud KMS API to decrypt the ciphertext
        try:
            response = self.KMS_CLIENT.asymmetric_decrypt(
                request={"name": keyVersionName, "ciphertext": ciphertext, "ciphertext_crc32c": cipherTextCRC32C}
            )
        except (GoogleErrors.InvalidArgument) as e:
            self.log_failed_decryption(ciphertext=ciphertext, error=e)

        # Perform a integrity check on the decrypted data that Google Cloud KMS API returned
        # details: https://cloud.google.com/kms/docs/data-integrity-guidelines
        if (not response.verified_ciphertext_crc32c):
            # request sent to Google Cloud KMS API was corrupted in-transit
            raise CRC32ChecksumError("Ciphertext CRC32C checksum does not match.")
        if (response.plaintext_crc32c != crc32c(response.plaintext)):
            # response received from Google Cloud KMS API was corrupted in-transit
            raise CRC32ChecksumError("Plaintext CRC32C checksum does not match.")

        return response.plaintext

AESGCM = AESGCM()
RSA = RSA()

__all__ = [
    "AESGCM",
    "RSA"
]