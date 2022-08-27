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
import base64
from typing import Optional, Callable, Any
from binascii import Error as BinasciiError

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

class GCP_KMS:
    """Creates an authenticated Cloud KMS client that can be used for cryptographic operations."""
    def __init__(self) -> None:
        self.__KMS_CLIENT = kms.KeyManagementServiceClient.from_service_account_info(
            info=json.loads(SECRET_MANAGER.get_secret_payload(secretID="google-kms"))
        )
        self.__KEY_RING_ID = "dev" if (AC.DEBUG_MODE) else "web-app"

    def log_failed_decryption(self, ciphertext: bytes, error: Any) -> None:
        """Logs the failed decryption attempt to the Cloud Logger and raise DecryptionError."""
        try:
            ciphertextToLog = base64.urlsafe_b64encode(ciphertext).decode("utf-8")
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

class GCP_AESGCM(GCP_KMS):
    """Creates an authenticated GCP KMS client that uses AES-256-GCM for cryptographic operations."""
    def __init__(self, keyID: Optional[str] = None) -> None:
        """Constructor for GCP_AESGCM

        Attributes:
            keyID (str):
                The default key ID to use for encryption/decryption (Defaults to None)
        """
        self.KEY_ID = keyID
        super().__init__()

    def symmetric_encrypt(self, plaintext: str | bytes, keyID: Optional[str] = None, keyRingID: Optional[str] = None) -> bytes:
        """Using AES-256-GCM to encrypt the provided plaintext via GCP KMS.

        Args:
            plaintext (str|bytes): 
                the plaintext to encrypt
            keyRingID (str): 
                the key ring ID (Defaults to KEY_RING_ID attribute of the object)
            keyID (str): 
                the key ID/name of the key (Defaults to KEY_ID attribute of the object)

        Returns:
            ciphertext (bytes): the ciphertext in bytes format

        Raises:
            ValueError:
                If the keyID is not provided
            CRC32ChecksumError:
                If the integrity checks failed
        """
        if (keyID is None):
            if (self.KEY_ID is None):
                raise ValueError("Please provide a key ID.")
            keyID = self.KEY_ID

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

    def symmetric_decrypt(self, ciphertext: bytes, keyID: Optional[str] = None, 
                keyRingID: Optional[str] = None, decode: Optional[bool] = False) -> str | bytes:
        """Using AES-256-GCM to decrypt the provided ciphertext via GCP KMS.

        Args:
            ciphertext (bytes): 
                the ciphertext to decrypt
            keyRingID (str): 
                the key ring ID (Defaults to KEY_RING_ID attribute of the object)
            keyID (str): 
                the key ID/name of the key (Defaults to KEY_ID attribute of the object)
            decode (bool): 
                whether to decode the decrypted plaintext to string (Defaults to True)

        Returns:
            plaintext (str): the plaintext

        Raises:
            TypeError: 
                If the ciphertext is not bytes
            ValueError:
                If the keyID is not provided
            DecryptionError: 
                If the decryption failed
            CRC32ChecksumError: 
                If the integrity checks failed
        """
        if (isinstance(ciphertext, bytearray)):
            ciphertext = bytes(ciphertext)

        if (not isinstance(ciphertext, bytes)):
            print("cipher", ciphertext)
            raise TypeError(f"The ciphertext, {ciphertext} is in \"{type(ciphertext)}\" format. Please pass in a bytes type variable.")

        if (keyID is None):
            if (self.KEY_ID is None):
                raise ValueError("Please provide a key ID.")
            keyID = self.KEY_ID

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

class GCP_Asymmetric(GCP_KMS):
    """Creates an authenticated GCP KMS client that uses asymmetric cryptography operations."""
    def __init__(self, keyVerSecretID: str, keyID: Optional[str] = None) -> None:
        """Constructor for GCP_Asymmetric

        Attributes:
            keyVerSecretID (str):
                the secret ID of the latest key version that is stored in GCP Secret Manager API
            keyID (str):
                The default key ID to use for encryption/decryption (Defaults to None)
        """
        self.__KEY_VERSION_SECRET_ID = keyVerSecretID
        self.KEY_ID = keyID
        super().__init__()

    def get_latest_ver(self) -> int:
        """Returns the latest version of the key version that is stored in GCP Secret Manager API."""
        return int(SECRET_MANAGER.get_secret_payload(secretID=self.__KEY_VERSION_SECRET_ID))

    def get_public_key(self, keyID: Optional[str] = None, 
                       keyRingID: Optional[str] = None, version: Optional[int] = None) -> str:
        """Returns the public key of the provided key ID.

        Args:
            keyID (str): 
                the key ID/name of the key (Defaults to KEY_ID attribute of the object)
            keyRingID (str): 
                the key ring ID (Defaults to KEY_RING_ID attribute of the object)
            version (int):
                the key version (Defaults to the latest version)

        Returns:
            publicKey (str):
                The public key which will have to be serialised to a PEM format later
                in order to use it for cryptographic operations.

        Raises:
            ValueError:
                If the keyID is not provided
        """
        if (keyID is None):
            if (self.KEY_ID is None):
                raise ValueError("Please provide a key ID.")
            keyID = self.KEY_ID

        if (keyRingID is None):
            keyRingID = self.KEY_RING_ID

        if (version is None):
            version = self.get_latest_ver()

        # Construct the key version name
        keyVersionName = self.KMS_CLIENT.crypto_key_version_path(
            C.GOOGLE_PROJECT_NAME, C.GOOGLE_PROJECT_LOCATION, keyRingID, keyID, version
        )

        # Get the public key from Google Cloud KMS API
        return self.KMS_CLIENT.get_public_key(request={"name": keyVersionName}).pem

class GCP_RSA(GCP_Asymmetric):
    """Creates an authenticated GCP KMS client that uses RSA-OAEP-SHA for cryptographic operations."""
    def __init__(self, keyVerSecretID: str, keyID: Optional[str] = None, 
                 digestMethod: Optional[Callable] = hashes.SHA512) -> None:
        """Constructor for GCP_RSA

        Attributes:
            keyVerSecretID (str):
                the secret ID of the latest key version that is stored in GCP Secret Manager API
            digestMethod (Callable, Optional):
                The digest method to use (Defaults to SHA512) which must be part of the cryptography module
        """
        if (not issubclass(digestMethod, hashes.HashAlgorithm)):
            raise TypeError("digestMethod must be a subclass of cryptography.hazmat.primitives.hashes.HashAlgorithm")

        self.__DIGEST_METHOD = digestMethod
        super().__init__(keyID=keyID, keyVerSecretID=keyVerSecretID)

    def asymmetric_encrypt(self, plaintext: str | bytes, keyID: Optional[str] = None,
                keyRingID: Optional[str] = None, version: Optional[int] = None) -> bytes:
        """Encrypts the plaintext using RSA-OAEP-SHA via GCP KMS API.

        Args:
            plaintext (str|bytes):
                The plaintext to encrypt
            keyID (str):
                The key ID/name of the key (Defaults to KEY_ID attribute of the object)
            keyRingID (str):
                The key ring ID (Defaults to KEY_RING_ID attribute of the object)
            version (int):
                The key version (Defaults to the latest version)

        Returns:
            The ciphertext (bytes)

        Raises:
            ValueError:
                If the keyID is not provided
        """
        if (keyID is None):
            if (self.KEY_ID is None):
                raise ValueError("Please provide a key ID.")
            keyID = self.KEY_ID

        if (keyRingID is None):
            keyRingID = self.KEY_RING_ID

        if (version is None):
            version = self.get_latest_ver()

        if (isinstance(plaintext, str)):
            plaintext = plaintext.encode("utf-8")

        # Encrypt the plaintext with the public key
        publicKey = self.get_public_key(keyID=keyID, keyRingID=keyRingID, version=version)
        return rsa_encrypt(plaintext=plaintext, publicKey=publicKey, digestMethod=self.__DIGEST_METHOD)

    def asymmetric_decrypt(self, ciphertext: bytes, keyID: Optional[str] = None, 
                keyRingID: Optional[str] = None, version: Optional[int] = None, decode: Optional[bool] = False) -> bytes | str:
        """Encrypts the plaintext using RSA-OAEP-SHA via GCP KMS API.

        Args:
            ciphertext (bytes):
                The ciphertext to decrypt
            keyID (str):
                The key ID/name of the key (Defaults to KEY_ID attribute of the object)
            keyRingID (str):
                The key ring ID (Defaults to KEY_RING_ID attribute of the object)
            version (int):
                The key version (Defaults to the latest version)
            decode (bool):
                If True, the decrypted plaintext is returned as a string (Defaults to False)

        Returns:
            The plaintext (bytes|str)

        Raises:
            DecryptionError: 
                If the decryption failed
            ValueError:
                If the keyID is not provided
        """
        if (keyID is None):
            if (self.KEY_ID is None):
                raise ValueError("Please provide a key ID.")
            keyID = self.KEY_ID

        if (keyRingID is None):
            keyRingID = self.KEY_RING_ID

        if (version is None):
            version = self.get_latest_ver()

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

        return response.plaintext if (not decode) else response.plaintext.decode("utf-8")

class UserCookie(GCP_RSA, GCP_AESGCM):
    """Creates an authenticated GCP KMS client that uses RSA-OAEP-SHA and 
    AES-256-GCM for cryptographic operations with the user's cookies.
    """
    def __init__(self, digestMethod: Optional[Callable] = hashes.SHA512) -> None:
        """Constructor for UserCookie

        Attributes:
            digestMethod (Callable, Optional):
                The digest method to use (Defaults to SHA512) which must be part of the cryptography module
        """
        self.__RSA_KEY = AC.RSA_KEY_ID
        self.__AES_KEY = AC.COOKIE_ENCRYPTION_KEY
        super().__init__(keyVerSecretID=AC.RSA_VERSION_SECRET_ID, digestMethod=digestMethod)

    def get_api_public_key(self) -> str:
        """Gets the public key of the Cultured Downloader API."""
        return self.get_public_key(keyID=self.__RSA_KEY)

    def encrypt_cookie_data(self, cookieData: str | dict, userPublicKey: str) -> str:
        """Encrypts the cookie data using AES-256-GCM via GCP KMS API.

        Args:
            cookieData (str, dict):
                The cookieData to encrypt
            userPublicKey (str):
                The public key of the user

        Returns:
            The base64 encoded ciphertext in string format (utf-8 decoded)

        Raises:
            ValueError:
                If the keyID is not provided
            CRC32ChecksumError:
                If the integrity checks failed
        """
        if (isinstance(cookieData, dict)):
            cookieData = json.dumps(cookieData).encode("utf-8")

        encryptedCookieData = rsa_encrypt(
            plaintext=self.symmetric_encrypt(
                plaintext=cookieData,
                keyID=self.__AES_KEY
            ),
            publicKey=userPublicKey
        )
        return base64.b64encode(encryptedCookieData).decode("utf-8")

    def decrypt_cookie_data(self, encryptedCookieData: bytes, userPublicKey: str) -> str:
        """Decrypts the cookie data using AES-256-GCM via GCP KMS API.

        Args:
            encryptedCookieData (bytes):
                The encrypted cookie data to decrypt
            userPublicKey (str):
                The public key of the user

        Returns:
            The base64 encoded ciphertext in string format (utf-8 decoded)

        Raises:
            ValueError:
                If the keyID is not provided
            CRC32ChecksumError:
                If the integrity checks failed
        """
        cookieData = rsa_encrypt(
            plaintext=self.symmetric_decrypt(
                ciphertext=encryptedCookieData,
                keyID=self.__AES_KEY
            ),
            publicKey=userPublicKey
        )
        return base64.b64encode(cookieData).decode("utf-8")

    def decrypt_cookie_payload(self, encryptedCookie: bytes) -> dict:
        """Decrypts the cookie payload that was sent to the API using the API's private key.

        Args:
            encryptedCookie (bytes): 
                The cookie data to decrypt.

        Returns:
            The decrypted cookie data (dict).
        """
        try:
            encryptedCookie = base64.b64decode(encryptedCookie)
        except (BinasciiError, ValueError, TypeError):
            return {"error": "Failed to base64 decode the cookie ciphertext."}

        try:
            return {"payload": self.asymmetric_decrypt(ciphertext=encryptedCookie, keyID=self.__RSA_KEY)}
        except (DecryptionError):
            return {"error": "Failed to decrypt the cookie ciphertext."}

USER_COOKIE = UserCookie()

__all__ = [
    "GCP_RSA",
    "GCP_AESGCM",
    "USER_COOKIE"
]