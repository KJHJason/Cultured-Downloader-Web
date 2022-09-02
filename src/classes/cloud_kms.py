# For Google Cloud API Errors (Third-party libraries)
import google.api_core.exceptions as GoogleErrors

# For Google Cloud KMS (key management service) API (Third-party libraries)
from google.cloud import kms

# import third-party libraries
from cryptography.hazmat.primitives import hashes

# import Python's standard libraries
import json
import base64
import secrets
import warnings
from typing import Callable, Any
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
            info=json.loads(SECRET_MANAGER.get_secret_payload(secret_id="google-kms"))
        )
        self.__KEY_RING_ID = "api-sg"

    def log_failed_decryption(self, ciphertext: bytes, error: Any) -> None:
        """Logs the failed decryption attempt to the Cloud Logger and raise DecryptionError."""
        try:
            ciphertext_to_log = base64.urlsafe_b64encode(ciphertext).decode("utf-8")
        except:
            ciphertext_to_log = "Could not url-safe base64 encode the ciphertext..."

        CLOUD_LOGGER.info(
            content={
                "Decryption Error": str(error),
                "URL-base64 Encoded Ciphertext": ciphertext_to_log
            }
        )
        raise DecryptionError("Asymmetric Decryption failed.")

    def get_random_bytes(self, 
            n_bytes: int, 
            generate_from_hsm: bool | None = False, 
            return_hex: bool | None = False) -> bytes | str:
        """Generate a random byte/hex string of length n_bytes that is cryptographically secure.

        Args:
            n_bytes (int): 
                The number of bytes to generate.
            generate_from_hsm (bool, optional):
                If True, the random bytes will be generated from GCP KMS's Cloud HSM. (Default: False)
            return_hex (bool, optional):
                If True, the random bytes will be returned as a hex string. (Default: False)

        Returns:
            bytes | str:
                The random bytes or random hex string.
        """
        if (n_bytes < 1):
            raise ValueError("n_bytes must be greater than 0!")

        # Since GCP KMS RNG Cloud HSM's minimum length is 8 bytes, 
        # fallback to secrets library if n_bytes is less than 8
        if (generate_from_hsm and n_bytes < 8):
            warnings.warn(
                message="GCP KMS does not accept n_bytes less than 8, falling back to secrets library...",
                category=RuntimeWarning
            )
            generate_from_hsm = False

        if (not generate_from_hsm):
            if (return_hex):
                return secrets.token_hex(n_bytes)
            else:
                return secrets.token_bytes(n_bytes)

        # Construct the location name
        location_name = self.__KMS_CLIENT.common_location_path(
            C.GOOGLE_PROJECT_NAME, C.GOOGLE_PROJECT_LOCATION
        )

        # Check if the number of bytes exceeds GCP KMS RNG Cloud HSM limit
        if (n_bytes > 1024):
            # if exceeded, make multiple API calls to generate the random bytes
            bytes_arr = []
            max_bytes = 1024
            num_of_max_bytes = n_bytes // max_bytes
            for _ in range(num_of_max_bytes):
                bytes_arr.append(
                    self.__KMS_CLIENT.generate_random_bytes(
                        request={
                            "location": location_name,
                            "length_bytes": max_bytes,
                            "protection_level": kms.ProtectionLevel.HSM
                        }
                    )
                )

            remainder = n_bytes % max_bytes
            if (remainder > 0):
                bytes_arr.append(
                    self.__KMS_CLIENT.generate_random_bytes(
                        request={
                            "location": location_name,
                            "length_bytes": remainder,
                            "protection_level": kms.ProtectionLevel.HSM
                        }
                    )
                )
            random_bytes = b"".join(bytes_arr)
        else:
            # Call the Google Cloud Platform API to generate a random byte string.
            random_bytes_response = self.__KMS_CLIENT.generate_random_bytes(
                request={
                    "location": location_name, 
                    "length_bytes": n_bytes, 
                    "protection_level": kms.ProtectionLevel.HSM
                }
            )
            random_bytes = random_bytes_response.data

        return random_bytes if (not return_hex) else random_bytes.hex()

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
    def __init__(self) -> None:
        """Constructor for GCP_AESGCM"""
        super().__init__()

    def symmetric_encrypt(self, plaintext: str | bytes, key_id: str, key_ring_id: str | None = None) -> bytes:
        """Using AES-256-GCM to encrypt the provided plaintext via GCP KMS.

        Args:
            plaintext (str|bytes): 
                the plaintext to encrypt
            key_id (str): 
                the key ID/name of the key
            key_ring_id (str): 
                the key ring ID (Defaults to KEY_RING_ID attribute of the object)

        Returns:
            ciphertext (bytes): the ciphertext in bytes format

        Raises:
            ValueError:
                If the key_id is not provided
            CRC32ChecksumError:
                If the integrity checks failed
        """
        if (key_ring_id is None):
            key_ring_id = self.KEY_RING_ID

        if (isinstance(plaintext, str)):
            plaintext = plaintext.encode("utf-8")

        # Compute the plaintext's CRC32C checksum before sending it to Google Cloud KMS API
        plaintext_crc32c = crc32c(plaintext)

        # Construct the key version name
        key_version_name = self.KMS_CLIENT.crypto_key_path(
            C.GOOGLE_PROJECT_NAME, C.GOOGLE_PROJECT_LOCATION, key_ring_id, key_id
        )

        # Construct and send the request to Google Cloud KMS API to encrypt the plaintext
        response = self.KMS_CLIENT.encrypt(
            request={"name": key_version_name, "plaintext": plaintext, "plaintext_crc32c": plaintext_crc32c}
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

    def symmetric_decrypt(self, 
            ciphertext: bytes, 
            key_id: str, 
            key_ring_id: str | None = None, 
            decode: bool | None = False) -> str | bytes:
        """Using AES-256-GCM to decrypt the provided ciphertext via GCP KMS.

        Args:
            ciphertext (bytes): 
                the ciphertext to decrypt
            key_id (str): 
                the key ID/name of the key
            key_ring_id (str): 
                the key ring ID (Defaults to KEY_RING_ID attribute of the object)
            decode (bool): 
                whether to decode the decrypted plaintext to string (Defaults to True)

        Returns:
            plaintext (str): the plaintext

        Raises:
            TypeError: 
                If the ciphertext is not bytes
            ValueError:
                If the key_id is not provided
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

        if (key_ring_id is None):
            key_ring_id = self.KEY_RING_ID

        # Construct the key version name
        key_version_name = self.KMS_CLIENT.crypto_key_path(
            C.GOOGLE_PROJECT_NAME, C.GOOGLE_PROJECT_LOCATION, key_ring_id, key_id
        )

        # compute the ciphertext's CRC32C checksum before sending it to Google Cloud KMS API
        ciphertext_crc32c = crc32c(ciphertext)

        # construct and send the request to Google Cloud KMS API to decrypt the ciphertext
        try:
            response = self.KMS_CLIENT.decrypt(
                request={"name": key_version_name, "ciphertext": ciphertext, "ciphertext_crc32c": ciphertext_crc32c}
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
    def __init__(self) -> None:
        """Constructor for GCP_Asymmetric

        Attributes:
            key_secret_id (str):
                the secret ID of the latest key version that is stored in GCP Secret Manager API
            key_id (str):
                The default key ID to use for encryption/decryption (Defaults to None)
        """
        super().__init__()

    def get_latest_ver(self, key_secret_id: str) -> int:
        """Returns the latest version of the key version that is stored in GCP Secret Manager API.

        Args:
            key_secret_id (str):
                the secret ID of the latest key version that is stored in GCP Secret Manager API

        Returns:
            latest_ver (int): 
                the latest version of the key version that is stored in GCP Secret Manager API
        """
        return int(SECRET_MANAGER.get_secret_payload(secret_id=key_secret_id))

    def get_public_key(self, key_id: str, version: int, key_ring_id: str | None = None) -> str:
        """Returns the public key of the provided key ID.

        Args:
            key_id (str): 
                the key ID/name of the key
            key_ring_id (str): 
                the key ring ID (Defaults to KEY_RING_ID attribute of the object)
            version (int):
                the key version

        Returns:
            public_key (str):
                The public key which will have to be serialised to a PEM format later
                in order to use it for cryptographic operations.

        Raises:
            ValueError:
                If the key_id is not provided
        """
        if (key_ring_id is None):
            key_ring_id = self.KEY_RING_ID

        # Construct the key version name
        key_version_name = self.KMS_CLIENT.crypto_key_version_path(
            C.GOOGLE_PROJECT_NAME, C.GOOGLE_PROJECT_LOCATION, key_ring_id, key_id, version
        )

        # Get the public key from Google Cloud KMS API
        return self.KMS_CLIENT.get_public_key(request={"name": key_version_name}).pem

class GCP_RSA(GCP_Asymmetric):
    """Creates an authenticated GCP KMS client that uses RSA-OAEP-SHA for cryptographic operations."""
    def __init__(self) -> None:
        """Constructor for GCP_RSA"""
        super().__init__()

    def asymmetric_encrypt(self, 
            plaintext: str | bytes, 
            key_id: str, version: int,  
            key_ring_id: str | None = None, 
            digest_method: Callable | str | None = hashes.SHA512) -> bytes:
        """Encrypts the plaintext using RSA-OAEP-SHA via GCP KMS API.

        Args:
            plaintext (str|bytes):
                The plaintext to encrypt
            key_id (str):
                The key ID/name of the key
            key_ring_id (str):
                The key ring ID (Defaults to KEY_RING_ID attribute of the object)
            version (int):
                The key version
            digest_method (Callable|str):
                The digest method to use for the encryption (Defaults to SHA512)

        Returns:
            The ciphertext (bytes)

        Raises:
            ValueError:
                If the key_id is not provided
        """
        if (key_ring_id is None):
            key_ring_id = self.KEY_RING_ID

        if (isinstance(plaintext, str)):
            plaintext = plaintext.encode("utf-8")

        # Encrypt the plaintext with the public key
        public_key = self.get_public_key(key_id=key_id, key_ring_id=key_ring_id, version=version)
        return rsa_encrypt(plaintext=plaintext, public_key=public_key, digest_method=digest_method)

    def asymmetric_decrypt(self, 
            ciphertext: bytes, 
            key_id: str | None = None,
            key_ring_id: str | None = None, 
            version: int | None = None, 
            decode: bool | None = False) -> bytes | str:
        """Encrypts the plaintext using RSA-OAEP-SHA via GCP KMS API.

        Args:
            ciphertext (bytes):
                The ciphertext to decrypt
            key_id (str):
                The key ID/name of the key
            key_ring_id (str):
                The key ring ID (Defaults to KEY_RING_ID attribute of the object)
            version (int):
                The key version
            decode (bool):
                If True, the decrypted plaintext is returned as a string (Defaults to False)

        Returns:
            The plaintext (bytes|str)

        Raises:
            DecryptionError: 
                If the decryption failed
            ValueError:
                If the key_id is not provided
        """
        if (key_ring_id is None):
            key_ring_id = self.KEY_RING_ID

        # Construct the key version name
        key_version_name = self.KMS_CLIENT.crypto_key_version_path(
            C.GOOGLE_PROJECT_NAME, C.GOOGLE_PROJECT_LOCATION, key_ring_id, key_id, version
        )

        # Compute the ciphertext's CRC32C checksum before sending it to Google Cloud KMS API
        ciphertext_crc32c = crc32c(ciphertext)

        # send the request to Google Cloud KMS API to decrypt the ciphertext
        try:
            response = self.KMS_CLIENT.asymmetric_decrypt(
                request={"name": key_version_name, "ciphertext": ciphertext, "ciphertext_crc32c": ciphertext_crc32c}
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

class UserData(GCP_RSA, GCP_AESGCM):
    """Creates an authenticated GCP KMS client that uses RSA-OAEP-SHA and 
    AES-256-GCM for cryptographic operations with the user's data.
    """
    def __init__(self) -> None:
        """Constructor for UserData
        """
        self.__AES_KEY = AC.COOKIE_ENCRYPTION_KEY
        super().__init__()

    def get_rsa_key_info(self, digest_method: str) -> tuple[str, int]:
        """Get the key ID and key version of the RSA key depending on the digest method

        Args:
            digest_method (str):
                The digest method to use for the encryption.
                supported digest methods are: "sha256" and "sha512"

        Returns:
            The key ID and key version of the RSA key as a tuple
        ."""
        if (digest_method == "sha256"):
            key = AC.RSA_SHA256_KEY_ID
            secret_id = AC.RSA_SHA256_VERSION_SECRET_ID
        else:
            key = AC.RSA_SHA512_KEY_ID
            secret_id = AC.RSA_SHA512_VERSION_SECRET_ID

        return key, secret_id

    def get_key_info(self, digest_method: str, get_public_key: bool | None = False) -> dict:
        """Get the key ID and key version of the key depending on the digest method

        Args:
            digest_method (str):
                The digest method to use for the encryption.
                supported digest methods are: "sha256" and "sha512"
            get_public_key (bool):
                If True, the public key is also returned (Defaults to False)
                Defaults to False.

        Returns:
            The key ID and key version of the key as a dict.
            Example returned dictionary: {
                "key_id": str,
                "secret_id": int,
                "latest_version": int,
                "public_key": str | None
            }
        """
        key, secret_id = self.get_rsa_key_info(digest_method)
        latest_ver = self.get_latest_ver(key_secret_id=secret_id)
        key_info = {
            "key_id": key,
            "secret_id": secret_id,
            "latest_version": latest_ver
        }

        if (get_public_key):
            key_info["public_key"] = self.get_public_key(key_id=key, version=latest_ver)
            return key_info

        return key_info

    def get_api_rsa_public_key(self, digest_method: str) -> str:
        """Gets the RSA public key of the Cultured Downloader API.

        Args:
            digest_method (str):
                The digest method to use for the encryption

        Returns:
            The RSA public key of the Cultured Downloader API depending on the digest method
        """
        return self.get_key_info(digest_method=digest_method, get_public_key=True)["public_key"]

    def encrypt_user_data(self, 
            user_data: str | dict | bytes, 
            user_public_key: str, 
            digest_method: str | None = None) -> str:
        """Encrypts the user's data using AES-256-GCM via GCP KMS API.

        Args:
            user_data (str, dict, bytes):
                The user_data to encrypt
            user_public_key (str):
                The public key of the user
            digest_method (str):
                The digest method to use (Defaults to SHA512) for
                RSA-OAEP-SHA encryption which must be part of the cryptography module.

        Returns:
            The base64 encoded ciphertext in string format (utf-8 decoded).

        Raises:
            ValueError:
                If the key_id is not provided
            CRC32ChecksumError:
                If the integrity checks failed
        """
        if (isinstance(user_data, str)):
            user_data = user_data.encode("utf-8")
        elif (isinstance(user_data, dict)):
            user_data = json.dumps(user_data).encode("utf-8")

        encrypted_user_data = rsa_encrypt(
            plaintext=self.symmetric_encrypt(
                plaintext=user_data,
                key_id=self.__AES_KEY
            ),
            public_key=user_public_key,
            digest_method=digest_method
        )
        return base64.b64encode(encrypted_user_data).decode("utf-8")

    def decrypt_user_data(self, 
            encrypted_user_data: bytes, 
            user_public_key: str, 
            digest_method: str | None = None) -> str:
        """Decrypts the user's data using AES-256-GCM via GCP KMS API.

        Args:
            encrypted_user_data (bytes):
                The encrypted cookie data to decrypt
            user_public_key (str):
                The public key of the user
            digest_method (str):
                The digest method to use (Defaults to SHA512) for
                RSA-OAEP-SHA encryption which must be part of the cryptography module.

        Returns:
            The base64 encoded ciphertext in string format (utf-8 decoded)

        Raises:
            ValueError:
                If the key_id is not provided
            CRC32ChecksumError:
                If the integrity checks failed
        """
        user_data = rsa_encrypt(
            plaintext=self.symmetric_decrypt(
                ciphertext=encrypted_user_data,
                key_id=self.__AES_KEY
            ),
            public_key=user_public_key,
            digest_method=digest_method
        )
        return base64.b64encode(user_data).decode("utf-8")

    def decrypt_user_payload(self, encrypted_data: bytes, digest_method: str) -> dict[str, bytes]:
        """Decrypts the cookie payload that was sent to the API using the API's private key.

        Args:
            encrypted_data (bytes): 
                The cookie data to decrypt.
            digest_method (str):
                The digest method to use (Defaults to SHA512) for RSA-OAEP-SHA encryption.

        Returns:
            The decrypted cookie data (dict).
        """
        try:
            encrypted_data = base64.b64decode(encrypted_data)
        except (BinasciiError, ValueError, TypeError):
            return {"error": "Failed to base64 decode user's data ciphertext."}

        key_info = self.get_key_info(digest_method=digest_method)
        try:
            decrypted_data = self.asymmetric_decrypt(
                ciphertext=encrypted_data,
                key_id=key_info["key_id"],
                version=key_info["latest_version"]
            )
        except (DecryptionError):
            return {"error": "Failed to decrypt user's data ciphertext."}

        return {"payload": decrypted_data}

USER_DATA = UserData()

__all__ = [
    "GCP_RSA",
    "GCP_AESGCM",
    "USER_DATA"
]