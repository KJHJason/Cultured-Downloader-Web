# import third-party libraries
from authlib.jose.errors import JoseError
from authlib.jose import JsonWebToken, JWTClaims
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired, Signer

# import Python's standard libraries
import time
import hashlib
from typing import Any, Callable
from datetime import datetime
from zoneinfo import ZoneInfo

# import local python libraries
if (__package__ is None or __package__ == ""):
    from secret_manager import SECRET_MANAGER
    from cloud_logger import CLOUD_LOGGER
    from app_constants import APP_CONSTANTS
else:
    from .secret_manager import SECRET_MANAGER
    from .cloud_logger import CLOUD_LOGGER
    from .app_constants import APP_CONSTANTS

class JWT_HMAC:
    """Mainly for the API's JWT middleware that is capable of session cookies 
    similar to Flask's session cookies that uses the Authlib library for JWT support.

    Note that the key must be stored in Google Cloud Platform Secret Manager API 
    as there is no way to set the key in this class. This helps improves security at the expense of speed
    as the key will always be the latest key stored in Google Cloud Platform Secret Manager API.
    """
    def __init__(self, secret_key_id: str, digest_method: str, claim_options: dict | None = None) -> None:
        """Constructor for JWT_HMAC class.

        Example usage:
            jwt = JWT_HMAC(
                secret_key_id="secret_key_id",
                digest_method="sha256",
                claim_options={
                    "iss": {
                        "essential": True,
                        "value": "Cultured Downloader"
                    }
                }
            )

        Attributes:
            secret_key_id (str):
                The secret key ID of the HMAC secret key stored in Google Cloud Platform Secret Manager API.
            digest_method (str):
                Digest method name, "sha256", "sha384", "sha512".
            claim_options (dict, optional):
                Options for JWT claims which will be validated against the JWT token. Defaults to None.
                    More info:
                        https://docs.authlib.org/en/latest/jose/jwt.html#jwt-payload-claims-validation
        """
        if (not isinstance(claim_options, dict | None)):
            raise TypeError(f"Invalid claim_options type: {type(claim_options)}")

        self.__CLAIM_OPTIONS = claim_options
        self.__SECRET_KEY_ID = secret_key_id
        self.__ALGO_HEADER = {"alg": self.load_hmac_algorithm(digest_method)}
        self.__JWS = JsonWebToken(
            algorithms=[self.__ALGO_HEADER["alg"]]
        )

    def load_hmac_algorithm(self, digest_method: str) -> str:
        """Load HMAC algorithm from the digest method specified.

        Args:
            digest_method (str):
                digest method name.
                https://docs.authlib.org/en/latest/specs/rfc7518.html#algorithms-for-jws

        Returns:
            str: 
                HMAC algorithm name.
        """
        if (digest_method == "sha256"):
            return "HS256"
        elif (digest_method == "sha384"):
            return "HS384"
        elif (digest_method == "sha512"):
            return "HS512"
        else:
            raise ValueError(f"Only sh256, sha384, and sha512 are supported but not {digest_method}!")

    def __get_secret_key(self) -> bytes:
        """Get the secret key from Google Cloud Platform Secret Manager API."""
        return SECRET_MANAGER.get_secret_payload(
            secret_id=self.__SECRET_KEY_ID, 
            decode_secret=False
        )

    def __get_jwt_claims(
        self, 
        expiry_date: datetime | None = None,
        omit_claims: bool | None = False) -> dict[str, str | int]:
        """Get JWT claims for validations later if required.

        Refer to RFC7519 standards:
            https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1

        Args:
            expiry_date (datetime, optional):
                Expiry date of the JWT token. Defaults to None.
            omit_claims (bool, optional):
                Whether to omit the iss and iat claims from the JWT token. Defaults to False.

        Returns:
            dict[str, str | int]:
                JWT claims.
        """
        jwt_claims = {}
        if (not omit_claims):
            jwt_claims = {
                "iss": APP_CONSTANTS.ISSUER,
                "iat": int(time.time()),
            }

        if (expiry_date is not None):
            if (isinstance(expiry_date, datetime)):
                jwt_claims["exp"] = expiry_date.replace(tzinfo=ZoneInfo("UTC"))
            elif (isinstance(expiry_date, float)):
                jwt_claims["exp"] = int(expiry_date)
            elif (isinstance(expiry_date, int)):
                jwt_claims["exp"] = expiry_date
            else:
                raise TypeError(f"Invalid expiry_date type: {type(expiry_date)}")

        return jwt_claims

    def sign(
        self, 
        payload: dict, 
        expiry_date: datetime | int | float | None = None,
        omit_claims: bool | None = False) -> bytes:
        """Sign the JWT token.

        Args:
            payload (dict):
                Payload of the JWT token.
            expiry_date (datetime|int|float, optional):
                Expiry date of the JWT token. Defaults to None.
            omit_claims (bool, optional):
                Whether to omit the iss and iat claims from the JWT token. Defaults to False.

        Returns:
            bytes:
                Signed JWT token.
        """
        if (expiry_date is not None and not isinstance(expiry_date, datetime | int | float)):
            raise TypeError(f"expiry_date must be a datetime object, a float, or an integer!")

        payload.update(self.__get_jwt_claims(expiry_date, omit_claims))
        return self.__JWS.encode(
            header=self.__ALGO_HEADER,
            payload=payload,
            key=self.__get_secret_key()
        )

    def get(self, token: str | bytes, default: Any | None = None) -> JWTClaims | Any | None:
        """Get the JWT claims and its data payload from the token.

        Args:
            token (str | bytes):
                Signed JWT token.
            default (Any, optional):
                Default value to return if the token is invalid. Defaults to None.

        Returns:
            JWTClaims | Any | None:
                JWT claims if the token is valid. Otherwise, return the default value.
        """
        try:
            claims = self.__JWS.decode(
                token,
                key=self.__get_secret_key(),
                claims_options=self.__CLAIM_OPTIONS
            )
            if (self.__CLAIM_OPTIONS is not None):
                claims.validate()
        except (JoseError) as e:
            CLOUD_LOGGER.info(
                content={
                    "message": "Failed to decode and verify JWT token",
                    "error": str(e)
                }
            )
            return default

        return claims

class URLSafeSerialiserHMAC:
    """URL-safe serialiser (HMAC) using the itsdangerous module which 
    generally produces a shorter string length than the JWT HMAC class.

    Note that the secret key must be passed in upon construction of this class and is not 
    dynamically loaded from Google Cloud Platform Secret Manager API unlike the JWT HMAC class.
    Hence, this class is recommended only if the sensitivity of the data 
    to be serialised is not very high or requires high availability and speed.
    """
    def __init__(self, 
        secret_key: str | bytes,
        salt: str | bytes | None = "cultured-downloader".encode("utf-8"),
        digest_method: str = "sha512",
        max_age: int | None = 3600 * 24 * 7 # 7 days
    ) -> None:
        """Constructor for the URLSafeSerialiserHMAC class.

        Attributes:
            secret_key (str | bytes):
                Secret key that will be used to sign the data.
            salt (str | bytes, optional):
                Salt to be used to sign the data. Defaults to "cultured-downloader" that is utf-8 encoded.
            digest_method (str, optional):
                Digest method to be used to sign the data. Defaults to "sha512".
            max_age (int, optional):
                Maximum age of the signed data in seconds. Defaults to 7 days.
                Warning: If set to None, the signed data will never expire.
        """
        digest_method = digest_method.lower()
        if (digest_method != "sha1"):
            digest_method = self.get_digest_method_function(digest_method)
            signer_kwargs = {
                "digest_method": staticmethod(digest_method)
            }
        else:
            # Since the itsdangerous module uses 
            # sha1 as the digest method by default,
            # we do not need to pass in the digest_method 
            # argument in the signer_kwargs dictionary.
            signer_kwargs = None

        self.signer = URLSafeTimedSerializer(
            secret_key=secret_key, 
            salt=salt,
            signer_kwargs=signer_kwargs
        )
        self.max_age = max_age

    def get_digest_method_function(self, digest_method: str) -> Callable:
        """Get the digest method function from the hashlib module.

        Args:
            digest_method (str):
                digest method name.

        Returns:
            Callable: 
                digest method's hashlib function.
        """
        if (digest_method == "sha1"):
            return hashlib.sha1
        elif (digest_method == "sha256"):
            return hashlib.sha256
        elif (digest_method == "sha384"):
            return hashlib.sha384
        elif (digest_method == "sha512"):
            return hashlib.sha512
        else:
            raise ValueError(f"Only sha1, sh256, sha384, and sha512 are supported but not {digest_method}!")

    def sign(self, data: dict | str) -> str:
        """Sign the data with the secret key."""
        return self.signer.dumps(data)

    def get(self, token: str, default: Any | None = None) -> dict | str | Any | None:
        """Get the data payload from the token.

        Args:
            token (str):
                Signed token.
            default (Any, optional):
                Default value to return if the token is invalid. Defaults to None.

        Returns:
            dict | str | Any | None:
                Data payload if the token is valid. Otherwise, return the default value.
        """
        try:
            return self.signer.loads(token, max_age=self.max_age)
        except (BadSignature, SignatureExpired):
            return default

API_JWT_HMAC = JWT_HMAC(
    secret_key_id="api-hmac-secret-key",
    digest_method="sha512",
    claim_options={
        "iss": {
            "essential": True,
            "value": APP_CONSTANTS.ISSUER
        }
    }
)

__hmac_secret_key = SECRET_MANAGER.get_secret_payload(
    secret_id="api-hmac-secret-key",
    decode_secret=False
)
__hmac_salt = SECRET_MANAGER.get_secret_payload(
    secret_id="api-hmac-salt",
    decode_secret=False
)
API_HMAC = URLSafeSerialiserHMAC(
    secret_key=__hmac_secret_key,
    salt=__hmac_salt,
    digest_method="sha512",
    max_age=None
)
CSRF_HMAC = URLSafeSerialiserHMAC(
    secret_key=__hmac_secret_key,
    salt=__hmac_salt,
    digest_method="sha256",
    max_age=APP_CONSTANTS.CSRF_COOKIE_MAX_AGE
)

__all__ = [
    "JWT_HMAC",
    "URLSafeSerialiserHMAC",
    "API_JWT_HMAC",
    "API_HMAC",
    "CSRF_HMAC"
]