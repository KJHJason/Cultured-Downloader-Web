# import third-party libraries
from authlib.jose import JsonWebToken, JWTClaims
from authlib.jose.errors import JoseError
from starlette.config import Config
from starlette.datastructures import MutableHeaders
from starlette.requests import HTTPConnection
from starlette.types import ASGIApp, Message, Receive, Scope, Send

# import Python's standard libraries
import time
from typing import Any
from datetime import datetime
from zoneinfo import ZoneInfo

# import local python libraries
if (__package__ is None or __package__ == ""):
    import sys
    import pathlib
    sys.path.append(str(pathlib.Path(__file__).parent.parent))

    from secret_manager import SECRET_MANAGER
    from cloud_logger import CLOUD_LOGGER
    from app_constants import APP_CONSTANTS
else:
    from classes.secret_manager import SECRET_MANAGER
    from classes.cloud_logger import CLOUD_LOGGER
    from classes.app_constants import APP_CONSTANTS

class JWT_HMAC:
    """Mainly for the API's JWT middleware that is capable of session cookies 
    similar to Flask's session cookies that uses the Authlib library for JWT support.

    The key must be stored in Google Cloud Platform Secret Manager API as there is no way to set the key in this class.
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
        if (not isinstance(claim_options, dict)):
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

    def __get_jwt_claims(self, expiry_date: datetime | None = None) -> dict[str, str | int]:
        """Get JWT claims for validations later if required.

        Refer to RFC7519 standards:
            https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1

        Args:
            expiry_date (datetime, optional):
                Expiry date of the JWT token. Defaults to None.

        Returns:
            dict[str, str | int]:
                JWT claims.
        """
        jwt_claims = {
            "iss": APP_CONSTANTS.ISSUER,
            "iat": time.time(),
        }

        if (expiry_date is not None):
            jwt_claims["exp"] = expiry_date.replace(tzinfo=ZoneInfo("UTC"))

        return jwt_claims

    def sign(self, payload: dict, expiry_date: datetime | None = None) -> bytes:
        """Sign the JWT token.

        Args:
            payload (dict):
                Payload of the JWT token.
            expiry_date (datetime, optional):
                Expiry date of the JWT token. Defaults to None.

        Returns:
            bytes:
                Signed JWT token.
        """
        if (expiry_date is not None and not isinstance(expiry_date, datetime)):
            raise TypeError(f"expiry_date must be a datetime object!")

        payload.update(self.__get_jwt_claims(expiry_date))
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

API_HMAC = JWT_HMAC(
    secret_key_id="api-hmac-secret-key",
    digest_method="sha512",
    claim_options={
        "iss": {
            "essential": True,
            "value": APP_CONSTANTS.ISSUER
        }
    }
)

class AuthlibJWTMiddleware:
    """Authlib JWT middleware inspired by 
    https://github.com/aogier/starlette-authlib/blob/master/starlette_authlib/middleware.py

    This implementation of session middleware takes the secret key used from
    Google Cloud Platform Secret Manager API.
    """
    def __init__(self, 
        app: ASGIApp, 
        jwt_obj: JWT_HMAC,
        session_cookie: str = "session",
        max_age: int | None = 14 * 24 * 60 * 60,  # 14 days, in seconds
        path: str | None = "/",
        same_site: str = "lax",
        https_only: bool = False,
        domain: str | None = Config(".env")("DOMAIN", cast=str, default=None)
    ) -> None:
        """Constructor for AuthlibJWTMiddleware.

        Attributes:
            app (ASGIApp):
                Starlette application.
            jwt_obj (JWT_HMAC):
                JWT object with configuration set.
            session_cookie (str, optional):
                Name of the session cookie. Defaults to "session".
            max_age (int, optional):
                Maximum age of the session cookie. Defaults to 14 days in seconds.
                If None, the cookie will be a session cookie which expires when the browser is closed.
            path (str, optional):
                Path of the session cookie. Defaults to "/".
            same_site (str, optional):
                Same site policy of the session cookie. Defaults to "lax".
            https_only (bool, optional):
                Whether the session cookie can only be sent over HTTPS. Defaults to False.
            domain (str, optional):
                Domain of the session cookie. Defaults to None.
        """
        self.app = app
        self.jwt = jwt_obj
        self.domain = domain
        self.session_cookie = session_cookie
        self.max_age = max_age
        self.path = path
        self.security_flags = f"httponly; samesite={same_site}"
        if (https_only): 
            self.security_flags += "; secure"

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if (scope["type"] not in ("http", "websocket")):
            await self.app(scope, receive, send)
            return

        connection = HTTPConnection(scope)
        initial_session_was_empty = True
        if (self.session_cookie in connection.cookies):
            data = connection.cookies[self.session_cookie].encode("utf-8")
            data = self.jwt.get(data, default={})
            scope["session"] = data
            initial_session_was_empty = False
        else:
            scope["session"] = {}

        async def send_wrapper(message: Message) -> None:
            if (message["type"] == "http.response.start"):
                session = scope["session"]
                if (session):
                    if ("exp" not in session and self.max_age is not None):
                        session["exp"] = time.time() + self.max_age
                    data = self.jwt.sign(session)

                    headers = MutableHeaders(scope=message)
                    header_value = "{session_cookie}={data}; path={path}; {max_age}{security_flags}{domain}".format(
                        session_cookie=self.session_cookie,
                        data=data.decode("utf-8"),
                        path=self.path,
                        max_age=f"max-age={self.max_age}; " if (self.max_age is not None) else "",
                        security_flags=self.security_flags,
                        domain=f"; domain={self.domain}" if (self.domain is not None) else ""
                    )
                    headers.append("Set-Cookie", header_value)
                elif (not initial_session_was_empty):
                    # The session has been cleared.
                    headers = MutableHeaders(scope=message)
                    header_value = "{session_cookie}=null; path={path}; {expires}{security_flags}{domain}".format(
                        session_cookie=self.session_cookie,
                        path=self.path,
                        expires="expires=Thu, 01 Jan 1970 00:00:00 GMT; ",
                        security_flags=self.security_flags,
                        domain=f"; domain={self.domain}" if (self.domain is not None) else ""
                    )
                    headers.append("Set-Cookie", header_value)
            await send(message)

        await self.app(scope, receive, send_wrapper)