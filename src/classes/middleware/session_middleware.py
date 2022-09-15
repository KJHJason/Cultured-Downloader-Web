# import third-party libraries
from starlette.datastructures import MutableHeaders
from starlette.requests import HTTPConnection
from starlette.types import ASGIApp, Message, Receive, Scope, Send

# import Python's standard libraries
import time

# import local python libraries
if (__package__ is None or __package__ == ""):
    import sys
    import pathlib
    sys.path.append(str(pathlib.Path(__file__).parent.parent))

    from api_hmac import JWT_HMAC, URLSafeSerialiserHMAC
else:
    from classes.api_hmac import JWT_HMAC, URLSafeSerialiserHMAC

class SessionMiddleware:
    """Session middleware inspired by 
    https://github.com/aogier/starlette-authlib/blob/master/starlette_authlib/middleware.py

    This implementation of session middleware takes the secret key used from
    Google Cloud Platform Secret Manager API.
    """
    def __init__(self, 
        app: ASGIApp, 
        signer: JWT_HMAC | URLSafeSerialiserHMAC,
        session_cookie: str = "session",
        max_age: int | None = 3600 * 24 * 14,  # 14 days, in seconds
        path: str | None = "/",
        same_site: str = "lax",
        https_only: bool = False,
        domain: str | None = None
    ) -> None:
        """Constructor for AuthlibJWTMiddleware.

        Attributes:
            app (ASGIApp):
                Starlette application.
            signer (JWT_HMAC | URLSafeSerialiserHMAC):
                The signer to use for signing and verifying the session cookie.
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
        self.signer = signer
        self.domain = domain
        self.session_cookie = session_cookie
        self.max_age = max_age
        if (isinstance(signer, URLSafeSerialiserHMAC)):
            # A precaution if the URLSafeSerialiserHMAC is used 
            # and its max_age is not configured properly.
            signer.max_age = self.max_age

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
            data = self.signer.get(data, default={})
            scope["session"] = data
            initial_session_was_empty = False
        else:
            scope["session"] = {}

        async def send_wrapper(message: Message) -> None:
            if (message["type"] == "http.response.start"):
                session = scope["session"]
                if (session):
                    is_jwt = isinstance(self.signer, JWT_HMAC)
                    if (is_jwt and "exp" not in session and self.max_age is not None):
                        session["exp"] = time.time() + self.max_age

                    data = self.signer.sign(session)
                    if (is_jwt):
                        data = data.decode("utf-8")

                    headers = MutableHeaders(scope=message)
                    header_value = "{session_cookie}={data}; path={path}; {max_age}{security_flags}{domain}".format(
                        session_cookie=self.session_cookie,
                        data=data,
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