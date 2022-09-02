# import third-party libraries
from fastapi import Request, Response
from starlette.types import ASGIApp
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

# import Python's standard libraries
import re

class CacheControlURLRule:
    """Creates an object that contains the path and cache control headers for a route"""
    def __init__(self, path: str, cache_control: str) -> None:
        """Configure the cache control headers for a particular route URL

        Attributes:
            path (str|re.Pattern): 
                The url path of the route
            cache_control (str): 
                The cache control headers for the route
        """
        self.__path = path
        self.__cache_control = cache_control

    @property
    def path(self) -> str | re.Pattern:
        """The url path of the route"""
        return self.__path

    @property
    def cache_control(self) -> str:
        """The cache control headers for the route"""
        return self.__cache_control

class CacheControlMiddleware(BaseHTTPMiddleware):
    """Adds a Cache-Control header to the specified API routes (Only if the status code is 2XX).

    With reference to: https://github.com/attakei/fastapi-simple-cache_control"""
    def __init__(self, app: ASGIApp, routes: tuple[CacheControlURLRule] | list[CacheControlURLRule]) -> None:
        """Adds a Cache-Control header to the specified API routes.

        Attributes:
            cache_control (str):
                The cache-control header value
            routes (tuple | list):
                The API routes to add the cache-control header to
        """
        routes_rule = []
        for route in routes:
            if (isinstance(route, CacheControlURLRule)):
                routes_rule.append(route)
            else:
                raise TypeError(f"Invalid route type: {type(route)}")

        self.__routes = tuple(routes_rule)
        super().__init__(app)

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        user_req_path = request.url.path
        status_code = response.status_code
        if (status_code >= 200 and status_code < 300):
            for route in self.__routes:
                if (
                    (isinstance(route.path, str) and user_req_path == route.path) ^ 
                    (isinstance(route.path, re.Pattern) and route.path.match(user_req_path) is not None)
                ):
                    response.headers["Cache-Control"] = route.cache_control
                    return response

        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        return response