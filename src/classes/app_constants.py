# import Python's standard libraries
import re
from dataclasses import dataclass

@dataclass(frozen=True, repr=False)
class AppConstants:
    """This dataclass is used to store all the constants used in the application."""
    DEBUG_MODE: bool = True

    # For caching
    BLUEPRINT_ENDPOINT_REGEX: re.Pattern[str] = re.compile(r"^[\w]+(.)[\w]+$")

    # For limiter configurations
    DEFAULT_REQUEST_LIMIT: str = "15 per second"

APP_CONSTANTS = AppConstants()

__all__ = [
    "APP_CONSTANTS"
]