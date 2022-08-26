# import Python's standard libraries
import pathlib
from dataclasses import dataclass
from six import ensure_binary

# import third-party libraries
from google_crc32c import Checksum as g_crc32c

def crc32c(data: bytes | str) -> int:
    """Calculates the CRC32C checksum of the provided data

    Args:
        data (str|bytes): 
            The bytes of the data which the checksum should be calculated.
            If the data is in string format, it will be encoded to bytes.

    Returns:
        An int representing the CRC32C checksum of the provided bytes
    """
    return int(g_crc32c(initial_value=ensure_binary(data, encoding="utf-8")).hexdigest(), 16)

@dataclass(frozen=True, repr=False)
class Constants:
    """This dataclass is used to store all the important constants used 
    during initialisation of the web application.
    """
    # For the web application
    ROOT_DIR_PATH: pathlib.Path = pathlib.Path(__file__).parent.parent.absolute()
    CONFIG_DIR_PATH: pathlib.Path = ROOT_DIR_PATH.joinpath("config_files")

    # For GCP-related constants
    GOOGLE_PROJECT_NAME: str = "cultureddownloader"
    GOOGLE_PROJECT_LOCATION: str = "asia-southeast1"

CONSTANTS = Constants()

__all__ = [
    "CONSTANTS"
]