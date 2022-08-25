# import Python's standard libraries
import pathlib
from dataclasses import dataclass

@dataclass(frozen=True, repr=False)
class Constants:
    """This dataclass is used to store all the important constants used 
    during initialisation of the web application.
    """
    ROOT_DIR_PATH: pathlib.Path = pathlib.Path(__file__).parent.parent.absolute()
    CONFIG_DIR_PATH: pathlib.Path = ROOT_DIR_PATH.joinpath("config_files")
    GOOGLE_PROJECT_NAME: str = "cultureddownloader"

CONSTANTS = Constants()

__all__ = [
    "CONSTANTS"
]