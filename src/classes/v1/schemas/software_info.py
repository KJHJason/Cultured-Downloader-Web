# import third-party libraries
from pydantic import BaseModel, Field

class LatestVerResponse(BaseModel):
    """The JSON payload schema for the latest version of the Cultured Downloader software."""
    version: str = Field(
        description="The latest version of the Cultured Downloader software.",
        example="4.0.0"
    )
    download_url: str = Field(
        description="The URL to download the latest version of the Cultured Downloader software.",
        example="https://cultureddownloader.com/api/v1/software/latest/file"
    )