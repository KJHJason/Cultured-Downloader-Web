# import third-party libraries
from pydantic import BaseModel, Field

# import Python's standard libraries
import enum

@enum.unique
class GDriveAttachmentType(str, enum.Enum):
    """Supported attachment type when quering Google Drive API."""
    FILE = "file"
    FOLDER = "folder"

class GDriveJsonRequest(BaseModel):
    """The JSON payload schema for the user
    when querying the Google Drive API."""
    drive_id: str | set[str] = Field(
        min_items=2
    )
    attachment_type: GDriveAttachmentType