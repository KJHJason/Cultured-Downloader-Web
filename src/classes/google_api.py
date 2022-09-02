# import third-party libraries
import httpx
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request

# import Python's standard libraries
import json

# import local python libraries
if (__package__ is None or __package__ == ""):
    from initialise import CONSTANTS as C
    from secret_manager import SECRET_MANAGER
    from app_constants import APP_CONSTANTS as AC
    from cloud_logger import CLOUD_LOGGER
else:
    from .initialise import CONSTANTS as C
    from .secret_manager import SECRET_MANAGER
    from .app_constants import APP_CONSTANTS as AC
    from .cloud_logger import CLOUD_LOGGER

class GoogleOAuth2:
    """Creates the base Google API service object that can be used for creating
    authenticated API calls to other Google APIs that requires Google OAuth2 authentication"""
    def __init__(self) -> None:
        self.__CREDENTIALS = Credentials.from_authorized_user_info(
            info=json.loads(
                SECRET_MANAGER.get_secret_payload(
                    secret_id=C.OAUTH_TOKEN_SECRET_NAME
                )
            ), 
            scopes=C.GOOGLE_OAUTH_SCOPES
        )

    def get_oauth_access_token(self) -> str:
        """Sends a request to Google and retrieve a short-lived 30 mins to 1 hour token"""
        request = Request()
        self.CREDENTIALS.refresh(request)
        return self.CREDENTIALS.token

    @property
    def CREDENTIALS(self) -> Credentials:
        """Returns the credentials object that can be used to build other 
        authenticated Google API objects via the googleapiclient.discovery.build function"""
        return self.__CREDENTIALS

class GoogleDrive(GoogleOAuth2):
    """Creates an authenticated Google Drive Client that can be used 
    for communicating with Google Drive API v3 with async capabilities."""
    def __init__(self) -> None:
        super().__init__()
        # add some restrictions to prevent the user from reading my own gdrive files
        self.__QUERY = "(visibility='anyoneCanFind' or visibility='anyoneWithLink')"\
                       " and not ('kuanjunhaojason@gmail.com' in owners)"

    async def get_folder_contents(self, folder_id: str, headers: dict | None = None) -> list:
        """Sends a request to the Google Drive API to get the 
        json representation of the folder URL's directory structure

        Args:
            folder_id (str): 
                The ID of the Google Drive URL

        Returns:
            dict:
                The json representation of the gdrive URL's directory structure
        """
        if (headers is None):
            headers = AC.DRIVE_REQ_HEADERS.copy()
            headers["Authorization"] = f"Bearer {self.get_oauth_access_token()}"

        files, page_token = [], None
        async with httpx.AsyncClient(headers=headers, http2=True) as client:
            while (1):
                query = " ".join((f"'{folder_id}' in parents and", self.__QUERY))
                url = f"https://www.googleapis.com/drive/v3/files?q={query}&fields=nextPageToken,files(kind, id, name, mimeType)"
                if (page_token is not None):
                    url += f"&pageToken={page_token}"

                try:
                    response = await client.get(url=url)
                except (
                    httpx.RequestError,
                    httpx.HTTPStatusError,
                    httpx.HTTPError
                ) as e:
                    CLOUD_LOGGER.warning(
                        content={
                            "message": f"error retrieving content from folder, {folder_id}",
                            "error": str(e)
                        }
                    )
                    return {
                        "error": 
                            "could not retrieve file details from Google Drive API... "
                            "please try again later."
                    }

                response = response.json()
                for file in response.get("files", []):
                    files.append(file)

                page_token = response.get("nextPageToken", None)
                if (page_token is None):
                    break

        return {"folder_id": folder_id, "directory": files}

    async def get_file_details(self, file_id: str, headers: dict | None = None) -> dict:
        """Sends a request to the Google Drive API to
        get the json representation of the file details.

        Note that due to privacy reasons, a HTTP request will be sent instead of using
        the in-built Google Drive API, service.files().get(file_id=file_id).execute().

        Args:
            file_id (str): 
                The ID of the Google Drive file

        Returns:
            dict:
                The json representation of the file's details
        """
        if (headers is None):
            headers = AC.DRIVE_REQ_HEADERS.copy()
            headers["Authorization"] = f"Bearer {self.get_oauth_access_token()}"

        async with httpx.AsyncClient(headers=headers, http2=True) as client:
            try:
                url = f"https://www.googleapis.com/drive/v3/files/{file_id}?fields=kind, id, name, mimeType, owners, permissions"
                response = await client.get(url=url)
            except (
                httpx.RequestError,
                httpx.HTTPStatusError,
                httpx.HTTPError
            ) as e:
                CLOUD_LOGGER.warning(
                    content={
                        "message": f"error retrieving file, {file_id}",
                        "error": str(e)
                    }
                )
                return {
                    "error": 
                        "could not retrieve file details from Google Drive API... "
                        "please try again later."
                }

        return {"file_id": file_id, "response": response.json()}