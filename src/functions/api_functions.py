# import third party libraries
import requests
from requests.exceptions import HTTPError, ConnectionError, Timeout, RequestException

# import local python libraries
from classes import APP_CONSTANTS as AC

def send_request(gdriveID: str, gdriveType: str) -> dict:
    """Sends a request to the Google Drive API to get the 
    json representation of the gdrive URL's directory structure

    Args:
        gdriveID (str): 
            The ID of the Google Drive URL
        gdriveType (str):
            The type of the Google Drive URL

    Returns:
        dict:
            The json representation of the gdrive URL's directory structure
    """
    if (gdriveType == "file"):
        url = f"https://www.googleapis.com/drive/v3/files/{gdriveID}?key={AC.GDRIVE_API_TOKEN}"
    else:
        url = f"https://www.googleapis.com/drive/v3/files?q=%27{gdriveID}%27+in+parents&key={AC.GDRIVE_API_TOKEN}"

    try:
        return requests.get(url, headers=AC.REQ_HEADERS).json()
    except (HTTPError, ConnectionError, Timeout, RequestException) as e:
        return {"error": str(e)}