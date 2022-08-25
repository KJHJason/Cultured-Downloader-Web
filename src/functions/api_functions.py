# import third party libraries
import requests

# import local python libraries
from classes import APP_CONSTANTS as AC

def send_request(gdriveID: str, gdriveType: str) -> dict:
    if (gdriveType == "file"):
        return requests.get(
            f"https://www.googleapis.com/drive/v3/files/{gdriveID}?key={AC.GDRIVE_API_TOKEN}", 
            headers=AC.REQ_HEADERS
        ).json() 
    else:
        return requests.get(
            f"https://www.googleapis.com/drive/v3/files?q=%27{gdriveID}%27+in+parents&key={AC.GDRIVE_API_TOKEN}",
            headers=AC.REQ_HEADERS
        ).json()