# import third party libraries
import requests

# import local python libraries
from classes import CONSTANTS as C

def send_request(gdriveID: str, gdriveType: str) -> dict:
    if (gdriveType == "file"):
        return requests.get(
            f"https://www.googleapis.com/drive/v3/files/{gdriveID}?key={C.GDRIVE_API_TOKEN}", 
            headers=C.REQ_HEADERS
        ).json() 
    else:
        return requests.get(
            f"https://www.googleapis.com/drive/v3/files?q=%27{gdriveID}%27+in+parents&key={C.GDRIVE_API_TOKEN}",
            headers=C.REQ_HEADERS
        ).json()