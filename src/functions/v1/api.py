def format_gdrive_json_response(json_response: dict) -> dict:
    """Formats the JSON response to be returned to the user.

    Args:
        json_response (dict):
            The JSON response from GDrive API v3.

    Returns:
        dict:
            The formatted JSON response.
    """
    gdrive_json_response = json_response.get("response") or json_response
    mimetype = "folder" if (gdrive_json_response.get("mimeType") == "application/vnd.google-apps.folder") \
                        else "file"

    if ("error" not in gdrive_json_response and "permissions" not in gdrive_json_response):
        gdrive_json_response.pop("owners", None)
        return {mimetype: gdrive_json_response}

    # Permissions checking only concerns when retrieving a file details.
    # If the response returned the permissions of a file,
    # it means that I have writer/owner access to the file.
    # Hence, checking if anyone can view the file due to privacy reasons
    # as we don't want to expose the file id of my own personal files.
    if ("permissions" in gdrive_json_response):
        permission_list = gdrive_json_response["permissions"]
        for permission_dict in permission_list:
            permission_id = permission_dict["id"]
            if (permission_id == "anyoneWithLink" or permission_id == "anyoneCanFind"):
                gdrive_json_response.pop("owners", None)
                gdrive_json_response.pop("permissions", None)
                return {mimetype: gdrive_json_response}

    # check if it's because of invalid credentials in the header or
    # there was a problem with the request such as 404 not found.
    if ("error" in gdrive_json_response):
        error_dict = gdrive_json_response["error"]
        error_code = error_dict["code"]
        if (error_code == 404):
            error_msg = {}
            if ("file_id" in json_response):
                error_msg["file_id"] = json_response["file_id"]

            error_msg["error"] = {
                "code": 404,
                "message": f"{mimetype} not found"
            }
            return error_msg

        # check the error reasons
        error_list = error_dict.get("errors", None)
        if (isinstance(error_list, list)):
            if (error_list[0].get("reason", "") == "authError"):
                error_msg = {}
                if ("file_id" in json_response):
                    error_msg["file_id"] = json_response["file_id"]

                error_msg["error"] = {
                    "code": 401,
                    "message": "cultured downloader is facing some issues with google drive API",
                    "suggested action": "please raise an issue on github or try again later"
                }
                return error_msg

    return gdrive_json_response # return the original gdrive API JSON response

def format_file_json_responses(json_responses: list[dict]) -> list[dict]:
    """Formats an array of JSON responses to be returned to the user.

    Args:
        json_responses (list[dict]):
            The JSON responses from GDrive API v3.

    Returns:
        list[dict]:
            The formatted JSON responses.
    """
    return [
        format_gdrive_json_response(json_response) 
        for json_response in json_responses
    ]

def format_directory_json_response(directory_json_response: dict) -> dict:
    """Formats the JSON response of a directory to be returned to the user.

    Args:
        directory_json_response (dict):
            The JSON response of a directory from GDrive API v3.

    Returns:
        dict:
            The formatted JSON response of a directory.
    """
    directory_response = directory_json_response["directory"]
    if (len(directory_response) < 1):
        directory_response = {
            "error": {
                "code": 404,
                "message": f"folder not found"
            }
        }
    else:
        directory_response = [
            format_gdrive_json_response(file_details) 
            for file_details in directory_response
        ]

    formatted_directory_json_response = {
        "folder_id": directory_json_response["folder_id"],
        "directory": directory_response
    }
    return formatted_directory_json_response

def format_directory_json_responses(directory_json_responses: list[dict]) -> list[dict]:
    """Formats an array of JSON responses of directories to be returned to the user.

    Args:
        directory_json_responses (list[dict]):
            The JSON responses of directories from GDrive API v3.

    Returns:
        list[dict]:
            The formatted JSON responses of directories.
    """
    return [
        format_directory_json_response(directory_json_response) 
        for directory_json_response in directory_json_responses
    ]