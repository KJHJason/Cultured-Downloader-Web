# import third party libraries
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.auth.exceptions import RefreshError

# import python standard libraries
import pathlib
import sys
import json
from typing import NoReturn
from importlib.util import spec_from_file_location, module_from_spec

# import local python libraries
FILE_PATH = pathlib.Path(__file__).parent.absolute()
PYTHON_FILES_PATH = FILE_PATH.parent.joinpath("src", "classes")

# add to sys path so that other files can be imported by cloud_kms.py
sys.path.append(str(PYTHON_FILES_PATH))

# import cloud_kms.py local python module using absolute path
KMS_PY_FILE = PYTHON_FILES_PATH.joinpath("cloud_kms.py")
spec = spec_from_file_location("cloud_kms", str(KMS_PY_FILE))
cloud_kms = module_from_spec(spec)
sys.modules[spec.name] = cloud_kms
spec.loader.exec_module(cloud_kms)

C = cloud_kms.C
SECRET_MANAGER = cloud_kms.SECRET_MANAGER
GCP_KMS = cloud_kms.GCP_KMS()

def shutdown() -> NoReturn:
    """For UX, prints shutdown message."""
    print()
    print("Shutting down...")
    input("Please press ENTER to exit...")
    print()
    sys.exit(0)

def get_input(prompt: str, available_inputs: tuple[str] | list[str], 
              default: str | None = None, extra_info: str | None = None) -> str:
    """Gets input from user.

    Args:
        prompt (str):
            The prompt to display to the user.
        available_inputs (tuple[str]|list[str]):
            The available inputs that the user can enter.
        default (str|None):
            The default input to return if the user enters nothing.
        extra_info (str|None):
            Extra information to display to the user before the prompt.

    Returns:
        str: 
            The user's input.

    Raises:
        TypeError:
            If the supplied available_inputs argument is not a tuple or a list.
    """
    if (not isinstance(available_inputs, tuple | list)):
        raise TypeError("available_inputs must be a tuple or list")

    if (isinstance(available_inputs, list)):
        available_inputs = tuple(available_inputs)

    while (1):
        if (extra_info is not None):
            print(extra_info)

        response = input(prompt).lower().strip()
        if (response == "" and default is not None):
            return default
        elif (response not in available_inputs):
            print("Invalid input. Please try again.", end="\n\n")
            continue
        else:
            return response

def generate_new_oauth_token() -> None:
    """Will try to initialise Google API by trying to authenticate with token.json
    stored in Google Cloud Platform Secret Manager API.
    On success, will not ask for credentials again.
    Otherwise, will ask to authenticate with Google.
    """
    try:
        choice = get_input(
            prompt="Do you want to save a new Google OAuth2 token? (y/N): ",
            available_inputs=("y", "n"),
            default="n"
        )
    except (KeyboardInterrupt):
        return

    if (choice != "y"):
        print("\nCancelling Google OAuth2 token creation...")
        return
    else:
        print(f"Will proceed to generate a new Google OAuth2 token, if it is invalid...")

    generated_token = False
    creds = None

    try:
        GOOGLE_TOKEN = json.loads(
            SECRET_MANAGER.get_secret_payload(
                secret_id=C.OAUTH_TOKEN_SECRET_NAME
            )
        )
    except (json.decoder.JSONDecodeError, TypeError):
        GOOGLE_TOKEN = None

    GOOGLE_OAUTH_CLIENT = json.loads(
        SECRET_MANAGER.get_secret_payload(
            secret_id=C.OAUTH_CLIENT_SECRET_NAME
        )
    )

    # The file google-token.json stores the user's access and refresh tokens,
    # and is stored in Google Secret Manager API.
    # It is created automatically when the authorization flow 
    # completes for the first time and will be saved to Google Secret Manager API.
    if (GOOGLE_TOKEN is not None):
        try:
            creds = Credentials.from_authorized_user_info(GOOGLE_TOKEN, C.GOOGLE_OAUTH_SCOPES)
        except (RefreshError):
            print("Token is no longer valid as there is a refresh error!\n")
    else:
        print("No token found.\n")

    # If there are no (valid) credentials available, let the user log in.
    if (creds is None or not creds.valid):
        if (creds and creds.expired and creds.refresh_token):
            print("Token is valid but might expire soon, refreshing token instead...", end="")
            creds.refresh(Request())
            print("\r\033[KRefreshed token!\n")
        else:
            print("Token is expired or invalid!\n")
            flow = InstalledAppFlow.from_client_config(GOOGLE_OAUTH_CLIENT, C.GOOGLE_OAUTH_SCOPES)
            creds = flow.run_local_server(port=8080)

        # For print message to indicate if the token is 
        # newly uploaded or loaded from GCP Secret Manager API
        generated_token = True

        try:
            destroy_all_past_ver = get_input(
                prompt="Do you want to DESTROY all past versions? (Y/n): ",
                available_inputs=("y", "n"),
                default="Y"
            )
        except (KeyboardInterrupt):
            print("\nCancelling Google OAuth2 token creation...")
            return

        destroy_all_past_ver = True if (destroy_all_past_ver != "n") else False

        # Save the credentials for the next run to Google Secret Manager API
        print(f"Adding new secret version to the secret ID, {C.OAUTH_TOKEN_SECRET_NAME}...", end="")
        response = SECRET_MANAGER.upload_new_secret_version(
            secret_id=C.OAUTH_TOKEN_SECRET_NAME,
            secret=creds.to_json(),
            destroy_past_ver=destroy_all_past_ver,
            destroy_optimise=True
        )
        print(f"\rNew secret version, {C.OAUTH_TOKEN_SECRET_NAME}, created:", response.name)

    try:
        # Build the Google Drive service from the credentials
        with build("drive", "v3", credentials=creds) as _:
            print(f"Status OK! {'Generated' if (generated_token) else 'Loaded'} token.json is valid.")
    except (HttpError) as error:
        print(f"\nAn error has occurred:\n{error}")
        print()
        sys.exit(1)

def flask_session() -> None:
    API_HMAC_SHA512_KEY = "api-hmac-secret-key"
    while (1):
        print("""
------------ API JWT Configurations Menu ------------
1. Generate a new API's HMAC secret key (Cloud HSM)
2. View the secret key from GCP Secret Manager API
X. Back to main menu
-----------------------------------------------------""")

        try:
            choice = get_input(
                prompt="Please enter your choice: ",
                available_inputs=("1", "2", "x")
            )
        except (KeyboardInterrupt):
            return

        if (choice == "x"):
            return
        elif (choice == "1"):
            try:
                generate_prompt = get_input(
                    prompt="Do you want to generate a new secret key? (y/N): ",
                    available_inputs=("y", "n"),
                    default="n"
                )
            except (KeyboardInterrupt):
                print("Generation of a new key will be aborted...")
                continue

            if (generate_prompt != "y"):
                print("\nCancelling key generation...", end="\n\n")
                continue

            try:
                destroy_all_past_ver = get_input(
                    prompt="Do you want to DESTROY all past versions? (Y/n): ",
                    available_inputs=("y", "n"),
                    default="Y"
                )
            except (KeyboardInterrupt):
                print("Generation of a new key will be aborted...")
                continue
            destroy_all_past_ver = True if (destroy_all_past_ver != "n") else False

            print("Generating a new API's HMAC secret key...", end="")
            response = SECRET_MANAGER.upload_new_secret_version(
                secret_id=API_HMAC_SHA512_KEY,
                secret=GCP_KMS.get_random_bytes(
                    n_bytes=512, 
                    generate_from_hsm=True
                ),
                destroy_past_ver=destroy_all_past_ver,
                destroy_optimise=True
            )
            print(f"\rGenerated the new API's HMAC secret key at \"{response.name}\"!", end="\n\n")

        elif (choice == "2"):
            try:
                view_in_hex = get_input(
                    prompt=f"Do you want to view the API's HMAC secret key in hexadecimal? (Y/n): ",
                    available_inputs=("y", "n"),
                    default="y"
                )
            except (KeyboardInterrupt):
                print(f"Viewing of the API's HMAC secret key will be aborted...")
                continue

            secret_payload = SECRET_MANAGER.get_secret_payload(
                secret_id=API_HMAC_SHA512_KEY,
                decode_secret=False
            )
            if (view_in_hex != "n"):
                secret_payload = secret_payload.hex()
            print(f"API's HMAC secret key that is currently in use:", secret_payload, sep="\n")
            del secret_payload

def main() -> None:
    while (1):
        print("""
---- Cultured Downloader Web App Menu ----
1. Generate a new Google OAuth2 token
2. API JWT Configurations menu
X. Shutdown program
------------------------------------------""")
        try:
            menu_choice = get_input(
                prompt="Enter command: ",
                available_inputs=("1", "2", "x")
            )
        except (KeyboardInterrupt):
            shutdown()
        if (menu_choice == "x"):
            shutdown()
        elif (menu_choice == "1"):
            generate_new_oauth_token()
        elif (menu_choice == "2"):
            flask_session()

if (__name__ == "__main__"):
    main()