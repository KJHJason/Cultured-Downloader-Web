# import Python's standard libraries
import pathlib
import sys
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

    while (True):
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

def flask_session() -> None:
    API_HMAC_SHA512_KEY = "api-hmac-secret-key"
    API_HMAC_SALT = "api-hmac-salt"
    while (True):
        print("""
------------ API JWT Configurations Menu ------------

1. Generate a new API's HMAC secret key (Cloud HSM)
2. Generate a new API's HMAC salt (Cloud HSM)
3. View the secret key from GCP Secret Manager API
4. View the salt from GCP Secret Manager API
X. Back to main menu

-----------------------------------------------------""")

        try:
            choice = get_input(
                prompt="Please enter your choice: ",
                available_inputs=("1", "2", "3", "4", "x")
            )
        except (KeyboardInterrupt):
            return

        if (choice == "x"):
            return
        elif (choice == "1" or choice == "2"):
            bytes_to_be_generated = "secret key" if (choice == "1") else "salt"
            secret_id = API_HMAC_SHA512_KEY if (choice == "1") else API_HMAC_SALT
            try:
                generate_prompt = get_input(
                    prompt=f"Do you want to generate a new {bytes_to_be_generated}? (y/N): ",
                    available_inputs=("y", "n"),
                    default="n"
                )
            except (KeyboardInterrupt):
                print(f"Generation of a new {bytes_to_be_generated} will be aborted...")
                continue

            if (generate_prompt != "y"):
                print(f"\nCancelling {bytes_to_be_generated} generation...", end="\n\n")
                continue

            try:
                destroy_all_past_ver = get_input(
                    prompt="Do you want to DESTROY all past versions? (Y/n): ",
                    available_inputs=("y", "n"),
                    default="Y"
                )
            except (KeyboardInterrupt):
                print(f"Generation of a new {bytes_to_be_generated} will be aborted...")
                continue
            destroy_all_past_ver = True if (destroy_all_past_ver != "n") else False

            print(f"Generating a new API's HMAC {bytes_to_be_generated}...", end="")
            response = SECRET_MANAGER.upload_new_secret_version(
                secret_id=secret_id,
                secret=GCP_KMS.get_random_bytes(
                    n_bytes=512 if (choice == "1") else 64, 
                    generate_from_hsm=True
                ),
                destroy_past_ver=destroy_all_past_ver,
                destroy_optimise=True
            )
            print(f"\rGenerated the new API's HMAC {bytes_to_be_generated} at \"{response.name}\"!", end="\n\n")

        elif (choice == "3" or choice == "4"):
            bytes_to_be_generated = "secret key" if (choice == "3") else "salt"
            secret_id = API_HMAC_SHA512_KEY if (choice == "3") else API_HMAC_SALT
            try:
                view_in_hex = get_input(
                    prompt=f"Do you want to view the API's HMAC {bytes_to_be_generated} in hexadecimal? (Y/n): ",
                    available_inputs=("y", "n"),
                    default="y"
                )
            except (KeyboardInterrupt):
                print(f"Viewing of the API's HMAC {bytes_to_be_generated} will be aborted...")
                continue

            secret_payload = SECRET_MANAGER.get_secret_payload(
                secret_id=secret_id,
                decode_secret=False
            )
            if (view_in_hex != "n"):
                secret_payload = secret_payload.hex()
            print(f"API's HMAC {bytes_to_be_generated} that is currently in use:", secret_payload, sep="\n")
            del secret_payload

def main() -> None:
    while (True):
        print("""
---- Cultured Downloader Web App Menu ----

1. API JWT/Serialiser Configurations menu
X. Shutdown program

------------------------------------------""")
        try:
            menu_choice = get_input(
                prompt="Enter command: ",
                available_inputs=("1", "x")
            )
        except (KeyboardInterrupt):
            shutdown()
        if (menu_choice == "x"):
            shutdown()
        elif (menu_choice == "1"):
            flask_session()

if (__name__ == "__main__"):
    main()