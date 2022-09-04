# import third-party libraries
import bson
import pymongo
import motor.motor_asyncio
import pymongo.collection as MongoCollection

# import Python's standard libraries
import pathlib
import sys
import asyncio
from typing import Any, NoReturn
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
AESGCM = cloud_kms.AESGCM

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

def get_mongodb_client() -> pymongo.MongoClient:
    """Returns an authenticated MongoDB client."""
    conn_str =  "mongodb+srv://{username}:{password}@cultured-downloader" \
                ".cjhfnzw.mongodb.net/?retryWrites=true&w=majority".format(
                    username=SECRET_MANAGER.get_secret_payload(
                        secret_id="mongodb-username"
                    ),
                    password=SECRET_MANAGER.get_secret_payload(
                        secret_id="mongodb-password"
                    )
                )

    # set a 5-second connection timeout
    client = pymongo.MongoClient(
        host=conn_str
    )
    return client

def get_async_mongodb_client() -> pymongo.MongoClient:
    """Returns an authenticated MongoDB client."""
    conn_str =  "mongodb+srv://{username}:{password}@cultured-downloader" \
                ".cjhfnzw.mongodb.net/?retryWrites=true&w=majority".format(
                    username=SECRET_MANAGER.get_secret_payload(
                        secret_id="mongodb-username"
                    ),
                    password=SECRET_MANAGER.get_secret_payload(
                        secret_id="mongodb-password"
                    )
                )

    client = motor.motor_asyncio.AsyncIOMotorClient(
        host=conn_str
    )
    return client

def reinitialise_database() -> None:
    """Main function to re-initialise the database."""
    reinitialise = get_input(
        prompt="Are you sure you want to re-initialise the database? (y/N): ",
        available_inputs=("y", "n"),
        default="n",
    )
    if (reinitialise == "n"):
        return print("Aborting re-initialisation of database...\n")

    print("\rInitialising database...", end="")
    with get_mongodb_client() as client:
        db = client["cultured-downloader"]
        db.drop_collection("keys")
        db.create_collection(
            name="keys",
            validator={
                "$jsonSchema": {
                    "bsonType": "object",
                    "required": ["_id", "key_id", "secret_key", "ip_address", "expiry"],
                    "properties": {
                        "key_id": {
                            "bsonType": "string",
                            "description": "must be a string and is required",
                            "minLength": 80,
                            "maxLength": 80
                        },
                        "secret_key": {
                            "bsonType": "binData",
                            "description": "must be a binary data and is required"
                        },
                        "ip_address": {
                            "bsonType": "string",
                            "description": "must be a string and is required"
                        },
                        "expiry": {
                            "bsonType": "date",
                            "description": "must be a date and is required"
                        }
                    }
                }
            }
        )

        # Create index for expiry
        expiry_date_ttl = 3600 * 24 * 7 * 4 # 4 weeks
        db["keys"].create_indexes([
            MongoCollection.IndexModel(
                keys="key_id",
                unique=True
            ),
            MongoCollection.IndexModel(
                keys=[("expiry", pymongo.DESCENDING)], 
                expireAfterSeconds=expiry_date_ttl
            )
        ])

    print("\rDatabase initialised successfully!\n")

async def reencrypt_and_update_document(document: dict[str, Any], collection: MongoCollection.Collection) -> None:
    """Re-encrypts and updates a document in the database.

    Args:
        document (dict[str, Any]):
            The document to re-encrypt and update.
        collection (MongoCollection.Collection):
            The collection that the document is in.

    Returns:
        None
    """
    MONGODB_KEY_ID = "mongodb-data"

    # Re-encrypt the user's secret key
    decrypted_key = AESGCM.symmetric_decrypt(
        ciphertext=document["secret_key"],
        key_id=MONGODB_KEY_ID
    )
    encrypted_key = AESGCM.symmetric_encrypt(
        plaintext=decrypted_key,
        key_id=MONGODB_KEY_ID
    )

    # Update the document in the database
    await collection.update_one(
        filter={"_id": document["_id"]},
        update={
            "$set": {
                "secret_key": bson.Binary(encrypted_key)
            }
        }
    )

async def reencrypt_database() -> None:
    """Main function to re-encrypt data in the database.
    Normally executed when there's a key rotation."""
    reinitialise = get_input(
        prompt="Are you sure you want to re-encrypt all data in the database? (y/N): ",
        available_inputs=("y", "n"),
        default="n",
    )
    if (reinitialise == "n"):
        return print("Abort re-encryption of data in database...\n")

    print("\rRe-encrypting data in database...", end="")
    try:
        client = get_async_mongodb_client()
        db = client["cultured-downloader"]
        keys = db["keys"]
        await asyncio.gather(*[
            reencrypt_and_update_document(
                document=document, 
                collection=keys
            ) 
            async for document in keys.find()
        ])
    except (pymongo.errors.PyMongoError) as e:
        print("\rRe-encryption of data in database failed!")
        print(f"Error:\n{e}\n")
    else:
        print("\r\033[KData re-encrypted successfully!\n")
    finally:
        client.close()

def main() -> None:
    """Main function."""
    while (1):
        print("""
---- Cultured Downloader Database Menu ----

1. Re-initialise database (DANGER: ALL DATA WILL BE LOST)
2. Re-encrypt all encrypted fields in database
X. Shutdown program

-------------------------------------------""")
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
            reinitialise_database()
        elif (menu_choice == "2"):
            asyncio.run(reencrypt_database())

if (__name__ == "__main__"):
    try:
        main()
    except (KeyboardInterrupt):
        print("\nExiting...\n")