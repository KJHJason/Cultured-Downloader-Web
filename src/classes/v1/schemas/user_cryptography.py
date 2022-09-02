# import third-party libraries
from pydantic import BaseModel, Field

# import Python's standard libraries
import enum

class PublicKeyResponse(BaseModel):
    """The response model for the public key when
    the user requests to see the server's public key."""
    public_key: str

@enum.unique
class UserHashAlgorithms(str, enum.Enum):
    """Supported digest methods for the user to use for
    RSA-OAEP algorithm before sending their payload to the server."""
    SHA1 = "sha1" # Not recommended but still supported if required such as for slow systems
    SHA256 = "sha256"
    SHA512 = "sha512"

class UserDataJsonRequest(BaseModel):
    """The JSON payload schema for the user when
    sending their cookie for encryption/decryption."""
    data: str = Field(
        description="The user's base64 encoded data to encrypt/decrypt."
    )
    public_key: str = Field(
        description="The user's public key."
    )
    digest_method: UserHashAlgorithms | None = Field(
        default=UserHashAlgorithms.SHA512,
        description="The digest method to use when encrypting the response with the user's public key."
    )

class UserDataJsonResponse(BaseModel):
    """The response to be sent back to the user
    after encryption/decryption of their sent data."""
    data: str