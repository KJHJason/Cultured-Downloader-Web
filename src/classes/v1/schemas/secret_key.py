# import third-party libraries
from pydantic import BaseModel, Field

# import local python libraries
from .user_cryptography import UserHashAlgorithms
from .public_key import ServerHashAlgorithms

class BaseUserRequest(BaseModel):
    """The request model for the user to get their secret key."""
    csrf_token: str
    server_digest_method: ServerHashAlgorithms = Field(
        description="The digest method used for RSA-OAEP-SHA algorithm when decrypting the user's sent payload."
    )
    client_public_key: str = Field(
        description="The user's public key."
    )
    client_digest_method: UserHashAlgorithms | None = Field(
        default=UserHashAlgorithms.SHA512,
        description="The digest method to use when encrypting the response with the user's public key."
    )

class GetKeyRequest(BaseUserRequest):
    """The request model for the user to get their secret key."""
    key_id_token: str = Field(
        description="The user's base64-encoded key ID token, which is asymmetrically encrypted, " \
                    "for the user to use to retrieve their secret key from the server."
    )

class GetKeyResponse(BaseModel):
    """The response model for the user to use to decrypt their data with the obtained secret key from the server."""
    secret_key: str = Field(
        description="The user's secret key, which is asymmetrically encrypted with " \
                    "the user's public key and is base64-encoded, for the user " \
                    "to use to decrypt their encrypted data."
    )

class SaveKeyRequest(BaseUserRequest):
    """The request model for the user to store their secret key."""
    secret_key: str = Field(
        description="The user's client-side generated base64-encoded secret key, " \
                    "which is also asymmetrically encrypted, for the server to use to store."
    )

class SaveKeyResponse(BaseModel):
    """The response model after saving the user's secret key in the server for 
    the user to use the generated key ID token to retrieve their secret key from the server later."""
    key_id_token: str = Field(
        description="The user's key ID token, which expires in a month and is asymmetrically encrypted with " \
                    "the user's public key and is base64-encoded, for the user to use to retrieve their secret key from the server in the future."
    )