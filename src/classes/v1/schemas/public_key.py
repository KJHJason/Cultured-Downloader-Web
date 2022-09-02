# import third-party libraries
from pydantic import BaseModel, Field

# import Python's standard libraries
import enum

@enum.unique
class PublicKeyAlgorithm(str, enum.Enum):
    """The available algorithms for asymmetric encryption used for the API."""
    RSA = "rsa"

@enum.unique
class ServerHashAlgorithms(str, enum.Enum):
    """Supported digest methods for the RSA4096-OAEP."""
    SHA256 = "sha256"
    SHA512 = "sha512"

class PublicKeyRequest(BaseModel):
    """The public key request JSON schema."""
    algorithm: PublicKeyAlgorithm = Field(
        description="The algorithm used for asymmetric encryption."
    )
    digest_method: ServerHashAlgorithms = Field(
        description="The digest method used for RSA-OAEP-SHA algorithm."
    )

class PublicKeyResponse(BaseModel):
    """The response model for the public key when
    the user requests to see the server's public key."""
    public_key: str = Field(
        description="The server's public key for the user to use to encrypt their payloads."
    )