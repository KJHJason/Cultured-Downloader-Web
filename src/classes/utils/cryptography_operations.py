# import third-party libraries
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, types

# import Python's standard libraries
from typing import Callable, Optional

def rsa_encrypt(plaintext: str | bytes, 
                publicKey: str | types.PUBLIC_KEY_TYPES, digestMethod: Optional[Callable] = hashes.SHA512) -> bytes:
    """Encrypts a plaintext using the public key (RSA-OAEP-SHA)

    Args:
        plaintext (str|bytes): 
            The plaintext to encrypt.
        publicKey (str|cryptography.hazmat.primitives.asymmetric.types.PUBLIC_KEY_TYPES): 
            The public key to use for encryption.
        digestMethod (cryptography.hazmat.primitives.hashes.HashAlgorithm):
            The hash algorithm to use for the encryption (defaults to SHA512).

    Returns:
        The encrypted ciphertext (bytes).

    Raises:
        TypeError:
            If the digest method is not a subclass of cryptography.hazmat.primitives.hashes.HashAlgorithm.
            If the public key is not an instance of cryptography.hazmat.primitives.asymmetric.types.PublicKey.
    """
    if (not issubclass(digestMethod, hashes.HashAlgorithm)):
        raise TypeError("digestMethod must be a subclass of cryptography.hazmat.primitives.hashes.HashAlgorithm")

    if (isinstance(publicKey, str)):
        # Extract and parse the public key as a PEM-encoded RSA public key
        publicKey = serialization.load_pem_public_key(
            data=publicKey.encode("utf-8"),
            backend=default_backend()
        )
    elif (not isinstance(publicKey, types.PUBLIC_KEY_TYPES)):
        raise TypeError("publicKey must be an instance of cryptography.hazmat.primitives.asymmetric.types.PUBLIC_KEY_TYPES")

    if (isinstance(plaintext, str)):
        plaintext = plaintext.encode("utf-8")

    # Construct the padding
    hashAlgo = digestMethod()
    mgf = padding.MGF1(algorithm=hashAlgo)
    pad = padding.OAEP(mgf=mgf, algorithm=hashAlgo, label=None)

    # Encrypt the plaintext using the public key
    return publicKey.encrypt(plaintext=plaintext, padding=pad)