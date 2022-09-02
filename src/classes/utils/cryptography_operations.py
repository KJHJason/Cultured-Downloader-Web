# import third-party libraries
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, types

# import Python's standard libraries
from typing import Callable

def convert_str_to_digest_method(digest_method: str | None) -> hashes.HashAlgorithm:
    """Converts a string to a digest method

    Args:
        digest_method (str): 
            The digest method to convert to a callable.
            Valid values are "sha1", "sha256", "sha384", "sha512".
            If the digest method is not valid, the default digest method will be used.

    Returns:
        The digest method as a callable (cryptography.hazmat.primitives.hashes.HashAlgorithm).
    """
    if (digest_method is None):
        return hashes.SHA512
    elif (isinstance(digest_method, str)):
        digest_method = digest_method.lower()
    else:
        raise TypeError("digest_method must be a string!")

    if (digest_method == "sha1"):
        return hashes.SHA1
    elif (digest_method == "sha256"):
        return hashes.SHA256
    elif (digest_method == "sha384"):
        return hashes.SHA384
    elif (digest_method == "sha512"):
        return hashes.SHA512
    else:
        raise ValueError("digest_method must be one of the following: SHA1, SHA256, SHA384, SHA512")

def rsa_encrypt(plaintext: str | bytes, 
                public_key: str | types.PUBLIC_KEY_TYPES, digest_method: Callable | None = hashes.SHA512) -> bytes:
    """Encrypts a plaintext using the public key (RSA-OAEP-SHA)

    Args:
        plaintext (str|bytes): 
            The plaintext to encrypt.
        public_key (str|cryptography.hazmat.primitives.asymmetric.types.PUBLIC_KEY_TYPES): 
            The public key to use for encryption.
        digest_method (cryptography.hazmat.primitives.hashes.HashAlgorithm):
            The hash algorithm to use for the encryption (defaults to SHA512).

    Returns:
        The encrypted ciphertext (bytes).

    Raises:
        TypeError:
            If the digest method is not a subclass of cryptography.hazmat.primitives.hashes.HashAlgorithm.
            If the public key is not an instance of cryptography.hazmat.primitives.asymmetric.types.public_key.
    """
    if (isinstance(digest_method, str)):
        digest_method = convert_str_to_digest_method(digest_method)
    elif (not issubclass(digest_method, hashes.HashAlgorithm)):
        raise TypeError("digest method must be a subclass of cryptography.hazmat.primitives.hashes.HashAlgorithm")

    if (isinstance(public_key, str)):
        # Extract and parse the public key as a PEM-encoded RSA public key
        public_key = serialization.load_pem_public_key(
            data=public_key.encode("utf-8"),
            backend=default_backend()
        )
    elif (not isinstance(public_key, types.PUBLIC_KEY_TYPES)):
        raise TypeError("public_key must be an instance of cryptography.hazmat.primitives.asymmetric.types.PUBLIC_KEY_TYPES")

    if (isinstance(plaintext, str)):
        plaintext = plaintext.encode("utf-8")

    # Construct the padding
    hash_algo = digest_method()
    mgf = padding.MGF1(algorithm=hash_algo)
    pad = padding.OAEP(mgf=mgf, algorithm=hash_algo, label=None)

    # Encrypt the plaintext using the public key
    return public_key.encrypt(plaintext=plaintext, padding=pad)