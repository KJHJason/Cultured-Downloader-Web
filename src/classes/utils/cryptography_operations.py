# import third-party libraries
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, types

# import Python's standard libraries
from typing import Callable, Optional

def rsa_encrypt(plaintext: str | bytes, 
                publicKey: types.PUBLIC_KEY_TYPES, digestMethod: Optional[Callable] = hashes.SHA512) -> bytes:
    """Encrypts a plaintext using the public key (RSA-OAEP-SHA)

    Args:
        plaintext (str|bytes): 
            The plaintext to encrypt.
        publicKey (cryptography.hazmat.primitives.asymmetric.types.PublicKey): 
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

    if (not isinstance(publicKey, types.PUBLIC_KEY_TYPES)):
        raise TypeError("publicKey must be an instance of cryptography.hazmat.primitives.asymmetric.types.PublicKey")

    if (isinstance(plaintext, str)):
        plaintext = plaintext.encode("utf-8")

    # Construct the padding
    hashAlgo = digestMethod()
    mgf = padding.MGF1(algorithm=hashAlgo)
    pad = padding.OAEP(mgf=mgf, algorithm=hashAlgo, label=None)

    # Encrypt the plaintext using the public key
    return publicKey.encrypt(plaintext=plaintext, padding=pad)

# def rsa_decrypt(ciphertext: bytes, privateKey: types.PRIVATE_KEY_TYPES, 
#                 digestMethod: Optional[Callable] = hashes.SHA512, decode: Optional[bool] = True) -> bytes | str:
#     """Decrypts a plaintext using the private key (RSA-OAEP-SHA)

#     Args:
#         plaintext (str | bytes): 
#             The plaintext to encrypt.
#         privateKey (cryptography.hazmat.primitives.asymmetric.types.PRIVATE_KEY_TYPES): 
#             The public key to use for encryption.
#         digestMethod (cryptography.hazmat.primitives.hashes.HashAlgorithm):
#             The hash algorithm to use for the encryption (defaults to SHA512).
#         decode (bool):
#             If True, the decrypted plaintext is returned as a string (Defaults to False)

#     Returns:
#         bytes: The decrypted ciphertext (bytes|str).

#     Raises:
#         TypeError:
#             If the digest method is not a subclass of cryptography.hazmat.primitives.hashes.HashAlgorithm.
#             If the private key is not an instance of cryptography.hazmat.primitives.asymmetric.types.PRIVATE_KEY_TYPES.
#     """
#     if (not issubclass(digestMethod, hashes.HashAlgorithm)):
#         raise TypeError("digestMethod must be a subclass of cryptography.hazmat.primitives.hashes.HashAlgorithm")

#     if (not issubclass(privateKey, types.PRIVATE_KEY_TYPES)):
#         raise TypeError("privateKey must be a subclass of cryptography.hazmat.primitives.asymmetric.types.PrivateKey")

#     # Construct the padding
#     hashAlgo = digestMethod()
#     mgf = padding.MGF1(algorithm=hashAlgo)
#     pad = padding.OAEP(mgf=mgf, algorithm=hashAlgo, label=None)

#     # Decrypt the ciphertext using the private key
#     plaintext = privateKey.decrypt(ciphertext=ciphertext, padding=pad)
#     return plaintext.decode("utf-8") if (decode) else plaintext