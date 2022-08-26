# import third-party libraries
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, types

# import Python's standard libraries
from typing import Callable, Optional

def rsa_encrypt(plaintext: str | bytes, 
                publicKey: types.PUBLIC_KEY_TYPES, digestMethod: Optional[Callable] = hashes.SHA512) -> bytes:
    if (not issubclass(digestMethod, hashes.HashAlgorithm)):
        raise TypeError("digestMethod must be a subclass of cryptography.hazmat.primitives.hashes.HashAlgorithm")

    if (not issubclass(publicKey, types.PUBLIC_KEY_TYPES)):
        raise TypeError("publicKey must be a subclass of cryptography.hazmat.primitives.asymmetric.types.PublicKey")

    if (isinstance(plaintext, str)):
        plaintext = plaintext.encode("utf-8")

    # Construct the padding
    hashAlgo = digestMethod()
    mgf = padding.MGF1(algorithm=hashAlgo)
    pad = padding.OAEP(mgf=mgf, algorithm=hashAlgo, label=None)

    # Encrypt the plaintext using the public key
    ciphertext = publicKey.encrypt(plaintext=plaintext, padding=pad)
    return ciphertext

def rsa_decrypt(ciphertext: bytes, privateKey: types.PRIVATE_KEY_TYPES, 
                digestMethod: Optional[Callable] = hashes.SHA512, decode: bool = True) -> bytes:
    if (not issubclass(digestMethod, hashes.HashAlgorithm)):
        raise TypeError("digestMethod must be a subclass of cryptography.hazmat.primitives.hashes.HashAlgorithm")

    if (not issubclass(privateKey, types.PRIVATE_KEY_TYPES)):
        raise TypeError("privateKey must be a subclass of cryptography.hazmat.primitives.asymmetric.types.PrivateKey")

    # Construct the padding
    hashAlgo = digestMethod()
    mgf = padding.MGF1(algorithm=hashAlgo)
    pad = padding.OAEP(mgf=mgf, algorithm=hashAlgo, label=None)

    # Decrypt the ciphertext using the private key
    plaintext = privateKey.decrypt(ciphertext=ciphertext, padding=pad)
    return plaintext.decode("utf-8") if (decode) else plaintext