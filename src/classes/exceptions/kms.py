class KMSCryptographicError(Exception):
    """Custom exception class for GCP KMS cryptographic errors."""

class CRC32ChecksumError(KMSCryptographicError):
    """Raised when the CRC32 checksum of the payload is not valid/does not match."""

class DecryptionError(KMSCryptographicError):
    """Raised when the decryption was not successful."""