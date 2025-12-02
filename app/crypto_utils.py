import base64
import time
import re
import pyotp

from cryptography.hazmat.primitives import hashes, serialization  # pyright: ignore[reportMissingImports]
from cryptography.hazmat.primitives.asymmetric import padding     # pyright: ignore[reportMissingImports]

# Regex for validating 64-character hex seed
HEX64_RE = re.compile(r'^[0-9a-f]{64}$')


# ------------------------------
# RSA PRIVATE KEY LOADING
# ------------------------------
def load_private_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


# ------------------------------
# RSA DECRYPTION
# ------------------------------
def decrypt_seed(encrypted_seed_b64: str, private_key) -> str:
    """
    Decrypt base64 OAEP-SHA256 encrypted seed and return 64-char hex string.
    """
    try:
        ciphertext = base64.b64decode(encrypted_seed_b64)
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        seed = plaintext.decode("utf-8").strip()

        if not HEX64_RE.match(seed):
            raise ValueError("Invalid seed format (must be 64-char hex)")

        return seed

    except Exception:
        raise


# ------------------------------
# TOTP HELPERS
# ------------------------------
def hex_to_base32(hex_seed: str) -> str:
    """
    Convert 64-character hex seed → bytes → Base32 string.
    Base32 is required by TOTP (RFC 6238).
    """
    seed_bytes = bytes.fromhex(hex_seed)
    b32 = base64.b32encode(seed_bytes).decode("utf-8")
    return b32.rstrip("=")   # remove padding for consistency


def generate_totp_code(hex_seed: str) -> str:
    """
    Generate current TOTP code (6 digits, 30s interval, SHA-1).
    """
    b32 = hex_to_base32(hex_seed)
    totp = pyotp.TOTP(b32, digits=6, interval=30, digest="sha1")
    return totp.now()


def totp_time_left() -> int:
    """
    Seconds remaining in the current 30-second TOTP window.
    """
    return 30 - (int(time.time()) % 30)


def verify_totp_code(hex_seed: str, code: str, valid_window: int = 1) -> bool:
    """
    Verify a TOTP code allowing ± valid_window steps (default 1 step = 30 seconds).
    This provides ±30s tolerance for /verify-2fa.
    """
    try:
        b32 = hex_to_base32(hex_seed)
        totp = pyotp.TOTP(b32, digits=6, interval=30, digest="sha1")
        return totp.verify(code, valid_window=valid_window)
    except:
        return False
