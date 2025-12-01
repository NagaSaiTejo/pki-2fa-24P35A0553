import base64
import re
from cryptography.hazmat.primitives import hashes, serialization # pyright: ignore[reportMissingImports]
from cryptography.hazmat.primitives.asymmetric import padding # pyright: ignore[reportMissingImports]
HEX64_RE = re.compile(r'^[0-9a-f]{64}$')
def load_private_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)
def decrypt_seed(encrypted_seed_b64: str, private_key) -> str:
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