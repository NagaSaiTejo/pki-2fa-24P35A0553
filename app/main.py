from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from pathlib import Path
import os
import time

from app.crypto_utils import (
    load_private_key,
    decrypt_seed,
    generate_totp_code,
    totp_time_left,
    verify_totp_code
)

app = FastAPI()

# Path handling for local vs docker
if os.getenv("USE_CONTAINER_PATH") == "1":
    DATA_DIR = Path("/data")
    PRIVATE_KEY_PATH = Path("/app/student_private.pem")
else:
    DATA_DIR = Path("./data")
    PRIVATE_KEY_PATH = Path("student_private.pem")

SEED_PATH = DATA_DIR / "seed.txt"


# -----------------------------
# Models
# -----------------------------
class DecryptRequest(BaseModel):
    encrypted_seed: str


class VerifyRequest(BaseModel):
    code: str


# -----------------------------
# /decrypt-seed
# -----------------------------
@app.post("/decrypt-seed")
async def decrypt_seed_endpoint(req: DecryptRequest):

    if not req.encrypted_seed:
        raise HTTPException(status_code=400, detail={"error": "Missing encrypted_seed"})

    try:
        private_key = load_private_key(str(PRIVATE_KEY_PATH))
    except:
        raise HTTPException(status_code=500, detail={"error": "Private key not found"})

    try:
        seed_hex = decrypt_seed(req.encrypted_seed, private_key)
    except:
        raise HTTPException(status_code=500, detail={"error": "Decryption failed"})

    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        with open(SEED_PATH, "w", newline="\n") as f:
            f.write(seed_hex + "\n")

        try:
            os.chmod(SEED_PATH, 0o600)
        except:
            pass

    except:
        raise HTTPException(status_code=500, detail={"error": "Failed to store seed"})

    return {"status": "ok"}


# -----------------------------
# /generate-2fa
# -----------------------------
@app.get("/generate-2fa")
async def generate_2fa():

    if not SEED_PATH.exists():
        raise HTTPException(status_code=500, detail={"error": "Seed not decrypted yet"})

    seed_hex = SEED_PATH.read_text().strip()

    try:
        code = generate_totp_code(seed_hex)
        remaining = totp_time_left()
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": "TOTP generation failed"})

    return {"code": code, "valid_for": remaining}

@app.post("/verify-2fa")
async def verify_2fa(req: VerifyRequest):

    if not req.code:
        raise HTTPException(status_code=400, detail={"error": "Missing code"})

    if not SEED_PATH.exists():
        raise HTTPException(status_code=500, detail={"error": "Seed not decrypted yet"})

    seed_hex = SEED_PATH.read_text().strip()

    try:
        is_valid = verify_totp_code(seed_hex, req.code, valid_window=1)
    except:
        raise HTTPException(status_code=500, detail={"error": "Verification failed"})

    return {"valid": is_valid}
