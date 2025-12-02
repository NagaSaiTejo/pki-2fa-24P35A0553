from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from pathlib import Path
import os

from app.crypto_utils import load_private_key, decrypt_seed

app = FastAPI()
if os.getenv("USE_CONTAINER_PATH") == "1":
    DATA_DIR = Path("/data")
    PRIVATE_KEY_PATH = Path("/app/student_private.pem")
else:
    DATA_DIR = Path("./data")
    PRIVATE_KEY_PATH = Path("student_private.pem")

SEED_PATH = DATA_DIR / "seed.txt"


class DecryptRequest(BaseModel):
    encrypted_seed: str


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

    # write seed.txt
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        with open(SEED_PATH, "w", newline="\n") as f:
            f.write(seed_hex + "\n")

        # ignore on Windows
        try:
            os.chmod(SEED_PATH, 0o600)
        except:
            pass

    except:
        raise HTTPException(status_code=500, detail={"error": "Failed to store seed"})

    return {"status": "ok"}
