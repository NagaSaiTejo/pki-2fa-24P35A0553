import base64
from app.proof_utils import (
    load_private_key,
    load_public_key,
    sign_message,
    encrypt_with_public_key
)

# -------- STEP 1: Load commit hash --------
commit_hash = input("Enter 40-char commit hash: ").strip()

if len(commit_hash) != 40:
    raise ValueError("Commit hash must be exactly 40 hex characters")

# -------- STEP 2: Load keys --------
student_private = load_private_key("student_private.pem")
instructor_public = load_public_key("instructor_public.pem")

# -------- STEP 3: Sign commit hash --------
signature = sign_message(commit_hash, student_private)

# -------- STEP 4: Encrypt signature --------
encrypted_sig = encrypt_with_public_key(signature, instructor_public)

# -------- STEP 5: Base64 encode --------
encrypted_b64 = base64.b64encode(encrypted_sig).decode("utf-8")

print("\n==================== PROOF GENERATED ====================")
print(f"Commit Hash: {commit_hash}")
print(f"Encrypted Signature: {encrypted_b64}")
print("=========================================================\n")
