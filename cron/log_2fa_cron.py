import time
from pathlib import Path
from app.crypto_utils import generate_totp_code, totp_time_left

SEED_PATH = Path("/data/seed.txt")
OUTPUT_PATH = Path("/cron/last_code.txt")

def main():
    if not SEED_PATH.exists():
        OUTPUT_PATH.write_text("Seed not found\n")
        return

    seed_hex = SEED_PATH.read_text().strip()

    try:
        code = generate_totp_code(seed_hex)
        remaining = totp_time_left()
        timestamp = int(time.time())
        line = f"{timestamp},{code},{remaining}\n"
        OUTPUT_PATH.write_text(line)
    except Exception as e:
        OUTPUT_PATH.write_text(f"Error: {str(e)}\n")

if __name__ == "__main__":
    main()
