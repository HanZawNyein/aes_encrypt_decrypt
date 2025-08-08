import json
import os
from base64 import urlsafe_b64encode, urlsafe_b64decode
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import qrcode
from io import BytesIO

# ==== Config ====
KEY = os.environ.get("TOKEN_AES_KEY")
if not KEY:
    KEY = os.urandom(32)  # Demo only; in production load securely
elif isinstance(KEY, str):
    KEY = KEY.encode()

aes = AESGCM(KEY)

# ==== Helpers ====
def make_token(payload: dict) -> str:
    """
    Encrypts payload into URL-safe base64 token.
    """
    data = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    nonce = os.urandom(12)  # AES-GCM nonce
    ct = aes.encrypt(nonce, data, None)
    token_bytes = nonce + ct
    return urlsafe_b64encode(token_bytes).rstrip(b"=").decode("ascii")

def parse_token(token: str) -> dict:
    """
    Decrypts token and returns payload dict.
    """
    padding = '=' * (-len(token) % 4)
    token_bytes = urlsafe_b64decode(token + padding)
    nonce = token_bytes[:12]
    ct = token_bytes[12:]
    data = aes.decrypt(nonce, ct, None)
    return json.loads(data.decode("utf-8"))

def token_to_qr_png_bytes(token: str, url_prefix: str = "https://example.com/scan?token=") -> bytes:
    url = url_prefix + token
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10,
        border=4,
    )
    qr.add_data(url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return buf.read()

# ==== Demo ====
if __name__ == "__main__":
    token = make_token({"id": "order_1234", "type": "receipt"})
    print("TOKEN:", token)

    # Save QR
    png = token_to_qr_png_bytes(token)
    with open("token_qr.png", "wb") as f:
        f.write(png)
    print("QR saved as token_qr.png")

    # Parse token back
    payload = parse_token(token)
    print("Payload:", payload)
