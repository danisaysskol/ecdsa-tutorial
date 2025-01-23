from flask import Flask, render_template, request
from ecdsa import SigningKey, NIST256p
import os
import requests

app = Flask(__name__)

# Ensure keys directory exists
KEYS_DIR = "keys"
os.makedirs(KEYS_DIR, exist_ok=True)

# Generate keys if not already generated
private_key_path = os.path.join(KEYS_DIR, "private.pem")
public_key_path = os.path.join(KEYS_DIR, "public.pem")

if not os.path.exists(private_key_path):
    sk = SigningKey.generate(curve=NIST256p)
    vk = sk.verifying_key

    with open(private_key_path, "wb") as f:
        f.write(sk.to_pem())
    with open(public_key_path, "wb") as f:
        f.write(vk.to_pem())

# Load the private key
with open(private_key_path, "rb") as f:
    sk = SigningKey.from_pem(f.read())

# Load the public key
with open(public_key_path, "rb") as f:
    vk = f.read()


@app.route("/", methods=["GET", "POST"])
def index():
    public_key = vk.decode("utf-8")
    message = None
    signature = None

    if request.method == "POST":
        message = request.form.get("message", "").encode("utf-8")
        signature = sk.sign(message).hex()

        # Send the message and signature to the server
        server_url = "http://127.0.0.1:5001/receive"
        data = {"message": message.hex(), "signature": signature}
        try:
            requests.post(server_url, json=data)
        except Exception as e:
            pass

    return render_template(
        "index.html",
        public_key=public_key,
        message=message.decode("utf-8") if message else "",
        signature=signature or "",
    )


if __name__ == "__main__":
    app.run(port=5000, debug=True)
