from flask import Flask, render_template, request
from ecdsa import SigningKey, NIST256p
import os
import requests

def ensure_keys_dir_exists(keys_dir="keys"):
    """Ensure the keys directory exists."""
    os.makedirs(keys_dir, exist_ok=True)

def generate_or_load_keys(keys_dir="keys"):
    """
    Generate keys if they do not exist, otherwise load them.
    Returns:
        (sk, vk) -> (SigningKey, bytes)
    """
    private_key_path = os.path.join(keys_dir, "private.pem")
    public_key_path = os.path.join(keys_dir, "public.pem")

    # Generate new keys if they don't exist
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

    # Load the public key (raw PEM)
    with open(public_key_path, "rb") as f:
        vk = f.read()

    return sk, vk

def create_app(sk, vk):
    """
    Create and configure the Flask application.
    """
    app = Flask(__name__)

    @app.route("/", methods=["GET", "POST"])
    def index():
        public_key = vk.decode("utf-8")
        message = None
        signature = None

        if request.method == "POST":
            # Retrieve the message from the form and sign it
            message = request.form.get("message", "").encode("utf-8")
            signature = sk.sign(message).hex()

            # Send the message and signature to a second server
            server_url = "http://127.0.0.1:5001/receive"
            data = {
                "message": message.hex(),
                "signature": signature
            }
            try:
                requests.post(server_url, json=data)
            except Exception as e:
                # You can log the exception if needed
                pass

        return render_template(
            "index.html",
            public_key=public_key,
            message=message.decode("utf-8") if message else "",
            signature=signature or "",
        )

    @app.route("/public_key", methods=["GET"])
    def public_key():
        """Return the public key in response to a GET request."""
        return vk.decode("utf-8")

    return app

def main():
    """Main entry point to run the application."""
    ensure_keys_dir_exists()
    sk, vk = generate_or_load_keys()
    app = create_app(sk, vk)
    app.run(port=5000, debug=True)

if __name__ == "__main__":
    main()
