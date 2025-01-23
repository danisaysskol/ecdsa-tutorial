from ecdsa import VerifyingKey, BadSignatureError
import os
import requests

# Ensure keys directory exists
KEYS_DIR = "keys"
os.makedirs(KEYS_DIR, exist_ok=True)

public_key_path = os.path.join(KEYS_DIR, "public.pem")

# Fetch the public key from the client if it doesn't exist
if not os.path.exists(public_key_path):
    print("Public key not found. Fetching from client...")
    try:
        client_url = "http://127.0.0.1:5000/public_key"
        response = requests.get(client_url)
        if response.status_code == 200:
            with open(public_key_path, "wb") as f:
                f.write(response.content)
            print("Public key fetched and saved.")
        else:
            raise Exception(f"Failed to fetch public key. Status code: {response.status_code}")
    except Exception as e:
        raise FileNotFoundError(f"Error fetching public key: {e}")

# Load the public key
with open(public_key_path, "rb") as f:
    vk = VerifyingKey.from_pem(f.read())


def verify_signature(message, signature):
    try:
        vk.verify(signature, message)
        return True
    except BadSignatureError:
        return False
