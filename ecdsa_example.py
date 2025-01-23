from ecdsa import SigningKey, NIST256p

# Generate the signing key (private key) and verifying key (public key) using the NIST256p curve
sk = SigningKey.generate(curve=NIST256p)  # Signing key (private key)
vk = sk.verifying_key  # Verifying key (public key)

# Message to sign
message = b"Hello, ECDSA!"

# Sign the message with the private key
signature = sk.sign(message)
print(f"Signature: {signature.hex()}")

# Verify the signature with the public key
try:
    vk.verify(signature, message)
    print("Signature is valid!")
except Exception as e:
    print(f"Invalid signature: {e}")

# Save keys to PEM format
with open("keys/private.pem", "wb") as f:
    f.write(sk.to_pem())
with open("keys/public.pem", "wb") as f:
    f.write(vk.to_pem())
