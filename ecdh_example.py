from ecdsa import ECDH, NIST256p

# Party 1 creates its private and public keys
party1 = ECDH(curve=NIST256p)
party1.generate_private_key()
party1_public_key = party1.get_public_key()

# Party 2 creates its private and public keys
party2 = ECDH(curve=NIST256p)
party2.generate_private_key()
party2_public_key = party2.get_public_key()

# Simulate exchanging public keys between the two parties
party1.load_received_public_key(party2_public_key)
party2.load_received_public_key(party1_public_key)

# Generate shared secret on both sides
party1_shared_secret = party1.generate_sharedsecret_bytes()
party2_shared_secret = party2.generate_sharedsecret_bytes()

# Verify that the shared secrets are the same
assert party1_shared_secret == party2_shared_secret
print("Shared secret established successfully!")

# Save keys and shared secret to files
with open("keys/party1_public.pem", "wb") as f:
    f.write(party1_public_key)
with open("keys/party2_public.pem", "wb") as f:
    f.write(party2_public_key)
