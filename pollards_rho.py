import base64
import random
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import ec

def decode_der_public_key(encoded_pubkey: str):
    """
    Decodes a PEM-encoded public key.

    Args:
        encoded_pubkey (str): The PEM-encoded public key.
        
    Returns:
        tuple: The x and y coordinates of the public key point.
    """
    try:
        # Remove PEM headers and footers, and fix any line breaks
        lines = encoded_pubkey.strip().split('\n')
        base64_key = ''.join(lines[1:-1])
        
        # Decode base64
        der_bytes = base64.b64decode(base64_key)
        
        # Parse the key using PEM 
        public_key = load_pem_public_key(encoded_pubkey.encode('utf-8'))
        
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            raise ValueError("The provided key is not an ECDSA public key.")
        
        # Extract the public numbers
        public_numbers = public_key.public_numbers()
        return public_numbers.x, public_numbers.y
    except Exception as e:
        print(f"Error decoding public key: {e}")
        return None

def pollards_rho(x, y, curve_order):
    """
    Pollard's Rho algorithm for finding discrete logarithms.

    Args:
        x (int): Base point x-coordinate
        y (int): Public key x-coordinate
        curve_order (int): Order of the elliptic curve group

    Returns:
        int: Potential private key or None if not found
    """
    def f(point, a, b):
        """Random walk function."""
        subset = point % 3
        if subset == 0:
            return (point * 2) % curve_order, (a * 2) % curve_order, (b * 2) % curve_order
        elif subset == 1:
            return (point + x) % curve_order, (a + 1) % curve_order, b
        else:
            return (point + y) % curve_order, a, (b + 1) % curve_order

    # Initialize
    x0 = random.randint(1, curve_order - 1)
    tortoise = (x0, x0, 0)
    hare = f(*tortoise)

    # Collision detection
    max_iterations = 100000000000000  # Prevent infinite loop
    iterations = 0
    while tortoise[0] != hare[0] and iterations < max_iterations:
        tortoise = f(*tortoise)
        hare = f(*f(*hare))
        iterations += 1

    # Check if we found a collision
    if iterations == max_iterations:
        print("Max iterations reached. Could not find collision.")
        return None

    # Extract collision values
    _, a1, b1 = tortoise
    _, a2, b2 = hare

    # Solve congruence equation
    try:
        # (b1 - b2)k ≡ (a2 - a1) (mod order)
        numerator = (a2 - a1) % curve_order
        denominator = (b1 - b2) % curve_order
        
        # Modular multiplicative inverse
        k = pow(denominator, -1, curve_order) * numerator % curve_order
        return k
    except Exception as e:
        print(f"Error solving congruence: {e}")
        return None

def apply_pollards(encoded_pubkey):
    """
    Apply Pollard's Rho algorithm to find the private key.

    Args:
        encoded_pubkey (str): PEM-encoded public key

    Returns:
        int: Potential private key or None
    """
    try:
        # Hardcoded curve parameters for NIST P-256 curve
        curve_order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

        # Decode the public key
        coords = decode_der_public_key(encoded_pubkey)
        if coords is None:
            print("Failed to decode public key")
            return None

        x, y = coords
        
        print("Applying Pollard's Rho Algorithm on Public Key")
        private_key = pollards_rho(x, y, curve_order)
        
        return private_key
    except Exception as e:
        print(f"Error in Pollard's Rho: {e}")
        return None

# Example usage
if __name__ == "__main__":
    # Example PEM-encoded public key (replace with your actual key)
    sample_key = """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEee4s8PEXWKPVuudSnJjabecy9TZTzdlWSk3Icw6O
M0oorr7sENo3ysLGF7eXiqnzWZWJoLAC+bsiuvVTOQxqbQ==
-----END PUBLIC KEY-----"""
    result = apply_pollards(sample_key)
    print(f"Potential Private Key: {result}")