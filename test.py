from ecdsa import SigningKey, SECP128r1
from random import randint

def generate_ecdsa_key():
    """
    Generates an ECDSA key pair using the SECP128r1 curve.
    """
    sk = SigningKey.generate(curve=SECP128r1)  # Private key
    vk = sk.verifying_key                    # Public key
    print(f"Private Key: {sk.to_string().hex()}")
    print(f"Public Key: {vk.to_string().hex()}")
    return sk, vk


def pollards_rho_attack(base_point, public_key, order):
    """
    Simplistic implementation of Pollard's Rho attack to solve discrete logarithm problems.
    This is for educational purposes and works for small curves.

    Args:
        base_point (tuple): The generator point (x, y) of the elliptic curve.
        public_key (tuple): The public key (x, y) to crack.
        order (int): The order of the base point.

    Returns:
        int: The discrete logarithm (private key) if found.
    """
    def f(x_tuple):
        # Extract values from the tuple
        x, a, b = x_tuple

        # Partition function for Pollard's Rho
        if x % 3 == 0:
            # First partition: Add the base point
            new_x = (x + base_point[0]) % order
            new_a = (a + 1) % order
            new_b = b
        elif x % 3 == 1:
            # Second partition: Add the public key
            new_x = (x + public_key[0]) % order
            new_a = a
            new_b = (b + 1) % order
        else:
            # Third partition: Perform squaring
            new_x = (x * x) % order
            new_a = (a * 2) % order
            new_b = (b * 2) % order

        return (new_x, new_a, new_b)

    # Initialize variables for Pollard's Rho
    x = (1, 0, 0)  # x = (value, a, b)
    y = (1, 0, 0)  # y = (value, a, b)

    while True:
        # Perform the "random walk" for x and y
        x = f(x)
        y = f(f(y))  # Double step for y

        # Check for collision
        if x[0] == y[0]:  # Collision detected
            numerator = (x[2] - y[2]) % order
            denominator = (y[1] - x[1]) % order

            try:
                # Solve for the private key using modular inverse
                private_key = (numerator * pow(denominator, -1, order)) % order
                return private_key
            except ValueError:
                # Modular inverse does not exist; continue searching
                continue


# Main script
if __name__ == "__main__":
    # Step 1: Generate ECDSA Key Pair
    sk, vk = generate_ecdsa_key()
    
    # Extract curve parameters
    curve = SECP128r1.curve
    base_point = (SECP128r1.generator.x(), SECP128r1.generator.y())
    order = SECP128r1.order
    public_key_point = vk.pubkey.point
    public_key = (public_key_point.x(), public_key_point.y())

    print("\nStarting Pollard's Rho Attack...\n")
    private_key = pollards_rho_attack(base_point, public_key, order)
    
    print(f"Recovered Private Key: {private_key}")
    print(f"Original Private Key: {int(sk.to_string().hex(), 16)}")
