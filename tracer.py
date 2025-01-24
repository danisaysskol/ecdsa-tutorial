from scapy.all import *
from pollards_rho import pollards_rho_ec, pollards_rho_mod

# Function to process a captured packet and check for the public key
def process_packet(packet):
    print(f"Captured packet: {packet.summary()}")
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        payload = packet[Raw].load.decode(errors="ignore")
        print(f"Payload: {payload[:100]}...")  # Print the first 100 characters of the payload for inspection

        # Look for the public key markers in the payload
        start_key = "-----BEGIN PUBLIC KEY-----"
        end_key = "-----END PUBLIC KEY-----"
        
        # Find the start and end of the public key
        start_idx = payload.find(start_key)
        end_idx = payload.find(end_key, start_idx)
        
        # If both markers are found, extract the public key
        if start_idx != -1 and end_idx != -1:
            public_key = payload[start_idx:end_idx + len(end_key)]
            print("Public Key Found!")
            print(public_key)
            handle_public_key(public_key)

# Function to handle the public key found in the packet
def handle_public_key(public_key):
    # You can implement any logic here to process the public key
    print("Processing the public key...")
        # Analyze the EC public key
    print("Analyzing the EC public key:")
    print(pollards_rho_ec(public_key))

    # Example use of modular Pollard's Rho
    print("\nModular Pollard's rho example:")
    n = 8051
    factor = pollards_rho_mod(n)
    if factor:
        print(f"Found a factor of {n}: {factor}")
    else:
        print(f"Failed to find a factor of {n}")


# Start sniffing the network for packets on the loopback interface
def capture_packets():
    print("Starting to capture HTTP packets...")
    sniff(prn=process_packet, store=0, filter="tcp port 5000", iface="lo")

# Run the packet capture
if __name__ == "__main__":
    capture_packets()
