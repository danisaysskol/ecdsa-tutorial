from scapy.all import *
from pollards_rho import apply_pollards

# Flag to indicate if the public key has been found
key_found = False

# Function to process a captured packet and check for the public key
def process_packet(packet):
    global key_found  
    
    print(f"Captured packet: {packet.summary()}")
    if packet.haslayer(TCP) and packet.haslayer(Raw) and not key_found:
        payload = packet[Raw].load.decode(errors="ignore")
        print(f"Payload: {payload[:100]}...")  

        start_key = "-----BEGIN PUBLIC KEY-----"
        end_key = "-----END PUBLIC KEY-----"
        
        start_idx = payload.find(start_key)
        end_idx = payload.find(end_key, start_idx)
        
        if start_idx != -1 and end_idx != -1:
            public_key = payload[start_idx:end_idx + len(end_key)]
            print("Public Key Found!")
            print(public_key)
            handle_public_key(public_key)
            key_found = True 

# Function to handle the public key found in the packet
def handle_public_key(public_key):
    print("Processing the public key...")
    
    private_key = apply_pollards(public_key)
    print(f"Private key found: {private_key}")

def stop_sniffing(packet):
    return key_found  

# Start sniffing the network for packets on the loopback interface
def capture_packets():
    print("Starting to capture HTTP packets...")
    
    try:
        sniff(prn=process_packet, store=0, filter="tcp port 5000", iface="lo", stop_filter=stop_sniffing)
    except Exception as e:
        print(f"Error occurred while sniffing packets: {e}")
    finally:
        print("Closing sniffing session...")
        
        # Explicitly clean up Scapy's sniffing socket
        if hasattr(conf, 'sniff_socket') and conf.sniff_socket:
            print("Closing internal sniff socket...")
            conf.sniff_socket.close()

# Run the packet capture
if __name__ == "__main__":
    capture_packets()
