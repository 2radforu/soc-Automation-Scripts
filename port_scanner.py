import socket
import sys

# Ensure the user provided all required arguments
if len(sys.argv) < 4:
    print("\n[!] Error: Missing inputs.")
    print("Usage: python3 port_scanner.py <target_ip> <start_port> <end_port>")
    print("Example: python3 port_scanner.py 127.0.0.1 20 85\n")
    sys.exit(1)

# Extract inputs directly from the terminal command line
target_host = sys.argv[1]
start_port = int(sys.argv[2])
end_port = int(sys.argv[3])

print("--- Initializing Dynamic Network Scan on " + target_host + " ---")

# Use the terminal variables to set our loop range
for target_port in range(start_port, end_port + 1):
    
    network_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    network_socket.settimeout(0.5)
    
    result = network_socket.connect_ex((target_host, target_port))
    
    if result == 0:
        print("[ALERT]: Port " + str(target_port) + " is OPEN!")
        
    network_socket.close()

print("--- Scan Complete! All target ports evaluated. ---")
