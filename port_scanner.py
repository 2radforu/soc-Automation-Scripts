import socket

target_host = "127.0.0.1"

print("--- Initializing Automated Multi-Port Scan ---")

# Use a loop to check ports 20 through 85 one by one
for target_port in range(20, 86):

    # Create the network connection block
    network_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    network_socket.settimeout(0.5) # Fast 0.5-second check per port
    
    # Attempt connection
    result = network_socket.connect_ex((target_host, target_port))
    
    if result == 0:
        print("[ALERT]: Port " + str(target_port) + " is OPEN!")
        
    # Close the socket before moving to the next port loop
    network_socket.close()
    
print("--- Scan Complete! All ports evaluated. ---")
