import socket 

# Define a function that trys to connect to a specific host and port
# Create a socket to connect to the port 
# Set a timeout to make sure we don't freeze 
# Try to connect to given host and port
def scan_port(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    result = s.connect_ex((host, port))
    s.close()
    return result

host = "127.0.0.1"

# Loop through common / well known ports
# Print the port as open if the conneciton was successful 
for port in range(1, 1025):
    result = scan_port(host, port)
    if result == 0:
        print(f"Port {port} is OPEN")
