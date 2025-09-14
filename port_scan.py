import socket 

def scan_port(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    result = s.connect_ex((host, port))
    s.close()
    return result

host = "127.0.0.1"
port = 80

result = scan_port(host, port)

if result == 0:
    print(f"Port {port} is OPEN")
else:
    print(f"Port {port} is CLOSED")