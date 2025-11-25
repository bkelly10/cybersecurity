import socket 

def scan_port(host, port, timeout=2):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    result = s.connect_ex((host, port))
    s.close()
    return result == 0

def scan_host(host, start_port, end_port):
    open_ports = []
    for port in range(start_port, end_port +1):
        if scan_port(host, port):
            print(f"Port {port} is OPEN")
            open_ports.append(port)
    return open_ports        

host = "127.0.0.1"
open_ports = scan_host(host, 1, 1024)
