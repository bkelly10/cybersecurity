import socket 

def scan_port(host, port, timeout=1):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    result = s.connect_ex((host, port))
    s.close()
    return result == 0

def scan_host(host, start_port, end_port):
    open_ports = []
    
    for port in range(start_port, end_port +1):
        if scan_port(host, port):
            print(f"Port {port} is OPEN")
            open_ports.append(port)
    
    print("\nScan complete.")
    print(f"Open ports found: {open_ports}\n")
    
    return open_ports        

def enumerate_services(host, open_ports): 
    for port in open_ports:
        print(f"[ENUM] Found open port {port}, checking service...")
        if port == 22:
            grab_ssh_banner(host, port)

def grab_ssh_banner(host, port=22, timeout=1):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        banner = s.recv(1024).decode(errors="ignore").strip()
        print(f"[SSH] {host}:{port} banner: {banner}")
    except Exception as e:
        print(f"[SSH] Error grabbing banner from {host}:{port} - {e}")
    finally:
        s.close()

host = "192.168.1.1"
open_ports = scan_host(host, 20, 445)
enumerate_services(host, open_ports)

