import socket

DEFAULT_TIMEOUT = 1  # Timeout in seconds

def scan_host(ip, start_port, end_port, udp=False):
    """
    Scan ports on given IP in a simple, single-threaded way.
    Prints open ports to console.
    """
    socket.setdefaulttimeout(DEFAULT_TIMEOUT)

    print(f"Starting {'UDP' if udp else 'TCP'} scan on {ip} ports {start_port} to {end_port}")

    for port in range(start_port, end_port + 1):
        try:
            if udp:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(DEFAULT_TIMEOUT)
                sock.sendto(b"\x00", (ip, port))
                try:
                    sock.recvfrom(1024)
                    print(f"[+] {ip}:{port}/UDP Open or Filtered (response)")
                except socket.timeout:
                    print(f"[+] {ip}:{port}/UDP Open or Filtered (no response)")
                sock.close()
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(DEFAULT_TIMEOUT)
                if sock.connect_ex((ip, port)) == 0:
                    print(f"[+] {ip}:{port}/TCP Open")
                sock.close()
        except Exception:
            continue

    print(f"Scan on {ip} complete.")


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 5:
        print("Usage: python3 portscanner_basic.py <IP> <start_port> <end_port> <tcp|udp>")
        sys.exit(1)

    ip = sys.argv[1]
    start_port = int(sys.argv[2])
    end_port = int(sys.argv[3])
    protocol = sys.argv[4].lower()
    udp_flag = protocol == "udp"

    scan_host(ip, start_port, end_port, udp=udp_flag)

