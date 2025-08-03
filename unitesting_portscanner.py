#!/usr/bin/python3
import socket              # For socket network connections
import threading           # For multithreaded port scanning
import queue               # Thread-safe queue for port numbers

DEFAULT_TIMEOUT = 0.5     # Socket timeout in seconds
OUTPUT_FILE = "scan_results.txt"  # Default output filename

def scan_port(ip, port, udp=False):
    """
    Scan a single port (TCP or UDP) on the given IP.
    Returns result string if open, else None.
    """
    try:
        if udp:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(DEFAULT_TIMEOUT)
            sock.sendto(b"\x00", (ip, port))
            try:
                sock.recvfrom(1024)
                return f"[+] {ip}:{port}/UDP Open or Filtered (response)"
            except socket.timeout:
                return f"[+] {ip}:{port}/UDP Open or Filtered (no response)"
            finally:
                sock.close()
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(DEFAULT_TIMEOUT)
            if sock.connect_ex((ip, port)) == 0:
                sock.close()
                return f"[+] {ip}:{port}/TCP Open"
            sock.close()
    except Exception:
        pass
    return None

def worker(ip, q, udp, results):
    """
    Thread worker: scan ports taken from queue, append results.
    """
    while True:
        port = q.get()
        if port is None:
            break
        res = scan_port(ip, port, udp)
        if res:
            results.append(res)
        q.task_done()

def scan_ports_multithread(ip, start_port, end_port, udp=False, thread_count=100):
    """
    Scan ports on ip with multiple threads.
    Returns list of open ports.
    """
    q = queue.Queue()
    results = []

    # Start worker threads
    threads = []
    for _ in range(thread_count):
        t = threading.Thread(target=worker, args=(ip, q, udp, results))
        t.daemon = True
        t.start()
        threads.append(t)

    # Add ports to queue
    for port in range(start_port, end_port + 1):
        q.put(port)

    # Wait for completion
    q.join()

    # Stop threads
    for _ in threads:
        q.put(None)
    for t in threads:
        t.join()

    return sorted(results)

def save_results(results, filename=OUTPUT_FILE):
    """
    Save results list to output file.
    """
    with open(filename, "w") as f:
        for line in results:
            f.write(line + "\n")

# Unit testing example scans
def unit_tests():
    print("Running Unit Tests\n")

    # Test 1: TCP scan on localhost ports 22-23
    print("Test 1: TCP scan localhost ports 22-23")
    res1 = scan_ports_multithread("127.0.0.1", 22, 23, udp=False)
    if res1:
        print("\n".join(res1))
    else:
        print("No open TCP ports found")
    print()

    # Test 2: UDP scan on localhost port 53
    print("Test 2: UDP scan localhost port 53")
    res2 = scan_ports_multithread("127.0.0.1", 53, 53, udp=True)
    if res2:
        print("\n".join(res2))
    else:
        print("No open UDP ports found")
    print()

    # Test 3: TCP scan on an unreachable IP
    print("Test 3: TCP scan unreachable IP 10.255.255.1 ports 80-81")
    res3 = scan_ports_multithread("10.255.255.1", 80, 81, udp=False)
    if res3:
        print("\n".join(res3))
    else:
        print("No open ports (expected for unreachable IP)")
    print()

if __name__ == "__main__":
    import sys

    # Run unit tests if no arguments
    if len(sys.argv) == 1:
        unit_tests()
    # Otherwise scan specified IP and ports
    elif len(sys.argv) == 5:
        ip = sys.argv[1]
        start_port = int(sys.argv[2])
        end_port = int(sys.argv[3])
        protocol = sys.argv[4].lower()
        udp_flag = protocol == "udp"

        print(f"Starting {'UDP' if udp_flag else 'TCP'} scan on {ip} ports {start_port}-{end_port}...\n")
        results = scan_ports_multithread(ip, start_port, end_port, udp=udp_flag)

        if results:
            for res in results:
                print(res)
            save_results(results)
            print(f"\nResults saved to {OUTPUT_FILE}")
        else:
            print("No open ports found.")
    else:
        print("Usage:")
        print("  To run unit tests (default): python3 portscanner.py")
        print("  To scan: python3 portscanner.py <IP> <start_port> <end_port> <tcp|udp>")
        print("Example: python3 portscanner.py 192.168.1.1 1 1024 tcp")

