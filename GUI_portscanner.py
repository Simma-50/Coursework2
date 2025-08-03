#!/usr/bin/python3
import socket                 # For network connections (TCP/UDP)
import tkinter as tk          # To create GUI windows and widgets
from tkinter import filedialog, ttk  # Additional GUI components and file dialogs
from threading import Thread  # To run scanning in a separate thread (non-blocking GUI)

# === CONFIGURABLE DEFAULTS === #
DEFAULT_TIMEOUT = 1          # Socket timeout in seconds
OUTPUT_FILE = "scan_results.txt"  # Default output file to save scan results

# Function to scan ports on a single host
def scan_host(ip, start_port, end_port, udp=False, output=None, display=None):
    result_lines = []  # Store scan results for saving to file or displaying

    # Display starting message in GUI text box if provided
    if display:
        display.insert(tk.END, f"[*] Starting {'UDP' if udp else 'TCP'} scan on {ip}\n")

    for port in range(start_port, end_port + 1):
        try:
            if udp:
                # Create UDP socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(DEFAULT_TIMEOUT)
                sock.sendto(b"\x00", (ip, port))  # Send empty packet
                
                try:
                    sock.recvfrom(1024)  # Try to receive response
                    result = f"[+] {ip}:{port}/UDP Open or Filtered (response)"
                except socket.timeout:
                    result = f"[+] {ip}:{port}/UDP Open or Filtered (no response)"
                sock.close()
            else:
                # Create TCP socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(DEFAULT_TIMEOUT)
                
                # Connect_ex returns 0 on success (port open)
                if sock.connect_ex((ip, port)) == 0:
                    result = f"[+] {ip}:{port}/TCP Open"
                else:
                    sock.close()
                    continue
                sock.close()

            # Save and display result
            result_lines.append(result)
            if display:
                display.insert(tk.END, result + "\n")
        except Exception:
            # Ignore errors and continue scanning
            continue

    # Display scan completion message
    if display:
        display.insert(tk.END, f"[+] {'UDP' if udp else 'TCP'} scan on {ip} complete\n")

    # Save results to file if specified
    if output:
        with open(output, "a") as f:
            for line in result_lines:
                f.write(line + "\n")

# Function called when user clicks "Start Scan"
def run_scan():
    target = entry_target.get()
    start_port = int(entry_start.get())
    end_port = int(entry_end.get())
    udp = var_udp.get()
    output = entry_output.get()

    # Clear previous output
    text_output.delete(1.0, tk.END)

    # Run scan in background thread to avoid freezing GUI
    Thread(target=scan_host, args=(target, start_port, end_port), kwargs={"udp": udp, "output": output, "display": text_output}).start()

# Function to open file dialog and let user select output file
def browse_file():
    file_path = filedialog.asksaveasfilename(defaultextension=".txt")
    if file_path:
        entry_output.delete(0, tk.END)
        entry_output.insert(0, file_path)

# Main GUI setup
if __name__ == "__main__":
    socket.setdefaulttimeout(DEFAULT_TIMEOUT)  # Set default socket timeout

    root = tk.Tk()
    root.title("TCP/UDP Port Scanner")
    root.geometry("800x600")  # Larger window for better visibility
    root.minsize(700, 500)    # Allow resizing with a minimum size

    main_frame = ttk.Frame(root, padding=15)
    main_frame.pack(fill=tk.BOTH, expand=True)

    # Target IP input
    ttk.Label(main_frame, text="Target IP:").grid(row=0, column=0, sticky="e", pady=5)
    entry_target = ttk.Entry(main_frame, width=40)
    entry_target.grid(row=0, column=1, padx=5)

    # Start Port input
    ttk.Label(main_frame, text="Start Port:").grid(row=1, column=0, sticky="e", pady=5)
    entry_start = ttk.Entry(main_frame, width=10)
    entry_start.grid(row=1, column=1, sticky="w", padx=5)

    # End Port input
    ttk.Label(main_frame, text="End Port:").grid(row=2, column=0, sticky="e", pady=5)
    entry_end = ttk.Entry(main_frame, width=10)
    entry_end.grid(row=2, column=1, sticky="w", padx=5)

    # Output file input + browse button
    ttk.Label(main_frame, text="Output File:").grid(row=3, column=0, sticky="e", pady=5)
    entry_output = ttk.Entry(main_frame, width=40)
    entry_output.insert(0, OUTPUT_FILE)
    entry_output.grid(row=3, column=1, padx=5)
    ttk.Button(main_frame, text="Browse", command=browse_file).grid(row=3, column=2, padx=5)

    # UDP scan checkbox
    var_udp = tk.BooleanVar()
    ttk.Checkbutton(main_frame, text="UDP Scan", variable=var_udp).grid(row=4, column=1, sticky="w", pady=5)

    # Start scan button
    ttk.Button(main_frame, text="Start Scan", command=run_scan).grid(row=5, column=1, pady=10)

    # Output text box with scrollbar
    ttk.Label(main_frame, text="Scan Output:").grid(row=6, column=0, sticky="nw", pady=(10, 0))
    text_output = tk.Text(main_frame, height=25, width=85, bg="#f9f9f9", font=("Courier", 10))
    text_output.grid(row=7, column=0, columnspan=3, padx=5, pady=5)
    scrollbar = ttk.Scrollbar(main_frame, command=text_output.yview)
    scrollbar.grid(row=7, column=3, sticky='ns')
    text_output['yscrollcommand'] = scrollbar.set

    root.mainloop()

