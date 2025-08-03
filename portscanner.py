import argparse
import requests
import socket
import urllib.parse as urlparse
import re
from colorama import Fore, Style, init
from pythonping import ping

init(autoreset=True)

def print_banner():
    print(Fore.CYAN + "\nWebsite Enumeration and Exploitation Tool")
    print(Style.BRIGHT + Fore.YELLOW + "\n[!] Use responsibly for ethical testing only.\n")

def get_ip(url):
    try:
        hostname = urlparse.urlparse(url).hostname
        ip = socket.gethostbyname(hostname)
        print(Fore.GREEN + f"[+] Resolved IP: {ip}")
        return ip
    except Exception as e:
        print(Fore.RED + f"[x] Could not resolve IP: {e}")
        return None

def get_headers(url):
    try:
        response = requests.get(url)
        print(Fore.GREEN + "\n[+] HTTP Headers:")
        for header, value in response.headers.items():
            print(f"{header}: {value}")
        print(Fore.GREEN + "\n[+] Custom Headers:")
        for header in ['Server', 'X-Powered-By']:
            if header in response.headers:
                print(f"{header}: {response.headers[header]}")
    except Exception as e:
        print(Fore.RED + f"[x] Failed to fetch headers: {e}")

def find_login_forms(url):
    try:
        response = requests.get(url)
        forms = re.findall(r'<form.*?>', response.text, re.IGNORECASE)
        print(Fore.GREEN + "\n[+] Login Page Detection:")
        if forms:
            print(Fore.GREEN + f"\n[✓] Found {len(forms)} form(s) at {url}")
        else:
            print(Fore.YELLOW + f"[-] No forms found at {url}")
    except Exception as e:
        print(Fore.RED + f"[x] Failed to detect login forms: {e}")

def enumerate_subdomains(domain, wordlist):
    print(Fore.GREEN + "\n[+] Subdomain Enumeration:")
    try:
        with open(wordlist, 'r') as file:
            for line in file:
                sub = line.strip()
                subdomain = f"http://{sub}.{domain}"
                try:
                    res = requests.get(subdomain, timeout=2)
                    print(Fore.GREEN + f"[✓] {subdomain} - {res.status_code}")
                except requests.RequestException:
                    print(Fore.RED + f"[x] {subdomain} - failed")
    except Exception as e:
        print(Fore.RED + f"[x] Error reading wordlist or making request: {e}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url", help="Target URL", required=True)
    parser.add_argument("-m", "--mode", help="Scan mode", choices=['all', 'headers', 'login', 'subdomains'], default="all")
    parser.add_argument("-w", "--wordlist", help="Subdomain wordlist", required=False)
    args = parser.parse_args()

    print_banner()

    if args.mode in ["all", "headers"]:
        get_headers(args.url)

    if args.mode in ["all", "login"]:
        find_login_forms(args.url)

    if args.mode in ["all", "subdomains"] and args.wordlist:
        parsed_url = urlparse.urlparse(args.url).hostname
        enumerate_subdomains(parsed_url, args.wordlist)

    if args.mode == "all":
        get_ip(args.url)

if __name__ == "__main__":
    main()

