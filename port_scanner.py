import socket
import argparse
import json
import concurrent.futures
import sys
import time
import requests
import threading
from tqdm import tqdm

# Shodan API Key (Replace with your own API Key)
SHODAN_API_KEY = "4kjh4tOW6DRlkbL0rxAT8RhU6lkttWiZ"

# Function to scan a single port
def scan_port(target, port, open_ports, lock):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((target, port))
            if result == 0:
                with lock:
                    open_ports.append(port)
    except Exception as e:
        pass

# Function to perform active scanning
def active_scan(target, ports, threads):
    open_ports = []
    lock = threading.Lock()
    total_ports = len(ports)
    print(f"[+] Performing active scan on {target}...")
    print(f"[+] Scanning {total_ports} ports...")
    
    with tqdm(total=total_ports, desc="Progress", unit="port") as pbar:
        def thread_worker(port):
            scan_port(target, port, open_ports, lock)
            pbar.update(1)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            executor.map(thread_worker, ports)
    
    return open_ports

# Function to perform passive scanning using Shodan
def passive_scan(target):
    print(f"[+] Performing passive scan via Shodan for {target}...")
    url = f"https://api.shodan.io/shodan/host/{target}?key={SHODAN_API_KEY}"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            return data.get("ports", [])
        else:
            print("[-] Shodan scan failed or no data available.")
    except requests.RequestException:
        print("[-] Failed to connect to Shodan API.")
    return []

# Function to save results to a file
def save_results(target, open_ports, output_file):
    data = {"target": target, "open_ports": open_ports}
    with open(output_file, "w") as f:
        json.dump(data, f, indent=4)
    print(f"[+] Results saved to {output_file}")

# Main function
def main():
    parser = argparse.ArgumentParser(description="Passive & Active Port Scanner")
    parser.add_argument("-t", "--target", required=True, help="Target domain or IP")
    parser.add_argument("-p", "--ports", default="1-1000", help="Port range (e.g., 1-1000 or 22,80,443)")
    parser.add_argument("--threads", type=int, default=10, help="Number of threads (default: 10)")
    parser.add_argument("-o", "--output", default="scan_results.json", help="Output file to save results")
    args = parser.parse_args()
    
    # Parse ports
    if "-" in args.ports:
        start, end = map(int, args.ports.split("-"))
        ports = range(start, end + 1)
    else:
        ports = list(map(int, args.ports.split(",")))
    
    # Perform passive scan via Shodan
    shodan_ports = passive_scan(args.target)
    print(f"[+] Shodan found open ports: {shodan_ports}")
    
    # Perform active scanning
    active_ports = active_scan(args.target, ports, args.threads)
    
    # Combine results
    all_open_ports = list(set(shodan_ports + active_ports))
    print(f"[+] Final open ports found: {all_open_ports}")
    
    # Save results
    save_results(args.target, all_open_ports, args.output)

if __name__ == "__main__":
    main()
