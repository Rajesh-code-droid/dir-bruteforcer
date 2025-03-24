import requests
import argparse
import concurrent.futures
import time
import re
from urllib.parse import urljoin
from tqdm import tqdm  # For visualization

# User-Agent to avoid detection
HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}

# Common CMS detection paths
CMS_PATHS = {
    "WordPress": ["/wp-login.php", "/wp-admin/", "/wp-content/"],
    "Joomla": ["/administrator/", "/templates/", "/media/"],
    "Drupal": ["/user/login", "/sites/default/", "/modules/"],
}

# Function to check directory existence
def check_directory(url, directory, status_codes, timeout):
    full_url = urljoin(url, directory)
    try:
        response = requests.get(full_url, headers=HEADERS, timeout=timeout)
        if response.status_code in status_codes:
            return full_url, response.status_code
    except requests.exceptions.RequestException:
        pass
    return None

# Function to detect CMS
def detect_cms(url, timeout):
    for cms, paths in CMS_PATHS.items():
        for path in paths:
            full_url = urljoin(url, path)
            try:
                response = requests.get(full_url, headers=HEADERS, timeout=timeout)
                if response.status_code == 200:
                    print(f"[+] Possible CMS detected: {cms} (Found: {full_url})")
                    return cms
            except requests.exceptions.RequestException:
                pass
    return "Unknown"

# Recursive Bruteforce
def recursive_scan(url, directories, status_codes, timeout, depth=1, max_depth=2):
    if depth > max_depth:
        return []

    found_dirs = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_dir = {executor.submit(check_directory, url, d, status_codes, timeout): d for d in directories}
        with tqdm(total=len(directories), desc=f"Scanning Depth {depth}", dynamic_ncols=True) as progress_bar:
            for future in concurrent.futures.as_completed(future_to_dir):
                result = future.result()
                progress_bar.update(1)
                if result:
                    print(f"[✔] Found: {result[0]} (Status: {result[1]})")
                    found_dirs.append(result[0])

    # Recursively scan newly found directories
    new_dirs = [d + "/" for d in found_dirs]
    for new_dir in new_dirs:
        found_dirs.extend(recursive_scan(new_dir, directories, status_codes, timeout, depth + 1, max_depth))

    return found_dirs

# Main function
def main():
    parser = argparse.ArgumentParser(description="Automated Directory Bruteforcer with CMS detection, recursion & visualization.")
    parser.add_argument("-u", "--url", required=True, help="Target URL (e.g., https://example.com/)")
    parser.add_argument("-w", "--wordlist", required=True, help="Path to wordlist file")
    parser.add_argument("-s", "--status", type=int, nargs="+", default=[200, 403], help="Filter by status codes (default: 200, 403)")
    parser.add_argument("-r", "--recursive", action="store_true", help="Enable recursive scanning")
    parser.add_argument("-md", "--max-depth", type=int, default=2, help="Max recursion depth (default: 2)")
    parser.add_argument("-t", "--timeout", type=int, default=5, help="Request timeout in seconds (default: 5)")
    parser.add_argument("-o", "--output", help="Save results to file")
    
    args = parser.parse_args()
    
    url = args.url.rstrip("/") + "/"
    wordlist_path = args.wordlist

    # Load wordlist
    try:
        with open(wordlist_path, "r") as f:
            directories = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print("[!] Wordlist file not found.")
        return
    
    print(f"\n[+] Scanning: {url}")
    print("[+] Detecting CMS...")
    detected_cms = detect_cms(url, args.timeout)
    print(f"[+] CMS Detection Result: {detected_cms}")

    # Start scanning
    start_time = time.time()
    if args.recursive:
        print("[+] Recursion enabled.")
        found_dirs = recursive_scan(url, directories, args.status, args.timeout, max_depth=args.max_depth)
    else:
        print("[+] Starting brute-force...")
        found_dirs = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_dir = {executor.submit(check_directory, url, d, args.status, args.timeout): d for d in directories}
            with tqdm(total=len(directories), desc="Scanning Directories", dynamic_ncols=True) as progress_bar:
                for future in concurrent.futures.as_completed(future_to_dir):
                    progress_bar.update(1)
                    result = future.result()
                    if result:
                        print(f"[✔] Found: {result[0]} (Status: {result[1]})")
                        found_dirs.append(result[0])

    # Save results
    if args.output:
        with open(args.output, "w") as f:
            for dir in found_dirs:
                f.write(dir + "\n")
        print(f"[+] Results saved to {args.output}")

    print(f"[✔] Scan completed in {time.time() - start_time:.2f} seconds.")

if __name__ == "__main__":
    main()
