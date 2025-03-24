import requests
import dns.resolver
import argparse
import json
import concurrent.futures
import sys
import time

# Function to fetch subdomains from crt.sh
def fetch_subdomains(domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    response = requests.get(url, timeout=10)
    
    if response.status_code != 200:
        print("Failed to retrieve data from crt.sh")
        return []
    
    subdomains = set()
    try:
        data = response.json()
        for entry in data:
            name = entry.get("name_value", "")
            subdomains.update(name.split('\n'))
    except json.JSONDecodeError:
        print("Error parsing JSON response from crt.sh")
        return []
    
    return list(subdomains)

# Function to perform brute-force subdomain enumeration
def brute_force_subdomains(domain, wordlist):
    subdomains = set()
    try:
        with open(wordlist, "r") as file:
            words = file.read().splitlines()
            for word in words:
                subdomains.add(f"{word}.{domain}")
    except FileNotFoundError:
        print("Wordlist file not found.")
    return list(subdomains)

# Function to validate active subdomains
def validate_subdomain(subdomain):
    try:
        dns.resolver.resolve(subdomain, 'A')
        return subdomain
    except:
        return None

def validate_subdomains(subdomains):
    active_subdomains = []
    total = len(subdomains)
    print(f"Validating active subdomains (Total: {total})...")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        results = executor.map(validate_subdomain, subdomains)
        for i, result in enumerate(results, 1):
            if result:
                active_subdomains.append(result)
            sys.stdout.write(f"\rProgress: {i}/{total} subdomains checked")
            sys.stdout.flush()
    
    print("\nValidation completed.")
    return active_subdomains

# Main function
def main():
    parser = argparse.ArgumentParser(description="Automated Subdomain Enumeration Tool")
    parser.add_argument("-d", "--domain", required=True, help="Target domain for subdomain enumeration")
    parser.add_argument("-o", "--output", help="File to save results", default="subdomains.json")
    parser.add_argument("-w", "--wordlist", help="Path to subdomain wordlist", default=None)
    args = parser.parse_args()
    
    print(f"Enumerating subdomains for: {args.domain}")
    subdomains = fetch_subdomains(args.domain)
    
    if args.wordlist:
        print("Running brute-force subdomain enumeration...")
        subdomains += brute_force_subdomains(args.domain, args.wordlist)
    
    subdomains = list(set(subdomains))
    print(f"Total subdomains found: {len(subdomains)}")
    
    active_subdomains = validate_subdomains(subdomains)
    
    print(f"\nFound {len(active_subdomains)} active subdomains:")
    for sub in active_subdomains:
        print(sub)
    
    with open(args.output, "w") as f:
        json.dump({"domain": args.domain, "subdomains": active_subdomains}, f, indent=4)
    print(f"Results saved to {args.output}")

if __name__ == "__main__":
    main()
