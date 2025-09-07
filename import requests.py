import requests
from bs4 import BeautifulSoup

# Target Website
url = "http://testphp.vulnweb.com/"

# Check headers
def check_headers(url):
    print("\n[+] Checking Security Headers...")
    response = requests.get(url)
    headers = response.headers
    security_headers = ["X-Frame-Options", "Content-Security-Policy", "Strict-Transport-Security"]

    for header in security_headers:
        if header in headers:
            print(f"[OK] {header}: {headers[header]}")
        else:
            print(f"[WARN] {header} not set")

# Check forms for XSS possibility
def check_xss(url):
    print("\n[+] Checking Forms for XSS Vulnerability...")
    response = requests.get(url)
    soup = BeautifulSoup(response.text, "html.parser")
    forms = soup.find_all("form")
    print(f"Found {len(forms)} forms")
    for form in forms:
        if form.get("action"):
            print(f"Possible vulnerable form at: {form['action']}")

if __name__ == "__main__":
    print("[*] Scanning:", url)
    check_headers(url)
    check_xss(url)
