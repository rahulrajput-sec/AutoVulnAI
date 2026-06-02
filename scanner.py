import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import sys

import ssl
import socket
import json
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

findings = []
# -----------------------------
# Website Crawler Function
# -----------------------------
def crawl_links(url):

    try:
        response = requests.get(url, timeout=10)

        soup = BeautifulSoup(response.text, "html.parser")

        print("\n[+] Crawled Links:\n")

        links = set()

        for link in soup.find_all("a"):

            href = link.get("href")

            if href:

                full_url = urljoin(url, href)

                if full_url not in links:
                    links.add(full_url)

                    print(full_url)

    except Exception as e:
        print(f"Error: {e}")

# # -----------------------------
# Security Header Checker
# -----------------------------
def directory_enum(url):

    print("\n[+] Starting Directory Enumeration...\n")

    directories = [
        "dashboard",
        "backup",
        "uploads"
    ]

    for directory in directories:

        target_url = f"{url}/{directory}"

        try:
            response = requests.get(target_url,timeout=10)

            if response.status_code == 200:

                print(f"[FOUND] {target_url}")

                findings.append(
                    f"[INFO] Directory Found: {target_url}"
                )

        except Exception:
            pass

def subdomain_enum(domain):

    print("\n[+] Subdomain Enumeration...\n")

    subdomains = [
        "www",
        "mail",
        "admin",
        "api",
        "dev",
        "test",
        "staging"
    ]

    for sub in subdomains:

        target = f"https://{sub}.{domain}"

        try:
            response = requests.get(target, timeout=3)

            if response.status_code < 400:
                print(f"[FOUND] {target}")
                findings.append(f"[INFO] Subdomain Found: {target}")

        except:
            pass
def check_headers(url):
    try:

        response = requests.get(url)

        headers = response.headers

        print("\n[+] Security Header Analysis:\n")

        security_headers = [
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "X-Frame-Options",
            "X-Content-Type-Options"
        ]

        for header in security_headers:

            if header in headers:

                print(f"[SECURE] {header} Found")

            else:

                print(f"[WARNING] Missing Header: {header}")
                findings.append(f"[MEDIUM] Missing Header: {header}")
    except Exception as e:

        print(f"Header Scan Error: {e}")
    # -----------------------------
# SQL Injection Checker
# -----------------------------
def check_xss(url):
    print("\n[+] Testing XSS...\n")

    payload = "<script>alert('XSS')</script>"

    try:
        response = requests.get(url, params={"q": payload}, timeout=10)

        if payload in response.text:
            print(f"[VULNERABLE] Possible XSS Found: {url}")
            findings.append(f"[HIGH] Possible XSS Found: {url}")
        else:
            print("[SAFE] No Reflected XSS Detected")

    except Exception as e:
        print(f"XSS Scan Error: {e}")
def check_sqli(url):
    print("\n[+] Testing SQL Injection...\n")


    test_url = url 

    try:

        response = requests.get(test_url, timeout=10)

        errors = {
            "you have an error in your sql syntax",
            "warning: mysql",
            "unclosed quotation mark",
            "quoted string not properly terminated"
        }

        for error in errors:

            if error in response.text.lower():

                print(f"[VULNERABLE] SQL Injection Possible: {test_url}")
                findings.append(f"SQL Injection Possible: {test_url}")

                return

        print("[SAFE] No SQL Injection Error Detected")

    except Exception as e:

        print(f"SQLi Scan Error: {e}")


def port_scan(domain):
    print("\n[+] Port Scanning...\n")

    ports = [21, 22, 23, 25, 53, 80, 443, 3306, 8080]

    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)

            result = sock.connect_ex((domain, port))

            if result == 0:
                print(f"[OPEN] Port {port}")
                findings.append(f"[INFO] Open Port: {port}")

            sock.close()

        except:
            pass


def ssl_checker(domain):
    print("\n[+] SSL Certificate Check...\n")

    try:
        context = ssl.create_default_context()

        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

                print(f"[INFO] SSL Issuer: {cert['issuer']}")
                findings.append("[INFO] SSL Certificate Found")

    except Exception as e:
        print(f"[WARNING] SSL Check Failed: {e}")

def tech_detect(url):
    print("\n[+] Technology Detection...\n")

    try:
        response = requests.get(url, timeout=10)

        server = response.headers.get("Server", "Unknown")
        powered = response.headers.get("X-Powered-By", "Unknown")

        print(f"Server: {server}")
        print(f"X-Powered-By: {powered}")

        findings.append(f"[INFO] Server: {server}")
        findings.append(f"[INFO] X-Powered-By: {powered}")

    except Exception as e:
        print(f"Technology Detection Error: {e}")


def banner_grab(domain):
    print("\n[+] Banner Grabbing...\n")

    ports = [21, 22, 25, 80, 443]

    for port in ports:
        try:
            sock = socket.socket()
            sock.settimeout(2)

            sock.connect((domain, port))

            banner = sock.recv(1024).decode(errors="ignore")

            print(f"[BANNER] Port {port}: {banner}")

            findings.append(
                f"[INFO] Banner Port {port}: {banner}"
            )

            sock.close()

        except:
            pass


def login_detector(url):
    print("\n[+] Searching Login Forms...\n")

    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, "html.parser")

        forms = soup.find_all("form")

        for form in forms:
            form_text = str(form).lower()

            if "password" in form_text:
                print("[FOUND] Login Form Detected")
                findings.append("[INFO] Login Form Found")
                return

        print("[INFO] No Login Form Found")

    except Exception as e:
        print(f"Login Detection Error: {e}")


def open_redirect_check(url):
    print("\n[+] Testing Open Redirect...\n")

    payload = "https://google.com"

    try:
        test_url = url + "?next=" + payload

        response = requests.get(test_url, allow_redirects=False, timeout=10)

        location = response.headers.get("Location", "")

        if payload in location:
            print("[VULNERABLE] Possible Open Redirect")
            findings.append("[HIGH] Open Redirect Found")
        else:
            print("[SAFE] Open Redirect Not Detected")

    except Exception as e:
        print(f"Open Redirect Error: {e}")

def check_robots(url):
    print("\n[+] Checking robots.txt...\n")

    try:
        robots_url = url + "/robots.txt"

        response = requests.get(robots_url)

        if response.status_code == 200:
            print(f"[FOUND] {robots_url}")

            findings.append(
                f"[INFO] robots.txt Found: {robots_url}"
            )

        else:
            print("[INFO] robots.txt Not Found")

    except Exception as e:
        print(f"robots.txt Error: {e}")


def sensitive_files(url):

    print("\n[+] Checking Sensitive Files...\n")

    files = [
        ".env",
        ".git/config",
        "backup.zip",
        "config.php.bak",
        "phpinfo.php",
        "database.sql"
    ]

    for file in files:

        try:
            target_url = f"{url}/{file}"

            response = requests.get(target_url, timeout=10)

            if response.status_code == 200:

                print(f"[CRITICAL] Exposed File Found: {target_url}")

                findings.append(
                    f"[CRITICAL] Exposed File Found: {target_url}"
                )

        except Exception:
            pass

def admin_finder(url):
    print("\n[+] Searching Admin Panels...\n")

    admin_paths = [
        "admin",
        "administrator",
        "wp-admin",
        "login",
        "admin/login"
    ]

    for path in admin_paths:
        try:
            admin_url = f"{url}/{path}"

            response = requests.get(admin_url, timeout=10)

            if response.status_code == 200:
                print(f"[FOUND] {admin_url}")
                findings.append(
                    f"[INFO] Admin Panel Found: {admin_url}"
                )

        except Exception:
            pass
def cookie_check(url):
    print("\n[+] Checking Cookies...\n")

    try:
        response = requests.get(url, timeout=10)

        cookies = response.cookies

        if cookies:
            for cookie in cookies:
                print(f"[INFO] Cookie Found: {cookie.name}")
                findings.append(f"[INFO] Cookie Found: {cookie.name}")
        else:
            print("[INFO] No Cookies Found")

    except Exception as e:
        print(f"Cookie Check Error: {e}")

# Main Function
# -----------------------------
def main():

    if len(sys.argv) != 2:
        print("Usage: python scanner.py https://example.com")
        return

    target = sys.argv[1]
    domain = target.replace("https://", "").replace("http://", "").split("/")[0]
    print(f"\nScanning Target: {target}")

    with ThreadPoolExecutor(max_workers=8) as executor:
     executor.submit(crawl_links, target)
     executor.submit(directory_enum, target)
     executor.submit(subdomain_enum, domain)
     executor.submit(check_headers, target) 
     executor.submit(check_xss, target)
     executor.submit(check_sqli, target)
     executor.submit(port_scan, domain)
     executor.submit(ssl_checker, domain)
     executor.submit(tech_detect, target)
     executor.submit(login_detector, target)
     executor.submit(open_redirect_check, target)
     executor.submit(check_robots, target)
     executor.submit(admin_finder, target)
     executor.submit(cookie_check, target)
     executor.submit(banner_grab, domain)
     executor.submit(sensitive_files, target)

    with open("report.txt", "w") as report:
            with open("report.html", "w") as html:
                html.write("""

<html>
<head>
<title>AutoVulnAI Report</title>

<style>

body {
    font-family: Arial;
    margin: 30px;
}

h1 {
    color: red;
}

table {
    border-collapse: collapse;
    width: 100%;
}

th, td {
    border: 1px solid black;
    padding: 8px;
}

th {
    background-color: #f2f2f2;
}

</style>

</head>
<body>
""")
                
                html.write("<h1>AutoVulnAI Security Report</h1>")
                html.write(f"<h3>Target: {target}</h3>")
                html.write(f"<h3>Total Findings: {len(findings)}</h3>")
                

                for finding in findings:
                    html.write(f"<p>{finding}</p>")

                html.write("</body></html>")

            report.write("=== AutoVulnAI Security Report ===\n\n")
            report.write(f"Scan Time: {datetime.now()}\n\n")
            report.write(f"Target: {target}\n\n")
            report.write(f"Total Findings: {len(findings)}\n\n")

            risk = "LOW"

            for finding in findings:
                if "[CRITICAL]" in finding:
                    risk = "CRITICAL"
                    break
                elif "[HIGH]" in finding:
                    risk = "HIGH"
                elif "[MEDIUM]" in finding and risk != "HIGH":
                    risk = "MEDIUM"

            report.write(f"Risk Level: {risk}\n\n")
            print(f"[+] Risk Level: {risk}")

            for finding in findings:
                report.write(finding + "\n")

    # JSON report
    data = {
    "target": target,
    "risk_level": risk,
    "total_findings": len(findings),
    "findings": findings
}

    with open("report.json", "w") as json_report:
        json.dump(data, json_report, indent=4)

    print("[+] Report saved as report.json")
    print("\n[+] Report saved as report.txt")
            

    
   
    
# -----------------------------
# Start Program
# -----------------------------
if __name__ == "__main__":
    main()