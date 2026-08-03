#!/usr/bin/env python3
"""
Web Vulnerability Scanner - OWASP Top 10
Author: nadirzhon | github.com/nadirzhon
"""

import argparse
import requests
import json
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
from colorama import Fore, Style, init

init(autoreset=True)
requests.packages.urllib3.disable_warnings()

SQLI_PAYLOADS = ["'", "' OR '1'='1", "'; DROP TABLE users--", "1 AND 1=1"]
XSS_PAYLOADS = ["<script>alert(1)</script>", '"onmouseover=alert(1)//', "<img src=x onerror=alert(1)>"]
SENSITIVE_PATHS = ["/.git/HEAD", "/.env", "/backup.zip", "/admin", "/phpinfo.php",
                   "/wp-config.php", "/config.json", "/.htaccess", "/robots.txt"]
SQLI_ERRORS = ["sql syntax", "mysql_fetch", "ORA-", "sqlite3", "syntax error"]

class VulnScanner:
    def __init__(self, base_url, timeout=10):
        self.base_url = base_url
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers["User-Agent"] = "Mozilla/5.0 (Security Audit)"
        self.findings = []

    def log(self, severity, vuln, detail):
        colors = {"HIGH": Fore.RED, "MEDIUM": Fore.YELLOW, "LOW": Fore.CYAN, "INFO": Fore.GREEN}
        c = colors.get(severity, "")
        print(f"  {c}[{severity}] {vuln}: {detail}{Style.RESET_ALL}")
        self.findings.append({"severity": severity, "vulnerability": vuln, "detail": detail})

    def check_security_headers(self):
        try:
            r = self.session.get(self.base_url, timeout=self.timeout)
            for header, msg in {
                "Content-Security-Policy": "Missing CSP",
                "X-Frame-Options": "Clickjacking risk",
                "Strict-Transport-Security": "Missing HSTS",
                "X-Content-Type-Options": "Missing X-Content-Type-Options"
            }.items():
                if header not in r.headers:
                    self.log("MEDIUM", "Security Header", msg)
        except Exception as e:
            print(f"  [-] {e}")

    def check_sensitive_files(self):
        for path in SENSITIVE_PATHS:
            url = urljoin(self.base_url, path)
            try:
                r = self.session.get(url, timeout=self.timeout, allow_redirects=False)
                if r.status_code == 200 and len(r.content) > 0:
                    self.log("HIGH", "Sensitive File", f"{path} exposed (HTTP 200, {len(r.content)}b)")
            except Exception:
                pass

    def check_params(self, url, params):
        for param in params:
            for payload in SQLI_PAYLOADS:
                test = params.copy()
                test[param] = payload
                try:
                    r = self.session.get(url, params=test, timeout=self.timeout)
                    if any(e.lower() in r.text.lower() for e in SQLI_ERRORS):
                        self.log("HIGH", "SQL Injection", f"param={param} at {url}")
                        break
                except Exception:
                    pass
            for payload in XSS_PAYLOADS:
                test = params.copy()
                test[param] = payload
                try:
                    r = self.session.get(url, params=test, timeout=self.timeout)
                    if payload in r.text:
                        self.log("HIGH", "Reflected XSS", f"param={param} at {url}")
                        break
                except Exception:
                    pass

    def run(self, crawl=False, output=None):
        print(f"\n{Fore.CYAN}[*] Scanning: {self.base_url}{Style.RESET_ALL}\n")
        print(f"{Fore.YELLOW}[*] Security headers...{Style.RESET_ALL}")
        self.check_security_headers()
        print(f"\n{Fore.YELLOW}[*] Sensitive files...{Style.RESET_ALL}")
        self.check_sensitive_files()

        if crawl:
            print(f"\n{Fore.YELLOW}[*] Crawling...{Style.RESET_ALL}")
            visited = set()
            queue = [self.base_url]
            while queue:
                url = queue.pop(0)
                if url in visited or len(visited) > 20:
                    continue
                visited.add(url)
                try:
                    r = self.session.get(url, timeout=self.timeout)
                    soup = BeautifulSoup(r.text, "html.parser")
                    for a in soup.find_all("a", href=True):
                        link = urljoin(url, a["href"])
                        if link.startswith(self.base_url) and link not in visited:
                            queue.append(link)
                    parsed = urlparse(url)
                    if parsed.query:
                        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
                        self.check_params(f"{parsed.scheme}://{parsed.netloc}{parsed.path}", params)
                except Exception:
                    pass

        print(f"\n{Fore.CYAN}[*] {len(self.findings)} findings total{Style.RESET_ALL}")
        if output:
            with open(output, "w") as f:
                json.dump(self.findings, f, indent=2)

def main():
    parser = argparse.ArgumentParser(description="Web Vulnerability Scanner")
    parser.add_argument("-u", "--url", required=True)
    parser.add_argument("--crawl", action="store_true")
    parser.add_argument("-o", "--output")
    args = parser.parse_args()
    scanner = VulnScanner(args.url)
    scanner.run(crawl=args.crawl, output=args.output)

if __name__ == "__main__":
    main()
