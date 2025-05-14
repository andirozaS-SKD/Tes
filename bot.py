import asyncio
import socket
import aiohttp
import requests
import logging
from bs4 import BeautifulSoup
import whois
import ssl
import OpenSSL
import sqlite3
from datetime import datetime
from googleapiclient.discovery import build

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Fungsi untuk mendeteksi CMS
def detect_cms(url):
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')

        # Cek meta generator
        meta_generator = soup.find('meta', attrs={'name': 'generator'})
        if meta_generator and 'content' in meta_generator.attrs:
            content = meta_generator['content'].lower()
            if 'wordpress' in content:
                return 'WordPress'
            elif 'joomla' in content:
                return 'Joomla'
            elif 'drupal' in content:
                return 'Drupal'
            elif 'shopify' in content:
                return 'Shopify'
            elif 'wix' in content:
                return 'Wix'
        
        # Cek URL struktur
        if "/wp-content/" in response.text:
            return 'WordPress'
        if "Joomla" in response.text:
            return 'Joomla'
        if "Drupal" in response.text:
            return 'Drupal'
        
        # Cek HTTP Header
        powered_by = response.headers.get('X-Powered-By', '').lower()
        if 'wordpress' in powered_by:
            return 'WordPress'
        if 'php' in powered_by:
            return 'PHP-based CMS'

    except Exception:
        pass

    return 'Unknown'

# Fungsi untuk mendapatkan IP dari domain
def get_ip(domain):
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except:
        return None

# Fungsi untuk mengambil subdomain dari crt.sh
def get_subdomains_crtsh(domain):
    url = f"https://crt.sh/?q={domain}&output=json"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            return [entry['name_value'] for entry in response.json()]
    except:
        return []
    return []

# Fungsi untuk scraping resource-hosting (misal img, js, css)
def scrape_resources(url):
    hosts = set()
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        for tag in soup.find_all(['img', 'script', 'link']):
            src = tag.get('src') or tag.get('href')
            if src:
                if src.startswith("http"):
                    hosts.add(src.split("/")[2])
    except:
        pass
    return hosts

# Fungsi untuk mendeteksi WAF (misal Cloudflare, Incapsula)
def detect_waf(ip):
    try:
        response = requests.get(f"http://{ip}", timeout=5)
        if "cloudflare" in response.text.lower():
            return "Cloudflare"
        elif "incapsula" in response.text.lower():
            return "Incapsula"
    except:
        pass
    return None

# Fungsi untuk mendapatkan geolocation IP
def get_geolocation(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        if response.status_code == 200:
            return response.json()
    except:
        pass
    return {}

# Fungsi untuk mengambil sertifikat SSL dan memeriksa tanggal kedaluwarsa
def check_ssl_expiry(domain):
    try:
        context = ssl.create_default_context()
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain)
        conn.connect((domain, 443))
        cert = conn.getpeercert()
        not_after = cert['notAfter']
        expiry_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y GMT")
        return expiry_date
    except:
        return None

# Fungsi untuk melakukan pemindaian port menggunakan asyncio
async def scan_port_async(ip, port, session):
    url = f"http://{ip}:{port}"
    try:
        async with session.get(url, timeout=1) as response:
            if response.status == 200:
                return port
    except:
        pass
    return None

async def scan_ports(ip, ports):
    open_ports = []
    async with aiohttp.ClientSession() as session:
        tasks = [scan_port_async(ip, port, session) for port in ports]
        results = await asyncio.gather(*tasks)
        open_ports = [port for port in results if port is not None]
    return sorted(open_ports)

# Fungsi untuk query WHOIS
def get_whois_info(domain):
    try:
        w = whois.whois(domain)
        return w
    except:
        return None

# Fungsi untuk input domain
def get_domains():
    print("Mode input domain?\n1. Manual\n2. Dari file .txt")
    choice = input("> ").strip()
    
    domains = []
    
    if choice == "1":
        domain = input("Masukkan domain target (contoh: tesla.com): ").strip()
        domains.append(domain)
    
    elif choice == "2":
        filename = input("Masukkan nama file .txt: ").strip()
        try:
            with open(filename, "r") as f:
                lines = f.readlines()
                for line in lines:
                    domain = line.strip()
                    if domain:
                        domains.append(domain)
        except:
            print("[!] Gagal membaca file.")
            exit(1)
    else:
        print("[!] Pilihan tidak valid.")
        exit(1)
    
    return domains

# Fungsi untuk memilih mode scan port
def choose_scan_mode():
    print("Pilih mode scan port?\n1. Penting saja (20,21,22,80,443,3306,3389)\n2. Full (1-65535)")
    mode = input("> ").strip()
    
    if mode == "1":
        ports = [20, 21, 22, 23, 25, 53, 80, 110, 443, 3306, 3389]
    elif mode == "2":
        ports = list(range(1, 65536))
    else:
        print("[!] Pilihan tidak valid.")
        exit(1)
    
    return ports

# Fungsi untuk menyimpan hasil ke database SQLite
def save_results_to_db(results):
    conn = sqlite3.connect('scan_results.db')
    c = conn.cursor()
    for domain, domain_result in results.items():
        for host, data in domain_result.items():
            c.execute('''INSERT INTO scan_results (domain, host, ip, open_ports, geolocation, waf_detected, ssl_expiry, whois_info, cms_detected)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''', 
                         (domain, host, data['ips'][0], str(data['open_ports'][data['ips'][0]]), str(data['geolocation'][data['ips'][0]]), 
                          data['waf_detected'], data['ssl_expiry'], str(data['whois_info']), data['cms_detected']))
    conn.commit()
    conn.close()

# Fungsi utama untuk melakukan scan
async def main():
    domains = get_domains()
    ports_to_scan = choose_scan_mode()

    results = {}

    for domain in domains:
        print(f"\n[+] Memproses: {domain}")
        ip = get_ip(domain)

        if not ip:
            print(f"[!] Gagal resolve IP untuk {domain}")
            continue

        print(f"[✓] IP ditemukan: {ip}")

        subdomains = get_subdomains_crtsh(domain)
        print(f"[✓] Subdomain ditemukan: {len(subdomains)}")

        hosts = scrape_resources(f"http://{domain}")
        all_hosts = set(subdomains + list(hosts))
        all_hosts.add(domain)

        domain_result = {}

        for host in all_hosts:
            print(f"[*] Memproses host: {host}")
            host_ip = get_ip(host)
            if not host_ip:
                continue

            waf = detect_waf(host_ip)
            open_ports = await scan_ports(host_ip, ports_to_scan)
            geo = get_geolocation(host_ip)
            ssl_expiry = check_ssl_expiry(host)
            whois_info = get_whois_info(host)
            cms_detected = detect_cms(f"http://{host}")

            domain_result[host] = {
                "ips": [host_ip],
                "waf_detected": waf,
                "open_ports": {host_ip: open_ports},
                "geolocation": {host_ip: geo},
                "ssl_expiry": ssl_expiry,
                "whois_info": whois_info,
                "cms_detected": cms_detected
            }

        results[domain] = domain_result

    save_results_to_db(results)

if __name__ == "__main__":
    asyncio.run(main())