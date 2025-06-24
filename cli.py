#!/usr/bin/env python3
import argparse
import socket
import requests
import ipaddress
import whois
import json
import time
from datetime import datetime
from urllib.parse import urlparse
import dns.resolver
import hashlib
import base64
import re
import os
import subprocess
import sys
import threading
import queue
import random
import string
from collections import OrderedDict


class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class StarexxTracker:
    def __init__(self):
        self.command_history = []
        self.running = True
        self.log_queue = queue.Queue()
        self.log_thread = None
        self.show_banner()
        
    def show_banner(self):
        banner = f"""
{Colors.OKGREEN}{Colors.BOLD}
      
  ██████ ▄▄▄█████▓ ▄▄▄       ██▀███  ▓█████ ▒██   ██▒▒██   ██▒
▒██    ▒ ▓  ██▒ ▓▒▒████▄    ▓██ ▒ ██▒▓█   ▀ ▒▒ █ █ ▒░▒▒ █ █ ▒░
░ ▓██▄   ▒ ▓██░ ▒░▒██  ▀█▄  ▓██ ░▄█ ▒▒███   ░░  █   ░░░  █   ░
  ▒   ██▒░ ▓██▓ ░ ░██▄▄▄▄██ ▒██▀▀█▄  ▒▓█  ▄  ░ █ █ ▒  ░ █ █ ▒ 
▒██████▒▒  ▒██▒ ░  ▓█   ▓██▒░██▓ ▒██▒░▒████▒▒██▒ ▒██▒▒██▒ ▒██▒
▒ ▒▓▒ ▒ ░  ▒ ░░    ▒▒   ▓▒█░░ ▒▓ ░▒▓░░░ ▒░ ░▒▒ ░ ░▓ ░▒▒ ░ ░▓ ░
░ ░▒  ░ ░    ░      ▒   ▒▒ ░  ░▒ ░ ▒░ ░ ░  ░░░   ░▒ ░░░   ░▒ ░
░  ░  ░    ░        ░   ▒     ░░   ░    ░    ░    ░   ░    ░  
      ░                 ░  ░   ░        ░  ░ ░    ░   ░    ░  
      
{Colors.ENDC}Starexx Basic Toolkit{Colors.ENDC}
Type '{Colors.WARNING}help{Colors.ENDC}' for available commands{Colors.ENDC}
"""
        print(banner)
        
    def log_command(self, command, success=True, error_msg=None):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        status = "SUCCESS" if success else "FAILED"
        log_entry = f"[{timestamp}] {command} - {status}"
        if error_msg:
            log_entry += f" - ERROR: {error_msg}"
        self.command_history.append(log_entry)
        self.log_queue.put(log_entry)
        
    def start_log_thread(self):
        if self.log_thread is None:
            self.log_thread = threading.Thread(target=self.print_logs, daemon=True)
            self.log_thread.start()
            
    def print_logs(self):
        while True:
            log_entry = self.log_queue.get()
            if log_entry is None:
                break
            print(f"{Colors.OKBLUE}[LOG]{Colors.ENDC} {log_entry}")
            
    def validate_ip(self, ip_str):
        try:
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            return False
            
    def validate_domain(self, domain):
        try:
            socket.gethostbyname(domain)
            return True
        except socket.gaierror:
            return False
            
    def is_private_ip(self, ip_str):
        try:
            ip = ipaddress.ip_address(ip_str)
            return ip.is_private
        except ValueError:
            return False
            
    def ipinfo(self, ip):
        try:
            if not self.validate_ip(ip):
                self.log_command(f"ipinfo {ip}", False, "Invalid IP address")
                print(f"{Colors.FAIL}Error: Invalid IP address{Colors.ENDC}")
                return
                
            is_private = self.is_private_ip(ip)
            print(f"{Colors.HEADER}IP Information for {ip}{Colors.ENDC}")
            print(f"{Colors.BOLD}Private:{Colors.ENDC} {'Yes' if is_private else 'No'}")
            
            if not is_private:
                try:
                    response = requests.get(f"http://ip-api.com/json/{ip}").json()
                    if response['status'] == 'success':
                        print(f"{Colors.BOLD}ISP:{Colors.ENDC} {response.get('isp', 'N/A')}")
                        print(f"{Colors.BOLD}ASN:{Colors.ENDC} {response.get('as', 'N/A')}")
                        print(f"{Colors.BOLD}Organization:{Colors.ENDC} {response.get('org', 'N/A')}")
                        print(f"{Colors.BOLD}City:{Colors.ENDC} {response.get('city', 'N/A')}")
                        print(f"{Colors.BOLD}Country:{Colors.ENDC} {response.get('country', 'N/A')}")
                        print(f"{Colors.BOLD}Region:{Colors.ENDC} {response.get('regionName', 'N/A')}")
                        print(f"{Colors.BOLD}ZIP:{Colors.ENDC} {response.get('zip', 'N/A')}")
                        print(f"{Colors.BOLD}Coordinates:{Colors.ENDC} {response.get('lat', 'N/A')}, {response.get('lon', 'N/A')}")
                    else:
                        print(f"{Colors.WARNING}Could not fetch additional IP information{Colors.ENDC}")
                except Exception as e:
                    print(f"{Colors.WARNING}Could not fetch additional IP information: {str(e)}{Colors.ENDC}")
                    
                # Reverse DNS
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                    print(f"{Colors.BOLD}Reverse DNS:{Colors.ENDC} {hostname}")
                except socket.herror:
                    print(f"{Colors.BOLD}Reverse DNS:{Colors.ENDC} Not available")
                    
            self.log_command(f"ipinfo {ip}", True)
        except Exception as e:
            self.log_command(f"ipinfo {ip}", False, str(e))
            print(f"{Colors.FAIL}Error: {str(e)}{Colors.ENDC}")
            
    def portscan(self, ip, port_range):
        try:
            if not self.validate_ip(ip):
                self.log_command(f"portscan {ip} {port_range}", False, "Invalid IP address")
                print(f"{Colors.FAIL}Error: Invalid IP address{Colors.ENDC}")
                return
                
            try:
                start_port, end_port = map(int, port_range.split('-'))
                if start_port < 1 or end_port > 65535 or start_port > end_port:
                    raise ValueError
            except ValueError:
                self.log_command(f"portscan {ip} {port_range}", False, "Invalid port range")
                print(f"{Colors.FAIL}Error: Invalid port range (use format start-end, e.g., 80-100){Colors.ENDC}")
                return
                
            print(f"{Colors.HEADER}Scanning ports {start_port}-{end_port} on {ip}{Colors.ENDC}")
            print(f"{Colors.BOLD}PORT\tSTATUS\tSERVICE{Colors.ENDC}")
            
            common_ports = {
                20: "FTP (Data)",
                21: "FTP (Control)",
                22: "SSH",
                23: "Telnet",
                25: "SMTP",
                53: "DNS",
                80: "HTTP",
                110: "POP3",
                143: "IMAP",
                443: "HTTPS",
                3306: "MySQL",
                3389: "RDP",
                5432: "PostgreSQL",
                8080: "HTTP-Alt"
            }
            
            for port in range(start_port, end_port + 1):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.5)
                    result = sock.connect_ex((ip, port))
                    if result == 0:
                        service = common_ports.get(port, "Unknown")
                        print(f"{Colors.OKGREEN}{port}\tOPEN\t{service}{Colors.ENDC}")
                    else:
                        print(f"{port}\tCLOSED\t-")
                    sock.close()
                except socket.timeout:
                    print(f"{port}\tTIMEOUT\t-")
                except Exception:
                    print(f"{port}\tERROR\t-")
                    
            self.log_command(f"portscan {ip} {port_range}", True)
        except Exception as e:
            self.log_command(f"portscan {ip} {port_range}", False, str(e))
            print(f"{Colors.FAIL}Error: {str(e)}{Colors.ENDC}")
            
    def httpheaders(self, url):
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
                
            parsed = urlparse(url)
            if not parsed.netloc:
                self.log_command(f"httpheaders {url}", False, "Invalid URL")
                print(f"{Colors.FAIL}Error: Invalid URL{Colors.ENDC}")
                return
                
            print(f"{Colors.HEADER}Fetching HTTP headers for {url}{Colors.ENDC}")
            
            try:
                response = requests.head(url, timeout=5, allow_redirects=True)
                final_url = response.url
                print(f"{Colors.BOLD}Final URL:{Colors.ENDC} {final_url}")
                print(f"{Colors.BOLD}Status Code:{Colors.ENDC} {response.status_code}")
                print(f"{Colors.BOLD}Headers:{Colors.ENDC}")
                
                for header, value in response.headers.items():
                    print(f"  {header}: {value}")
                    
                self.log_command(f"httpheaders {url}", True)
            except requests.exceptions.SSLError:
                print(f"{Colors.WARNING}SSL Certificate verification failed{Colors.ENDC}")
                try:
                    response = requests.head(url, timeout=5, allow_redirects=True, verify=False)
                    final_url = response.url
                    print(f"{Colors.BOLD}Final URL:{Colors.ENDC} {final_url}")
                    print(f"{Colors.BOLD}Status Code:{Colors.ENDC} {response.status_code}")
                    print(f"{Colors.BOLD}Headers (with SSL verification disabled):{Colors.ENDC}")
                    
                    for header, value in response.headers.items():
                        print(f"  {header}: {value}")
                        
                    self.log_command(f"httpheaders {url}", True)
                except Exception as e:
                    self.log_command(f"httpheaders {url}", False, str(e))
                    print(f"{Colors.FAIL}Site unreachable or blocked (ERR_CONN): {str(e)}{Colors.ENDC}")
            except requests.exceptions.RequestException as e:
                self.log_command(f"httpheaders {url}", False, str(e))
                print(f"{Colors.FAIL}Site unreachable or blocked (ERR_CONN): {str(e)}{Colors.ENDC}")
        except Exception as e:
            self.log_command(f"httpheaders {url}", False, str(e))
            print(f"{Colors.FAIL}Error: {str(e)}{Colors.ENDC}")
            
    def whois_lookup(self, target):
        try:
            print(f"{Colors.HEADER}WHOIS lookup for {target}{Colors.ENDC}")
            
            if self.validate_ip(target):
                
                w = whois.whois(target)
            elif self.validate_domain(target):
                
                if not target.startswith(('http://', 'https://')):
                    target = 'http://' + target
                parsed = urlparse(target)
                w = whois.whois(parsed.netloc or parsed.path)
            else:
                self.log_command(f"whois {target}", False, "Invalid IP or domain")
                print(f"{Colors.FAIL}Error: Invalid IP or domain{Colors.ENDC}")
                return
                
            if w:
                for key, value in w.items():
                    if isinstance(value, list):
                        print(f"{Colors.BOLD}{key}:{Colors.ENDC}")
                        for item in value:
                            print(f"  {item}")
                    else:
                        print(f"{Colors.BOLD}{key}:{Colors.ENDC} {value}")
            else:
                print(f"{Colors.WARNING}No WHOIS information found{Colors.ENDC}")
                
            self.log_command(f"whois {target}", True)
        except Exception as e:
            self.log_command(f"whois {target}", False, str(e))
            print(f"{Colors.FAIL}Error: {str(e)}{Colors.ENDC}")
            
    def geoip(self, ip):
        try:
            if not self.validate_ip(ip):
                self.log_command(f"geoip {ip}", False, "Invalid IP address")
                print(f"{Colors.FAIL}Error: Invalid IP address{Colors.ENDC}")
                return
                
            if self.is_private_ip(ip):
                print(f"{Colors.WARNING}Private IP addresses don't have geolocation data{Colors.ENDC}")
                return
                
            print(f"{Colors.HEADER}Geolocation data for {ip}{Colors.ENDC}")
            
            try:
                response = requests.get(f"http://ip-api.com/json/{ip}").json()
                if response['status'] == 'success':
                    print(f"{Colors.BOLD}Country:{Colors.ENDC} {response.get('country', 'N/A')}")
                    print(f"{Colors.BOLD}Country Code:{Colors.ENDC} {response.get('countryCode', 'N/A')}")
                    print(f"{Colors.BOLD}Region:{Colors.ENDC} {response.get('regionName', 'N/A')}")
                    print(f"{Colors.BOLD}City:{Colors.ENDC} {response.get('city', 'N/A')}")
                    print(f"{Colors.BOLD}ZIP:{Colors.ENDC} {response.get('zip', 'N/A')}")
                    print(f"{Colors.BOLD}Latitude:{Colors.ENDC} {response.get('lat', 'N/A')}")
                    print(f"{Colors.BOLD}Longitude:{Colors.ENDC} {response.get('lon', 'N/A')}")
                    print(f"{Colors.BOLD}Timezone:{Colors.ENDC} {response.get('timezone', 'N/A')}")
                    print(f"{Colors.BOLD}ISP:{Colors.ENDC} {response.get('isp', 'N/A')}")
                    print(f"{Colors.BOLD}Organization:{Colors.ENDC} {response.get('org', 'N/A')}")
                    print(f"{Colors.BOLD}AS:{Colors.ENDC} {response.get('as', 'N/A')}")
                else:
                    print(f"{Colors.WARNING}Could not fetch geolocation data{Colors.ENDC}")
                    
                self.log_command(f"geoip {ip}", True)
            except Exception as e:
                self.log_command(f"geoip {ip}", False, str(e))
                print(f"{Colors.FAIL}Error fetching geolocation data: {str(e)}{Colors.ENDC}")
        except Exception as e:
            self.log_command(f"geoip {ip}", False, str(e))
            print(f"{Colors.FAIL}Error: {str(e)}{Colors.ENDC}")
            
    def reverse_dns(self, ip):
        try:
            if not self.validate_ip(ip):
                self.log_command(f"reverse {ip}", False, "Invalid IP address")
                print(f"{Colors.FAIL}Error: Invalid IP address{Colors.ENDC}")
                return
                
            print(f"{Colors.HEADER}Reverse DNS lookup for {ip}{Colors.ENDC}")
            
            try:
                hostname, aliaslist, ipaddrlist = socket.gethostbyaddr(ip)
                print(f"{Colors.BOLD}Hostname:{Colors.ENDC} {hostname}")
                if aliaslist:
                    print(f"{Colors.BOLD}Aliases:{Colors.ENDC}")
                    for alias in aliaslist:
                        print(f"  {alias}")
                if ipaddrlist:
                    print(f"{Colors.BOLD}IP Addresses:{Colors.ENDC}")
                    for addr in ipaddrlist:
                        print(f"  {addr}")
                        
                self.log_command(f"reverse {ip}", True)
            except socket.herror:
                self.log_command(f"reverse {ip}", False, "No reverse DNS record found")
                print(f"{Colors.WARNING}No reverse DNS record found{Colors.ENDC}")
        except Exception as e:
            self.log_command(f"reverse {ip}", False, str(e))
            print(f"{Colors.FAIL}Error: {str(e)}{Colors.ENDC}")
            
    def tracklog(self, live=False):
        try:
            if live:
                print(f"{Colors.HEADER}Live command log (last 20 entries){Colors.ENDC}")
                print(f"{Colors.WARNING}Press Ctrl+C to stop live logging{Colors.ENDC}")
                try:
                    while True:
                        last_entries = self.command_history[-20:] if len(self.command_history) > 20 else self.command_history
                        os.system('cls' if os.name == 'nt' else 'clear')
                        for entry in last_entries:
                            print(entry)
                        time.sleep(2)
                except KeyboardInterrupt:
                    return
            else:
                print(f"{Colors.HEADER}Command log (last 20 entries){Colors.ENDC}")
                last_entries = self.command_history[-20:] if len(self.command_history) > 20 else self.command_history
                for entry in last_entries:
                    print(entry)
                    
            self.log_command("tracklog", True)
        except Exception as e:
            self.log_command("tracklog", False, str(e))
            print(f"{Colors.FAIL}Error: {str(e)}{Colors.ENDC}")
            
 
    
    def dns_lookup(self, domain, record_type='A'):
        try:
            valid_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
            if record_type.upper() not in valid_types:
                self.log_command(f"dns {domain} {record_type}", False, "Invalid record type")
                print(f"{Colors.FAIL}Error: Invalid record type. Valid types are: {', '.join(valid_types)}{Colors.ENDC}")
                return
                
            print(f"{Colors.HEADER}DNS {record_type} records for {domain}{Colors.ENDC}")
            
            try:
                answers = dns.resolver.resolve(domain, record_type)
                for rdata in answers:
                    print(rdata.to_text())
                    
                self.log_command(f"dns {domain} {record_type}", True)
            except dns.resolver.NoAnswer:
                self.log_command(f"dns {domain} {record_type}", False, "No records found")
                print(f"{Colors.WARNING}No {record_type} records found{Colors.ENDC}")
            except dns.resolver.NXDOMAIN:
                self.log_command(f"dns {domain} {record_type}", False, "Domain does not exist")
                print(f"{Colors.FAIL}Domain does not exist{Colors.ENDC}")
            except Exception as e:
                self.log_command(f"dns {domain} {record_type}", False, str(e))
                print(f"{Colors.FAIL}Error: {str(e)}{Colors.ENDC}")
        except Exception as e:
            self.log_command(f"dns {domain} {record_type}", False, str(e))
            print(f"{Colors.FAIL}Error: {str(e)}{Colors.ENDC}")
            
    def subdomain_scan(self, domain, wordlist=None):
        try:
            print(f"{Colors.HEADER}Subdomain scan for {domain}{Colors.ENDC}")
            
            common_subdomains = [
                'www', 'mail', 'ftp', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
                'blog', 'dev', 'test', 'admin', 'secure', 'portal', 'cpanel',
                'webdisk', 'autodiscover', 'api', 'm', 'mobile', 'shop'
            ]
            
            if wordlist:
                try:
                    with open(wordlist, 'r') as f:
                        custom_subdomains = [line.strip() for line in f if line.strip()]
                    common_subdomains.extend(custom_subdomains)
                except Exception as e:
                    print(f"{Colors.WARNING}Could not read wordlist file: {str(e)}{Colors.ENDC}")
                    
            found = False
            for sub in common_subdomains:
                full_domain = f"{sub}.{domain}"
                try:
                    ip = socket.gethostbyname(full_domain)
                    print(f"{Colors.OKGREEN}{full_domain.ljust(30)} {ip}{Colors.ENDC}")
                    found = True
                except socket.gaierror:
                    continue
                    
            if not found:
                print(f"{Colors.WARNING}No common subdomains found{Colors.ENDC}")
                
            self.log_command(f"subdomain {domain}", True)
        except Exception as e:
            self.log_command(f"subdomain {domain}", False, str(e))
            print(f"{Colors.FAIL}Error: {str(e)}{Colors.ENDC}")
            
    def hash_string(self, text, algorithm='sha256'):
        try:
            valid_algorithms = ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512']
            if algorithm.lower() not in valid_algorithms:
                self.log_command(f"hash {algorithm} <text>", False, "Invalid algorithm")
                print(f"{Colors.FAIL}Error: Invalid algorithm. Valid options: {', '.join(valid_algorithms)}{Colors.ENDC}")
                return
                
            print(f"{Colors.HEADER}{algorithm.upper()} hash{Colors.ENDC}")
            
            h = hashlib.new(algorithm)
            h.update(text.encode('utf-8'))
            print(h.hexdigest())
            
            self.log_command(f"hash {algorithm} <text>", True)
        except Exception as e:
            self.log_command(f"hash {algorithm} <text>", False, str(e))
            print(f"{Colors.FAIL}Error: {str(e)}{Colors.ENDC}")
            
    def encode_base64(self, text):
        try:
            print(f"{Colors.HEADER}Base64 encoded{Colors.ENDC}")
            encoded = base64.b64encode(text.encode('utf-8')).decode('utf-8')
            print(encoded)
            
            self.log_command("encode base64 <text>", True)
        except Exception as e:
            self.log_command("encode base64 <text>", False, str(e))
            print(f"{Colors.FAIL}Error: {str(e)}{Colors.ENDC}")
            
    def decode_base64(self, text):
        try:
            print(f"{Colors.HEADER}Base64 decoded{Colors.ENDC}")
            decoded = base64.b64decode(text.encode('utf-8')).decode('utf-8')
            print(decoded)
            
            self.log_command("decode base64 <text>", True)
        except Exception as e:
            self.log_command("decode base64 <text>", False, str(e))
            print(f"{Colors.FAIL}Error: {str(e)}{Colors.ENDC}")
            
    def generate_password(self, length=12, complexity=3):
        try:
            if length < 4 or length > 64:
                self.log_command("generate_password", False, "Invalid length (4-64)")
                print(f"{Colors.FAIL}Error: Password length must be between 4 and 64{Colors.ENDC}")
                return
                
            if complexity < 1 or complexity > 4:
                self.log_command("generate_password", False, "Invalid complexity (1-4)")
                print(f"{Colors.FAIL}Error: Complexity must be between 1 and 4{Colors.ENDC}")
                return
                
            print(f"{Colors.HEADER}Generated Password{Colors.ENDC}")
            
            lower = string.ascii_lowercase
            upper = string.ascii_uppercase
            digits = string.digits
            special = '!@#$%^&*()_+-=[]{}|;:,.<>?'
            
            chars = lower
            if complexity >= 2:
                chars += upper + digits
            if complexity >= 3:
                chars += special
            if complexity >= 4:
                chars += ' '  
                
            password = ''.join(random.choice(chars) for _ in range(length))
            print(password)
            
            self.log_command("generate_password", True)
        except Exception as e:
            self.log_command("generate_password", False, str(e))
            print(f"{Colors.FAIL}Error: {str(e)}{Colors.ENDC}")
            
    def analyze_headers(self, url):
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
                
            parsed = urlparse(url)
            if not parsed.netloc:
                self.log_command(f"analyze {url}", False, "Invalid URL")
                print(f"{Colors.FAIL}Error: Invalid URL{Colors.ENDC}")
                return
                
            print(f"{Colors.HEADER}Security Header Analysis for {url}{Colors.ENDC}")
            
            try:
                response = requests.get(url, timeout=5, allow_redirects=True)
                headers = response.headers
                
                security_headers = {
                    'Strict-Transport-Security': {
                        'description': 'Enforces secure (HTTP over SSL/TLS) connections to the server',
                        'recommended': 'max-age=31536000; includeSubDomains; preload',
                        'status': 'OK' if 'Strict-Transport-Security' in headers else 'MISSING'
                    },
                    'X-Frame-Options': {
                        'description': 'Protects against clickjacking attacks',
                        'recommended': 'DENY or SAMEORIGIN',
                        'status': headers.get('X-Frame-Options', 'MISSING')
                    },
                    'X-Content-Type-Options': {
                        'description': 'Prevents MIME-sniffing attacks',
                        'recommended': 'nosniff',
                        'status': headers.get('X-Content-Type-Options', 'MISSING')
                    },
                    'Content-Security-Policy': {
                        'description': 'Prevents XSS attacks by controlling resources',
                        'recommended': 'See CSP documentation for proper policy',
                        'status': 'OK' if 'Content-Security-Policy' in headers else 'MISSING'
                    },
                    'X-XSS-Protection': {
                        'description': 'Enables XSS filtering in older browsers',
                        'recommended': '1; mode=block',
                        'status': headers.get('X-XSS-Protection', 'MISSING')
                    },
                    'Referrer-Policy': {
                        'description': 'Controls referrer information in requests',
                        'recommended': 'no-referrer-when-downgrade or stricter',
                        'status': headers.get('Referrer-Policy', 'MISSING')
                    },
                    'Feature-Policy': {
                        'description': 'Controls which features can be used',
                        'recommended': 'See Feature Policy documentation',
                        'status': 'OK' if 'Feature-Policy' in headers else 'MISSING'
                    }
                }
                
                for header, info in security_headers.items():
                    status = info['status']
                    color = Colors.OKGREEN if status != 'MISSING' else Colors.FAIL
                    print(f"{Colors.BOLD}{header}:{Colors.ENDC} {color}{status}{Colors.ENDC}")
                    print(f"  {info['description']}")
                    if status != 'MISSING' and status != info.get('recommended', ''):
                        print(f"  {Colors.WARNING}Note: Recommended value is '{info['recommended']}'{Colors.ENDC}")
                    print()
                    
                self.log_command(f"analyze {url}", True)
            except requests.exceptions.RequestException as e:
                self.log_command(f"analyze {url}", False, str(e))
                print(f"{Colors.FAIL}Site unreachable or blocked (ERR_CONN): {str(e)}{Colors.ENDC}")
        except Exception as e:
            self.log_command(f"analyze {url}", False, str(e))
            print(f"{Colors.FAIL}Error: {str(e)}{Colors.ENDC}")
            
    def check_http_methods(self, url):
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
                
            parsed = urlparse(url)
            if not parsed.netloc:
                self.log_command(f"httpmethods {url}", False, "Invalid URL")
                print(f"{Colors.FAIL}Error: Invalid URL{Colors.ENDC}")
                return
                
            print(f"{Colors.HEADER}Allowed HTTP Methods for {url}{Colors.ENDC}")
            
            methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH', 'TRACE']
            allowed_methods = []
            
            try:
             
                response = requests.options(url, timeout=5)
                if 'Allow' in response.headers:
                    allowed = response.headers['Allow'].split(', ')
                    allowed_methods.extend([m.upper() for m in allowed])
                else:
                
                    for method in methods:
                        try:
                            if method == 'GET':
                                requests.get(url, timeout=2)
                                allowed_methods.append(method)
                            elif method == 'POST':
                                requests.post(url, timeout=2, data={'test': 'test'})
                                allowed_methods.append(method)
                            elif method == 'PUT':
                                requests.put(url, timeout=2, data={'test': 'test'})
                                allowed_methods.append(method)
                            elif method == 'DELETE':
                                requests.delete(url, timeout=2)
                                allowed_methods.append(method)
                            elif method == 'HEAD':
                                requests.head(url, timeout=2)
                                allowed_methods.append(method)
                            elif method == 'OPTIONS':
                                allowed_methods.append(method)
                            elif method == 'PATCH':
                                requests.patch(url, timeout=2, data={'test': 'test'})
                                allowed_methods.append(method)
                            elif method == 'TRACE':
                                
                                try:
                                    requests.request('TRACE', url, timeout=2)
                                    allowed_methods.append(method)
                                except:
                                    pass
                        except requests.exceptions.RequestException:
                            pass
                            
                if allowed_methods:
                    print(f"{Colors.OKGREEN}Allowed methods: {', '.join(allowed_methods)}{Colors.ENDC}")
                    
                    
                    dangerous = set(allowed_methods) & {'PUT', 'DELETE', 'TRACE'}
                    if dangerous:
                        print(f"{Colors.WARNING}Warning: Potentially dangerous methods allowed: {', '.join(dangerous)}{Colors.ENDC}")
                else:
                    print(f"{Colors.WARNING}Could not determine allowed methods{Colors.ENDC}")
                    
                self.log_command(f"httpmethods {url}", True)
            except requests.exceptions.RequestException as e:
                self.log_command(f"httpmethods {url}", False, str(e))
                print(f"{Colors.FAIL}Site unreachable or blocked (ERR_CONN): {str(e)}{Colors.ENDC}")
        except Exception as e:
            self.log_command(f"httpmethods {url}", False, str(e))
            print(f"{Colors.FAIL}Error: {str(e)}{Colors.ENDC}")
            
    def check_robots_txt(self, url):
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
                
            parsed = urlparse(url)
            if not parsed.netloc:
                self.log_command(f"robots {url}", False, "Invalid URL")
                print(f"{Colors.FAIL}Error: Invalid URL{Colors.ENDC}")
                return
                
            robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
            print(f"{Colors.HEADER}Checking {robots_url}{Colors.ENDC}")
            
            try:
                response = requests.get(robots_url, timeout=5)
                if response.status_code == 200:
                    print(response.text)
                    
                    lines = response.text.split('\n')
                    disallowed = [line.split('Disallow:')[1].strip() for line in lines if line.startswith('Disallow:')]
                    if disallowed:
                        print(f"\n{Colors.BOLD}Disallowed paths:{Colors.ENDC}")
                        for path in disallowed:
                            print(f"  {path}")
                else:
                    print(f"{Colors.WARNING}robots.txt not found (HTTP {response.status_code}){Colors.ENDC}")
                    
                self.log_command(f"robots {url}", True)
            except requests.exceptions.RequestException as e:
                self.log_command(f"robots {url}", False, str(e))
                print(f"{Colors.FAIL}Could not fetch robots.txt: {str(e)}{Colors.ENDC}")
        except Exception as e:
            self.log_command(f"robots {url}", False, str(e))
            print(f"{Colors.FAIL}Error: {str(e)}{Colors.ENDC}")
            
    def check_cors(self, url):
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
                
            parsed = urlparse(url)
            if not parsed.netloc:
                self.log_command(f"cors {url}", False, "Invalid URL")
                print(f"{Colors.FAIL}Error: Invalid URL{Colors.ENDC}")
                return
                
            print(f"{Colors.HEADER}CORS Test for {url}{Colors.ENDC}")
            
            try:
                headers = {
                    'Origin': 'https://example.com',
                    'Access-Control-Request-Method': 'GET',
                    'Access-Control-Request-Headers': 'X-Requested-With'
                }
                
               
                response = requests.options(url, headers=headers, timeout=5)
                cors_headers = {
                    'Access-Control-Allow-Origin': response.headers.get('Access-Control-Allow-Origin', 'NOT SET'),
                    'Access-Control-Allow-Credentials': response.headers.get('Access-Control-Allow-Credentials', 'NOT SET'),
                    'Access-Control-Allow-Methods': response.headers.get('Access-Control-Allow-Methods', 'NOT SET'),
                    'Access-Control-Allow-Headers': response.headers.get('Access-Control-Allow-Headers', 'NOT SET')
                }
                
                print(f"{Colors.BOLD}Preflight Response:{Colors.ENDC}")
                for header, value in cors_headers.items():
                    print(f"  {header}: {value}")
                    
               
                if cors_headers['Access-Control-Allow-Origin'] == '*':
                    print(f"{Colors.WARNING}Warning: Access-Control-Allow-Origin is set to '*' which is insecure{Colors.ENDC}")
                    
                
                response = requests.get(url, headers={'Origin': 'https://example.com'}, timeout=5)
                acao = response.headers.get('Access-Control-Allow-Origin', 'NOT SET')
                acac = response.headers.get('Access-Control-Allow-Credentials', 'NOT SET')
                
                print(f"\n{Colors.BOLD}Actual Request Response:{Colors.ENDC}")
                print(f"  Access-Control-Allow-Origin: {acao}")
                print(f"  Access-Control-Allow-Credentials: {acac}")
                
                
                if acao == '*' and acac == 'true':
                    print(f"{Colors.FAIL}Critical: Insecure CORS configuration - Credentials with wildcard origin{Colors.ENDC}")
                elif acao == 'https://example.com' and acac == 'true':
                    print(f"{Colors.OKGREEN}Proper CORS configuration - Specific origin with credentials{Colors.ENDC}")
                elif acao == '*' and acac == 'NOT SET':
                    print(f"{Colors.WARNING}Warning: CORS allows any origin but credentials not enabled{Colors.ENDC}")
                    
                self.log_command(f"cors {url}", True)
            except requests.exceptions.RequestException as e:
                self.log_command(f"cors {url}", False, str(e))
                print(f"{Colors.FAIL}Could not test CORS: {str(e)}{Colors.ENDC}")
        except Exception as e:
            self.log_command(f"cors {url}", False, str(e))
            print(f"{Colors.FAIL}Error: {str(e)}{Colors.ENDC}")
            
    def check_redirects(self, url):
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
                
            parsed = urlparse(url)
            if not parsed.netloc:
                self.log_command(f"redirects {url}", False, "Invalid URL")
                print(f"{Colors.FAIL}Error: Invalid URL{Colors.ENDC}")
                return
                
            print(f"{Colors.HEADER}Redirect Chain for {url}{Colors.ENDC}")
            
            try:
                response = requests.get(url, timeout=5, allow_redirects=False)
                redirect_count = 0
                current_url = url
                
                while response.status_code in (301, 302, 303, 307, 308):
                    redirect_count += 1
                    print(f"{redirect_count}. {current_url} → {response.status_code} → {response.headers['Location']}")
                    current_url = response.headers['Location']
                    response = requests.get(current_url, timeout=5, allow_redirects=False)
                    
                if redirect_count == 0:
                    print("No redirects detected")
                else:
                    print(f"\nFinal URL: {current_url}")
                    
                self.log_command(f"redirects {url}", True)
            except requests.exceptions.RequestException as e:
                self.log_command(f"redirects {url}", False, str(e))
                print(f"{Colors.FAIL}Could not trace redirects: {str(e)}{Colors.ENDC}")
        except Exception as e:
            self.log_command(f"redirects {url}", False, str(e))
            print(f"{Colors.FAIL}Error: {str(e)}{Colors.ENDC}")
            
    def check_ssl(self, domain):
        try:
            if not self.validate_domain(domain):
                self.log_command(f"ssl {domain}", False, "Invalid domain")
                print(f"{Colors.FAIL}Error: Invalid domain{Colors.ENDC}")
                return
                
            print(f"{Colors.HEADER}SSL Certificate Check for {domain}{Colors.ENDC}")
            
            try:
                import ssl
                import OpenSSL
                from cryptography import x509
                from cryptography.hazmat.backends import default_backend
                
                
                cert = ssl.get_server_certificate((domain, 443))
                x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
                
                
                subject = x509.get_subject()
                print(f"{Colors.BOLD}Subject:{Colors.ENDC}")
                for k, v in subject.get_components():
                    print(f"  {k.decode()}: {v.decode()}")
                    
                
                issuer = x509.get_issuer()
                print(f"\n{Colors.BOLD}Issuer:{Colors.ENDC}")
                for k, v in issuer.get_components():
                    print(f"  {k.decode()}: {v.decode()}")
                    
              
                not_before = x509.get_notBefore().decode('ascii')
                not_after = x509.get_notAfter().decode('ascii')
                print(f"\n{Colors.BOLD}Validity:{Colors.ENDC}")
                print(f"  Not Before: {not_before[:4]}-{not_before[4:6]}-{not_before[6:8]}")
                print(f"  Not After : {not_after[:4]}-{not_after[4:6]}-{not_after[6:8]}")
                
                
                expiration_date = datetime.strptime(not_after, '%Y%m%d%H%M%SZ')
                days_left = (expiration_date - datetime.now()).days
                if days_left < 30:
                    color = Colors.FAIL
                elif days_left < 90:
                    color = Colors.WARNING
                else:
                    color = Colors.OKGREEN
                print(f"  Days Left : {color}{days_left}{Colors.ENDC}")
                
              
                print(f"\n{Colors.BOLD}Signature Algorithm:{Colors.ENDC} {x509.get_signature_algorithm().decode()}")
                
              
                print(f"\n{Colors.BOLD}Security Checks:{Colors.ENDC}")
                
               
                sig_algo = x509.get_signature_algorithm().decode()
                if 'sha1' in sig_algo.lower():
                    print(f"  {Colors.FAIL}Insecure: Certificate signed with SHA-1{Colors.ENDC}")
                else:
                    print(f"  {Colors.OKGREEN}Secure: Certificate not signed with SHA-1{Colors.ENDC}")
                    
                
                pub_key = x509.get_pubkey()
                bits = pub_key.bits()
                if bits < 2048:
                    print(f"  {Colors.FAIL}Insecure: Key length is only {bits} bits (should be at least 2048){Colors.ENDC}")
                else:
                    print(f"  {Colors.OKGREEN}Secure: Key length is {bits} bits{Colors.ENDC}")
                    
                self.log_command(f"ssl {domain}", True)
            except ImportError:
                self.log_command(f"ssl {domain}", False, "Required libraries not installed")
                print(f"{Colors.FAIL}Error: Required libraries (pyOpenSSL, cryptography) not installed{Colors.ENDC}")
            except Exception as e:
                self.log_command(f"ssl {domain}", False, str(e))
                print(f"{Colors.FAIL}Error checking SSL certificate: {str(e)}{Colors.ENDC}")
        except Exception as e:
            self.log_command(f"ssl {domain}", False, str(e))
            print(f"{Colors.FAIL}Error: {str(e)}{Colors.ENDC}")
            
    def check_email_security(self, domain):
        try:
            if not self.validate_domain(domain):
                self.log_command(f"emailsec {domain}", False, "Invalid domain")
                print(f"{Colors.FAIL}Error: Invalid domain{Colors.ENDC}")
                return
                
            print(f"{Colors.HEADER}Email Security Checks for {domain}{Colors.ENDC}")
            
            try:
               
                try:
                    answers = dns.resolver.resolve(domain, 'TXT')
                    spf_found = any('v=spf1' in rdata.to_text().lower() for rdata in answers)
                    if spf_found:
                        print(f"{Colors.OKGREEN}SPF record found{Colors.ENDC}")
                    else:
                        print(f"{Colors.FAIL}No SPF record found{Colors.ENDC}")
                except dns.resolver.NoAnswer:
                    print(f"{Colors.FAIL}No SPF record found{Colors.ENDC}")
                except Exception:
                    print(f"{Colors.WARNING}Could not check SPF record{Colors.ENDC}")
                    
                
                common_selectors = ['default', 'dkim', 'google', 'selector1', 'selector2']
                dkim_found = False
                for selector in common_selectors:
                    try:
                        dns.resolver.resolve(f"{selector}._domainkey.{domain}", 'TXT')
                        dkim_found = True
                        print(f"{Colors.OKGREEN}DKIM record found (selector: {selector}){Colors.ENDC}")
                        break
                    except dns.resolver.NoAnswer:
                        continue
                    except Exception:
                        continue
                        
                if not dkim_found:
                    print(f"{Colors.FAIL}No DKIM records found for common selectors{Colors.ENDC}")
                    
                
                try:
                    answers = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
                    dmarc_found = any('v=dmarc1' in rdata.to_text().lower() for rdata in answers)
                    if dmarc_found:
                        print(f"{Colors.OKGREEN}DMARC record found{Colors.ENDC}")
                    else:
                        print(f"{Colors.FAIL}No DMARC record found{Colors.ENDC}")
                except dns.resolver.NoAnswer:
                    print(f"{Colors.FAIL}No DMARC record found{Colors.ENDC}")
                except Exception:
                    print(f"{Colors.WARNING}Could not check DMARC record{Colors.ENDC}")
                    
                
                try:
                    answers = dns.resolver.resolve(domain, 'MX')
                    mx_records = [str(rdata.exchange) for rdata in answers]
                    print(f"\n{Colors.BOLD}MX Records:{Colors.ENDC}")
                    for mx in mx_records:
                        print(f"  {mx}")
                except dns.resolver.NoAnswer:
                    print(f"{Colors.FAIL}No MX records found{Colors.ENDC}")
                except Exception:
                    print(f"{Colors.WARNING}Could not check MX records{Colors.ENDC}")
                    
                self.log_command(f"emailsec {domain}", True)
            except Exception as e:
                self.log_command(f"emailsec {domain}", False, str(e))
                print(f"{Colors.FAIL}Error checking email security: {str(e)}{Colors.ENDC}")
        except Exception as e:
            self.log_command(f"emailsec {domain}", False, str(e))
            print(f"{Colors.FAIL}Error: {str(e)}{Colors.ENDC}")
            
    def check_http_server(self, url):
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
                
            parsed = urlparse(url)
            if not parsed.netloc:
                self.log_command(f"serverinfo {url}", False, "Invalid URL")
                print(f"{Colors.FAIL}Error: Invalid URL{Colors.ENDC}")
                return
                
            print(f"{Colors.HEADER}HTTP Server Information for {url}{Colors.ENDC}")
            
            try:
                response = requests.head(url, timeout=5, allow_redirects=True)
                server = response.headers.get('Server', 'NOT DISCLOSED')
                powered_by = response.headers.get('X-Powered-By', 'NOT DISCLOSED')
                
                print(f"{Colors.BOLD}Server:{Colors.ENDC} {server}")
                print(f"{Colors.BOLD}X-Powered-By:{Colors.ENDC} {powered_by}")
                
                
                print(f"\n{Colors.BOLD}Security Notes:{Colors.ENDC}")
                
                
                if server == 'NOT DISCLOSED' and powered_by == 'NOT DISCLOSED':
                    print(f"  {Colors.OKGREEN}Good: Server information not disclosed{Colors.ENDC}")
                else:
                    print(f"  {Colors.WARNING}Note: Server information disclosed{Colors.ENDC}")
                    
                
                outdated = False
                if 'Apache/2.2' in server:
                    print(f"  {Colors.FAIL}Critical: Outdated Apache version (2.2){Colors.ENDC}")
                    outdated = True
                if 'Apache/2.4' in server and '2.4.' in server and int(server.split('2.4.')[1][0]) < 5:
                    print(f"  {Colors.WARNING}Warning: Older Apache 2.4 version{Colors.ENDC}")
                    outdated = True
                if 'nginx/' in server and float(server.split('nginx/')[1].split()[0]) < 1.14:
                    print(f"  {Colors.WARNING}Warning: Older nginx version{Colors.ENDC}")
                    outdated = True
                if 'IIS/7.' in server or 'IIS/6.' in server:
                    print(f"  {Colors.FAIL}Critical: Outdated IIS version{Colors.ENDC}")
                    outdated = True
                    
                if not outdated:
                    print(f"  {Colors.OKGREEN}No obviously outdated server version detected{Colors.ENDC}")
                    
                self.log_command(f"serverinfo {url}", True)
            except requests.exceptions.RequestException as e:
                self.log_command(f"serverinfo {url}", False, str(e))
                print(f"{Colors.FAIL}Site unreachable or blocked (ERR_CONN): {str(e)}{Colors.ENDC}")
        except Exception as e:
            self.log_command(f"serverinfo {url}", False, str(e))
            print(f"{Colors.FAIL}Error: {str(e)}{Colors.ENDC}")
            
    def check_web_tech(self, url):
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
                
            parsed = urlparse(url)
            if not parsed.netloc:
                self.log_command(f"webtech {url}", False, "Invalid URL")
                print(f"{Colors.FAIL}Error: Invalid URL{Colors.ENDC}")
                return
                
            print(f"{Colors.HEADER}Web Technology Detection for {url}{Colors.ENDC}")
            
            try:
                response = requests.get(url, timeout=5, allow_redirects=True)
                headers = response.headers
                html = response.text
                
                detected = []
                
                
                server = headers.get('Server', '')
                powered_by = headers.get('X-Powered-By', '')
                
                if server:
                    detected.append(f"Server: {server}")
                if powered_by:
                    detected.append(f"Powered By: {powered_by}")
                    
             
                framework_patterns = {
                    'WordPress': r'wp-content|wordpress',
                    'Joomla': r'joomla',
                    'Drupal': r'drupal',
                    'React': r'react|react-dom',
                    'Angular': r'angular',
                    'Vue.js': r'vue',
                    'jQuery': r'jquery',
                    'Bootstrap': r'bootstrap',
                    'Laravel': r'laravel',
                    'Django': r'csrfmiddlewaretoken|django',
                    'Ruby on Rails': r'rails',
                    '.NET': r'__VIEWSTATE|asp.net'
                }
                
                for name, pattern in framework_patterns.items():
                    if re.search(pattern, html, re.IGNORECASE):
                        detected.append(name)
                        
             
                analytics_patterns = {
                    'Google Analytics': r'google-analytics.com/ga.js',
                    'Google Tag Manager': r'googletagmanager.com/gtm.js',
                    'Facebook Pixel': r'connect.facebook.net/en_US/fbevents.js',
                    'Hotjar': r'hotjar.com'
                }
                
                for name, pattern in analytics_patterns.items():
                    if re.search(pattern, html, re.IGNORECASE):
                        detected.append(name)
                        
                if detected:
                    print(f"{Colors.BOLD}Detected Technologies:{Colors.ENDC}")
                    for tech in sorted(set(detected)):
                        print(f"  {tech}")
                else:
                    print(f"{Colors.WARNING}No common web technologies detected{Colors.ENDC}")
                    
                self.log_command(f"webtech {url}", True)
            except requests.exceptions.RequestException as e:
                self.log_command(f"webtech {url}", False, str(e))
                print(f"{Colors.FAIL}Site unreachable or blocked (ERR_CONN): {str(e)}{Colors.ENDC}")
        except Exception as e:
            self.log_command(f"webtech {url}", False, str(e))
            print(f"{Colors.FAIL}Error: {str(e)}{Colors.ENDC}")
            
    def check_dns_leak(self):
        try:
            print(f"{Colors.HEADER}DNS Leak Test{Colors.ENDC}")
            
            try:
         
                if os.name == 'nt': 
                    import winreg
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters") as key:
                        dns_servers = []
                        try:
                            i = 0
                            while True:
                                name, value, _ = winreg.EnumValue(key, i)
                                if name.startswith('NameServer'):
                                    dns_servers.extend(value.split(','))
                                i += 1
                        except WindowsError:
                            pass
                else:  # Unix-like
                    with open('/etc/resolv.conf') as f:
                        dns_servers = [line.split()[1] for line in f if line.startswith('nameserver')]
                        
                if not dns_servers:
                    print(f"{Colors.WARNING}Could not detect DNS servers{Colors.ENDC}")
                    return
                    
                print(f"{Colors.BOLD}Configured DNS Servers:{Colors.ENDC}")
                for server in dns_servers:
                    print(f"  {server}")
                    
            
                test_domains = ['google.com', 'facebook.com', 'amazon.com', 'microsoft.com']
                used_servers = set()
                
                print(f"\n{Colors.BOLD}Testing DNS queries:{Colors.ENDC}")
                for domain in test_domains:
                    try:
                        answers = dns.resolver.resolve(domain, 'A')
                        for rdata in answers:
                            print(f"  {domain} resolved to {rdata.address}")
                    except Exception as e:
                        print(f"  {Colors.WARNING}Could not resolve {domain}: {str(e)}{Colors.ENDC}")
                        
             
                print(f"\n{Colors.BOLD}Potential DNS Leak Detection:{Colors.ENDC}")
                if len(dns_servers) > 2:
                    print(f"  {Colors.WARNING}Warning: Multiple DNS servers configured{Colors.ENDC}")
                else:
                    print(f"  {Colors.OKGREEN}No obvious DNS leak detected{Colors.ENDC}")
                    
                self.log_command("dnsleak", True)
            except Exception as e:
                self.log_command("dnsleak", False, str(e))
                print(f"{Colors.FAIL}Error testing DNS leak: {str(e)}{Colors.ENDC}")
        except Exception as e:
            self.log_command("dnsleak", False, str(e))
            print(f"{Colors.FAIL}Error: {str(e)}{Colors.ENDC}")
            
    def check_ip_leak(self):
        try:
            print(f"{Colors.HEADER}IP Leak Test{Colors.ENDC}")
            
            try:            
                services = [
                    'https://api.ipify.org',
                    'https://ident.me',
                    'https://ifconfig.me/ip',
                    'https://ipecho.net/plain'
                ]
                
                ips = []
                for service in services:
                    try:
                        ip = requests.get(service, timeout=3).text.strip()
                        if self.validate_ip(ip):
                            ips.append(ip)
                            print(f"  {service}: {ip}")
                        else:
                            print(f"  {service}: {Colors.WARNING}Invalid response{Colors.ENDC}")
                    except Exception as e:
                        print(f"  {service}: {Colors.WARNING}Failed ({str(e)}){Colors.ENDC}")
                        
                if not ips:
                    print(f"{Colors.FAIL}Could not determine public IP{Colors.ENDC}")
                    return
                    
           
                unique_ips = set(ips)
                if len(unique_ips) > 1:
                    print(f"\n{Colors.FAIL}Warning: IP leak detected - different IPs reported{Colors.ENDC}")
                else:
                    print(f"\n{Colors.OKGREEN}No IP leak detected - consistent IP reported{Colors.ENDC}")
                    
                self.log_command("ipleak", True)
            except Exception as e:
                self.log_command("ipleak", False, str(e))
                print(f"{Colors.FAIL}Error testing IP leak: {str(e)}{Colors.ENDC}")
        except Exception as e:
            self.log_command("ipleak", False, str(e))
            print(f"{Colors.FAIL}Error: {str(e)}{Colors.ENDC}")
            
    def check_breaches(self, email):
        try:
            if '@' not in email or '.' not in email.split('@')[1]:
                self.log_command(f"breach {email}", False, "Invalid email")
                print(f"{Colors.FAIL}Error: Invalid email address{Colors.ENDC}")
                return
                
            print(f"{Colors.HEADER}Checking breaches for {email}{Colors.ENDC}")
            
            try:
                # Using haveibeenpwned.com API (requires API key for full access)
                # Note: This is a simulated check as the actual API requires a paid key
                
                # Simulate checking known breaches
                known_breaches = {
                    'example@example.com': ['Adobe', 'LinkedIn', 'Dropbox'],
                    'test@test.com': ['Yahoo', 'Last.fm']
                }
                
                if email in known_breaches:
                    print(f"{Colors.FAIL}Email found in {len(known_breaches[email])} breaches:{Colors.ENDC}")
                    for breach in known_breaches[email]:
                        print(f"  {breach}")
                else:
                    print(f"{Colors.OKGREEN}No known breaches found for this email{Colors.ENDC}")
                    
                print(f"\n{Colors.WARNING}Note: This is a simulated check. For real results, use haveibeenpwned.com API{Colors.ENDC}")
                
                self.log_command(f"breach {email}", True)
            except Exception as e:
                self.log_command(f"breach {email}", False, str(e))
                print(f"{Colors.FAIL}Error checking breaches: {str(e)}{Colors.ENDC}")
        except Exception as e:
            self.log_command(f"breach {email}", False, str(e))
            print(f"{Colors.FAIL}Error: {str(e)}{Colors.ENDC}")
            
    def check_password_strength(self, password):
        try:
            print(f"{Colors.HEADER}Password Strength Analysis{Colors.ENDC}")
            
            strength = 0
            feedback = []
            
      
            if len(password) >= 12:
                strength += 2
                feedback.append(f"{Colors.OKGREEN}✓ Good length (12+ characters){Colors.ENDC}")
            elif len(password) >= 8:
                strength += 1
                feedback.append(f"{Colors.WARNING}✓ Minimum length (8+ characters){Colors.ENDC}")
            else:
                feedback.append(f"{Colors.FAIL}✗ Too short (less than 8 characters){Colors.ENDC}")
                
       
            has_upper = any(c.isupper() for c in password)
            has_lower = any(c.islower() for c in password)
            has_digit = any(c.isdigit() for c in password)
            has_special = any(not c.isalnum() for c in password)
            
            if has_upper and has_lower:
                strength += 1
                feedback.append(f"{Colors.OKGREEN}✓ Contains both uppercase and lowercase letters{Colors.ENDC}")
            elif has_upper or has_lower:
                strength += 0.5
                feedback.append(f"{Colors.WARNING}✓ Contains only one case (should have both){Colors.ENDC}")
            else:
                feedback.append(f"{Colors.FAIL}✗ No letters or only one case{Colors.ENDC}")
                
            if has_digit:
                strength += 1
                feedback.append(f"{Colors.OKGREEN}✓ Contains numbers{Colors.ENDC}")
            else:
                feedback.append(f"{Colors.FAIL}✗ No numbers{Colors.ENDC}")
                
            if has_special:
                strength += 1
                feedback.append(f"{Colors.OKGREEN}✓ Contains special characters{Colors.ENDC}")
            else:
                feedback.append(f"{Colors.WARNING}✗ No special characters{Colors.ENDC}")
                
      
            common_passwords = ['password', '123456', 'qwerty', 'letmein', 'welcome']
            if password.lower() in common_passwords:
                strength = 0
                feedback.append(f"{Colors.FAIL}✗ Extremely common password{Colors.ENDC}")
                
       
            if any(password[i:i+3].isdigit() and 
                 int(password[i])+1 == int(password[i+1]) and 
                 int(password[i+1])+1 == int(password[i+2]) 
                 for i in range(len(password)-2)):
                strength -= 1
                feedback.append(f"{Colors.WARNING}✗ Contains sequential characters{Colors.ENDC}")
                
          
            if any(c * 3 in password for c in password):
                strength -= 1
                feedback.append(f"{Colors.WARNING}✗ Contains repeated characters{Colors.ENDC}")
                
        
            strength = max(0, min(5, strength))
            strength_text = {
                0: f"{Colors.FAIL}Very Weak{Colors.ENDC}",
                1: f"{Colors.FAIL}Weak{Colors.ENDC}",
                2: f"{Colors.WARNING}Moderate{Colors.ENDC}",
                3: f"{Colors.OKGREEN}Good{Colors.ENDC}",
                4: f"{Colors.OKGREEN}Strong{Colors.ENDC}",
                5: f"{Colors.OKGREEN}Very Strong{Colors.ENDC}"
            }[int(strength)]
            
            print("\n".join(feedback))
            print(f"\n{Colors.BOLD}Password Strength:{Colors.ENDC} {strength_text}")
            
            self.log_command("pwdstrength", True)
        except Exception as e:
            self.log_command("pwdstrength", False, str(e))
            print(f"{Colors.FAIL}Error: {str(e)}{Colors.ENDC}")
            
    def show_help(self):
        help_text = f"""
{Colors.HEADER}{Colors.BOLD}Available Commands:{Colors.ENDC}
{Colors.BOLD}Core Networking Tools:{Colors.ENDC}
  ipinfo <ip>           - Get detailed information about an IP address
  portscan <ip> <start>-<end> - Scan ports on a target IP
  httpheaders <url>     - Fetch HTTP headers from a URL
  whois <domain/ip>     - Perform WHOIS lookup
  geoip <ip>            - Get geolocation data for an IP
  reverse <ip>          - Perform reverse DNS lookup

{Colors.BOLD}DNS Tools:{Colors.ENDC}
  dns <domain> [type]   - Perform DNS lookup (A, AAAA, MX, NS, TXT, etc.)
  subdomain <domain>    - Scan for common subdomains
  emailsec <domain>     - Check email security (SPF, DKIM, DMARC)
  dnsleak               - Check for DNS leaks
  ipleak                - Check for IP leaks

{Colors.BOLD}Web Security Tools:{Colors.ENDC}
  analyze <url>         - Analyze HTTP security headers
  httpmethods <url>     - Check allowed HTTP methods
  robots <url>          - Check robots.txt file
  cors <url>            - Test CORS configuration
  redirects <url>       - Trace URL redirects
  ssl <domain>          - Check SSL certificate
  serverinfo <url>      - Get web server information
  webtech <url>         - Detect web technologies

{Colors.BOLD}Password Tools:{Colors.ENDC}
  hash <text> <alg>     - Hash text with algorithm (md5, sha1, sha256, etc.)
  encode base64 <text>  - Base64 encode text
  decode base64 <text>  - Base64 decode text
  pwdgen [len] [complexity] - Generate strong password
  pwdstrength <pwd>     - Check password strength

{Colors.BOLD}Privacy Tools:{Colors.ENDC}
  breach <email>        - Check if email appears in known breaches

{Colors.BOLD}System Tools:{Colors.ENDC}
  tracklog [--live]     - Show command history (add --live for real-time)
  clear                 - Clear the screen
  help                  - Show this help message
  exit                  - Exit the program
"""
        print(help_text)
        
    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')
        
    def run(self):
        self.start_log_thread()
        
        while self.running:
            try:
                command = input(f"{Colors.BOLD}{Colors.OKGREEN}⟩{Colors.ENDC}{Colors.ENDC} ").strip()
                if not command:
                    continue
                    
                parts = command.split()
                cmd = parts[0].lower()
                args = parts[1:]
                
                if cmd == 'ipinfo' and len(args) == 1:
                    self.ipinfo(args[0])
                elif cmd == 'portscan' and len(args) == 2:
                    self.portscan(args[0], args[1])
                elif cmd == 'httpheaders' and len(args) == 1:
                    self.httpheaders(args[0])
                elif cmd == 'whois' and len(args) == 1:
                    self.whois_lookup(args[0])
                elif cmd == 'geoip' and len(args) == 1:
                    self.geoip(args[0])
                elif cmd == 'reverse' and len(args) == 1:
                    self.reverse_dns(args[0])
                elif cmd == 'dns' and 1 <= len(args) <= 2:
                    record_type = args[1] if len(args) == 2 else 'A'
                    self.dns_lookup(args[0], record_type)
                elif cmd == 'subdomain' and len(args) >= 1:
                    wordlist = args[1] if len(args) >= 2 else None
                    self.subdomain_scan(args[0], wordlist)
                elif cmd == 'hash' and len(args) >= 2:
                    self.hash_string(' '.join(args[1:]), args[0])
                elif cmd == 'encode' and args[0] == 'base64' and len(args) >= 2:
                    self.encode_base64(' '.join(args[1:]))
                elif cmd == 'decode' and args[0] == 'base64' and len(args) >= 2:
                    self.decode_base64(' '.join(args[1:]))
                elif cmd == 'pwdgen':
                    length = int(args[0]) if len(args) >= 1 and args[0].isdigit() else 12
                    complexity = int(args[1]) if len(args) >= 2 and args[1].isdigit() else 3
                    self.generate_password(length, complexity)
                elif cmd == 'analyze' and len(args) == 1:
                    self.analyze_headers(args[0])
                elif cmd == 'httpmethods' and len(args) == 1:
                    self.check_http_methods(args[0])
                elif cmd == 'robots' and len(args) == 1:
                    self.check_robots_txt(args[0])
                elif cmd == 'cors' and len(args) == 1:
                    self.check_cors(args[0])
                elif cmd == 'redirects' and len(args) == 1:
                    self.check_redirects(args[0])
                elif cmd == 'ssl' and len(args) == 1:
                    self.check_ssl(args[0])
                elif cmd == 'emailsec' and len(args) == 1:
                    self.check_email_security(args[0])
                elif cmd == 'serverinfo' and len(args) == 1:
                    self.check_http_server(args[0])
                elif cmd == 'webtech' and len(args) == 1:
                    self.check_web_tech(args[0])
                elif cmd == 'dnsleak':
                    self.check_dns_leak()
                elif cmd == 'ipleak':
                    self.check_ip_leak()
                elif cmd == 'breach' and len(args) == 1:
                    self.check_breaches(args[0])
                elif cmd == 'pwdstrength' and len(args) >= 1:
                    self.check_password_strength(' '.join(args))
                elif cmd == 'tracklog':
                    live = '--live' in args
                    self.tracklog(live)
                elif cmd == 'clear':
                    self.clear_screen()
                elif cmd == 'help':
                    self.show_help()
                elif cmd == 'exit':
                    self.running = False
                else:
                    print(f"{Colors.FAIL}Error: Unknown command or invalid arguments{Colors.ENDC}")
                    print(f"Type 'help' for available commands")
            except KeyboardInterrupt:
                print("\nType 'exit' to quit or 'help' for commands")
            except Exception as e:
                print(f"{Colors.FAIL}Error: {str(e)}{Colors.ENDC}")
                
        print(f"{Colors.OKGREEN}Exiting...{Colors.ENDC}")

if __name__ == "__main__":
    tracker = StarexxTracker()
    tracker.run()_main__":
    tracker = StarexxTracker()
    tracker.run()
