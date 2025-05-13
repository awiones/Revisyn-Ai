import requests
import socket
import ssl
import datetime
import json
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from colorama import Fore, Style
import re
import dns.resolver
import whois
import time
import os

class Scanner:
    def __init__(self):
        self.headers = {
            'User-Agent': 'Revisyn-AI-Scanner/1.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'close',
        }
        self.timeout = 10
    
    def get_timestamp(self):
        """Get current timestamp for reports"""
        return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    def basic_recon(self, url):
        """Perform basic reconnaissance on the target URL"""
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        results = {
            "url": url,
            "domain": domain,
            "ip_addresses": [],
            "http_headers": {},
            "server_info": {},
            "dns_records": {},
            "whois_info": {},
            "technologies": [],
            "open_ports": [],
            "certificates": {}
        }
        
        # Get IP addresses
        try:
            print(f"{Fore.CYAN}[*] Resolving IP addresses...{Style.RESET_ALL}")
            ip_addresses = socket.gethostbyname_ex(domain)[2]
            results["ip_addresses"] = ip_addresses
            print(f"    Found {len(ip_addresses)} IP addresses")
        except Exception as e:
            print(f"{Fore.RED}[!] Error resolving IP addresses: {str(e)}{Style.RESET_ALL}")
        
        # Get HTTP headers
        try:
            print(f"{Fore.CYAN}[*] Retrieving HTTP headers...{Style.RESET_ALL}")
            response = requests.get(url, headers=self.headers, timeout=self.timeout, verify=False)
            results["http_headers"] = dict(response.headers)
            results["status_code"] = response.status_code
            print(f"    HTTP Status: {response.status_code}")
            
            # Check for security headers
            security_headers = [
                'Strict-Transport-Security',
                'Content-Security-Policy',
                'X-Content-Type-Options',
                'X-Frame-Options',
                'X-XSS-Protection',
                'Referrer-Policy',
                'Permissions-Policy',
                'Cross-Origin-Embedder-Policy',
                'Cross-Origin-Opener-Policy',
                'Cross-Origin-Resource-Policy'
            ]
            
            missing_headers = []
            for header in security_headers:
                if header not in response.headers:
                    missing_headers.append(header)
            
            if missing_headers:
                print(f"{Fore.YELLOW}[!] Missing security headers: {', '.join(missing_headers)}{Style.RESET_ALL}")
                results["missing_security_headers"] = missing_headers
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error retrieving HTTP headers: {str(e)}{Style.RESET_ALL}")
        
        # Get DNS records
        try:
            print(f"{Fore.CYAN}[*] Retrieving DNS records...{Style.RESET_ALL}")
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
            dns_records = {}
            
            for record_type in record_types:
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    records = [str(answer) for answer in answers]
                    dns_records[record_type] = records
                    print(f"    Found {len(records)} {record_type} records")
                except Exception:
                    pass
            
            results["dns_records"] = dns_records
        except Exception as e:
            print(f"{Fore.RED}[!] Error retrieving DNS records: {str(e)}{Style.RESET_ALL}")
        
        # Get WHOIS information
        try:
            print(f"{Fore.CYAN}[*] Retrieving WHOIS information...{Style.RESET_ALL}")
            whois_info = whois.whois(domain)
            # Convert to dict and handle datetime objects
            whois_dict = {}
            for key, value in whois_info.items():
                if isinstance(value, datetime.datetime):
                    whois_dict[key] = value.strftime("%Y-%m-%d %H:%M:%S")
                elif isinstance(value, list) and value and isinstance(value[0], datetime.datetime):
                    whois_dict[key] = [v.strftime("%Y-%m-%d %H:%M:%S") if isinstance(v, datetime.datetime) else v 
                                       for v in value]
                else:
                    whois_dict[key] = value
            results["whois_info"] = whois_dict
            print(f"    WHOIS data retrieved successfully")
        except Exception as e:
            print(f"{Fore.RED}[!] Error retrieving WHOIS information: {str(e)}{Style.RESET_ALL}")
        
        # Check for SSL/TLS certificate info
        if parsed_url.scheme == 'https':
            try:
                print(f"{Fore.CYAN}[*] Checking SSL/TLS certificate...{Style.RESET_ALL}")
                context = ssl.create_default_context()
                with socket.create_connection((domain, 443)) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        cert = ssock.getpeercert()
                        
                        # Extract relevant certificate information
                        cert_info = {
                            "subject": dict(x[0] for x in cert['subject']),
                            "issuer": dict(x[0] for x in cert['issuer']),
                            "version": cert['version'],
                            "serialNumber": cert['serialNumber'],
                            "notBefore": cert['notBefore'],
                            "notAfter": cert['notAfter']
                        }
                        
                        # Check certificate expiration
                        expiry_date = ssl.cert_time_to_seconds(cert['notAfter'])
                        current_time = time.time()
                        days_to_expiry = (expiry_date - current_time) / (24 * 60 * 60)
                        
                        if days_to_expiry < 30:
                            print(f"{Fore.YELLOW}[!] Certificate expires in {int(days_to_expiry)} days{Style.RESET_ALL}")
                            cert_info["expiry_warning"] = f"Certificate expires in {int(days_to_expiry)} days"
                        
                        results["certificates"] = cert_info
                        print(f"    Certificate issued by: {cert_info['issuer'].get('organizationName', 'Unknown')}")
                        
            except Exception as e:
                print(f"{Fore.RED}[!] Error checking SSL/TLS certificate: {str(e)}{Style.RESET_ALL}")
        
        # Detect technologies
        if 'http_headers' in results and results['http_headers']:
            try:
                print(f"{Fore.CYAN}[*] Detecting web technologies...{Style.RESET_ALL}")
                technologies = []
                
                # Check headers for common technologies
                headers = results['http_headers']
                
                if 'Server' in headers:
                    technologies.append(f"Server: {headers['Server']}")
                
                if 'X-Powered-By' in headers:
                    technologies.append(f"Powered by: {headers['X-Powered-By']}")
                
                # Check for common frameworks and CMS in response body
                try:
                    response = requests.get(url, headers=self.headers, timeout=self.timeout, verify=False)
                    html = response.text
                    soup = BeautifulSoup(html, 'html.parser')
                    
                    # Check for WordPress
                    wp_patterns = [
                        re.compile(r'wp-content'),
                        re.compile(r'wp-includes'),
                        re.compile(r'wordpress')
                    ]
                    
                    for pattern in wp_patterns:
                        if pattern.search(html.lower()):
                            technologies.append("CMS: WordPress")
                            break
                    
                    # Check for Joomla
                    if any(x in html.lower() for x in ['joomla', '/administrator', 'com_content']):
                        technologies.append("CMS: Joomla")
                    
                    # Check for Drupal
                    if any(x in html.lower() for x in ['drupal', 'drupal.settings']):
                        technologies.append("CMS: Drupal")
                    
                    # Check for JavaScript frameworks
                    js_frameworks = {
                        'React': ['react.js', 'react-dom', 'reactjs'],
                        'Angular': ['ng-app', 'angular.js', 'ng-controller'],
                        'Vue.js': ['vue.js', 'vue-router', 'vuex'],
                        'jQuery': ['jquery']
                    }
                    
                    for framework, patterns in js_frameworks.items():
                        if any(pattern in html.lower() for pattern in patterns):
                            technologies.append(f"Frontend: {framework}")
                    
                except Exception as e:
                    print(f"{Fore.RED}[!] Error analyzing page content: {str(e)}{Style.RESET_ALL}")
                
                results["technologies"] = technologies
                if technologies:
                    print(f"    Detected technologies: {', '.join(technologies)}")
                else:
                    print("    No specific technologies detected")
                    
            except Exception as e:
                print(f"{Fore.RED}[!] Error detecting technologies: {str(e)}{Style.RESET_ALL}")
        
        # Check for open ports (common web ports)
        try:
            print(f"{Fore.CYAN}[*] Checking common web ports...{Style.RESET_ALL}")
            common_ports = [80, 443, 8080, 8443]
            open_ports = []
            
            for port in common_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    result = sock.connect_ex((domain, port))
                    if result == 0:
                        open_ports.append(port)
                    sock.close()
                except:
                    pass
            
            results["open_ports"] = open_ports
            if open_ports:
                print(f"    Open ports: {', '.join(map(str, open_ports))}")
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error checking for open ports: {str(e)}{Style.RESET_ALL}")
        
        return results
    
    def crawl_website(self, url, max_pages=10):
        """
        Crawl website to discover pages and endpoints
        """
        print(f"{Fore.CYAN}[*] Crawling website (max {max_pages} pages)...{Style.RESET_ALL}")
        
        base_url = url
        parsed_base = urlparse(base_url)
        base_domain = parsed_base.netloc
        
        visited_urls = set()
        to_visit = [url]
        discovered_urls = []
        
        while to_visit and len(visited_urls) < max_pages:
            current_url = to_visit.pop(0)
            
            if current_url in visited_urls:
                continue
                
            try:
                print(f"    Crawling: {current_url}")
                response = requests.get(current_url, headers=self.headers, timeout=self.timeout, verify=False)
                visited_urls.add(current_url)
                discovered_urls.append({
                    "url": current_url,
                    "status_code": response.status_code
                })
                
                # Parse HTML and extract links
                soup = BeautifulSoup(response.text, 'html.parser')
                links = soup.find_all('a', href=True)
                
                for link in links:
                    href = link['href']
                    
                    # Handle relative URLs
                    if href.startswith('/'):
                        href = f"{parsed_base.scheme}://{base_domain}{href}"
                    elif not href.startswith(('http://', 'https://')):
                        continue
                    
                    # Stay on the same domain
                    if urlparse(href).netloc == base_domain and href not in visited_urls:
                        to_visit.append(href)
                        
            except Exception as e:
                print(f"{Fore.YELLOW}    Error crawling {current_url}: {str(e)}{Style.RESET_ALL}")
        
        print(f"{Fore.GREEN}[+] Discovered {len(discovered_urls)} URLs{Style.RESET_ALL}")
        return discovered_urls
    
    def extract_endpoints(self, urls):
        """
        Extract API endpoints and parameters from discovered URLs
        """
        endpoints = []
        
        for url_data in urls:
            url = url_data["url"]
            parsed = urlparse(url)
            
            # Check if URL has query parameters
            if parsed.query:
                endpoint = {
                    "url": url,
                    "path": parsed.path,
                    "parameters": {}
                }
                
                # Extract parameters
                for param in parsed.query.split('&'):
                    if '=' in param:
                        key, value = param.split('=', 1)
                        endpoint["parameters"][key] = value
                
                endpoints.append(endpoint)
        
        return endpoints

    def discover_web_content(self, url, level='standard', timeout=1):
        """
        Discover hidden directories and files using wordlist-based scanning
        
        Args:
            url (str): Target URL to scan
            level (str): Scanning depth - 'basic' (1000 entries), 'standard' (2500 entries), or 'deep' (all entries)
            timeout (int): Timeout for each request in seconds
            
        Returns:
            dict: Results of the web content discovery scan
        """
        # Parse the URL
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        # Set scan depth based on level
        if level == 'basic':
            max_entries = 1000
            print(f"{Fore.CYAN}[*] Starting basic web content discovery (1000 entries)...{Style.RESET_ALL}")
        elif level == 'standard':
            max_entries = 2500
            print(f"{Fore.CYAN}[*] Starting standard web content discovery (2500 entries)...{Style.RESET_ALL}")
        elif level == 'deep':
            max_entries = float('inf')  # No limit
            print(f"{Fore.CYAN}[*] Starting deep web content discovery (all entries)...{Style.RESET_ALL}")
        else:
            max_entries = 2500  # Default to standard
            print(f"{Fore.YELLOW}[!] Invalid level specified, defaulting to standard (2500 entries){Style.RESET_ALL}")
        
        # Path to wordlist file
        wordlist_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
                                    "modules", "seclists", "Discovery", "Web-Content", "directory-list-2.3-big.txt")
        
        # Initialize results container
        results = {
            "target_url": url,
            "scan_level": level,
            "discovered_paths": [],
            "stats": {
                "total_requests": 0,
                "successful_responses": 0,
                "client_errors": 0,
                "server_errors": 0,
                "redirects": 0
            }
        }
        
        # Check if wordlist file exists
        if not os.path.exists(wordlist_path):
            print(f"{Fore.RED}[!] Wordlist file not found: {wordlist_path}{Style.RESET_ALL}")
            results["error"] = f"Wordlist file not found: {wordlist_path}"
            return results
        
        try:
            # Use requests session for better performance
            session = requests.Session()
            session.headers = self.headers
            
            # Prepare progress tracking variables
            line_count = 0
            start_time = time.time()
            
            # Filter out comment lines and read the wordlist
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                wordlist = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            # Truncate wordlist based on selected level
            if max_entries != float('inf'):
                wordlist = wordlist[:max_entries]
            # Display total entries to be scanned
            total_entries = len(wordlist)
            print(f"{Fore.CYAN}[*] Loaded {total_entries} entries from wordlist{Style.RESET_ALL}")

            # --- Progress bar animation setup ---
            from modules.utils import URLScanTracker
            tracker = URLScanTracker(total_entries, prefix='Web Content Progress', length=40)
            # ------------------------------------

            # Iterate through the wordlist
            for entry in wordlist:
                line_count += 1
                # Construct target URL
                target_path = f"{base_url}/{entry}"
                try:
                    response = session.get(target_path, timeout=timeout, allow_redirects=False, verify=False)
                    results["stats"]["total_requests"] += 1
                    status_code = response.status_code
                    # Update progress bar for each request
                    tracker.update(target_path, status_code)
                    if 200 <= status_code < 300:
                        results["stats"]["successful_responses"] += 1
                        results["discovered_paths"].append({
                            "path": entry,
                            "url": target_path,
                            "status_code": status_code,
                            "content_length": len(response.content),
                            "content_type": response.headers.get('Content-Type', 'Unknown')
                        })
                    elif 300 <= status_code < 400:
                        redirect_url = response.headers.get('Location', '')
                        results["stats"]["redirects"] += 1
                        results["discovered_paths"].append({
                            "path": entry,
                            "url": target_path,
                            "status_code": status_code,
                            "redirect_to": redirect_url
                        })
                    elif 400 <= status_code < 500:
                        if status_code == 403:
                            results["discovered_paths"].append({
                                "path": entry,
                                "url": target_path,
                                "status_code": status_code
                            })
                        results["stats"]["client_errors"] += 1
                    elif 500 <= status_code < 600:
                        results["stats"]["server_errors"] += 1
                        results["discovered_paths"].append({
                            "path": entry,
                            "url": target_path,
                            "status_code": status_code
                        })
                except requests.Timeout:
                    tracker.update(target_path, 0)
                    pass
                except requests.RequestException as e:
                    tracker.update(target_path, 0)
                    pass
                except KeyboardInterrupt:
                    print(f"{Fore.YELLOW}[!] User interrupted scan{Style.RESET_ALL}")
                    break
            tracker.finish()
        except Exception as e:
            print(f"{Fore.RED}[!] Error during web content discovery: {str(e)}{Style.RESET_ALL}")
            results["error"] = str(e)
        
        # Calculate scan duration and statistics
        scan_duration = time.time() - start_time
        results["scan_duration"] = scan_duration
        
        # Print summary
        print(f"\n{Fore.GREEN}[+] Web content discovery completed in {scan_duration:.2f} seconds{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Total requests: {results['stats']['total_requests']}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Found {len(results['discovered_paths'])} interesting paths{Style.RESET_ALL}")
        
        return results

import time