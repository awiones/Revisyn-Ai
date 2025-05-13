import requests
import re
import json
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from colorama import Fore, Style
import ssl
import socket
import time
import datetime
import glob
import os

class VulnerabilityChecker:
    def _load_sqli_payloads(self, base_dir):
        """
        Recursively load all SQLi payloads from base_dir and its subdirectories.
        Returns a list of payload strings.
        """
        payloads = []
        for file_path in glob.glob(os.path.join(base_dir, '**', '*.txt'), recursive=True):
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            payloads.append(line)
            except Exception:
                continue
        return payloads

    def __init__(self):
        self.headers = {
            'User-Agent': 'Revisyn-AI-Scanner/1.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'close',
        }
        self.timeout = 10
        
        # Load payload lists
        self.xss_payloads = self._load_payloads('modules/seclists/xss-payloads.txt')
        self.sqli_payloads = self._load_sqli_payloads('modules/seclists/sql-injection')
        self.lfi_payloads = self._load_payloads('modules/seclists/lfi-payloads.txt')
        
    def _load_payloads(self, filepath):
        """Load payloads from file, with fallback to default payloads if file not found"""
        try:
            with open(filepath, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"{Fore.YELLOW}[!] Warning: Payload file {filepath} not found. Using default payloads.{Style.RESET_ALL}")
            
            # Default minimal payloads
            if 'xss' in filepath:
                return ['<script>alert(1)</script>', '"><script>alert(1)</script>', 
                        '<img src=x onerror=alert(1)>', "'-alert(1)-'"]
            elif 'sqli' in filepath:
                return ["'", "1' OR '1'='1", "1; DROP TABLE users--", 
                        "' OR 1=1--", "' UNION SELECT 1,2,3--"]
            elif 'lfi' in filepath:
                return ['../../../etc/passwd', '../../../../etc/passwd', 
                        '/etc/passwd', 'C:\\Windows\\System32\\drivers\\etc\\hosts']
            else:
                return []
    
    def scan_common_vulns(self, url, scan_level="standard", vuln_types=None):
        """
        Scan for common vulnerabilities based on the specified scan level and types
        vuln_types: list of strings (e.g. ["xss", "sqli", "lfi"]). If None, scan all.
        """
        results = {
            "xss": [],
            "sqli": [],
            "open_redirect": [],
            "header_issues": [],
            "information_disclosure": [],
            "insecure_configs": [],
            "lfi": [],
            "csrf": [],
            "severity_counts": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0
            }
        }
        if vuln_types is not None:
            vuln_types = [v.lower() for v in vuln_types]
        # Check for issues in HTTP headers
        if vuln_types is None or "header" in vuln_types or "header_issues" in vuln_types:
            header_issues = self.check_header_issues(url)
            if header_issues:
                results["header_issues"] = header_issues
                for issue in header_issues:
                    results["severity_counts"][issue["severity"]] += 1
        # Check for information disclosure
        if vuln_types is None or "information_disclosure" in vuln_types or "info" in vuln_types:
            info_disclosure = self.check_information_disclosure(url)
            if info_disclosure:
                results["information_disclosure"] = info_disclosure
                for issue in info_disclosure:
                    results["severity_counts"][issue["severity"]] += 1
        # Find forms and check for XSS and CSRF
        forms = self.find_forms(url) if (vuln_types is None or "xss" in vuln_types or "csrf" in vuln_types) else []
        if forms:
            print(f"{Fore.BLUE}[*] Found {len(forms)} forms to test{Style.RESET_ALL}")
            # Test for XSS in forms
            if vuln_types is None or "xss" in vuln_types:
                xss_results = self.check_xss_in_forms(url, forms)
                if xss_results:
                    results["xss"].extend(xss_results)
                    for issue in xss_results:
                        results["severity_counts"][issue["severity"]] += 1
            # Test for CSRF
            if vuln_types is None or "csrf" in vuln_types:
                csrf_results = self.check_csrf(url, forms)
                if csrf_results:
                    results["csrf"].extend(csrf_results)
                    for issue in csrf_results:
                        results["severity_counts"][issue["severity"]] += 1
        # Check for open redirects
        if vuln_types is None or "open_redirect" in vuln_types or "redirect" in vuln_types:
            redirect_results = self.check_open_redirect(url)
            if redirect_results:
                results["open_redirect"].extend(redirect_results)
                for issue in redirect_results:
                    results["severity_counts"][issue["severity"]] += 1
        # Check for SQL injection (basic)
        if vuln_types is None or "sqli" in vuln_types or "sql" in vuln_types:
            sqli_results = self.check_sqli(url)
            if sqli_results:
                results["sqli"].extend(sqli_results)
                for issue in sqli_results:
                    results["severity_counts"][issue["severity"]] += 1
        # Check for Local File Inclusion
        if vuln_types is None or "lfi" in vuln_types:
            lfi_results = self.check_lfi(url)
            if lfi_results:
                results["lfi"].extend(lfi_results)
                for issue in lfi_results:
                    results["severity_counts"][issue["severity"]] += 1
        # If scan level is deep, perform more intensive checks
        if scan_level == "deep":
            print(f"{Fore.BLUE}[*] Performing deep scan for additional vulnerabilities...{Style.RESET_ALL}")
            # Additional XSS checks on URL parameters
            if vuln_types is None or "xss" in vuln_types:
                url_xss_results = self.check_xss_in_url_params(url)
                if url_xss_results:
                    results["xss"].extend(url_xss_results)
                    for issue in url_xss_results:
                        results["severity_counts"][issue["severity"]] += 1
            # More thorough SQLi checks
            if vuln_types is None or "sqli" in vuln_types or "sql" in vuln_types:
                deep_sqli_results = self.deep_sqli_scan(url)
                if deep_sqli_results:
                    results["sqli"].extend(deep_sqli_results)
                    for issue in deep_sqli_results:
                        results["severity_counts"][issue["severity"]] += 1
            # Check for insecure configuration files
            if vuln_types is None or "insecure_configs" in vuln_types or "config" in vuln_types:
                config_results = self.check_insecure_configs(url)
                if config_results:
                    results["insecure_configs"].extend(config_results)
                    for issue in config_results:
                        results["severity_counts"][issue["severity"]] += 1
        return results
    
    def find_forms(self, url):
        """Find all forms on a webpage"""
        print(f"{Fore.CYAN}[*] Looking for forms...{Style.RESET_ALL}")
        forms = []
        
        try:
            response = requests.get(url, headers=self.headers, timeout=self.timeout, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            form_elements = soup.find_all('form')
            
            for form in form_elements:
                form_info = {
                    "action": form.get("action", ""),
                    "method": form.get("method", "get").lower(),
                    "inputs": []
                }
                
                for input_field in form.find_all(['input', 'textarea', 'select']):
                    input_info = {
                        "name": input_field.get("name", ""),
                        "type": input_field.get("type", "text"),
                        "value": input_field.get("value", "")
                    }
                    form_info["inputs"].append(input_info)
                
                forms.append(form_info)
            
            return forms
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error finding forms: {str(e)}{Style.RESET_ALL}")
            return []
    
    def check_header_issues(self, url):
        """Check for security issues in HTTP headers"""
        print(f"{Fore.CYAN}[*] Checking for header security issues...{Style.RESET_ALL}")
        issues = []
        
        try:
            response = requests.get(url, headers=self.headers, timeout=self.timeout, verify=False)
            headers = response.headers
            
            # Check for missing security headers
            security_headers = {
                'Strict-Transport-Security': {
                    'severity': 'medium',
                    'description': 'Missing HSTS header. This header helps protect against protocol downgrade attacks and cookie hijacking.'
                },
                'Content-Security-Policy': {
                    'severity': 'medium',
                    'description': 'Missing Content Security Policy. CSP helps prevent XSS attacks by specifying which resources can be loaded.'
                },
                'X-Content-Type-Options': {
                    'severity': 'low',
                    'description': 'Missing X-Content-Type-Options header. This helps prevent MIME type sniffing attacks.'
                },
                'X-Frame-Options': {
                    'severity': 'medium',
                    'description': 'Missing X-Frame-Options header. This helps prevent clickjacking attacks.'
                },
                'X-XSS-Protection': {
                    'severity': 'low',
                    'description': 'Missing X-XSS-Protection header. This header enables browser-based XSS filters.'
                },
                'Referrer-Policy': {
                    'severity': 'low',
                    'description': 'Missing Referrer-Policy header. This controls how much referrer information is included with requests.'
                }
            }
            
            for header, info in security_headers.items():
                if header not in headers:
                    issues.append({
                        "type": "missing_header",
                        "header": header,
                        "severity": info['severity'],
                        "description": info['description'],
                        "recommendation": f"Add the {header} header to your server responses."
                    })
            
            # Check for information disclosure in headers
            sensitive_headers = [
                'Server', 'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version'
            ]
            
            for header in sensitive_headers:
                if header in headers:
                    issues.append({
                        "type": "information_disclosure",
                        "header": header,
                        "value": headers[header],
                        "severity": "low",
                        "description": f"The {header} header reveals information about the technology stack.",
                        "recommendation": f"Remove or obfuscate the {header} header."
                    })
            
            # Check for insecure cookie settings
            if 'Set-Cookie' in headers:
                cookies = response.cookies
                for cookie in cookies:
                    if not cookie.secure:
                        issues.append({
                            "type": "insecure_cookie",
                            "cookie": cookie.name,
                            "severity": "medium",
                            "description": f"Cookie '{cookie.name}' is set without the Secure flag, allowing transmission over unencrypted HTTP.",
                            "recommendation": "Set the Secure flag on all cookies to ensure they are only transmitted over HTTPS."
                        })
                    
                    if not cookie.has_nonstandard_attr('HttpOnly'):
                        issues.append({
                            "type": "insecure_cookie",
                            "cookie": cookie.name,
                            "severity": "medium",
                            "description": f"Cookie '{cookie.name}' is set without the HttpOnly flag, making it accessible to JavaScript.",
                            "recommendation": "Set the HttpOnly flag on cookies to prevent JavaScript access, protecting against XSS attacks."
                        })
            
            return issues
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error checking headers: {str(e)}{Style.RESET_ALL}")
            return []
    
    def check_information_disclosure(self, url):
        """Check for information disclosure vulnerabilities"""
        print(f"{Fore.CYAN}[*] Checking for information disclosure...{Style.RESET_ALL}")
        issues = []
        
        # Common paths that might leak information
        sensitive_paths = [
            '/robots.txt',
            '/.git/HEAD',
            '/.env',
            '/config.php.bak',
            '/backup/',
            '/.svn/entries',
            '/wp-config.php.bak',
            '/.DS_Store',
            '/phpinfo.php',
            '/server-status',
            '/server-info'
        ]
        
        base_url = url.rstrip('/')
        parsed_url = urlparse(base_url)
        base = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        for path in sensitive_paths:
            try:
                target_url = urljoin(base, path)
                response = requests.get(target_url, headers=self.headers, timeout=self.timeout, verify=False)
                
                if response.status_code == 200:
                    # Check content to avoid false positives
                    if path == '/robots.txt' and 'Disallow:' in response.text:
                        issues.append({
                            "type": "information_disclosure",
                            "url": target_url,
                            "severity": "info",
                            "description": "robots.txt file found. Check for sensitive paths.",
                            "recommendation": "Review robots.txt to ensure it doesn't disclose sensitive paths."
                        })
                    elif path == '/.git/HEAD' and 'ref:' in response.text:
                        issues.append({
                            "type": "information_disclosure",
                            "url": target_url,
                            "severity": "high",
                            "description": "Git repository exposed. This could lead to source code disclosure.",
                            "recommendation": "Remove .git directory from public access or block it via server configuration."
                        })
                    elif path == '/.env' and ('DB_' in response.text or 'API_' in response.text):
                        issues.append({
                            "type": "information_disclosure",
                            "url": target_url,
                            "severity": "critical",
                            "description": "Environment file (.env) exposed. May contain sensitive credentials.",
                            "recommendation": "Remove .env file from public access and ensure it's properly protected."
                        })
                    elif 'phpinfo()' in response.text:
                        issues.append({
                            "type": "information_disclosure",
                            "url": target_url,
                            "severity": "high",
                            "description": "PHPInfo page found. Reveals detailed server configuration.",
                            "recommendation": "Remove phpinfo.php file from production or restrict access to it."
                        })
                    elif path in ['/server-status', '/server-info'] and '<h1>' in response.text:
                        issues.append({
                            "type": "information_disclosure",
                            "url": target_url,
                            "severity": "medium",
                            "description": f"Apache {path[1:]} page exposed. Reveals server configuration details.",
                            "recommendation": f"Restrict access to {path} in your Apache configuration."
                        })
                    else:
                        issues.append({
                            "type": "potential_information_disclosure",
                            "url": target_url,
                            "severity": "low",
                            "description": f"Potentially sensitive file found at {path}",
                            "recommendation": f"Review the content at {path} and restrict access if necessary."
                        })
            except Exception:
                continue
        
        return issues
    
    def check_xss_in_forms(self, url, forms):
        """Check for XSS vulnerabilities in forms"""
        print(f"{Fore.CYAN}[*] Testing forms for XSS vulnerabilities...{Style.RESET_ALL}")
        vulnerabilities = []
        
        for form in forms:
            form_action = form["action"]
            if not form_action.startswith(('http://', 'https://')):
                # Handle relative URLs
                form_action = urljoin(url, form_action)
            
            # Use only a subset of payloads for efficiency
            test_payloads = self.xss_payloads[:3] if len(self.xss_payloads) > 3 else self.xss_payloads
            
            for payload in test_payloads:
                data = {}
                
                # Prepare form data with XSS payload
                for input_field in form["inputs"]:
                    if input_field["type"] not in ["submit", "image", "button", "hidden"]:
                        data[input_field["name"]] = payload
                    else:
                        data[input_field["name"]] = input_field["value"]
                
                try:
                    if form["method"] == "post":
                        response = requests.post(form_action, data=data, headers=self.headers, timeout=self.timeout, verify=False)
                    else:
                        response = requests.get(form_action, params=data, headers=self.headers, timeout=self.timeout, verify=False)
                    
                    # Check if the payload is reflected in the response
                    if payload in response.text:
                        vulnerabilities.append({
                            "type": "reflected_xss",
                            "url": form_action,
                            "method": form["method"],
                            "payload": payload,
                            "severity": "high",
                            "description": f"Reflected XSS vulnerability found in {form['method'].upper()} form.",
                            "recommendation": "Implement proper input validation and output encoding."
                        })
                        # Break to avoid testing more payloads on this form
                        break
                        
                except Exception as e:
                    print(f"{Fore.YELLOW}[!] Error testing form for XSS: {str(e)}{Style.RESET_ALL}")
        
        return vulnerabilities
    
    def check_xss_in_url_params(self, url):
        """Check for XSS in URL parameters"""
        print(f"{Fore.CYAN}[*] Testing URL parameters for XSS...{Style.RESET_ALL}")
        vulnerabilities = []
        parsed_url = urlparse(url)
        
        # If no query parameters in the original URL, try adding some common ones
        if not parsed_url.query:
            test_params = ['id', 'page', 'search', 'q', 'query', 'param']
            
            for param in test_params:
                for payload in self.xss_payloads[:2]:
                    test_url = f"{url}{'&' if '?' in url else '?'}{param}={payload}"
                    
                    try:
                        response = requests.get(test_url, headers=self.headers, timeout=self.timeout, verify=False)
                        
                        if payload in response.text:
                            vulnerabilities.append({
                                "type": "reflected_xss",
                                "url": test_url,
                                "parameter": param,
                                "payload": payload,
                                "severity": "high",
                                "description": f"Reflected XSS vulnerability found in URL parameter '{param}'.",
                                "recommendation": "Implement proper input validation and output encoding for URL parameters."
                            })
                            break
                    except Exception:
                        continue
        else:
            # Test existing parameters
            params = dict(param.split('=') for param in parsed_url.query.split('&') if '=' in param)
            
            for param_name, param_value in params.items():
                for payload in self.xss_payloads[:2]:
                    # Create a copy of params and modify the one we're testing
                    test_params = params.copy()
                    test_params[param_name] = payload
                    
                    # Reconstruct the URL with the test payload
                    query_string = '&'.join([f"{k}={v}" for k, v in test_params.items()])
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{query_string}"
                    
                    try:
                        response = requests.get(test_url, headers=self.headers, timeout=self.timeout, verify=False)
                        
                        if payload in response.text:
                            vulnerabilities.append({
                                "type": "reflected_xss",
                                "url": test_url,
                                "parameter": param_name,
                                "payload": payload,
                                "severity": "high",
                                "description": f"Reflected XSS vulnerability found in URL parameter '{param_name}'.",
                                "recommendation": "Implement proper input validation and output encoding for URL parameters."
                            })
                            break
                    except Exception:
                        continue
        
        return vulnerabilities
    
    def check_csrf(self, url, forms):
        """Check for CSRF vulnerabilities in forms"""
        print(f"{Fore.CYAN}[*] Checking for CSRF vulnerabilities...{Style.RESET_ALL}")
        vulnerabilities = []
        
        for form in forms:
            # Skip GET forms (CSRF mainly affects state-changing operations)
            if form["method"] != "post":
                continue
            
            # Check for CSRF token in form inputs
            has_csrf_token = False
            for input_field in form["inputs"]:
                input_name = input_field["name"].lower()
                if any(token_name in input_name for token_name in ['csrf', 'token', 'nonce', '_token']):
                    has_csrf_token = True
                    break
            
            if not has_csrf_token:
                vulnerabilities.append({
                    "type": "csrf",
                    "url": urljoin(url, form["action"]),
                    "severity": "medium",
                    "description": "Form lacks CSRF protection. This could allow attackers to perform actions on behalf of authenticated users.",
                    "recommendation": "Implement CSRF tokens for all state-changing operations. Use a framework's built-in CSRF protection if available."
                })
        
        return vulnerabilities
    
    def check_sqli(self, url):
        """Check for SQL injection vulnerabilities"""
        print(f"{Fore.CYAN}[*] Checking for SQL injection...{Style.RESET_ALL}")
        vulnerabilities = []
        parsed_url = urlparse(url)
        
        # If no query parameters in the original URL, try adding some common ones
        if not parsed_url.query:
            test_params = ['id', 'page', 'item', 'product', 'category', 'user']
            
            for param in test_params:
                for payload in self.sqli_payloads[:3]:
                    test_url = f"{url}{'&' if '?' in url else '?'}{param}={payload}"
                    
                    try:
                        response = requests.get(test_url, headers=self.headers, timeout=self.timeout, verify=False)
                        
                        # Check for SQL error messages
                        sql_errors = [
                            "SQL syntax", "mysql_fetch_array", "You have an error in your SQL syntax",
                            "ORA-", "Oracle Error", "PostgreSQL ERROR", "ERROR:", "unclosed quotation mark",
                            "Warning: mysql_", "Warning: pg_", "quoted string not properly terminated"
                        ]
                        
                        if any(error in response.text for error in sql_errors):
                            vulnerabilities.append({
                                "type": "sql_injection",
                                "url": test_url,
                                "parameter": param,
                                "payload": payload,
                                "severity": "high",
                                "description": f"Potential SQL injection vulnerability found in parameter '{param}'.",
                                "recommendation": "Use prepared statements or parameterized queries to prevent SQL injection attacks."
                            })
                            break
                    except Exception:
                        continue
        else:
            # Test existing parameters
            params = dict(param.split('=') for param in parsed_url.query.split('&') if '=' in param)
            
            for param_name, param_value in params.items():
                for payload in self.sqli_payloads[:3]:
                    # Create a copy of params and modify the one we're testing
                    test_params = params.copy()
                    test_params[param_name] = payload
                    
                    # Reconstruct the URL with the test payload
                    query_string = '&'.join([f"{k}={v}" for k, v in test_params.items()])
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{query_string}"
                    
                    try:
                        response = requests.get(test_url, headers=self.headers, timeout=self.timeout, verify=False)
                        
                        # Check for SQL error messages
                        sql_errors = [
                            "SQL syntax", "mysql_fetch_array", "You have an error in your SQL syntax",
                            "ORA-", "Oracle Error", "PostgreSQL ERROR", "ERROR:", "unclosed quotation mark",
                            "Warning: mysql_", "Warning: pg_", "quoted string not properly terminated"
                        ]
                        
                        if any(error in response.text for error in sql_errors):
                            vulnerabilities.append({
                                "type": "sql_injection",
                                "url": test_url,
                                "parameter": param_name,
                                "payload": payload,
                                "severity": "high",
                                "description": f"Potential SQL injection vulnerability found in parameter '{param_name}'.",
                                "recommendation": "Use prepared statements or parameterized queries to prevent SQL injection attacks."
                            })
                            break
                    except Exception:
                        continue
        
        return vulnerabilities
    
    def deep_sqli_scan(self, url):
        """Perform more thorough SQL injection tests (deep scan only)"""
        print(f"{Fore.CYAN}[*] Performing deep SQL injection scan...{Style.RESET_ALL}")
        vulnerabilities = []
        parsed_url = urlparse(url)
        
        # Boolean-based tests
        boolean_payloads = [
            "1' AND 1=1--", "1' AND 1=2--",
            "1 AND 1=1--", "1 AND 1=2--"
        ]
        
        # Time-based tests
        time_payloads = [
            "1' AND (SELECT * FROM (SELECT(SLEEP(2)))a)--",
            "1 AND (SELECT * FROM (SELECT(SLEEP(2)))a)--"
        ]
        
        # If URL has parameters, test each one
        if parsed_url.query:
            params = dict(param.split('=') for param in parsed_url.query.split('&') if '=' in param)
            
            for param_name, param_value in params.items():
                # Boolean-based tests
                baseline_response = None
                for i, payload in enumerate(boolean_payloads):
                    test_params = params.copy()
                    test_params[param_name] = payload
                    
                    query_string = '&'.join([f"{k}={v}" for k, v in test_params.items()])
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{query_string}"
                    
                    try:
                        response = requests.get(test_url, headers=self.headers, timeout=self.timeout, verify=False)
                        
                        # First payload (true condition) becomes our baseline
                        if i == 0:
                            baseline_response = response.text
                        # Compare false condition to true condition
                        elif i == 1 and baseline_response != response.text:
                            vulnerabilities.append({
                                "type": "boolean_based_sqli",
                                "url": test_url,
                                "parameter": param_name,
                                "payload": payload,
                                "severity": "high",
                                "description": f"Boolean-based SQL injection vulnerability found in parameter '{param_name}'.",
                                "recommendation": "Use prepared statements or parameterized queries to prevent SQL injection attacks."
                            })
                            break
                    except Exception:
                        continue
                
                # Time-based tests 
                for payload in time_payloads:
                    test_params = params.copy()
                    test_params[param_name] = payload
                    
                    query_string = '&'.join([f"{k}={v}" for k, v in test_params.items()])
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{query_string}"
                    
                    try:
                        # Set a timeout higher than the sleep time in the payload
                        start_time = time.time()
                        response = requests.get(test_url, headers=self.headers, timeout=5, verify=False)
                        elapsed_time = time.time() - start_time
                        
                        # If response time is close to the sleep time in the payload
                        if elapsed_time >= 2:
                            vulnerabilities.append({
                                "type": "time_based_sqli",
                                "url": test_url,
                                "parameter": param_name,
                                "payload": payload,
                                "severity": "high",
                                "description": f"Time-based SQL injection vulnerability found in parameter '{param_name}'.",
                                "recommendation": "Use prepared statements or parameterized queries to prevent SQL injection attacks."
                            })
                            break
                    except requests.Timeout:
                        # Timeout can also indicate successful time-based injection
                        vulnerabilities.append({
                            "type": "time_based_sqli",
                            "url": test_url,
                            "parameter": param_name,
                            "payload": payload,
                            "severity": "high", 
                            "description": f"Time-based SQL injection vulnerability found in parameter '{param_name}'.",
                            "recommendation": "Use prepared statements or parameterized queries to prevent SQL injection attacks."
                        })
                        break
                    except Exception:
                        continue
        
        return vulnerabilities
    
    def check_lfi(self, url):
        """Check for Local File Inclusion vulnerabilities"""
        print(f"{Fore.CYAN}[*] Checking for Local File Inclusion...{Style.RESET_ALL}")
        vulnerabilities = []
        parsed_url = urlparse(url)
        
        # Indicators of successful LFI for different OS
        unix_indicators = ["root:x:", "bin:x:", "nobody:x:"]
        windows_indicators = ["[autorun]", "[boot loader]", "[fonts]"]
        
        # If no query parameters in the original URL, try adding some common ones
        if not parsed_url.query:
            test_params = ['file', 'page', 'include', 'path', 'document', 'folder', 'root', 'template']
            
            for param in test_params:
                for payload in self.lfi_payloads[:3]:
                    test_url = f"{url}{'&' if '?' in url else '?'}{param}={payload}"
                    
                    try:
                        response = requests.get(test_url, headers=self.headers, timeout=self.timeout, verify=False)
                        
                        # Check for LFI indicators in response
                        if any(indicator in response.text for indicator in unix_indicators + windows_indicators):
                            vulnerabilities.append({
                                "type": "local_file_inclusion",
                                "url": test_url,
                                "parameter": param,
                                "payload": payload,
                                "severity": "high",
                                "description": f"Local File Inclusion vulnerability found in parameter '{param}'.",
                                "recommendation": "Validate and sanitize file paths. Don't directly use user input to include files."
                            })
                            break
                    except Exception:
                        continue
        else:
            # Test existing parameters
            params = dict(param.split('=') for param in parsed_url.query.split('&') if '=' in param)
            
            for param_name, param_value in params.items():
                for payload in self.lfi_payloads[:3]:
                    # Create a copy of params and modify the one we're testing
                    test_params = params.copy()
                    test_params[param_name] = payload
                    
                    # Reconstruct the URL with the test payload
                    query_string = '&'.join([f"{k}={v}" for k, v in test_params.items()])
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{query_string}"
                    
                    try:
                        response = requests.get(test_url, headers=self.headers, timeout=self.timeout, verify=False)
                        
                        # Check for LFI indicators in response
                        if any(indicator in response.text for indicator in unix_indicators + windows_indicators):
                            vulnerabilities.append({
                                "type": "local_file_inclusion",
                                "url": test_url,
                                "parameter": param_name,
                                "payload": payload,
                                "severity": "high",
                                "description": f"Local File Inclusion vulnerability found in parameter '{param_name}'.",
                                "recommendation": "Validate and sanitize file paths. Don't directly use user input to include files."
                            })
                            break
                    except Exception:
                        continue
        
        return vulnerabilities
    
    def check_open_redirect(self, url):
        """Check for open redirect vulnerabilities"""
        print(f"{Fore.CYAN}[*] Checking for open redirect vulnerabilities...{Style.RESET_ALL}")
        vulnerabilities = []
        parsed_url = urlparse(url)
        
        redirect_payloads = [
            "https://example.com",
            "//example.com",
            "\\\\example.com"
        ]
        
        redirect_params = ['redirect', 'url', 'next', 'redir', 'return', 'returnUrl', 'redirectUrl', 'redirect_uri', 'to', 'goto']
        
        # If URL has parameters, test each one that seems like a redirect parameter
        if parsed_url.query:
            params = dict(param.split('=') for param in parsed_url.query.split('&') if '=' in param)
            
            for param_name, param_value in params.items():
                if any(redir_param in param_name.lower() for redir_param in redirect_params):
                    for payload in redirect_payloads:
                        # Create a copy of params and modify the one we're testing
                        test_params = params.copy()
                        test_params[param_name] = payload
                        
                        # Reconstruct the URL with the test payload
                        query_string = '&'.join([f"{k}={v}" for k, v in test_params.items()])
                        test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{query_string}"
                        
                        try:
                            response = requests.get(test_url, headers=self.headers, timeout=self.timeout, verify=False, allow_redirects=False)
                            
                            # Check for 3xx redirect code and location header
                            if 300 <= response.status_code < 400 and response.headers.get('Location'):
                                if payload in response.headers.get('Location'):
                                    vulnerabilities.append({
                                        "type": "open_redirect",
                                        "url": test_url,
                                        "parameter": param_name,
                                        "payload": payload,
                                        "redirects_to": response.headers.get('Location'),
                                        "severity": "medium",
                                        "description": f"Open redirect vulnerability found in parameter '{param_name}'.",
                                        "recommendation": "Implement a whitelist of allowed redirect destinations and validate all redirect URLs."
                                    })
                                    break
                        except Exception as e:
                            print(f"{Fore.YELLOW}[!] Error testing for open redirect: {str(e)}{Style.RESET_ALL}")
                            continue
        else:
            # Try adding redirect parameters
            for param in redirect_params:
                for payload in redirect_payloads:
                    test_url = f"{url}{'&' if '?' in url else '?'}{param}={payload}"
                    
                    try:
                        response = requests.get(test_url, headers=self.headers, timeout=self.timeout, verify=False, allow_redirects=False)
                        
                        # Check for 3xx redirect code and location header
                        if 300 <= response.status_code < 400 and response.headers.get('Location'):
                            if payload in response.headers.get('Location'):
                                vulnerabilities.append({
                                    "type": "open_redirect",
                                    "url": test_url,
                                    "parameter": param,
                                    "payload": payload,
                                    "redirects_to": response.headers.get('Location'),
                                    "severity": "medium",
                                    "description": f"Open redirect vulnerability found in parameter '{param}'.",
                                    "recommendation": "Implement a whitelist of allowed redirect destinations and validate all redirect URLs."
                                })
                                break
                    except Exception as e:
                        print(f"{Fore.YELLOW}[!] Error testing for open redirect: {str(e)}{Style.RESET_ALL}")
                        continue
        
        return vulnerabilities
    
    def check_insecure_configs(self, url):
        """Check for insecure configuration files"""
        print(f"{Fore.CYAN}[*] Checking for insecure configuration files...{Style.RESET_ALL}")
        vulnerabilities = []
        parsed_url = urlparse(url)
        base = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        config_files = [
            '/config.json', 
            '/app.config',
            '/settings.json',
            '/wp-config.php.bak',
            '/config.php.bak',
            '/configuration.php',
            '/config.inc.php',
            '/settings.php',
            '/.htaccess',
            '/web.config',
            '/database.yml',
            '/config.yml',
            '/credentials.json',
            '/.env.bak',
            '/config/database.yml'
        ]
        
        for config_file in config_files:
            try:
                target_url = urljoin(base, config_file)
                response = requests.get(target_url, headers=self.headers, timeout=self.timeout, verify=False)
                
                if response.status_code == 200:
                    # Look for sensitive content patterns in the response
                    sensitive_patterns = [
                        'password', 'passwd', 'pwd', 'secret', 'api_key', 'apikey', 'token', 
                        'access_key', 'auth', 'credential', 'database', 'db_', 'pass'
                    ]
                    
                    if any(pattern in response.text.lower() for pattern in sensitive_patterns):
                        vulnerabilities.append({
                            "type": "exposed_config",
                            "url": target_url,
                            "severity": "critical",
                            "description": f"Exposed configuration file found at {config_file} containing potentially sensitive information.",
                            "recommendation": "Remove configuration files from publicly accessible directories or restrict access to them."
                        })
                    else:
                        vulnerabilities.append({
                            "type": "exposed_config",
                            "url": target_url,
                            "severity": "medium",
                            "description": f"Configuration file found at {config_file}.",
                            "recommendation": "Review the configuration file and ensure it doesn't contain sensitive information."
                        })
            except Exception:
                continue
        
        return vulnerabilities
    
    def scan_ssl_tls(self, url):
        """Check for SSL/TLS vulnerabilities"""
        print(f"{Fore.CYAN}[*] Scanning SSL/TLS configuration...{Style.RESET_ALL}")
        vulnerabilities = []
        parsed_url = urlparse(url)
        
        # Only run on HTTPS urls
        if parsed_url.scheme != 'https':
            return vulnerabilities
        
        hostname = parsed_url.netloc
        port = 443  # Default HTTPS port
        
        try:
            # Check certificate validity
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check certificate expiration
                    not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    not_before = datetime.datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                    current_time = datetime.datetime.utcnow()
                    
                    # Certificate expired
                    if current_time > not_after:
                        vulnerabilities.append({
                            "type": "expired_certificate",
                            "url": url,
                            "severity": "high",
                            "expiry_date": cert['notAfter'],
                            "description": "SSL certificate has expired.",
                            "recommendation": "Renew the SSL certificate immediately."
                        })
                    
                    # Certificate about to expire (within 30 days)
                    days_to_expiry = (not_after - current_time).days
                    if 0 < days_to_expiry < 30:
                        vulnerabilities.append({
                            "type": "expiring_certificate",
                            "url": url,
                            "severity": "medium",
                            "days_to_expiry": days_to_expiry,
                            "expiry_date": cert['notAfter'],
                            "description": f"SSL certificate will expire in {days_to_expiry} days.",
                            "recommendation": "Plan to renew the SSL certificate soon."
                        })
                    
                    # Certificate not yet valid
                    if current_time < not_before:
                        vulnerabilities.append({
                            "type": "invalid_certificate",
                            "url": url,
                            "severity": "high",
                            "valid_from": cert['notBefore'],
                            "description": "SSL certificate is not yet valid.",
                            "recommendation": "Check the certificate's validity period and server's system time."
                        })
                    
                    # Check for weak signature algorithm
                    if 'SHA1' in cert.get('signatureAlgorithm', ''):
                        vulnerabilities.append({
                            "type": "weak_signature_algorithm",
                            "url": url,
                            "severity": "medium",
                            "algorithm": cert.get('signatureAlgorithm'),
                            "description": "SSL certificate uses a weak signature algorithm (SHA1).",
                            "recommendation": "Reissue the certificate with a stronger signature algorithm (SHA256 or higher)."
                        })
            
            # Test supported protocols
            protocols_to_test = [
                ("SSLv2", ssl.PROTOCOL_SSLv23),
                ("SSLv3", ssl.PROTOCOL_SSLv23),
                ("TLSv1.0", ssl.PROTOCOL_TLSv1),
                ("TLSv1.1", getattr(ssl, 'PROTOCOL_TLSv1_1', None))
            ]
            
            weak_protocols = []
            for protocol_name, protocol in protocols_to_test:
                if protocol is None:  # Skip if protocol is not supported by Python
                    continue
                    
                try:
                    context = ssl.SSLContext(protocol)
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    
                    with socket.create_connection((hostname, port), timeout=5) as sock:
                        with context.wrap_socket(sock) as ssock:
                            weak_protocols.append(protocol_name)
                except (ssl.SSLError, socket.error):
                    # Connection failed, protocol not supported (good)
                    pass
            
            if weak_protocols:
                vulnerabilities.append({
                    "type": "weak_protocols",
                    "url": url,
                    "severity": "high",
                    "protocols": weak_protocols,
                    "description": f"Server supports weak SSL/TLS protocols: {', '.join(weak_protocols)}",
                    "recommendation": "Disable support for legacy SSL/TLS protocols (SSLv2, SSLv3, TLSv1.0, TLSv1.1)."
                })
                
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Error in SSL/TLS scan: {str(e)}{Style.RESET_ALL}")
        
        return vulnerabilities
    
    def check_directory_listing(self, url):
        """Check for directory listing vulnerabilities"""
        print(f"{Fore.CYAN}[*] Checking for directory listing...{Style.RESET_ALL}")
        vulnerabilities = []
        parsed_url = urlparse(url)
        base = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        # Common directories to check
        test_dirs = [
            '/images/', '/uploads/', '/assets/', '/backup/', '/files/', 
            '/includes/', '/js/', '/css/', '/data/', '/temp/', '/docs/'
        ]
        
        directory_listing_indicators = [
            "Index of", "Directory Listing", "Parent Directory",
            "<title>Index of", "<h1>Index of", "[To Parent Directory]"
        ]
        
        for directory in test_dirs:
            try:
                test_url = urljoin(base, directory)
                response = requests.get(test_url, headers=self.headers, timeout=self.timeout, verify=False)
                
                if response.status_code == 200:
                    # Check for directory listing indicators
                    if any(indicator in response.text for indicator in directory_listing_indicators):
                        vulnerabilities.append({
                            "type": "directory_listing",
                            "url": test_url,
                            "severity": "medium",
                            "description": f"Directory listing is enabled for {directory}",
                            "recommendation": "Disable directory listing in your web server configuration."
                        })
            except Exception:
                continue
        
        return vulnerabilities
    
    def check_cors_misconfig(self, url):
        """Check for CORS misconfigurations"""
        print(f"{Fore.CYAN}[*] Checking for CORS misconfigurations...{Style.RESET_ALL}")
        vulnerabilities = []
        
        # Test domains
        test_origins = [
            "https://evil.com", 
            "https://attacker.com", 
            "https://null.evil.com",
            "null",
            f"https://{urlparse(url).netloc}.evil.com"
        ]
        
        for origin in test_origins:
            try:
                headers = self.headers.copy()
                headers["Origin"] = origin
                
                response = requests.get(url, headers=headers, timeout=self.timeout, verify=False)
                
                acao_header = response.headers.get("Access-Control-Allow-Origin")
                acac_header = response.headers.get("Access-Control-Allow-Credentials")
                
                # Check for permissive CORS headers
                if acao_header:
                    if acao_header == "*" and acac_header == "true":
                        vulnerabilities.append({
                            "type": "cors_misconfiguration",
                            "url": url,
                            "severity": "high",
                            "headers": {
                                "Access-Control-Allow-Origin": acao_header,
                                "Access-Control-Allow-Credentials": acac_header
                            },
                            "description": "CORS misconfiguration: Wildcard origin with credentials allowed.",
                            "recommendation": "Do not set Access-Control-Allow-Origin to '*' when Access-Control-Allow-Credentials is 'true'."
                        })
                        break
                    elif origin == acao_header and acac_header == "true" and "evil.com" in origin:
                        vulnerabilities.append({
                            "type": "cors_misconfiguration",
                            "url": url,
                            "severity": "high",
                            "tested_origin": origin,
                            "headers": {
                                "Access-Control-Allow-Origin": acao_header,
                                "Access-Control-Allow-Credentials": acac_header
                            },
                            "description": "CORS misconfiguration: Insecure origin reflection with credentials allowed.",
                            "recommendation": "Validate the Origin header against a whitelist of trusted domains."
                        })
                        break
            except Exception as e:
                print(f"{Fore.YELLOW}[!] Error checking CORS: {str(e)}{Style.RESET_ALL}")
                continue
                
        return vulnerabilities
    
    def check_http_methods(self, url):
        """Check for dangerous HTTP methods"""
        print(f"{Fore.CYAN}[*] Checking allowed HTTP methods...{Style.RESET_ALL}")
        vulnerabilities = []
        
        try:
            response = requests.options(url, headers=self.headers, timeout=self.timeout, verify=False)
            
            # Check the Allow header
            if 'Allow' in response.headers:
                allowed_methods = response.headers['Allow'].split(', ')
                dangerous_methods = ['PUT', 'DELETE', 'TRACE', 'CONNECT']
                
                found_dangerous = [method for method in dangerous_methods if method in allowed_methods]
                
                if found_dangerous:
                    vulnerabilities.append({
                        "type": "dangerous_http_methods",
                        "url": url,
                        "severity": "medium",
                        "allowed_methods": allowed_methods,
                        "dangerous_methods": found_dangerous,
                        "description": f"Dangerous HTTP methods are enabled: {', '.join(found_dangerous)}",
                        "recommendation": "Disable unnecessary HTTP methods. Only allow GET, HEAD, POST for most web applications."
                    })
                    
                    # If TRACE is enabled, check for Cross-Site Tracing (XST)
                    if 'TRACE' in found_dangerous:
                        try:
                            trace_headers = self.headers.copy()
                            trace_headers['X-Custom-Test-Header'] = 'XSTtest'
                            trace_response = requests.request('TRACE', url, headers=trace_headers, timeout=self.timeout, verify=False)
                            
                            if 'XSTtest' in trace_response.text:
                                vulnerabilities.append({
                                    "type": "cross_site_tracing",
                                    "url": url,
                                    "severity": "medium",
                                    "description": "Cross-Site Tracing (XST) is possible due to enabled TRACE method.",
                                    "recommendation": "Disable the TRACE HTTP method on your web server."
                                })
                        except Exception:
                            pass
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Error checking HTTP methods: {str(e)}{Style.RESET_ALL}")
        
        return vulnerabilities
    
    def generate_report(self, results, url):
        """Generate a formatted vulnerability report"""
        report = {
            "scan_info": {
                "url": url,
                "scan_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "scanner": "Revisyn-AI-Scanner/1.0"
            },
            "vulnerability_summary": {
                "total": sum(results["severity_counts"].values()),
                "by_severity": results["severity_counts"]
            },
            "vulnerabilities": []
        }
        
        # Collect all vulnerabilities into a single list
        for vuln_type, vuln_list in results.items():
            if vuln_type != "severity_counts" and isinstance(vuln_list, list):
                for vuln in vuln_list:
                    # Add vulnerability type if not already in the vulnerability
                    if "type" not in vuln:
                        vuln["type"] = vuln_type
                    report["vulnerabilities"].append(vuln)
        
        # Sort vulnerabilities by severity
        severity_order = {
            "critical": 0,
            "high": 1,
            "medium": 2,
            "low": 3,
            "info": 4
        }
        
        report["vulnerabilities"].sort(key=lambda x: severity_order.get(x.get("severity", "low"), 5))
        
        return report
    
    def print_report_summary(self, report):
        """Print a summary of the vulnerability report to the console"""
        print("\n" + "="*80)
        print(f"{Fore.BLUE}VULNERABILITY SCAN REPORT SUMMARY{Style.RESET_ALL}")
        print("="*80)
        
        print(f"\n{Fore.CYAN}Scan Information:{Style.RESET_ALL}")
        print(f"  Target: {report['scan_info']['url']}")
        print(f"  Scan Time: {report['scan_info']['scan_time']}")
        print(f"  Scanner: {report['scan_info']['scanner']}")
        
        print(f"\n{Fore.CYAN}Vulnerability Summary:{Style.RESET_ALL}")
        print(f"  Total Vulnerabilities: {report['vulnerability_summary']['total']}")
        
        severity_colors = {
            "critical": Fore.LIGHTRED_EX,
            "high": Fore.RED,
            "medium": Fore.YELLOW,
            "low": Fore.GREEN,
            "info": Fore.BLUE
        }
        
        for severity, count in report['vulnerability_summary']['by_severity'].items():
            color = severity_colors.get(severity, Fore.WHITE)
            print(f"  {color}{severity.capitalize()}: {count}{Style.RESET_ALL}")
        
        # Print top vulnerabilities
        if report['vulnerabilities']:
            print(f"\n{Fore.CYAN}Top Vulnerabilities:{Style.RESET_ALL}")
            
            # Group vulnerabilities by type
            vuln_types = {}
            for vuln in report['vulnerabilities']:
                vuln_type = vuln.get('type', 'unknown')
                if vuln_type not in vuln_types:
                    vuln_types[vuln_type] = []
                vuln_types[vuln_type].append(vuln)
            
            # Print summary by type
            severity_order = {
                "critical": 0,
                "high": 1,
                "medium": 2,
                "low": 3,
                "info": 4
            }
            
            for vuln_type, vulns in vuln_types.items():
                highest_severity = min([severity_order.get(v.get('severity', 'low'), 5) for v in vulns])
                highest_severity_name = [k for k, v in severity_order.items() if v == highest_severity][0]
                color = severity_colors.get(highest_severity_name, Fore.WHITE)
                
                print(f"  {color}[{highest_severity_name.upper()}] {vuln_type.replace('_', ' ').title()} ({len(vulns)}){Style.RESET_ALL}")
        
        print("\n" + "="*80)
        print(f"{Fore.BLUE}End of Summary{Style.RESET_ALL}")
        print("="*80 + "\n")

    def save_report(self, report, output_format="json", filename=None):
        """Save the vulnerability report to a file"""
        if filename is None:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            target_domain = urlparse(report["scan_info"]["url"]).netloc.replace(":", "_")
            filename = f"vuln_report_{target_domain}_{timestamp}"
        
        if output_format == "json":
            filename = f"{filename}.json"
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2)
        elif output_format == "html":
            filename = f"{filename}.html"
            self._generate_html_report(report, filename)
        
        print(f"{Fore.GREEN}[+] Report saved to {filename}{Style.RESET_ALL}")
        return filename
    
    def _generate_html_report(self, report, filename):
        """Generate an HTML report from the vulnerability data"""
        html_template = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Vulnerability Scan Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 0; padding: 20px; color: #333; }
                h1, h2, h3 { color: #2c3e50; }
                .container { max-width: 1200px; margin: 0 auto; }
                .header { background-color: #34495e; color: white; padding: 20px; border-radius: 5px; }
                .summary { display: flex; justify-content: space-between; margin: 20px 0; }
                .summary-box { background-color: #f8f9fa; border-radius: 5px; padding: 15px; flex: 1; margin: 0 10px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
                .vulnerability { background-color: #f8f9fa; margin: 15px 0; padding: 15px; border-radius: 5px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
                .vulnerability h3 { margin-top: 0; }
                .critical { border-left: 5px solid #e74c3c; }
                .high { border-left: 5px solid #e67e22; }
                .medium { border-left: 5px solid #f1c40f; }
                .low { border-left: 5px solid #2ecc71; }
                .info { border-left: 5px solid #3498db; }
                .severity { display: inline-block; padding: 3px 8px; border-radius: 3px; font-size: 12px; font-weight: bold; color: white; }
                .severity.critical { background-color: #e74c3c; border: none; }
                .severity.high { background-color: #e67e22; border: none; }
                .severity.medium { background-color: #f1c40f; border: none; }
                .severity.low { background-color: #2ecc71; border: none; }
                .severity.info { background-color: #3498db; border: none; }
                table { width: 100%; border-collapse: collapse; margin: 10px 0; }
                table, th, td { border: 1px solid #ddd; }
                th, td { padding: 8px; text-align: left; }
                th { background-color: #f2f2f2; }
                .details { margin-top: 10px; }
                .recommendation { background-color: #e8f4f8; padding: 10px; border-radius: 5px; margin-top: 10px; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Vulnerability Scan Report</h1>
                    <p>Target: {target_url}</p>
                    <p>Scan Time: {scan_time}</p>
                    <p>Scanner: {scanner}</p>
                </div>
                
                <h2>Vulnerability Summary</h2>
                <div class="summary">
                    <div class="summary-box">
                        <h3>Total Vulnerabilities</h3>
                        <p style="font-size: 24px;">{total_vulns}</p>
                    </div>
                    <div class="summary-box">
                        <h3>By Severity</h3>
                        <p>Critical: {critical_count}</p>
                        <p>High: {high_count}</p>
                        <p>Medium: {medium_count}</p>
                        <p>Low: {low_count}</p>
                        <p>Info: {info_count}</p>
                    </div>
                </div>
                
                <h2>Vulnerabilities</h2>
                {vulnerabilities}
            </div>
        </body>
        </html>
        """
        
        vulnerability_template = """
        <div class="vulnerability {severity}">
            <h3>{title}</h3>
            <span class="severity {severity}">{severity}</span>
            
            <div class="details">
                <p>{description}</p>
                
                <table>
                    <tr>
                        <th>Type</th>
                        <td>{type}</td>
                    </tr>
                    <tr>
                        <th>URL</th>
                        <td>{url}</td>
                    </tr>
                    {extra_details}
                </table>
                
                <div class="recommendation">
                    <strong>Recommendation:</strong> {recommendation}
                </div>
            </div>
        </div>
        """
        
        # Generate HTML for each vulnerability
        vulnerabilities_html = ""
        for vuln in report['vulnerabilities']:
            # Generate title from type
            title = vuln.get('type', '').replace('_', ' ').title()
            
            # Generate extra details
            extra_details = ""
            for key, value in vuln.items():
                if key not in ['type', 'url', 'severity', 'description', 'recommendation']:
                    # Skip internal fields or complex objects
                    if isinstance(value, (dict, list)) or key.startswith('_'):
                        continue
                    
                    # Format the key for display
                    display_key = key.replace('_', ' ').title()
                    
                    extra_details += f"""
                    <tr>
                        <th>{display_key}</th>
                        <td>{value}</td>
                    </tr>
                    """
            
            # Replace placeholders in the vulnerability template
            vuln_html = vulnerability_template.format(
                title=title,
                severity=vuln.get('severity', 'low'),
                description=vuln.get('description', 'No description provided.'),
                type=vuln.get('type', 'unknown').replace('_', ' ').Title(),
                url=vuln.get('url', 'N/A'),
                extra_details=extra_details,
                recommendation=vuln.get('recommendation', 'No recommendation provided.')
            )
            
            vulnerabilities_html += vuln_html
        
        # Replace placeholders in the main template
        html_report = html_template.format(
            target_url=report['scan_info']['url'],
            scan_time=report['scan_info']['scan_time'],
            scanner=report['scan_info']['scanner'],
            total_vulns=report['vulnerability_summary']['total'],
            critical_count=report['vulnerability_summary']['by_severity'].get('critical', 0),
            high_count=report['vulnerability_summary']['by_severity'].get('high', 0),
            medium_count=report['vulnerability_summary']['by_severity'].get('medium', 0),
            low_count=report['vulnerability_summary']['by_severity'].get('low', 0),
            info_count=report['vulnerability_summary']['by_severity'].get('info', 0),
            vulnerabilities=vulnerabilities_html
        )
        
        # Write the HTML report to file
        with open(filename, 'w') as f:
            f.write(html_report)
    
    def check_lfi_realtime(self, url):
        """Yield real-time LFI test results for each payload/parameter."""
        print(f"{Fore.CYAN}[*] Checking for Local File Inclusion (real-time)...{Style.RESET_ALL}")
        parsed_url = urlparse(url)
        unix_indicators = ["root:x:", "bin:x:", "nobody:x:"]
        windows_indicators = ["[autorun]", "[boot loader]", "[fonts]"]
        # If no query parameters in the original URL, try adding some common ones
        if not parsed_url.query:
            test_params = ['file', 'page', 'include', 'path', 'document', 'folder', 'root', 'template']
            for param in test_params:
                for payload in self.lfi_payloads:
                    test_url = f"{url}{'&' if '?' in url else '?'}{param}={payload}"
                    try:
                        response = requests.get(test_url, headers=self.headers, timeout=self.timeout, verify=False)
                        is_vuln = any(ind in response.text for ind in unix_indicators + windows_indicators)
                        yield {
                            'url': test_url,
                            'parameter': param,
                            'payload': payload,
                            'valid': is_vuln,
                            'vuln_info': {
                                "type": "local_file_inclusion",
                                "url": test_url,
                                "parameter": param,
                                "payload": payload,
                                "severity": "high",
                                "description": f"Local File Inclusion vulnerability found in parameter '{param}'." if is_vuln else None,
                                "recommendation": "Validate and sanitize file paths. Don't directly use user input to include files."
                            } if is_vuln else None
                        }
                    except Exception:
                        yield {
                            'url': test_url,
                            'parameter': param,
                            'payload': payload,
                            'valid': False
                        }
        else:
            params = dict(param.split('=') for param in parsed_url.query.split('&') if '=' in param)
            for param_name, param_value in params.items():
                for payload in self.lfi_payloads:
                    test_params = params.copy()
                    test_params[param_name] = payload
                    query_string = '&'.join([f"{k}={v}" for k, v in test_params.items()])
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{query_string}"
                    try:
                        response = requests.get(test_url, headers=self.headers, timeout=self.timeout, verify=False)
                        is_vuln = any(ind in response.text for ind in unix_indicators + windows_indicators)
                        yield {
                            'url': test_url,
                            'parameter': param_name,
                            'payload': payload,
                            'valid': is_vuln,
                            'vuln_info': {
                                "type": "local_file_inclusion",
                                "url": test_url,
                                "parameter": param_name,
                                "payload": payload,
                                "severity": "high",
                                "description": f"Local File Inclusion vulnerability found in parameter '{param_name}'." if is_vuln else None,
                                "recommendation": "Validate and sanitize file paths. Don't directly use user input to include files."
                            } if is_vuln else None
                        }
                    except Exception:
                        yield {
                            'url': test_url,
                            'parameter': param_name,
                            'payload': payload,
                            'valid': False
                        }