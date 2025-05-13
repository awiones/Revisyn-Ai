# Utility functions for Revisyn-AI
# Author: Revisyn-AI

import re
import json
import socket
import ipaddress
import platform
import datetime
import os
import sys
from urllib.parse import urlparse
from colorama import Fore, Style, init

# Initialize colorama for cross-platform colored terminal text
init(autoreset=True)

def banner():
    """
    Display the Revisyn-AI banner
    """
    banner_text = """
    ________            _____                          _______________
    ___  __ \_______   ____(_)___________  ________    ___    |___  _/
    __  /_/ /  _ \_ | / /_  /__  ___/_  / / /_  __ \   __  /| |__  /  
    _  _, _//  __/_ |/ /_  / _(__  )_  /_/ /_  / / /   _  ___ |_/ /   
    /_/ |_| \___/_____/ /_/  /____/ _\__, / /_/ /_/    /_/  |_/___/   
                                /____/                            
                                          Intelligent Security Scanner
    """
    print(f"{Fore.CYAN}{banner_text}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Version: Beta 0.0.2{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}https://github.com/revisyn-ai/revisyn-ai{Style.RESET_ALL}")
    print("")
    print(f"{Fore.GREEN}[*] {platform.system()} {platform.release()} ({platform.machine()}){Style.RESET_ALL}")
    print(f"{Fore.GREEN}[*] Python {platform.python_version()}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[*] Started at {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")
    print("")

def validate_url(url):
    """
    Validate if the provided string is a properly formatted URL
    
    Args:
        url (str): The URL to validate
        
    Returns:
        bool: True if valid URL, False otherwise
    """
    if not url:
        return False
        
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc]) and result.scheme in ['http', 'https']
    except Exception:
        return False

def is_valid_ip(ip):
    """
    Validate if the provided string is a valid IP address
    
    Args:
        ip (str): The IP address to validate
        
    Returns:
        bool: True if valid IP, False otherwise
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_valid_domain(domain):
    """
    Validate if the provided string is a valid domain name
    
    Args:
        domain (str): The domain to validate
        
    Returns:
        bool: True if valid domain, False otherwise
    """
    pattern = r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$'
    return bool(re.match(pattern, domain, re.IGNORECASE))

def resolve_host(host):
    """
    Resolve a hostname to IP address(es)
    
    Args:
        host (str): Hostname or domain to resolve
        
    Returns:
        list: List of IP addresses
    """
    try:
        return socket.gethostbyname_ex(host)[2]
    except socket.gaierror:
        return []

def format_output(scan_results, output_format="console"):
    """
    Format scan results according to the specified output format
    
    Args:
        scan_results (dict): Scan results to format
        output_format (str): Output format (console, json, html)
    """
    if output_format == "json":
        # Format and write results as JSON
        output_file = f"revisyn_scan_{scan_results['scan_time'].replace(' ', '_').replace(':', '-')}.json"
        with open(output_file, 'w') as f:
            json.dump(scan_results, f, indent=2)
        print(f"{Fore.GREEN}[+] Results saved to {output_file}{Style.RESET_ALL}")
        
    elif output_format == "html":
        # Generate HTML report
        html_report = generate_html_report(scan_results)
        # Ensure results directory exists
        results_dir = "results"
        if not os.path.exists(results_dir):
            os.makedirs(results_dir)
        # Extract domain from URL
        parsed_url = urlparse(scan_results["url"])
        domain = parsed_url.netloc.replace(":", "_")
        base_filename = f"{domain}.html"
        output_file = os.path.join(results_dir, base_filename)
        # If file exists, append a number
        counter = 1
        while os.path.exists(output_file):
            output_file = os.path.join(results_dir, f"{domain}_{counter}.html")
            counter += 1
        with open(output_file, 'w') as f:
            f.write(html_report)
        print(f"{Fore.GREEN}[+] HTML report saved to {output_file}{Style.RESET_ALL}")
        
    else:  # console output
        print("\n" + "="*80)
        print(f"{Fore.CYAN}[SCAN RESULTS] - {scan_results['url']}{Style.RESET_ALL}")
        print(f"Scan completed at: {scan_results['scan_time']}")
        print("="*80 + "\n")
        
        # Print reconnaissance data
        print(f"{Fore.BLUE}[*] RECONNAISSANCE DATA:{Style.RESET_ALL}")
        recon = scan_results.get('recon_data', {})
        
        if recon.get('ip_addresses'):
            print(f"  IP Addresses: {', '.join(recon.get('ip_addresses', []))}")
            
        if recon.get('technologies'):
            print(f"  Technologies: {', '.join(recon.get('technologies', []))}")
            
        if recon.get('open_ports'):
            print(f"  Open Ports: {', '.join(map(str, recon.get('open_ports', [])))}")
            
        # Print security headers
        if recon.get('missing_security_headers'):
            print(f"\n{Fore.YELLOW}[!] Missing Security Headers:{Style.RESET_ALL}")
            for header in recon.get('missing_security_headers', []):
                print(f"  - {header}")
        
        # Print vulnerabilities summary
        print(f"\n{Fore.BLUE}[*] VULNERABILITY SUMMARY:{Style.RESET_ALL}")
        severity_counts = scan_results.get('severity_counts', {})
        
        print(f"  {Fore.RED}Critical: {severity_counts.get('critical', 0)}{Style.RESET_ALL}")
        print(f"  {Fore.MAGENTA}High: {severity_counts.get('high', 0)}{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}Medium: {severity_counts.get('medium', 0)}{Style.RESET_ALL}")
        print(f"  {Fore.BLUE}Low: {severity_counts.get('low', 0)}{Style.RESET_ALL}")
        print(f"  {Fore.CYAN}Info: {severity_counts.get('info', 0)}{Style.RESET_ALL}")
        
        # Print detailed vulnerability findings
        vulns = scan_results.get('vulnerabilities', {})
        # Defensive: skip non-list findings (e.g. severity_counts)
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            vuln_found = False
            for vuln_type, findings in vulns.items():
                if not isinstance(findings, list):
                    continue
                severity_findings = [v for v in findings if isinstance(v, dict) and v.get('severity') == severity]
                if severity_findings:
                    if not vuln_found:
                        severity_color = {
                            'critical': Fore.RED, 
                            'high': Fore.MAGENTA, 
                            'medium': Fore.YELLOW,
                            'low': Fore.BLUE,
                            'info': Fore.CYAN
                        }.get(severity, Fore.WHITE)
                        print(f"\n{severity_color}[{severity.upper()} SEVERITY FINDINGS]{Style.RESET_ALL}")
                        vuln_found = True
                    print(f"\n{Fore.CYAN}[*] {vuln_type.upper().replace('_', ' ')}:{Style.RESET_ALL}")
                    for finding in severity_findings:
                        print(f"  - {finding.get('description')}")
                        if 'url' in finding:
                            print(f"    URL: {finding.get('url')}")
                        if 'recommendation' in finding:
                            print(f"    {Fore.GREEN}Recommendation: {finding.get('recommendation')}{Style.RESET_ALL}")
        
        # Print AI analysis if available
        if 'ai_analysis' in scan_results:
            print(f"\n{Fore.BLUE}[*] AI ENHANCED ANALYSIS:{Style.RESET_ALL}")
            print(f"{scan_results['ai_analysis']}")
            
        print("\n" + "="*80)
        print(f"{Fore.GREEN}[+] Scan complete!{Style.RESET_ALL}")

def generate_html_report(scan_results):
    """
    Generate an HTML report from scan results
    
    Args:
        scan_results (dict): Scan results to format
        
    Returns:
        str: HTML content
    """
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Revisyn AI - Scan Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            color: #333;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: #fff;
            padding: 20px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
            border-radius: 5px;
        }}
        header {{
            background-color: #2c3e50;
            color: #fff;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 5px 5px 0 0;
        }}
        h1 {{
            margin: 0;
        }}
        .summary-box {{
            display: flex;
            flex-wrap: wrap;
            margin-bottom: 20px;
        }}
        .summary-item {{
            flex: 1;
            min-width: 150px;
            border-radius: 5px;
            padding: 15px;
            margin: 10px;
            color: white;
            text-align: center;
        }}
        .critical {{ background-color: #e74c3c; }}
        .high {{ background-color: #9b59b6; }}
        .medium {{ background-color: #f39c12; }}
        .low {{ background-color: #3498db; }}
        .info {{ background-color: #1abc9c; }}
        
        .section {{
            margin-bottom: 30px;
            border: 1px solid #ddd;
            border-radius: 5px;
            overflow: hidden;
        }}
        .section-header {{
            background-color: #34495e;
            color: white;
            padding: 10px;
            font-weight: bold;
        }}
        .section-content {{
            padding: 15px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background-color: #f2f2f2;
        }}
        tr:hover {{
            background-color: #f5f5f5;
        }}
        .vulnerability {{
            margin-bottom: 15px;
            padding: 15px;
            border-radius: 5px;
        }}
        .vulnerability-critical {{ border-left: 5px solid #e74c3c; background-color: #fadbd8; }}
        .vulnerability-high {{ border-left: 5px solid #9b59b6; background-color: #ebdef0; }}
        .vulnerability-medium {{ border-left: 5px solid #f39c12; background-color: #fef5e7; }}
        .vulnerability-low {{ border-left: 5px solid #3498db; background-color: #ebf5fb; }}
        .vulnerability-info {{ border-left: 5px solid #1abc9c; background-color: #e8f8f5; }}
        .recommendation {{
            margin-top: 10px;
            font-style: italic;
            color: #27ae60;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Revisyn AI - Security Scan Report</h1>
            <p>URL: {scan_results['url']}</p>
            <p>Scan Time: {scan_results['scan_time']}</p>
        </header>
        
        <div class="section">
            <div class="section-header">Vulnerability Summary</div>
            <div class="section-content">
                <div class="summary-box">
                    <div class="summary-item critical">
                        <h3>Critical</h3>
                        <span style="font-size: 24px;">{scan_results.get('severity_counts', {}).get('critical', 0)}</span>
                    </div>
                    <div class="summary-item high">
                        <h3>High</h3>
                        <span style="font-size: 24px;">{scan_results.get('severity_counts', {}).get('high', 0)}</span>
                    </div>
                    <div class="summary-item medium">
                        <h3>Medium</h3>
                        <span style="font-size: 24px;">{scan_results.get('severity_counts', {}).get('medium', 0)}</span>
                    </div>
                    <div class="summary-item low">
                        <h3>Low</h3>
                        <span style="font-size: 24px;">{scan_results.get('severity_counts', {}).get('low', 0)}</span>
                    </div>
                    <div class="summary-item info">
                        <h3>Info</h3>
                        <span style="font-size: 24px;">{scan_results.get('severity_counts', {}).get('info', 0)}</span>
                    </div>
                </div>
            </div>
        </div>
    """
    
    # Add reconnaissance data
    recon = scan_results.get('recon_data', {})
    html += """
        <div class="section">
            <div class="section-header">Reconnaissance Data</div>
            <div class="section-content">
    """
    
    if recon.get('ip_addresses'):
        html += f"""
                <h3>IP Addresses</h3>
                <ul>
                    {"".join(f"<li>{ip}</li>" for ip in recon.get('ip_addresses', []))}
                </ul>
        """
    
    if recon.get('technologies'):
        html += f"""
                <h3>Technologies</h3>
                <ul>
                    {"".join(f"<li>{tech}</li>" for tech in recon.get('technologies', []))}
                </ul>
        """
    
    if recon.get('open_ports'):
        html += f"""
                <h3>Open Ports</h3>
                <ul>
                    {"".join(f"<li>{port}</li>" for port in recon.get('open_ports', []))}
                </ul>
        """
    
    html += """
            </div>
        </div>
    """
    
    # Add vulnerabilities by severity
    vulns = scan_results.get('vulnerabilities', {})
    any_vulns = False
    for severity in ['critical', 'high', 'medium', 'low', 'info']:
        has_severity = any(
            any(v.get('severity') == severity for v in findings)
            for findings in vulns.values() if isinstance(findings, list)
        )
        if has_severity:
            any_vulns = True
            html += f"""
            <div class="section">
                <div class="section-header">{severity.capitalize()} Severity Findings</div>
                <div class="section-content">
            """
            for vuln_type, findings in vulns.items():
                if not isinstance(findings, list):
                    continue
                severity_findings = [v for v in findings if v.get('severity') == severity]
                if severity_findings:
                    html += f"<h3>{vuln_type.upper().replace('_', ' ')}</h3>"
                    for finding in severity_findings:
                        html += f"""
                        <div class="vulnerability vulnerability-{severity}">
                            <h4>{finding.get('type', '').replace('_', ' ').title()}</h4>
                            <p>{finding.get('description', '')}</p>
                        """
                        if 'url' in finding:
                            html += f"<p><strong>URL:</strong> {finding.get('url')}</p>"
                        if 'recommendation' in finding:
                            html += f"""
                            <div class="recommendation">
                                <strong>Recommendation:</strong> {finding.get('recommendation')}
                            </div>
                            """
                        html += "</div>"
            html += """
                </div>
            </div>
            """
    # If no vulnerabilities, show a clear message
    if not any_vulns:
        html += """
        <div class="section">
            <div class="section-header">Vulnerability Findings</div>
            <div class="section-content">
                <p style='color:green;font-weight:bold;font-size:1.2em;'>No vulnerabilities were detected. This website appears to be safe (supposed).</p>
            </div>
        </div>
        """
    
    # Add AI analysis if available
    if 'ai_analysis' in scan_results:
        html += f"""
        <div class="section">
            <div class="section-header">AI Enhanced Analysis</div>
            <div class="section-content">
                <pre style="white-space: pre-wrap;">{scan_results['ai_analysis']}</pre>
            </div>
        </div>
        """
    
    # Close the HTML
    html += """
    </div>
    <footer style="text-align: center; margin-top: 20px; color: #777;">
        <p>Generated by Revisyn AI - Intelligent Security Scanner</p>
    </footer>
</body>
</html>
    """
    
    return html

def check_dependencies():
    """
    Check if all required dependencies are installed
    
    Returns:
        bool: True if all dependencies are met, False otherwise
    """
    required_modules = [
        'requests', 'colorama', 'beautifulsoup4', 'dnspython', 'python-whois'
    ]
    
    missing_modules = []
    
    for module in required_modules:
        try:
            __import__(module)
        except ImportError:
            missing_modules.append(module)
    
    if missing_modules:
        print(f"{Fore.RED}[!] Missing dependencies: {', '.join(missing_modules)}")
        print(f"{Fore.YELLOW}[*] Please install required dependencies:")
        print(f"    pip install {' '.join(missing_modules)}{Style.RESET_ALL}")
        return False
    
    return True

def get_timestamp():
    """
    Get current timestamp in standard format
    
    Returns:
        str: Formatted timestamp
    """
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def get_random_user_agent():
    """
    Get a random user agent string
    
    Returns:
        str: User agent string
    """
    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.59',
        'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1'
    ]
    return user_agents[datetime.datetime.now().microsecond % len(user_agents)]

def create_directory_if_not_exists(directory):
    """
    Create directory if it doesn't exist
    
    Args:
        directory (str): Directory path to create
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        if not os.path.exists(directory):
            os.makedirs(directory)
        return True
    except Exception as e:
        print(f"{Fore.RED}[!] Error creating directory: {str(e)}{Style.RESET_ALL}")
        return False

def save_to_file(content, filename):
    """
    Save content to file
    
    Args:
        content (str): Content to save
        filename (str): Filename to save to
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(content)
        return True
    except Exception as e:
        print(f"{Fore.RED}[!] Error writing to file: {str(e)}{Style.RESET_ALL}")
        return False

def print_vuln_summary(vulns):
    """
    Print a summary of vulnerabilities
    
    Args:
        vulns (dict): Vulnerability dictionary
    """
    severity_counts = {
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0,
        'info': 0
    }
    
    # Count vulnerabilities by severity
    for vuln_type, findings in vulns.items():
        for finding in findings:
            severity = finding.get('severity', 'info')
            severity_counts[severity] += 1
    
    # Print summary
    print("\n" + "="*50)
    print(f"{Fore.BLUE}[*] VULNERABILITY SUMMARY:{Style.RESET_ALL}")
    print(f"  {Fore.RED}Critical: {severity_counts['critical']}{Style.RESET_ALL}")
    print(f"  {Fore.MAGENTA}High: {severity_counts['high']}{Style.RESET_ALL}")
    print(f"  {Fore.YELLOW}Medium: {severity_counts['medium']}{Style.RESET_ALL}")
    print(f"  {Fore.BLUE}Low: {severity_counts['low']}{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}Info: {severity_counts['info']}{Style.RESET_ALL}")
    print("="*50)

def progress_bar(iteration, total, prefix='', suffix='', length=50, fill='█', url=None, status_code=None, show_urls=True):
    """
    Display a terminal progress bar with URL status tracking
    
    Args:
        iteration (int): Current iteration
        total (int): Total iterations
        prefix (str): Prefix string
        suffix (str): Suffix string
        length (int): Character length of bar
        fill (str): Bar fill character
        url (str, optional): Current URL being processed
        status_code (int, optional): HTTP status code of the current URL
        show_urls (bool): Whether to show URLs with successful status codes
    """
    percent = "{0:.1f}".format(100 * (iteration / float(total)))
    filled_length = int(length * iteration // total)
    bar = fill * filled_length + '-' * (length - filled_length)
    
    # Base progress information
    progress_info = f'\r{prefix} |{bar}| {percent}% {suffix}'
    
    # Add URL info if provided and status code is 200 or 301
    if show_urls and url and status_code in [200, 301]:
        status_color = Fore.GREEN if status_code == 200 else Fore.YELLOW
        status_text = "OK" if status_code == 200 else "Redirect"
        url_info = f" - {status_color}[{status_code} {status_text}]{Style.RESET_ALL} {url}"
        # Ensure URL doesn't extend too far
        max_url_length = 50
        if len(url) > max_url_length:
            url_info = f" - {status_color}[{status_code} {status_text}]{Style.RESET_ALL} {url[:max_url_length-3]}..."
        print(f"{progress_info}{url_info}")
    else:
        # Just update the progress bar without new line
        print(progress_info, end='\r')
    
    # Print new line on completion
    if iteration == total:
        print()

class URLScanTracker:
    """
    Track and display progress of URL scanning with status information
    """
    def __init__(self, total_urls, prefix='Scanning URLs', length=40):
        """
        Initialize URL scan tracker
        
        Args:
            total_urls (int): Total number of URLs to scan
            prefix (str): Prefix for the progress bar
            length (int): Length of the progress bar
        """
        self.total_urls = total_urls
        self.scanned_urls = 0
        self.successful_urls = 0
        self.prefix = prefix
        self.length = length
        self.start_time = datetime.datetime.now()
        
        # Initialize progress display
        print(f"{Fore.BLUE}[*] Starting scan of {total_urls} URLs{Style.RESET_ALL}")
        progress_bar(0, total_urls, prefix=prefix, length=length)
    
    def update(self, url, status_code):
        """
        Update progress with newly scanned URL
        
        Args:
            url (str): URL that was scanned
            status_code (int): HTTP status code of the response
        """
        self.scanned_urls += 1
        
        # Track successful responses
        if status_code in [200, 301]:
            self.successful_urls += 1
        
        # Calculate elapsed time and estimated time remaining
        elapsed = (datetime.datetime.now() - self.start_time).total_seconds()
        if self.scanned_urls > 0 and elapsed > 0:
            urls_per_second = self.scanned_urls / elapsed
            remaining_urls = self.total_urls - self.scanned_urls
            eta_seconds = remaining_urls / urls_per_second if urls_per_second > 0 else 0
            eta = str(datetime.timedelta(seconds=int(eta_seconds)))
            suffix = f"ETA: {eta} ({self.successful_urls} successful)"
        else:
            suffix = ""
        
        # Update progress bar
        progress_bar(
            self.scanned_urls, 
            self.total_urls,
            prefix=self.prefix,
            suffix=suffix,
            length=self.length,
            url=url,
            status_code=status_code
        )
    
    def finish(self):
        """
        Finalize and display scan summary
        """
        duration = datetime.datetime.now() - self.start_time
        print(f"{Fore.GREEN}[+] Scan completed in {duration.total_seconds():.2f} seconds{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Scanned {self.scanned_urls} URLs, {self.successful_urls} successful ({{200}}/OK or {{301}}/Redirect){Style.RESET_ALL}")