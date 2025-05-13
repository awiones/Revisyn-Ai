from modules.auth import handle_auth_arg, print_auth_instructions
import os
import sys
import argparse
import json
import requests
from urllib.parse import urlparse
from colorama import init, Fore, Style
from dotenv import load_dotenv
import urllib3

from modules.ai_engine import AIEngine
from modules.scanner import Scanner
from modules.utils import banner, validate_url, format_output, progress_bar, URLScanTracker
from modules.vuln_check import VulnerabilityChecker

# Call handle_auth_arg() first to allow --auth to work before .env check
handle_auth_arg()

# --- Early check for .env and GITHUB_TOKEN ---
if not os.path.exists('.env'):
    # Create an empty .env file
    with open('.env', 'w') as f:
        f.write('GITHUB_TOKEN=\n')
    print_auth_instructions()
    exit(1)
else:
    # Check if GITHUB_TOKEN is present and non-empty in .env
    with open('.env', 'r') as f:
        lines = f.readlines()
    token_line = [line for line in lines if line.strip().startswith('GITHUB_TOKEN=')]
    token = ''
    if token_line:
        token = token_line[0].strip().split('=', 1)[-1]
    if not token:
        print_auth_instructions()
        exit(1)

# Load environment variables from .env file if present
load_dotenv()

# Initialize colorama for cross-platform colored terminal text
init(autoreset=True)

# Suppress only the single InsecureRequestWarning from urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def auto_fix_url(url):
    """
    Ensure the URL has a scheme. If not, prepend 'https://'.
    """
    parsed = urlparse(url)
    if not parsed.scheme:
        return 'https://' + url
    return url

class RevisynAI:
    def __init__(self):
        self.ai_engine = AIEngine()
        self.scanner = Scanner()
        self.vuln_checker = VulnerabilityChecker()
        
    def scan_url(self, url, scan_level="basic", output_format="console", vuln_types=None):
        url = auto_fix_url(url)
        print(f"{Fore.BLUE}[*] Starting Revisyn AI scan on {url}{Style.RESET_ALL}")
        if not validate_url(url):
            print(f"{Fore.RED}[!] Invalid URL format: {url}{Style.RESET_ALL}")
            return False
        print(f"{Fore.BLUE}[*] Performing initial reconnaissance...{Style.RESET_ALL}")
        recon_data = self.scanner.basic_recon(url)
        if vuln_types and len(vuln_types) == 1 and vuln_types[0].lower() == "lfi":
            print(f"{Fore.BLUE}[*] Scanning for Local File Inclusion (LFI) vulnerabilities...{Style.RESET_ALL}")
            lfi_results = []
            lfi_payloads = getattr(self.vuln_checker, 'lfi_payloads', None)
            if lfi_payloads is None:
                try:
                    with open('modules/seclists/lfi-payloads.txt', 'r') as f:
                        lfi_payloads = [line.strip() for line in f if line.strip()]
                except Exception:
                    lfi_payloads = [None] * 50  # fallback to 50 if unknown
            # Limit payloads based on scan_level
            if scan_level == 'basic':
                max_payloads = 250
            elif scan_level == 'standard':
                max_payloads = 500
            elif scan_level == 'deep':
                max_payloads = len(lfi_payloads)
            else:
                max_payloads = 250
            lfi_payloads = lfi_payloads[:max_payloads]
            total_payloads = len(lfi_payloads)
            tracker = URLScanTracker(total_payloads, prefix='LFI Progress', length=40)
            tested = 0
            for idx, result in enumerate(self.vuln_checker.check_lfi_realtime(url)):
                if idx >= max_payloads:
                    break
                tested += 1
                status_code = result.get('status_code', 200 if result['valid'] else 404)
                tracker.update(result['url'], status_code)
                if result['valid']:
                    print(f"{Fore.GREEN}[LFI FOUND]{Style.RESET_ALL} {result['url']} param={result['parameter']} payload={result['payload']}")
                elif status_code in [200, 301]:
                    print(f"{Fore.YELLOW}[LFI TESTED]{Style.RESET_ALL} {result['url']} param={result['parameter']} payload={result['payload']} - Not vulnerable")
                if result.get('vuln_info'):
                    lfi_results.append(result['vuln_info'])
            tracker.finish()
            print(f"{Fore.BLUE}[*] Performing AI-enhanced analysis for LFI...{Style.RESET_ALL}")
            ai_analysis = self.ai_engine.analyze_scan_results(url, recon_data, {"lfi": lfi_results})
            scan_results = {
                "url": url,
                "scan_time": self.scanner.get_timestamp(),
                "recon_data": recon_data,
                "vulnerabilities": {"lfi": lfi_results},
                "ai_analysis": ai_analysis
            }
            format_output(scan_results, output_format)
            return scan_results
        if vuln_types and len(vuln_types) == 1 and vuln_types[0].lower() == "web_content":
            print(f"{Fore.BLUE}[*] Discovering Web Content (directories/files)...{Style.RESET_ALL}")
            web_content_results = self.scanner.discover_web_content(url, scan_level)
            print(f"{Fore.BLUE}[*] Performing AI-enhanced analysis for Web Content Discovery...{Style.RESET_ALL}")
            ai_analysis = self.ai_engine.analyze_scan_results(url, recon_data, {"web_content": web_content_results})
            scan_results = {
                "url": url,
                "scan_time": self.scanner.get_timestamp(),
                "recon_data": recon_data,
                "vulnerabilities": {"web_content": web_content_results},
                "ai_analysis": ai_analysis
            }
            format_output(scan_results, output_format)
            return scan_results
        # Otherwise, do normal scan
        print(f"{Fore.BLUE}[*] Scanning for common vulnerabilities...{Style.RESET_ALL}")
        vuln_results = self.vuln_checker.scan_common_vulns(url, scan_level, vuln_types)
        print(f"{Fore.BLUE}[*] Performing AI-enhanced analysis...{Style.RESET_ALL}")
        ai_analysis = self.ai_engine.analyze_scan_results(url, recon_data, vuln_results)
        scan_results = {
            "url": url,
            "scan_time": self.scanner.get_timestamp(),
            "recon_data": recon_data,
            "vulnerabilities": vuln_results,
            "ai_analysis": ai_analysis
        }
        format_output(scan_results, output_format)
        return scan_results
    
    def interactive_mode(self):
        """Interactive CLI mode for Revisyn AI"""
        banner()
        print(f"{Fore.GREEN}Welcome to Revisyn AI Interactive Mode{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Type 'exit' or 'quit' to leave interactive mode{Style.RESET_ALL}")
        print(f"{Fore.CYAN}You can specify scan types: scan <url> [xss,sqli,lfi] (optional)\n{Style.RESET_ALL}")
        while True:
            try:
                user_input = input(f"\n{Fore.GREEN}revisyn> {Style.RESET_ALL}").strip()
                if user_input.lower() in ['exit', 'quit']:
                    print(f"{Fore.YELLOW}Exiting Revisyn AI. Goodbye!{Style.RESET_ALL}")
                    break
                if user_input.lower().startswith('scan '):
                    parts = user_input[5:].strip().split()
                    url = parts[0] if parts else ''
                    vuln_types = None
                    if len(parts) > 1:
                        vuln_types = [v.strip() for v in parts[1].split(',')]
                    url = auto_fix_url(url)
                    self.scan_url(url, vuln_types=vuln_types)
                elif user_input.lower() == 'help':
                    print(f"\n{Fore.CYAN}Available commands:{Style.RESET_ALL}")
                    print(f"  scan <url> [xss,sqli,lfi] - Scan a URL for specific vulnerabilities (optional types)")
                    print(f"  help - Show this help message")
                    print(f"  exit/quit - Exit interactive mode")
                else:
                    print(f"{Fore.RED}Unknown command. Type 'help' for available commands.{Style.RESET_ALL}")
            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}Operation cancelled by user.{Style.RESET_ALL}")
                continue
            except Exception as e:
                print(f"{Fore.RED}Error: {str(e)}{Style.RESET_ALL}")

def main():
    banner()
    parser = argparse.ArgumentParser(description="Revisyn AI - Intelligent Cybersecurity Scanner")
    parser.add_argument("-u", "--url", help="Target URL to scan")
    parser.add_argument("-l", "--level", choices=["basic", "standard", "deep"], default="basic", 
                        help="Scan intensity level (default: basic)")
    parser.add_argument("-o", "--output", choices=["console", "json", "html"], default="console",
                        help="Output format (default: console)")
    parser.add_argument("-i", "--interactive", action="store_true", help="Run in interactive mode")
    parser.add_argument("-v", "--vuln-types", help="Comma-separated list of vulnerability types to scan for (e.g. xss,sqli,lfi)")
    args = parser.parse_args()
    vuln_types = [v.strip() for v in args.vuln_types.split(",")] if args.vuln_types else None
    revisyn_ai = RevisynAI()
    if args.interactive:
        revisyn_ai.interactive_mode()
    elif args.url:
        revisyn_ai.scan_url(args.url, args.level, args.output, vuln_types)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()