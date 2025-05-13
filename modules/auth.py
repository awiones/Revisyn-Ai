from colorama import Fore, Style
import sys
import os

def print_auth_instructions():
    print(f"{Fore.RED}[!] No API key detected.{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}You must provide an API key to use Revisyn-AI.{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Run: python main.py --auth github <your_github_token>{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Run: python main.py --auth SHODAN <your_shodan_api_key>{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Run: python main.py --auth CENSYS-ID <your_censys_api_id>{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Run: python main.py --auth CENSYS-SECRET <your_censys_api_secret>{Style.RESET_ALL}")
    print(f"{Fore.CYAN}You can generate a GitHub token at: https://github.com/settings/tokens{Style.RESET_ALL}")
    print(f"{Fore.CYAN}You can get a Shodan key at: https://account.shodan.io/register{Style.RESET_ALL}")
    print(f"{Fore.CYAN}You can get Censys credentials at: https://censys.io/account/api{Style.RESET_ALL}")

def handle_auth_arg():
    """
    If --auth <type> <token> is provided, save the token to .env and exit.
    """
    if '--auth' in sys.argv:
        idx = sys.argv.index('--auth')
        if idx + 2 < len(sys.argv):
            auth_type = sys.argv[idx + 1].strip().upper()
            token = sys.argv[idx + 2].strip()
            env_map = {
                'GITHUB': 'GITHUB_TOKEN',
                'SHODAN': 'SHODAN_API_KEY',
                'CENSYS-ID': 'CENSYS_API_ID',
                'CENSYS-SECRET': 'CENSYS_API_SECRET',
            }
            if auth_type not in env_map:
                print(f"{Fore.RED}[!] Invalid auth type. Use one of: github, SHODAN, CENSYS-ID, CENSYS-SECRET{Style.RESET_ALL}")
                sys.exit(1)
            env_key = env_map[auth_type]
            # Read existing .env lines
            lines = []
            if os.path.exists('.env'):
                with open('.env', 'r') as f:
                    lines = f.readlines()
            # Update or add the relevant key
            found = False
            for i, line in enumerate(lines):
                if line.strip().startswith(env_key + '='):
                    lines[i] = f'{env_key}={token}\n'
                    found = True
                    break
            if not found:
                lines.append(f'{env_key}={token}\n')
            # Remove any lines that are just the token by itself (bad format)
            lines = [l for l in lines if not (l.strip() == token or l.strip() == '')]
            # Write back
            with open('.env', 'w') as f:
                f.writelines(lines)
            print(f"{Fore.GREEN}[+] {env_key} saved to .env!{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}You can now run Revisyn-AI normally.{Style.RESET_ALL}")
            sys.exit(0)
        else:
            print(f"{Fore.RED}[!] Usage: python main.py --auth <github|SHODAN|CENSYS-ID|CENSYS-SECRET> <token>{Style.RESET_ALL}")
            sys.exit(1)
