import os
import json
import yaml
import configparser
from pathlib import Path
from colorama import Fore, Style

# Default configuration paths
DEFAULT_CONFIG_DIR = os.path.expanduser("~/.revisyn-ai")
DEFAULT_CONFIG_FILE = os.path.join(DEFAULT_CONFIG_DIR, "config.json")
DEFAULT_PROFILES_DIR = os.path.join(DEFAULT_CONFIG_DIR, "profiles")

class ConfigManager:
    """Manages configuration settings for Revisyn-AI"""
    
    def __init__(self, config_file=None):
        """
        Initialize the configuration manager
        
        Args:
            config_file (str, optional): Path to config file. Defaults to ~/.revisyn-ai/config.json
        """
        self.config_file = config_file or DEFAULT_CONFIG_FILE
        self.config = {
            "general": {
                "default_scan_level": "standard",
                "default_output_format": "console",
                "timeout": 10,
                "user_agent": "Revisyn-AI-Scanner/1.0",
                "max_threads": 5
            },
            "api_keys": {
                "github_token": os.environ.get("GITHUB_TOKEN", ""),
                "shodan_key": os.environ.get("SHODAN_API_KEY", ""),
                "censys_id": os.environ.get("CENSYS_API_ID", ""),
                "censys_secret": os.environ.get("CENSYS_API_SECRET", "")
            },
            "scan_options": {
                "follow_redirects": True,
                "max_redirects": 5,
                "verify_ssl": False,
                "max_pages_to_crawl": 10,
                "scan_subdomains": False,
                "analyze_javascript": False
            }
        }
        
        # Ensure config directory exists
        os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
        
        # Load configuration if it exists
        self.load_config()
    
    def load_config(self):
        """
        Load configuration from file
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    file_config = json.load(f)
                    # Update the default config with values from file
                    self._update_nested_dict(self.config, file_config)
                return True
            else:
                # Save default config if no config file exists
                self.save_config()
                print(f"{Fore.YELLOW}[*] Created default configuration at {self.config_file}{Style.RESET_ALL}")
                return True
        except Exception as e:
            print(f"{Fore.RED}[!] Error loading configuration: {str(e)}{Style.RESET_ALL}")
            return False
    
    def save_config(self):
        """
        Save configuration to file
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
            return True
        except Exception as e:
            print(f"{Fore.RED}[!] Error saving configuration: {str(e)}{Style.RESET_ALL}")
            return False
    
    def get_value(self, section, key, default=None):
        """
        Get a configuration value
        
        Args:
            section (str): Configuration section
            key (str): Configuration key
            default (any, optional): Default value if not found
            
        Returns:
            any: Configuration value or default
        """
        try:
            return self.config.get(section, {}).get(key, default)
        except Exception:
            return default
    
    def set_value(self, section, key, value):
        """
        Set a configuration value
        
        Args:
            section (str): Configuration section
            key (str): Configuration key
            value (any): Value to set
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            if section not in self.config:
                self.config[section] = {}
            
            self.config[section][key] = value
            return self.save_config()
        except Exception as e:
            print(f"{Fore.RED}[!] Error setting configuration value: {str(e)}{Style.RESET_ALL}")
            return False
    
    def _update_nested_dict(self, d, u):
        """
        Recursively update a nested dictionary
        
        Args:
            d (dict): Dictionary to update
            u (dict): Dictionary with updates
            
        Returns:
            dict: Updated dictionary
        """
        for k, v in u.items():
            if isinstance(v, dict) and k in d and isinstance(d[k], dict):
                self._update_nested_dict(d[k], v)
            else:
                d[k] = v
        return d

class ScanProfileManager:
    """Manages scan profiles for different target types"""
    
    def __init__(self, profiles_dir=None):
        """
        Initialize the scan profile manager
        
        Args:
            profiles_dir (str, optional): Directory for scan profiles
        """
        self.profiles_dir = profiles_dir or DEFAULT_PROFILES_DIR
        os.makedirs(self.profiles_dir, exist_ok=True)
        
        # Create default profiles if they don't exist
        self._create_default_profiles()
    
    def _create_default_profiles(self):
        """Create default scan profiles if they don't exist"""
        default_profiles = {
            "standard-web": {
                "description": "Standard web application scan profile",
                "scan_level": "standard",
                "check_xss": True,
                "check_sqli": True,
                "check_lfi": True,
                "check_open_redirect": True,
                "check_csrf": True,
                "check_headers": True,
                "crawler": {
                    "enabled": True,
                    "max_pages": 10,
                    "respect_robots": True
                }
            },
            "deep-web": {
                "description": "Deep scan for web applications",
                "scan_level": "deep",
                "check_xss": True,
                "check_sqli": True,
                "check_lfi": True,
                "check_open_redirect": True,
                "check_csrf": True,
                "check_headers": True,
                "crawler": {
                    "enabled": True,
                    "max_pages": 50,
                    "respect_robots": True
                },
                "api_endpoints": {
                    "enabled": True,
                    "check_methods": ["GET", "POST", "PUT", "DELETE"]
                }
            },
            "api-only": {
                "description": "API-focused scan profile",
                "scan_level": "standard",
                "check_xss": False,
                "check_sqli": True,
                "check_lfi": True,
                "check_open_redirect": False,
                "check_csrf": False,
                "check_headers": True,
                "crawler": {
                    "enabled": False
                },
                "api_endpoints": {
                    "enabled": True,
                    "check_methods": ["GET", "POST", "PUT", "DELETE", "PATCH"]
                }
            },
            "passive-only": {
                "description": "Passive checks only (no active testing)",
                "scan_level": "basic",
                "check_xss": False,
                "check_sqli": False,
                "check_lfi": False,
                "check_open_redirect": False,
                "check_csrf": False,
                "check_headers": True,
                "crawler": {
                    "enabled": False
                },
                "passive_checks": {
                    "enabled": True,
                    "check_dns": True,
                    "check_whois": True,
                    "check_ssl": True,
                    "check_headers": True
                }
            }
        }
        
        for profile_name, profile_data in default_profiles.items():
            profile_path = os.path.join(self.profiles_dir, f"{profile_name}.json")
            if not os.path.exists(profile_path):
                try:
                    with open(profile_path, 'w') as f:
                        json.dump(profile_data, f, indent=2)
                    print(f"{Fore.GREEN}[+] Created default profile: {profile_name}{Style.RESET_ALL}")
                except Exception as e:
                    print(f"{Fore.RED}[!] Error creating default profile {profile_name}: {str(e)}{Style.RESET_ALL}")
    
    def get_profile(self, profile_name):
        """
        Get a scan profile by name
        
        Args:
            profile_name (str): Name of the profile
            
        Returns:
            dict: Profile data or None if not found
        """
        profile_path = os.path.join(self.profiles_dir, f"{profile_name}.json")
        
        if not os.path.exists(profile_path):
            print(f"{Fore.YELLOW}[!] Profile {profile_name} not found{Style.RESET_ALL}")
            return None
        
        try:
            with open(profile_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"{Fore.RED}[!] Error loading profile {profile_name}: {str(e)}{Style.RESET_ALL}")
            return None
    
    def save_profile(self, profile_name, profile_data):
        """
        Save a scan profile
        
        Args:
            profile_name (str): Name of the profile
            profile_data (dict): Profile data
            
        Returns:
            bool: True if successful, False otherwise
        """
        profile_path = os.path.join(self.profiles_dir, f"{profile_name}.json")
        
        try:
            with open(profile_path, 'w') as f:
                json.dump(profile_data, f, indent=2)
            return True
        except Exception as e:
            print(f"{Fore.RED}[!] Error saving profile {profile_name}: {str(e)}{Style.RESET_ALL}")
            return False
    
    def delete_profile(self, profile_name):
        """
        Delete a scan profile
        
        Args:
            profile_name (str): Name of the profile
            
        Returns:
            bool: True if successful, False otherwise
        """
        profile_path = os.path.join(self.profiles_dir, f"{profile_name}.json")
        
        if not os.path.exists(profile_path):
            print(f"{Fore.YELLOW}[!] Profile {profile_name} not found{Style.RESET_ALL}")
            return False
        
        try:
            os.remove(profile_path)
            return True
        except Exception as e:
            print(f"{Fore.RED}[!] Error deleting profile {profile_name}: {str(e)}{Style.RESET_ALL}")
            return False
    
    def list_profiles(self):
        """
        List all available scan profiles
        
        Returns:
            list: List of profile names
        """
        try:
            return [f.stem for f in Path(self.profiles_dir).glob('*.json')]
        except Exception as e:
            print(f"{Fore.RED}[!] Error listing profiles: {str(e)}{Style.RESET_ALL}")
            return []

def load_environment_variables(env_file='.env'):
    """
    Load environment variables from .env file
    
    Args:
        env_file (str): Path to .env file
        
    Returns:
        bool: True if successful, False otherwise
    """
    if not os.path.exists(env_file):
        return False
    
    try:
        with open(env_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                    
                key, value = line.split('=', 1)
                os.environ[key.strip()] = value.strip().strip('"\'')
        
        return True
    except Exception as e:
        print(f"{Fore.RED}[!] Error loading environment variables: {str(e)}{Style.RESET_ALL}")
        return False

def check_api_keys():
    """
    Check if required API keys are set
    
    Returns:
        dict: Dictionary with API key status
    """
    keys_status = {
        "github_token": {
            "name": "GitHub Token",
            "status": os.environ.get("GITHUB_TOKEN", "") != "",
            "env_var": "GITHUB_TOKEN"
        },
        "shodan_key": {
            "name": "Shodan API Key",
            "status": os.environ.get("SHODAN_API_KEY", "") != "",
            "env_var": "SHODAN_API_KEY"
        },
        "censys_id": {
            "name": "Censys API ID",
            "status": os.environ.get("CENSYS_API_ID", "") != "",
            "env_var": "CENSYS_API_ID"
        },
        "censys_secret": {
            "name": "Censys API Secret",
            "status": os.environ.get("CENSYS_API_SECRET", "") != "",
            "env_var": "CENSYS_API_SECRET"
        }
    }
    
    return keys_status

def print_api_keys_status():
    """Print status of API keys"""
    keys_status = check_api_keys()
    
    print(f"\n{Fore.BLUE}[*] API Keys Status:{Style.RESET_ALL}")
    for key, info in keys_status.items():
        status_color = Fore.GREEN if info["status"] else Fore.RED
        status_text = "Set" if info["status"] else "Missing"
        print(f"  {info['name']}: {status_color}{status_text}{Style.RESET_ALL}")
    
    print("")

def parse_yaml_config(yaml_path):
    """
    Parse YAML configuration file
    
    Args:
        yaml_path (str): Path to YAML config file
        
    Returns:
        dict: Configuration data or None if error
    """
    try:
        if not os.path.exists(yaml_path):
            return None
            
        with open(yaml_path, 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        print(f"{Fore.RED}[!] Error parsing YAML config: {str(e)}{Style.RESET_ALL}")
        return None