# Revisyn-AI

**Revisyn-AI** is an intelligent cybersecurity scanner powered by AI, currently in early beta. It aims to help security professionals and developers identify, analyze, and remediate web vulnerabilities with the assistance of advanced AI models.

## 🚧 Beta Notice

This project is under active development and is not yet feature-complete. Many features are experimental, and results may be incomplete or inaccurate. Your feedback and contributions are welcome!

## What Revisyn-AI Does

- **Automated Reconnaissance:** Gathers information about target web applications, including IPs, DNS, HTTP headers, technologies, and more.
- **Vulnerability Scanning:** Checks for common web vulnerabilities such as XSS, SQLi, LFI, open redirects, insecure headers, and more.
- **AI-Enhanced Analysis:** Uses AI to analyze scan results, prioritize findings, and suggest remediation steps.
- **Flexible Output:** Supports console, JSON, and HTML reporting.
- **Interactive CLI:** Offers an interactive mode for step-by-step scanning and exploration.

## Getting Started

1. **Install dependencies:**  
   `pip install -r requirements.txt`
2. **Set up environment variables:**  
   Copy `.env` and add your API keys (GitHub token required for AI features).
3. **Run a scan:**  
   `python main.py -u https://target.com`

## Specifying Vulnerability Types with Lists

You can specify which vulnerabilities to scan for by providing a comma-separated list using the `-v` or `--vuln-types` parameter. Supported types are listed below:

| Type | Description          |
| ---- | -------------------- |
| xss  | Cross-Site Scripting |
| sqli | SQL Injection        |
| lfi  | Local File Inclusion |

**Example:**

```
python main.py -u https://target.com -v xss,sqli,lfi
```

This command will scan only for XSS, SQL Injection, and Local File Inclusion vulnerabilities on the target URL.

## Disclaimer

Revisyn-AI is for educational and authorized security testing only. Do not use it against systems you do not own or have explicit permission to test.
