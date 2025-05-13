<p align="center">
  <img src="images/logo.png" alt="Revisyn-AI Logo" width="250" />
</p>

<h1 align="center">Revisyn-AI</h1>
<h3 align="center">AI-Powered Analysis Scanner</h3>

<p align="center">
  <a href="https://github.com/awiones/Revisyn-Ai"><img src="https://img.shields.io/github/stars/awiones/Revisyn-Ai?style=flat-square" alt="GitHub stars"></a>
  <a href="https://github.com/awiones/Revisyn-Ai"><img src="https://img.shields.io/github/forks/awiones/Revisyn-Ai?style=flat-square" alt="GitHub forks"></a>
  <a href="https://github.com/awiones/Revisyn-Ai/blob/main/LICENSE"><img src="https://img.shields.io/github/license/awiones/Revisyn-Ai?style=flat-square" alt="License"></a>
  <img src="https://img.shields.io/badge/status-beta-yellow?style=flat-square" alt="Beta Status">
</p>

# Revisyn-AI

**Revisyn-AI** is an intelligent, AI-powered cybersecurity scanner. It helps security professionals and developers identify, analyze, and remediate web vulnerabilities with advanced AI models and automated techniques.

---

## 🚧 Beta Notice

> **Note:** Revisyn-AI is under active development and not yet feature-complete. Many features are experimental, and results may be incomplete or inaccurate. Feedback and contributions are welcome!

---

## 🚀 Getting Started

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
2. **Set up API keys:**
   - Use the following command to add your GitHub token (required for AI features):
     ```bash
     python main.py --auth github <your_github_token>
     ```
   - For Shodan or Censys, use:
     ```bash
     python main.py --auth SHODAN <your_shodan_api_key>
     python main.py --auth CENSYS-ID <your_censys_api_id>
     python main.py --auth CENSYS-SECRET <your_censys_api_secret>
     ```
3. **Run a scan:**
   ```bash
   python main.py -u https://target.com
   ```

---

## 🔍 Specifying Vulnerability Types

You can specify which vulnerabilities to scan for by providing a comma-separated list using the `-v` or `--vuln-types` parameter. Supported types are listed below:

| Type        | Description                                      |
| ----------- | ------------------------------------------------ |
| xss         | Cross-Site Scripting                             |
| sqli        | SQL Injection                                    |
| lfi         | Local File Inclusion                             |
| web_content | Web-Content Discovery (hidden files/directories) |

**Example:**

```bash
python main.py -u https://target.com -v xss,sqli,lfi,web_content
```

This command scans only for XSS, SQL Injection, and Local File Inclusion vulnerabilities on the target URL.

---

## 📦 Output Formats

- **Console:** Human-readable output in the terminal (default)
- **JSON:** Machine-readable output for automation
- **HTML:** Beautiful, shareable reports

**Example:**

```bash
python main.py -u https://target.com -o html
```

---

## 💡 Interactive Mode

Launch an interactive CLI for step-by-step scanning:

```bash
python main.py -i
```

---

## ⚠️ Disclaimer

Revisyn-AI is for educational and authorized security testing only. **Do not use it against systems you do not own or have explicit permission to test.**

---

## 🤝 Contributing

Contributions, bug reports, and feature requests are welcome! Please open an issue or pull request on [GitHub](https://github.com/awiones/Revisyn-Ai).

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
