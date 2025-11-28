DaarkPyramid-Reconnaissance – Advanced Web Recon & Fingerprinting Framework

DaarkPyramid-Reconnaissance is a lightweight yet powerful Python-based reconnaissance framework designed to gather comprehensive information about web targets.
It includes built‑in fingerprinting modules, technology detection, security header analysis, port scanning, plugins support, and much more.

🚀 Features
Extract domain name & resolve IP

GeoIP + ASN lookup

Full HTTP response analysis

Common ports scanning

Redirect chain detection

HTML title extraction

CMS detection (WordPress, Joomla, Drupal, Magento, OpenCart…)

WAF detection (Cloudflare, ModSecurity, Sucuri, F5 BIG‑IP, Akamai…)

CDN identification

Technology detection (PHP, ASP.NET, Node.js, Python, Nginx, Apache)

JavaScript / CSS / Image assets extraction

Cookies enumeration

Security headers inspection

Favicon MD5 hashing

Plugin system for extending the scanner’s capabilities

📌 Requirements

Install these dependencies before running the tool:

pip install requests colorama

🛠️ How to Run

Use the following command:

python3 webxscanner.py <url

Example:

python3 DaarkPyramid-Reconnaissance https://example.com

📦 Creating Custom Plugins

To add your own plugin:

Place your file inside the directory:
plugins/

    Your plugin must contain a single function named run:

def run(url, headers, body):
    return "Plugin output here"

The framework automatically loads all plugins inside the folder on startup.
⚠️ Legal Disclaimer

This tool is intended ONLY for:

    Internal security testing

    Red team operations

    Research

    Educational and training purposes

❗ Unauthorized scanning or testing of systems without explicit permission is illegal and strictly prohibited.
❗ The developer assumes no liability for any misuse or illegal activities performed with this tool.
👤 Author

Kareem (DaarkPyramid)
Cyber Security – Penetration Tester

plugins/
