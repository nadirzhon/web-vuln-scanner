# 🕸️ Web Vulnerability Scanner

Automated web application scanner covering OWASP Top 10.

## Checks
| Vulnerability | Method |
|---------------|--------|
| SQL Injection | Error-based payloads |
| XSS Reflected | Script injection in params |
| Open Redirect | Redirect param fuzzing |
| Sensitive Files | /.git, /.env, /backup |
| Security Headers | CSP, HSTS, X-Frame-Options |

## Usage
```bash
pip install -r requirements.txt

python scanner.py -u https://target.com
python scanner.py -u https://target.com --crawl -o report.json
```

**Only test systems you own or have written permission to test.**
