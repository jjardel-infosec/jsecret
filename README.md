# jsecret v2.2

`jsecret` is a simple, extremely fast, and concurrent tool designed to detect sensitive data (API keys, tokens, passwords, etc.) in source code files, specifically optimized for JavaScript.

## What's New in v2.2?

- **🚀 Performance O(1):** Rewritten with `sync.Map` for global hash deduplication. No more thread-locking bottle-necks.
- **🛡️ SSL/TLS Bypass:** Automatically ignores expired or invalid certificates (`InsecureSkipVerify`). Perfect for old subdomains and internal assets.
- **🔍 Full Scanning:** Unlike older versions that stopped at the first match, v2.2 finds **all** secrets within a single file.
- **📊 Priority System:** Results are now categorized by severity:
  - 🔴 **CRITICAL**: Cloud Keys (AWS, GCP), Database URIs, Private Keys, Hardcoded Passwords.
  - 🟠 **HIGH**: SaaS Tokens (GitHub, Slack, Stripe, Twilio), CI/CD Secrets.
  - 🟡 **MEDIUM**: Analytics Keys, OAuth Client IDs, Bot Tokens.
  - 🔵 **LOW / NOISE**: Internal IPs, Dev/Staging URLs, generic Base64 blobs.
- **📄 CSV Export:** Built-in safe CSV generation via `-csv` flag for easy spreadsheet analysis.

## Installation

### Via Go
```bash
go install github.com/jjardel-infosec/jsecret@latest
```

### From Source
1. Clone and Build:
   ```bash
   git clone https://github.com/jjardel-infosec/jsecret.git
   cd jsecret
   go build -o jsecret
   ```

2. Move to global path:
   ```bash
   sudo mv jsecret /usr/local/bin/
   ```

## Usage

### Flags
- `-u`: Scan a single URL.
- `-f`: Scan a list of URLs from a file.
- `-d`: Recursive directory scan for `.js` files.
- `-o`: Save results to a plain TXT file.
- `-csv`: Export results to a formatted CSV file (Target, Priority, Type, Secret).
- `-t`: Set concurrent threads (default: 50).
- `-s`: Silent mode (no banner).
- `-h`: Show help.

### Examples

**1. Pipe through other tools**
```bash
cat subdomains.txt | httpx | jsecret
```

**2. Recursive local scan**
```bash
jsecret -d ./my_project -t 100
```

**3. Generate CSV Report**
```bash
jsecret -f js_urls.txt -csv reconnaissance_report.csv
```

**4. Single URL analysis**
```bash
jsecret -u https://example.com/assets/config.js
```

## Output Format

### Terminal (Colored)
`[target] [PRIORITY] Finding Name : match_content`

### CSV Export
| Target | Priority | Finding Type | Matched Secret |
| :--- | :--- | :--- | :--- |
| http://site.com/v.js | CRITICAL | AWS Access Key ID | AKIA... |

---
**Maintained by @jjardel-infosec**
