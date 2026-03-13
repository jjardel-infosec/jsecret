# jsecret v2.3

`jsecret` is a fast, concurrent scanner for JavaScript files that now combines classic secret detection with lightweight static analysis for risky code patterns.

## What's New in v2.3?

- **Hybrid scanning:** Keeps the existing regex signatures for known tokens and adds heuristic analysis for JavaScript security flaws.
- **JavaScript heuristics:** Flags potential DOM XSS, SQL injection, command injection, SSRF, open redirect, path traversal, insecure storage, weak crypto, wildcard `postMessage`, disabled TLS validation, and more.
- **Line-aware evidence:** Heuristic findings include the line number and code snippet that triggered the alert.
- **Full secret pass:** Signature matching still finds all matches in the same file and remains deduplicated by content hash.
- **CSV export:** Built-in CSV reporting via `-csv`.

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
- `-csv`: Export results to a formatted CSV file (Target, Priority, Type, Evidence).
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

## Detection Coverage

`jsecret` now uses two complementary passes:

- **Signature pass:** Detects known secrets such as cloud keys, SaaS tokens, DB URIs, JWTs, webhooks, private keys, and hardcoded credentials.
- **Heuristic pass:** Detects risky JavaScript patterns such as dynamic HTML sinks, `eval`, `new Function`, query concatenation, unsafe redirects, tainted file access, insecure web storage usage, weak hashing, predictable token generation, and disabled certificate validation.

Heuristic findings are intentionally labeled as `Potential ...` when the result depends on code context rather than an exact signature.

## Output Format

### Terminal (Colored)
`[target] [PRIORITY] Finding Name : match_content`

### CSV Export
| Target | Priority | Finding Type | Evidence |
| :--- | :--- | :--- | :--- |
| http://site.com/v.js | CRITICAL | AWS Access Key ID | AKIA... |

---
**Maintained by @jjardel-infosec**
