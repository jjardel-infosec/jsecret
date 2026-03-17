# jsecret v2.4 (AI/Cloud & Security Heuristics Enhanced!)

`jsecret` is a simple, extremely fast, and concurrent tool designed to detect sensitive data (API keys, tokens, passwords, etc.) in source code files, specifically optimized for JavaScript.

## What's New in v2.4?

- **Enhanced AI/ML Token Detection:** Added support for OpenAI Project Keys (`sk-proj-`), Anthropic (`sk-ant-`), Google AI Studio, Groq, Mistral, and Together AI.
- **Expanded Cloud Service Coverage:** New integration with Grafana, Postman, Doppler, Figma, Notion, Airtable, Contentful, Mapbox, and more modern SaaS platforms.
- **Improved Accuracy:** Fixed false positives in Slack, Dropbox, Asana, and Telegram token patterns; added entropy validation for generic patterns.
- **Advanced Security Heuristics:** Detects Prototype Pollution, Template Injection, Insecure Deserialization, Mass Assignment, JWT weak algorithms, and hardcoded JWT secrets.
- **Safelist Pattern:** Known hashes (SHA1/256/MD5 empty strings) and test values excluded from detection.
- **Hybrid scanning:** Regex signatures for known tokens + heuristic analysis for JavaScript security flaws.
- **Line-aware evidence:** Heuristic findings include the line number and code snippet that triggered the alert.
- **CSV export:** Built-in CSV reporting via `-csv`.

## Improvements in v2.4

### Fixed False Positive Patterns
- **Slack Token:** Made suffix required for stricter matching
- **Dropbox Token:** Increased minimum length to 130 chars to avoid file path matches
- **Asana Token:** Added word boundaries and limited to hex characters only
- **Telegram Token:** Added word boundaries and range validation (8-10 digits for chat ID)

### Pattern Quality Enhancements
- **Entropy Validation:** Generic hex patterns now require Shannon entropy ≥ 3.5
- **Safelist Filtering:** Known test hashes and placeholder values automatically excluded
- **Context Requirements:** API patterns include minimum length and format strictness requirements
- **Negative Lookaheads:** Prevent token pattern extension into adjacent code

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

### Signature Pass
**Cloud & API Credentials (80+ patterns):**
- AWS (Access Key ID, Secret Key, STS Session Token)
- Azure, Google Cloud, Alibaba Cloud
- Vault (Hashicorp) - `hvs.` and legacy `s.` formats
- GitHub, GitLab, Gitea, Bitbucket tokens
- **AI/ML Services:** OpenAI (`sk-` and `sk-proj-`), Anthropic (`sk-ant-`), Hugging Face, Google AI Studio, Groq, Mistral
- **Modern Cloud/SaaS:** Supabase, Vercel, NPM, PyPI, Clerk, Planetscale, Neon, Railway, Render, Google OAuth, Grafana, Postman, Doppler, Figma, Notion, Airtable, Contentful, Mapbox
- Datadog, Bugsnag, Loggly, PagerDuty, SendGrid, Slack, Telegram, Asana, Dropbox
- Database URIs (MongoDB, Redis, PostgreSQL, MySQL, etc.)
- JWT/Bearer tokens, Private RSA/SSH/PGP keys
- Hardcoded credentials in variable assignments

### Heuristic Pass
**Security Vulnerability Patterns:**
- **Code Injection:** Dynamic code execution (`eval`, `new Function`), potential SQL injection, command injection
- **XSS & HTML Injection:** DOM XSS sinks (`innerHTML`, `dangerouslySetInnerHTML`, `insertAdjacentHTML`), taint tracking
- **SSRF & Open Redirect:** Untrusted outbound requests, user-controlled redirects
- **Path Traversal:** File access with user input
- **Template Injection:** Jinja, EJS, Handlebars, Mustache rendering with user input
- **Prototype Pollution:** Direct prototype object mutation (`__proto__`, `constructor.prototype`)
- **Insecure Deserialization:** `JSON.parse` from untrusted sources, `yaml.load`, `pickle.loads`
- **Mass Assignment:** Direct object updates with request body without field filtering
- **Web Storage & Cookies:** Sensitive data stored in `localStorage`, `sessionStorage`, or `document.cookie`
- **Weak Cryptography:** MD5, SHA1, DES, RC4, ECB mode
- **Predictable Token Generation:** Security-sensitive variables using `Math.random()`
- **JWT Weaknesses:** Weak algorithms (`none`, `HS256`), hardcoded secrets
- **TLS Validation Disabled:** `rejectUnauthorized: false`, `NODE_TLS_REJECT_UNAUTHORIZED`
- **CORS Misconfiguration:** Wildcard origin with credentials enabled
- **Wildcard postMessage:** Cross-window messaging without origin verification

Heuristic findings are intentionally labeled as `Potential ...` when the result depends on code context rather than an exact signature.

### Safelist Features
- **Known Safe Hashes:** SHA1/256/MD5 empty string hashes, sequential character sets
- **Test Values:** Common placeholder strings (`xxxxxxxx`, `00000000`) excluded
- **Entropy Validation:** Generic patterns require minimum Shannon entropy of 3.5 to reduce false positives

## Output Format

### Terminal (Colored)
`[target] [PRIORITY] Finding Name : match_content`

### CSV Export
| Target | Priority | Finding Type | Evidence |
| :--- | :--- | :--- | :--- |
| http://site.com/v.js | CRITICAL | AWS Access Key ID | AKIA... |

---
**Maintained by @jjardel-infosec**
