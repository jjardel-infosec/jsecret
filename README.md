# jsecret v3.1 — The Ultimate JS Security Scanner

`jsecret` is a blazing-fast, zero-dependency Go tool that detects secrets, credentials, and security vulnerabilities in JavaScript/TypeScript files. It combines **200+ regex signatures** for known token formats with **50+ heuristic checks** for code-level security flaws.

## What's New in v3.1

- **`.jsecretignore` support** — exclude paths with gitignore-style patterns
- **Test/mock file awareness** — suppresses generic noisy signatures on `*.test.js`, `*.spec.js`, `__tests__/`, `__mocks__/`, `fixtures/` etc.
- **Bcrypt/Argon2/Scrypt hash recognition** — properly hashed passwords are no longer flagged as hardcoded credentials
- **Expanded entropy thresholds** — 10 more signatures now have per-pattern entropy gates (Fastly, Splunk, Logz.io, Hetzner, Vultr, etc.)
- **File path / CSS selector FP filter** — values starting with `/`, `./`, `../` or `.class-name` are no longer flagged as secrets
- **52 tests** with CI workflow and cross-compilation Makefile

## Installation

### Via Go
```bash
go install github.com/jjardel-infosec/jsecret@latest
```

### From Source
```bash
git clone https://github.com/jjardel-infosec/jsecret.git
cd jsecret
go build -o jsecret
```

Move to global path (Linux/macOS):
```bash
sudo mv jsecret /usr/local/bin/
```

## Usage

### Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-u` | Single URL to scan | |
| `-f` | File containing list of URLs | |
| `-d` | Directory to scan recursively | |
| `-o` | Save results to TXT file | |
| `-csv` | Save results to CSV file | |
| `-json` | Save results to JSON file | |
| `-sarif` | Save results to SARIF v2.1.0 file | |
| `-min` | Minimum severity: CRITICAL, HIGH, MEDIUM, LOW | all |
| `-proxy` | HTTP/HTTPS proxy URL | |
| `-ext` | Custom file extensions (comma-separated) | `.js,.mjs,.cjs,.jsx,.ts,.tsx,.vue,.svelte` |
| `-t` | Concurrent threads | 50 |
| `-s` | Silent mode (no banner/summary) | false |
| `-strict` | Exit code 1 if CRITICAL/HIGH findings | false |
| `-h` | Show help | |

### Examples

```bash
# Pipe from other tools
cat subdomains.txt | httpx | jsecret

# Recursive local scan with severity filter
jsecret -d ./my_project -min HIGH -strict

# URL scan with JSON output
jsecret -u https://example.com/app.js -json findings.json

# Bulk scan with SARIF output for CI integration
jsecret -f urls.txt -sarif report.sarif -strict

# Custom extensions and proxy
jsecret -d . -ext .js,.ts,.vue -proxy http://127.0.0.1:8080

# CSV report with high concurrency
jsecret -f js_urls.txt -csv report.csv -t 200

# Directory scan, only critical findings
jsecret -d /path/to/project -min CRITICAL -o critical.txt
```

## Detection Coverage

### Signature Pass (200+ patterns)

| Category | Examples | Count |
|----------|---------|-------|
| **Cloud Providers** | AWS (Access Key, Secret, STS, RDS), GCP, Azure, Alibaba, DigitalOcean, Heroku | 20+ |
| **AI/ML Services** | OpenAI, Anthropic, DeepSeek, xAI/Grok, Perplexity, Fireworks, HuggingFace, Groq, Cohere, Mistral, Together, Pinecone, Weaviate, Qdrant, Replicate | 17 |
| **Databases** | MongoDB, PostgreSQL, MySQL, Redis, Elasticsearch, Snowflake, CockroachDB, ClickHouse, Cassandra, Supabase, Firebase, JDBC, RabbitMQ, Memcached, InfluxDB | 20+ |
| **Git Platforms** | GitHub (PAT, Fine-Grained, OAuth), GitLab (PAT, Runner), Bitbucket | 10 |
| **CI/CD** | CircleCI, Travis, Jenkins, Azure DevOps, GitHub Actions, Buildkite, Terraform, Pulumi | 12 |
| **Payments** | Stripe (Secret/Publishable), Square, Braintree, PayPal, Adyen, Coinbase, Plaid | 9 |
| **Communication** | Slack (Token/Webhook), Twilio, SendGrid, Mailgun, Telegram, Discord, Postmark, Mailchimp, SparkPost, Vonage, Pusher, Ably | 15+ |
| **Modern SaaS** | Supabase, Vercel, Clerk, PlanetScale, Neon, Railway, Render, Fly.io, Deno Deploy, Expo, Arcjet, Trigger.dev, Resend, Infisical, Doppler | 20+ |
| **Secrets/Vault** | HashiCorp Vault, 1Password Connect, Doppler, Kubernetes Secrets | 8 |
| **Observability** | Datadog, Sentry, New Relic, Bugsnag, Grafana, Splunk HEC, Dynatrace, Honeycomb, LaunchDarkly, PagerDuty, Elastic APM, Logz.io | 15+ |
| **DevOps/Infra** | Scaleway, Hetzner, Linode, Vultr, Fastly, Cloudflare Workers KV | 10+ |
| **Keys & Certs** | RSA/DSA/EC/OPENSSH/PGP Private Keys, PEM Certificates | 3 |
| **Generic** | JWT, Bearer Tokens, Base64 High Entropy, Password Assignments, Basic Auth | 15+ |

### Heuristic Pass (50+ detections)

| Category | Detections |
|----------|------------|
| **Injection** | SQL Injection, NoSQL Injection, Command Injection, Template Injection |
| **XSS** | DOM XSS (innerHTML, outerHTML, document.write, dangerouslySetInnerHTML), HTML Injection Sinks |
| **SSRF/Redirect** | Untrusted Outbound Requests, Open Redirect |
| **Crypto** | Weak Cryptography (MD5, SHA1, DES, RC4, ECB), Predictable Token Generation (Math.random) |
| **Auth/Session** | JWT Weak Algorithm, Hardcoded JWT Secret, Hardcoded Credentials, Web Storage Sensitive Data |
| **CORS** | Wildcard Origin + Credentials, Origin Reflection without validation |
| **Cookies** | Missing Secure/HttpOnly flags |
| **Prototype** | Prototype Pollution, Object Merge with User Input, Mass Assignment |
| **Config** | Debug Mode in Production, GraphQL Introspection Enabled, Exposed Source Maps |
| **Leaks** | Exposed Stack Trace, NPM Config Leak (_auth/_authToken) |
| **Privacy** | Path Traversal, Insecure Deserialization, TLS Validation Disabled |
| **ReDoS** | Nested quantifiers `(a+)+`, triple greedy `.*.*.*`, star-star overlap, nested repetition |
| **postMessage** | Wildcard target origin |

### False Positive Prevention

- **67+ placeholder patterns** (changeme, your_key_here, ${TOKEN}, {{SECRET}}, etc.)
- **Per-pattern entropy thresholds** — 25+ signatures require minimum Shannon entropy
- **Test/mock file suppression** — generic signatures (API Key Generic, Session ID, etc.) suppressed in test/spec/fixture files
- **Bcrypt/Argon2/Scrypt detection** — properly hashed passwords are never flagged
- **Minified content skip** — noise-prone signatures suppressed on minified lines
- **Vendor/bundle detection** — skips jQuery, React, webpack bundles, hex-named chunks
- **Known safe strings** — SHA1/256/MD5 empty hashes, Base64 charsets, test values
- **Code reference filter** — skips `process.env.*`, `config.*` variable dereferences
- **File path filter** — skips values that are file paths (`/usr/...`, `./...`, `../...`)
- **CSS class filter** — skips values that look like CSS selectors (`.btn-primary`)
- **Repeated character filter** — skips strings with >60% same character
- **`.jsecretignore`** — user-defined exclusion patterns (see below)

### `.jsecretignore`

Create a `.jsecretignore` file in the scan root directory. Uses glob-style patterns:

```
# Skip test directories
tests/
__tests__/
__mocks__/

# Skip specific files
config.example.js
*.test.js
*.spec.ts

# Skip generated code
**/generated/**
dist/
build/
```

## Output Formats

### TXT (default terminal)
```
[https://example.com/app.js] [CRITICAL] AWS Access Key ID : AKIAIOSFODNN7EXAMPLE
```

### JSON (`-json`)
```json
[
  {
    "target": "https://example.com/app.js",
    "priority": "CRITICAL",
    "finding": "AWS Access Key ID",
    "evidence": "AKIAIOSFODNN7EXAMPLE",
    "category": "signature"
  }
]
```

### SARIF v2.1.0 (`-sarif`)
Compatible with GitHub Code Scanning, VS Code SARIF Viewer, and other SARIF-aware tools.

### CSV (`-csv`)
| Target | Priority | Finding Type | Evidence |
|--------|----------|-------------|----------|
| app.js | CRITICAL | AWS Access Key ID | AKIA... |

## CI/CD Integration

Use `-strict` to fail pipelines when CRITICAL or HIGH findings are detected:

```bash
jsecret -d ./src -min HIGH -strict -sarif results.sarif
```

Exit code `1` = findings found. Upload `results.sarif` to GitHub Code Scanning or your SIEM.

## Architecture

- **Zero external dependencies** — stdlib-only Go
- **Worker pool** — configurable concurrency (default 50 workers)
- **Two-pass analysis** — regex signatures + heuristic code analysis
- **Content dedup** — MD5-based `sync.Map` prevents re-scanning identical content
- **Connection pooling** — 200 idle connections, 20 per host
- **Body limit** — 10MB max to prevent OOM on large files
- **Source map resolution** — follows `sourceMappingURL` to scan original sources
- **Prefix pre-filtering** — static substring check before regex evaluation

---
**Maintained by @jjardel-infosec**
