# jsecret

> Also available in: [Português (pt-BR)](README.pt-br.md)

`jsecret` is a zero-dependency static scanner for JavaScript and TypeScript assets. It is built to find exposed secrets, risky client-side patterns, and bug bounty-relevant findings in source code, compiled bundles, remote scripts, and exposed source maps.

It combines a broad provider-aware signature catalog with a growing set of context-aware heuristics, then spends real effort suppressing the false positives that normally make scanners noisy in real projects.

Current release: `v3.3.0`

## Why jsecret

- built for real JS and TS targets, not only toy examples
- useful for bug bounty, appsec reviews, CI gates, and client-side recon
- deterministic TXT, CSV, JSON, SARIF, and Markdown outputs
- tuned to reduce noise from tests, fixtures, placeholders, env references, bundles, and generated code
- stdlib-only Go implementation with no third-party runtime dependencies
- backed by `128` automated tests, including CLI integration coverage

## What It Detects

### Signature detections

`jsecret` ships with `200+` signature patterns across categories such as:

- cloud and infrastructure: AWS, GCP, Azure, Alibaba, DigitalOcean, Heroku, Scaleway, Hetzner, Linode, Vultr, Fastly
- AI, LLM, and vector providers: OpenAI, Anthropic, DeepSeek, xAI, Perplexity, Fireworks, Groq, Cohere, Mistral, Together, Pinecone, Weaviate, Qdrant, Replicate
- databases and queues: MongoDB, PostgreSQL, MySQL, Redis, Elasticsearch, Snowflake, CockroachDB, ClickHouse, Cassandra, RabbitMQ, Memcached, InfluxDB
- source control and CI/CD: GitHub, GitLab, Bitbucket, CircleCI, Travis, Jenkins, Azure DevOps, GitHub Actions, Buildkite, Terraform, Pulumi
- payment and communications: Stripe, Square, Braintree, PayPal, Adyen, Coinbase, Plaid, Slack, Twilio, SendGrid, Mailgun, Telegram, Discord, Postmark, Mailchimp, SparkPost, Vonage, Pusher, Ably
- SaaS and deployment platforms: Vercel, Clerk, PlanetScale, Neon, Railway, Render, Fly.io, Deno Deploy, Expo, Arcjet, Trigger.dev, Resend, Infisical, Doppler
- keys and certificates: private key blocks, PEM material, generic high-signal auth material, JWTs, bearer tokens, and more

### Heuristic detections

`jsecret` also detects `50+` risky code patterns, including:

- DOM XSS and unsafe HTML sinks
- SQL, NoSQL, command, and template injection patterns
- SSRF, open redirect, and unsafe outbound request flows
- weak crypto, insecure token generation, and disabled TLS validation
- hardcoded credentials and JWT misuse
- permissive CORS and wildcard postMessage usage
- insecure cookie settings and web storage abuse
- prototype pollution, mass assignment, and unsafe regex construction
- GraphQL introspection exposure and source map exposure
- exposed stack traces and npm auth leakage

## False Positive Strategy

The project is explicitly optimized for signal quality. It does not just add patterns; it also removes bad ones.

Key controls include:

- placeholder and example suppression for values such as `changeme`, `your_key_here`, `${TOKEN}`, and `{{SECRET}}`
- per-pattern entropy thresholds for noisy token classes
- test, spec, fixture, mock, and env-example awareness
- bcrypt, Argon2, and scrypt hash recognition
- minified-content suppression for selected noisy signatures
- vendor and generated bundle suppression
- safe-value suppression for empty hashes, charsets, and common example material
- code-reference suppression for values such as `process.env.*` and `config.*`
- path-like and CSS-selector-like value suppression
- targeted heuristic refinements for React sanitization, webhook handlers, debug checks, CORS wildcard handling, GraphQL introspection, error leakage, header taint, source maps, and user-controlled regexes

## Quick Start

### Install

With Go:

```bash
go install github.com/jjardel-infosec/jsecret@latest
```

From source:

```bash
git clone https://github.com/jjardel-infosec/jsecret.git
cd jsecret
go build -o jsecret
```

Optional install path on Linux or macOS:

```bash
sudo mv jsecret /usr/local/bin/
```

### First scan

Scan a local project:

```bash
jsecret -d ./frontend
```

Scan remote assets from stdin:

```bash
cat urls.txt | jsecret
```

Generate a CI-friendly SARIF report and fail on blocking findings:

```bash
jsecret -d . -min HIGH -strict -sarif results.sarif
```

## Scan Modes

| Mode | Flag | Input |
|------|------|-------|
| Single target | `-u` | one remote script URL |
| Target list file | `-f` | one target per line |
| Recursive directory scan | `-d` | local directory |
| Stdin mode | none | one target per line from stdin |

Directory mode scans these extensions by default:

` .js, .mjs, .cjs, .jsx, .ts, .tsx, .vue, .svelte `

Use `-ext` to override the set.

## CLI Reference

| Flag | Description | Default |
|------|-------------|---------|
| `-u` | Single URL to scan | |
| `-f` | File containing a list of targets | |
| `-d` | Directory to scan recursively | |
| `-o` | Save results to TXT file | |
| `-csv` | Save results to CSV file | |
| `-json` | Save results to JSON file | |
| `-sarif` | Save results to SARIF v2.1.0 file | |
| `-md` | Save results to Markdown report | |
| `-min` | Minimum severity: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` | all |
| `-proxy` | HTTP/HTTPS proxy URL | |
| `-k` | Skip TLS certificate verification for HTTPS requests | `false` |
| `-ext` | Custom file extensions for directory scans | `.js,.mjs,.cjs,.jsx,.ts,.tsx,.vue,.svelte` |
| `-t` | Concurrent threads | `50` |
| `-s` | Silent mode: suppress banner, summary, and fetch warnings | `false` |
| `-strict` | Exit with code `1` if `CRITICAL` or `HIGH` findings exist | `false` |
| `-h` | Show help output | |

## Practical Examples

Scan a local application and only keep high-signal findings:

```bash
jsecret -d ./webapp -min HIGH
```

Write a Markdown report for manual review:

```bash
jsecret -d ./assets -md report.md
```

Scan a file containing collected script URLs:

```bash
jsecret -f js_urls.txt -json findings.json
```

Use a proxy during recon:

```bash
jsecret -f urls.txt -proxy http://127.0.0.1:8080 -json proxy-scan.json
```

Scan a self-signed staging target:

```bash
jsecret -u https://staging.example.local/app.js -k
```

Scan custom file types in a repo:

```bash
jsecret -d . -ext .js,.ts,.scan,.bundle
```

Use stdin mode in a pipeline:

```bash
cat subdomains.txt | httpx | jsecret -min HIGH
```

## Output Formats

### TXT

Default console-style output, also available through `-o`.

```text
[https://example.com/app.js] [CRITICAL] AWS Access Key ID : AKIAIOSFODNN7EXAMPLE
```

### CSV

Useful for spreadsheets and quick triage exports.

Columns:

- `Target`
- `Priority`
- `Finding Type`
- `Evidence`

### JSON

Structured output for custom automation.

```json
[
  {
    "target": "https://example.com/app.js",
    "priority": "CRITICAL",
    "finding": "AWS Access Key ID",
    "evidence": "AKIAIOSFODNN7EXAMPLE",
    "category": "signature",
    "line": 42
  }
]
```

Notes:

- `category` is `signature` or `heuristic`
- `line` is populated when line-aware evidence exists, typically for heuristics

### SARIF

Use `-sarif` for GitHub Code Scanning, VS Code SARIF viewers, or other SARIF-aware tooling.

The SARIF output includes:

- rule metadata
- normalized severities
- artifact locations
- line regions when available

### Markdown

Use `-md` when you want a readable report grouped by severity and target. This is useful for bug bounty submissions, review handoffs, and manual triage.

## Severity Model

`jsecret` emits four severities:

- `CRITICAL`: highest-confidence secrets or immediately dangerous exposures
- `HIGH`: likely exploitable or high-risk findings
- `MEDIUM`: relevant security weakness that needs review
- `LOW`: informative finding that may support broader analysis

Use `-min` to suppress lower-priority output and `-strict` to fail when blocking findings are present.

## Ignoring Files with .jsecretignore

Create a `.jsecretignore` file in the scan root to exclude known-noisy or intentionally ignored content.

Supported matching behavior:

- basename globs such as `*.test.js`
- nested directory patterns such as `generated/`
- root-anchored paths such as `/build/`
- recursive patterns such as `**/generated/**`

Example:

```text
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
/build/
```

Important behavior:

- `dist/` and `build/` are scanned by default
- hidden directories, `.git`, and `node_modules` are skipped automatically
- use `.jsecretignore` only when you explicitly want to suppress content

## CI/CD Integration

Use `-strict` to fail a pipeline when `CRITICAL` or `HIGH` findings are present.

```bash
jsecret -d ./src -min HIGH -strict -sarif results.sarif
```

Recommended pre-release workflow:

```bash
make verify
jsecret -d . -min HIGH -strict -sarif results.sarif
```

Example GitHub Actions step:

```yaml
- name: Verify repository
  run: make verify

- name: Scan JavaScript assets
  run: ./jsecret -d . -min HIGH -strict -sarif results.sarif
```

## Exit Codes

- `0`: scan completed without blocking findings, or help output was shown
- `1`: invalid CLI input, output or proxy setup failure, or `-strict` found `CRITICAL` or `HIGH` results

## Troubleshooting

No findings from compiled output:
Check `.jsecretignore`. `dist/` and `build/` are included by default now.

Remote scan fails with TLS errors:
Use `-k` only when you intentionally need to scan a self-signed or intercepted endpoint.

Remote scan prints warnings:
Fetch warnings are deduplicated in normal mode and suppressed entirely with `-s`.

Custom file types are skipped:
Pass `-ext` with a comma-separated list such as `.js,.ts,.scan`.

Need a single validation command before pushing changes:
Use `make verify`.

## Architecture

Core design choices:

- zero external dependencies
- two-pass analysis: signatures plus heuristics
- SHA-256 content deduplication to skip repeated assets
- connection pooling with keep-alive reuse
- `10 MB` response body limit for remote fetches
- source map resolution when exposed assets reference them
- prefix pre-filtering before expensive regex evaluation
- deterministic result ordering across JSON, SARIF, and Markdown outputs

At a high level:

- [jjsecret.go](jjsecret.go) handles CLI, input orchestration, summaries, and outputs
- [analysis.go](analysis.go) handles signatures, heuristics, normalization, and false-positive suppression
- [signatures.go](signatures.go) contains the signature catalog
- [nano.go](nano.go) handles fetching, transport setup, hashing, diagnostics, and source maps

## Limitations

`jsecret` is a static scanner. It does not execute JavaScript, emulate browser state, or prove exploitability.

That means:

- a finding may still need human validation
- remote coverage depends on what the target actually serves
- source map analysis only happens when the source map is referenced and retrievable
- directory scans only consider the configured extensions

These limits are intentional: the tool is built to be fast, portable, and easy to trust in CI and recon pipelines.

## Development

Requirements:

- Go `1.21+`

Common commands:

```bash
make verify
make build
make test
make bench
make cover
make cross
```

Direct Go commands:

```bash
go test ./...
go test -run=^$ -bench=. -benchmem ./...
```

## Ethical and Responsible Use

`jsecret` and `recon-js.sh` were developed exclusively to support legitimate information security activities, including authorized penetration tests, bug bounty programs, technical audits, and academic research.

Use must strictly follow these principles:

**Prior authorization**
The tools must only be used against assets, systems, or environments for which formal, documented authorization exists.

**Legal and regulatory compliance**
The user is fully responsible for ensuring that use complies with all applicable laws, including data protection and cybercrime legislation.

**Respect for confidentiality and integrity**
Accessing, collecting, storing, or disclosing sensitive data without a justified technical need and explicit authorization is prohibited.

**Proportional and responsible use**
Vulnerability exploitation must be limited to what is necessary for technical validation, avoiding service disruption, operational impact, or any form of damage.

**Accountability**
Misuse of these tools may result in civil, administrative, and criminal sanctions, and is the sole responsibility of the user.

The purpose of these tools is to contribute to stronger system security and user privacy, promoting ethical and responsible practices in the offensive security ecosystem.

---

## License

This project is distributed under the license in [LICENSE](LICENSE).

---

Maintained by `@jjardel-infosec`
