# jsecret v4.0.1 — Release Notes

**Patch — False Positive Reduction for Bundled & Minified JS**  
*Released: April 12, 2026*

---

## What's Fixed in v4.0.1

This patch significantly reduces false positives when scanning third-party and bundled JavaScript files (Salesforce EclairNG, Aura, Sentry SDKs, React UMD bundles, etc.).

### False Positives Suppressed

| Pattern | Root Cause | Fix |
|---|---|---|
| `tr_header_brandlogoalttext` → "Trigger.dev API Key" | Old regex too broad; matched any `tr_word_word` | Regex tightened to require env prefix + 16+ alphanumeric chars; `looksLikeTranslationKey()` filter added |
| ES5 `b.__proto__=a` → "Potential Prototype Pollution" | Old broad pattern matched dot-notation `__proto__` | `prototypePollutionPattern` narrowed to bracket-access only; new `es5InheritancePattern` excludes standard class inheritance |
| Short minified lines (~300 chars) passed minification check | Old threshold was 600 chars | Threshold lowered to 300 chars; semicolon density secondary check added |
| EclairNG.js, aura_prod.js, sentry-wrapper.pack.*.js not recognized as vendor | Missing markers | `vendorSubstringMarkers` extended with `eclair`, `aura_`, `sentry`, `.pack.`, `_prod.js`, `.umd.js`, `.umd.cjs`, `polyfill` |
| Numeric-ID webpack bundles (`function(t,e,n){`) not detected as bundled | Missing pattern | `isLikelyBundledContent` now detects numeric-ID webpack modules and UMD wrappers |

### New FP Regression Tests Added (14 total, all passing)

`TestFP_ES5InheritanceNotPrototypePollution`, `TestFP_VendorDetection_Eclair`, `TestFP_VendorDetection_SentryPack`, `TestFP_VendorDetection_UMD`, `TestFP_MinifiedLineDetection`, `TestFP_BundledContent_NumericWebpack`, `TestFP_BookingTranslationKeysNotTriggerDev`, and more.

### Upgrade from v4.0.0

```bash
go build -ldflags="-s -w" -o jsecret
```

> **Note:** v4.0.0 release binaries have these false positives. Rebuild from source or use the v4.0.1 binary.

---

# jsecret v4.0.0 — Release Notes

**Phase 1 — Confidence Scoring, Line Tracking & Triage UX**  
*Released: April 12, 2026*

---

## Overview

v4.0.0 transforms jsecret findings from static severity labels into **actionable intelligence**. Every finding now carries a dynamic confidence score (0–100), a precise line number, a provider identity, classification tags, Shannon entropy, and optional surrounding code context. Two new source files add ~800 lines of pure-stdlib Go with zero new dependencies.

---

## New Files

### `validators.go` — Provider Format Validation

Validates the structural format of detected secrets before scoring them.

- **`ValidationResult`** type: `{ Valid bool, Provider string, ConfidenceBoost int }`
- **`ValidateFormat(sigName, rawValue)`** — entry point called by the scoring engine
- **~30 provider validators** covering:
  - Cloud: AWS (AKIA prefix + 20-char key, 40-char secret), Google (`AIza` + 35 chars), Azure, Alibaba
  - Payments: Stripe (`sk_live_` / `sk_test_`), Adyen, PayPal
  - VCS / CI: GitHub PAT (`ghp_`, `gho_`, `ghs_`, `ghr_`, `github_pat_`), GitLab, Bitbucket
  - Comms: Slack (`xoxb-`, `xoxp-`), SendGrid (`SG.`), Twilio (SK + 32 hex)
  - AI: OpenAI (`sk-` / `sk-proj-`), Anthropic (`sk-ant-`), HuggingFace, Replicate, Groq, Pinecone
  - Auth: JWT (3-part base64url with valid `alg` header), Bearer tokens
  - Other: DigitalOcean, Heroku, Cloudflare, Terraform, Firebase, PKI/PGP
- **Helper functions**: `trimQuotes`, `extractSecretValue`, `isBase64Charset`, `isAlphanumDashUnderscore`

### `scoring.go` — Confidence Scoring Engine

Computes a 0–100 confidence score and enriches each result with metadata.

#### `computeConfidence(r, content, target) int`

Starts at base **50** and applies additive/subtractive factors:

| Signal | Adjustment |
|---|---|
| Entropy ≥ 4.0 | +15 |
| Entropy ≥ 3.5 | +10 |
| Entropy ≥ 3.0 | +5 |
| Entropy < 2.5 (value len > 4) | −20 |
| Format validation passes | +ConfidenceBoost (provider-specific) |
| Placeholder / dummy value detected | −30 |
| Real, non-placeholder value | +10 |
| Test / mock / `.env.example` file | −15 |
| Production file | +5 |
| Vendor / minified target | −10 |
| Normal source file | +5 |
| Value length ≥ 20 chars | +5 |
| Value length < 8 chars | −10 |
| Auth-related code in surrounding context | +10 |
| **Final score clamped to [0, 100]** | — |

#### Other functions in `scoring.go`

- **`providerMap`** — 100+ signature name → provider string mappings (aws, google, azure, stripe, github, slack, openai, anthropic, …)
- **`classifyTags(r, target)`** — assigns tags: `auth-related`, `third-party`, `internal-api`, `tracking`, `config-leak`, `database`, `crypto`
- **`extractCodeContext(content, lineNumber, radius)`** — returns ±N surrounding lines, truncated to 500 chars
- **`enrichResult(r, content, target, contextLines)`** — orchestrator: sets Provider, Tags, Context, Entropy, Confidence on a Result
- **`extractDomain(target)`** — extracts hostname from URL targets
- **`hasAuthContext(context)`** — checks surrounding code for auth-pattern markers
- **`containsAny(s, substrs…)`** — substring helper

---

## Modified Files

### `nano.go`

- **`Result` struct** extended with 6 new fields:
  - `Line int` — 1-based line number of the match (0 = unknown)
  - `Confidence int` — dynamic confidence score 0–100
  - `Provider string` — identified provider (aws, stripe, github, …)
  - `Tags []string` — classification tags
  - `Entropy float64` — Shannon entropy of matched value
  - `Context string` — surrounding code snippet
- **`scanContextLines int`** — package-level var; set by CLI before worker pool starts, consumed by `matcher()`
- **`matcher()`** — now calls `scanContentWithOptions(target, content, scanContextLines)` instead of `scanContent()`

### `analysis.go`

- **`resultCollector` struct** — gained `content string` and `contextLines int` fields for enrichment pass
- **`scanContent()`** — now delegates to `scanContentWithOptions(target, content, 0)` (backward-compatible)
- **`scanContentWithOptions(target, content, contextLines)`** — new primary scan path; passes content and context radius to the collector
- **`buildLineOffsets(content) []int`** — builds a byte-offset index for O(1)-prep / O(log n) line lookups
- **`offsetToLine(offsets, byteOffset) int`** — binary search mapping byte offset → 1-based line number
- **`collectSignatureFindings`** — switched from `FindAllString` to `FindAllStringIndex`; each match now carries its byte offset, resolved to a line number via `offsetToLine`
- **`addWithLine(name, priority, match, line)`** — creates a `Result` with the `Line` field set, then calls `enrichResult()` for full scoring/tagging
- **`addHeuristicEvidence(name, priority, match)`** — extracts the line number from `"line N: …"` evidence format (produced by `formatLineEvidence`), then calls `addWithLine`
- **`extractLineNumberFromEvidence(evidence)`** — parses `"line N: …"` strings without regex (pure string walking); returns 0 if format doesn't match
- **`add(name, priority, match)`** — kept for backward compatibility; delegates to `addWithLine` with `line = 0`

### `jjsecret.go`

- **Version** bumped to `v4.0.0` (banner + SARIF driver)
- **`JSONResult` struct** extended: `Confidence int`, `Provider string`, `Tags []string`, `Entropy float64`, `Context string`
- **New CLI flags:**
  - `-confidence-min N` — suppress findings below confidence score N (0–100)
  - `-providers aws,github` — include only findings from specified providers
  - `-tags auth-related` — include only findings with any of the specified tags
  - `-context N` — attach N surrounding lines of code to each finding (0–10)
- **Filter pipeline** — confidence, provider, and tag filters applied after severity filter in the output goroutine
- **`writeJSONOutput`** — populates all new `JSONResult` fields; uses `r.Line` directly instead of parsing evidence strings
- **`writeSARIFOutput`** — message now includes `[confidence:N]` prefix; line number sourced from `r.Line` with fallback to evidence parsing
- **`writeMarkdownOutput`** — finding labels include `[provider]` suffix when set; confidence shown as `(confidence: N%)`
- **CSV output** — header updated to `Target, Priority, Finding Type, Evidence, Confidence, Provider, Line`
- **`scanContextLines = contextLines`** — wires the `-context` flag into the package-level var consumed by `matcher()`

### `Makefile`

- `VERSION` bumped from `3.3.0` → `4.0.0`

---

## New Test Files (28 tests — all passing)

### `analysis_ext_test.go`

| Test | What it verifies |
|---|---|
| `TestBuildLineOffsets` | Correct byte offsets for 3-line content |
| `TestBuildLineOffsets_SingleLine` | Single-line edge case |
| `TestBuildLineOffsets_Empty` | Empty string edge case |
| `TestOffsetToLine` | Binary search: 7 offset→line mappings |
| `TestExtractLineNumberFromEvidence` | Parses `"line N: …"` including invalid inputs |
| `TestScanContentWithOptions_LineTracking` | AWS key detected on line 3 with confidence and provider set |
| `TestScanContentWithOptions_Context` | Context string populated when `contextLines > 0` |
| `TestScanContent_BackwardsCompat` | `scanContent()` still works after refactor |

### `scoring_test.go`

| Test | What it verifies |
|---|---|
| `TestComputeConfidence_HighEntropy` | High-entropy AWS key scores ≥ 50 |
| `TestComputeConfidence_PlaceholderLowersScore` | Placeholder value scores ≤ 40 |
| `TestComputeConfidence_TestFilePenalty` | Test file scores lower than production file |
| `TestComputeConfidence_VendorPenalty` | Vendor (`.min.js`) scores lower than source file |
| `TestComputeConfidence_ClampsBounds` | Score always in [0, 100] |
| `TestHasAuthContext` | Detects auth markers in surrounding code |
| `TestClassifyTags` | AWS provider gets `auth-related` + `third-party` tags |
| `TestExtractDomain` | URL vs. file path handling |
| `TestExtractCodeContext` | Returns correct surrounding lines |
| `TestEnrichResult` | Provider and confidence set on a GitHub PAT result |

### `validators_test.go`

| Test | What it verifies |
|---|---|
| `TestValidateFormat_AWS` | `AKIA`-prefixed 20-char key → valid, provider = aws |
| `TestValidateFormat_AWSInvalid` | Short AKIA key → invalid |
| `TestValidateFormat_GoogleAPIKey` | `AIza` + 35 chars → valid |
| `TestValidateFormat_StripeSecretKey` | `sk_live_` key → valid, provider = stripe |
| `TestValidateFormat_GitHubPAT` | `ghp_` token → valid, provider = github |
| `TestValidateFormat_SlackBot` | `xoxb-` token → valid |
| `TestValidateFormat_SendGrid` | `SG.` key → valid |
| `TestValidateFormat_JWT` | Well-formed 3-part JWT → valid, provider = jwt |
| `TestValidateFormat_UnknownSig` | Unknown signature name → invalid, boost = 0 |
| `TestTrimQuotes` | Single, double, backtick, and unquoted values |

---

## Breaking Changes

None. All existing CLI flags, output formats, and scan behavior are fully backward-compatible. The new fields in JSON output are additive (omitempty where applicable).

---

## Upgrade

```bash
git pull
go build -ldflags="-s -w" -o jsecret
./jsecret -d . -confidence-min 60 -json findings.json
```
