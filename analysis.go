package main

import (
	"fmt"
	"math"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

type resultCollector struct {
	target       string
	content      string
	contextLines int
	seen         map[string]struct{}
	results      []Result
}

// knownSafeStrings contains hashes/strings that commonly appear in code but are not secrets
var knownSafeStrings = map[string]bool{
	// SHA1 empty string
	"da39a3ee5e6b4b0d3255bfef95601890afd80709": true,
	// SHA256 empty string
	"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": true,
	// MD5 empty string
	"d41d8cd98f00b204e9800998ecf8427e": true,
	// SHA256 test vectors
	"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad": true,
	"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08": true,
	// Sequential alphabets (common in charset definitions)
	"0123456789abcdefghijklmnopqrstuv":                                  true,
	"abcdefghijklmnopqrstuvwxyz012345":                                  true,
	"0123456789abcdef":                                                  true,
	"0123456789abcdefghijklmnopqrstuvwxyz":                              true,
	"abcdefghijklmnopqrstuvwxyz":                                        true,
	"abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz0123456789+/":  true,
	"abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz0123456789+/=": true,
	"abcdefghijklmnopqrstuvwxyz0123456789":                              true,
	// Common test/example values
	"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx":         true,
	"00000000000000000000000000000000":         true,
	"11111111111111111111111111111111":         true,
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": true,
	"test1234567890test1234567890test":         true,
	"sample_key_do_not_use":                    true,
	// React / Angular / Next.js framework strings
	"__react_internal_instance$": true,
	"__next_data__":              true,
	"__zone_symbol__":            true,
}

// lowEntropyPatterns require minimum entropy for matches
var lowEntropyPatterns = map[string]float64{
	"GitHub OAuth App Secret":      3.5,
	"Loggly Token":                 3.5,
	"Base64 High Entropy String":   4.2,
	"Mistral API Key":              3.5,
	"Together AI Key":              3.5,
	"Algolia API Key":              3.5,
	"API Key in Variable":          3.2,
	"Secret in Variable":           3.2,
	"API Key Generic Detector":     3.5,
	"Session ID":                   3.0,
	"CSRF Token":                   3.0,
	"Cohere API Key":               3.5,
	"Weaviate API Key":             3.5,
	"Qdrant API Key":               3.2,
	"Bugsnag API Key":              3.5,
	"Datadog API Key":              3.5,
	"Fastly API Token":             3.5,
	"Elastic APM Secret Token":     3.5,
	"Splunk HEC Token":             3.5,
	"Logz.io Token":                3.5,
	"Vultr API Key":                3.5,
	"Linode Personal Access Token": 3.5,
	"Hetzner API Token":            3.5,
	"PayPal Client Secret":         3.5,
	"Adyen API Key":                3.5,
	"Password Assignment":          3.0,
}

// suppressedOnVendor lists sigs suppressed on vendor/library files to reduce noise
var suppressedOnVendor = map[string]bool{
	"Base64 High Entropy String": true,
	"Localhost Reference":        true,
	"Private IP (Internal)":      true,
	"Dev/Stage URL":              true,
	"Basic Auth String":          true,
	"OAuth Client Secret":        true,
	"OAuth Client ID":            true,
	"Helm Secret Value":          true,
	"Bearer Token Generic":       true,
	"Cookie Name Generic":        true,
	"API Key Generic Detector":   true,
	"Secret in Variable":         true,
	"API Key in Variable":        true,
	"Session ID":                 true,
	"CSRF Token":                 true,
	// Frontend router definitions are not exposed server paths
	"Admin Panel Path":    true,
	"Internal/Debug Path": true,
}

// skipOnMinified lists sigs suppressed on minified lines to reduce noise
var skipOnMinified = map[string]bool{
	"Private IP (Internal)":      true,
	"Localhost Reference":        true,
	"Dev/Stage URL":              true,
	"AWS S3 Bucket URL":          true,
	"Session ID":                 true,
	"Cookie Name Generic":        true,
	"CSRF Token":                 true,
	"Bearer Token Generic":       true,
	"API Key Generic Detector":   true,
	"Loggly Token":               true,
	"JJARDEL (Legacy)":           true,
	"SEGREDOS WAR (Legacy)":      true,
	"Base64 High Entropy String": true,
}

// isLikelyCodeReference checks if a matched value looks like a variable dereference, not a literal secret
func isLikelyCodeReference(value string) bool {
	v := strings.TrimSpace(value)
	// process.env.SOMETHING
	if strings.HasPrefix(v, "process.env.") {
		return true
	}
	// import.meta.env.VITE_* (Vite/Deno)
	if strings.HasPrefix(v, "import.meta.env.") {
		return true
	}
	// Deno.env.get("..."), os.Getenv("..."), os.environ["..."]
	if strings.Contains(v, "Deno.env.") || strings.Contains(v, "os.Getenv") || strings.Contains(v, "os.environ") {
		return true
	}
	// config.get("..."), conf.get(), settings.get()
	if matched, _ := regexp.MatchString(`(?i)^(?:config|conf|settings|env|cfg)\b\.`, v); matched {
		return true
	}
	// config.something or settings.something — dotted object references
	if strings.Contains(v, ".") && !strings.Contains(v, " ") && !strings.Contains(v, "/") && len(v) < 60 {
		// Skip values with @ (emails) or that look like hostnames/filenames
		if strings.Contains(v, "@") {
			return false
		}
		parts := strings.SplitN(v, ".", 2)
		if len(parts) == 2 && len(parts[0]) > 0 && parts[0][0] >= 'a' && parts[0][0] <= 'z' {
			// If the value has 2+ dots, verify it doesn't look like a hostname
			if strings.Count(v, ".") >= 2 && looksLikeHostname(v) {
				return false
			}
			// If the last segment looks like a file extension or TLD, skip
			lastDot := strings.LastIndex(v, ".")
			suffix := v[lastDot+1:]
			if looksLikeTLDOrExtension(suffix) {
				return false
			}
			return true
		}
	}
	return false
}

// isLikelyUUID returns true if the value looks like a UUID (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)
var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// looksLikeHostname returns true if the value appears to be a hostname (all lowercase alphanumeric with dots/hyphens)
func looksLikeHostname(v string) bool {
	for _, c := range v {
		if c != '.' && c != '-' && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

// looksLikeTLDOrExtension returns true if suffix looks like a TLD or file extension, not a JS property
func looksLikeTLDOrExtension(suffix string) bool {
	known := map[string]bool{
		"com": true, "net": true, "org": true, "io": true, "dev": true, "app": true,
		"co": true, "me": true, "info": true, "biz": true, "us": true, "uk": true,
		"internal": true, "local": true, "corp": true, "intra": true, "private": true,
		"json": true, "xml": true, "yaml": true, "yml": true, "html": true, "js": true,
		"ts": true, "css": true, "csv": true, "txt": true, "log": true, "env": true,
		"conf": true, "cfg": true, "ini": true, "toml": true,
	}
	return known[strings.ToLower(suffix)]
}

func isLikelyUUID(value string) bool {
	trimmed := trimLiteralValue(value)
	return uuidPattern.MatchString(trimmed)
}

// isPureNumeric returns true if the value contains only digits (not a real secret)
func isPureNumeric(value string) bool {
	trimmed := trimLiteralValue(value)
	if len(trimmed) < 8 {
		return false
	}
	for _, r := range trimmed {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func trimLiteralValue(value string) string {
	return strings.Trim(strings.TrimSpace(value), `'"`+"`")
}

// looksLikeTranslationKey returns true if value looks like an i18n key (tr_word_word_word)
// rather than a real API key (tr_dev_A8f7BcD32e91K4m6N)
func looksLikeTranslationKey(value string) bool {
	v := trimLiteralValue(value)
	lower := strings.ToLower(v)
	stripped := strings.TrimPrefix(lower, "tr_")
	if stripped == lower {
		return false
	}
	// Real API keys contain uppercase letters; translation keys don't
	origStripped := v[3:] // skip "tr_" or "TR_" etc.
	for _, r := range origStripped {
		if r >= 'A' && r <= 'Z' {
			return false
		}
	}
	parts := strings.Split(stripped, "_")
	if len(parts) < 2 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			continue
		}
		for _, r := range p {
			if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')) {
				return false
			}
		}
	}
	return true
}

func normalizeMatchedValue(match string) string {
	if quoted := extractQuotedValue(match); quoted != "" {
		return trimLiteralValue(quoted)
	}

	trimmed := trimLiteralValue(match)
	for _, separator := range []string{"=", ":"} {
		idx := strings.LastIndex(trimmed, separator)
		if idx == -1 || idx >= len(trimmed)-1 {
			continue
		}
		candidate := trimLiteralValue(trimmed[idx+1:])
		if candidate != "" {
			return candidate
		}
	}

	return trimmed
}

func isLikelyPlaceholderValue(value string) bool {
	lower := strings.ToLower(trimLiteralValue(value))
	if lower == "" {
		return false
	}

	placeholders := []string{
		"example", "sample", "placeholder", "dummy", "test", "mock",
		"changeme", "replace_me", "replace-me", "your_", "your-",
		"todo", "tbd", "notset", "unset", "default",
	}

	for _, marker := range placeholders {
		if strings.Contains(lower, marker) {
			return true
		}
	}

	return false
}

// extractQuotedValue extracts the last quoted string from a match (e.g. password = "value" → value)
func extractQuotedValue(match string) string {
	// Find the last quoted value in the match
	for _, q := range []byte{'"', '\''} {
		last := strings.LastIndexByte(match, q)
		if last <= 0 {
			continue
		}
		prev := strings.LastIndexByte(match[:last], q)
		if prev >= 0 && prev < last-1 {
			return match[prev+1 : last]
		}
	}
	return ""
}

// hasRepeatedChars returns true if >60% of chars are the same (e.g. "aaaaaaa...")
func hasRepeatedChars(s string) bool {
	if len(s) < 8 {
		return false
	}
	counts := make(map[byte]int)
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	for _, count := range counts {
		if float64(count)/float64(len(s)) > 0.6 {
			return true
		}
	}
	return false
}

var (
	suspiciousAssignmentPattern = regexp.MustCompile("(?i)\\b(?:const|let|var)?\\s*([A-Za-z_$][\\w$]*(?:secret|token|password|passwd|api[_-]?key|apikey|auth|jwt|clientsecret|accesskey|accesstoken|privatekey)[A-Za-z0-9_$]*)\\b\\s*[:=]\\s*(?:'([^'\\n]{8,})'|\"([^\"\\n]{8,})\"|`([^`\\n]{8,})`)")
	xssSinkPattern              = regexp.MustCompile(`(?i)(?:\.innerHTML\s*=|\.outerHTML\s*=|insertAdjacentHTML\s*\(|document\.write\s*\(|\.srcdoc\s*=|dangerouslySetInnerHTML\s*[:=])`)
	taintSourcePattern          = regexp.MustCompile(`(?i)(?:window\.)?location\.(?:hash|search|href)|document\.(?:URL|documentURI|referrer)|window\.name|(?:event|message)\.data|(?:localStorage|sessionStorage)\.getItem\s*\(|req\.(?:query|params|body|headers)|request\.(?:query|params|body|headers)|ctx\.(?:query|params|request\.body)|router\.query|searchParams\.get\s*\(|URLSearchParams\s*\(|process\.argv`)
	sqlExecutionPattern         = regexp.MustCompile(`(?i)\b(?:query|execute|sequelize\.query|knex\.raw|pool\.query|client\.query)\s*\(`)
	sqlKeywordPattern           = regexp.MustCompile(`(?i)\b(?:select|insert|update|delete|from|where|union)\b`)
	dynamicDataPattern          = regexp.MustCompile(`(?:\+|\$\{)`)
	dynamicCodePattern          = regexp.MustCompile("(?i)\\b(?:eval\\s*\\(|new\\s+Function\\s*\\(|set(?:Timeout|Interval)\\s*\\(\\s*['\"`]|vm\\.runIn(?:New|This)Context\\s*\\()")
	commandExecPattern          = regexp.MustCompile(`(?i)(?:^|[^.$\w])(?:child_process\.)?(?:exec|execSync|spawn|spawnSync|fork)\s*\(`)
	shellTruePattern            = regexp.MustCompile(`(?i)shell\s*:\s*true`)
	weakCryptoPattern           = regexp.MustCompile(`(?i)(?:createHash\s*\(\s*['"](?:md5|sha1)['"]|CryptoJS\.(?:MD5|SHA1)\s*\(|\bmd5\s*\(|\bsha1\s*\(|createCipher\s*\(|createDecipher\s*\(|\bDES\b|\bRC4\b|\bECB\b)`)
	insecureTLSPattern          = regexp.MustCompile(`(?i)(?:rejectUnauthorized\s*:\s*false|strictSSL\s*:\s*false|process\.env\.NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0['"]?|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0['"]?)`)
	insecureStoragePattern      = regexp.MustCompile(`(?i)(?:localStorage|sessionStorage)\.setItem\s*\(`)
	storageSetItemPattern       = regexp.MustCompile(`(?i)(?:localStorage|sessionStorage)\.setItem\s*\(\s*([^,\)\n]+)`)
	documentCookiePattern       = regexp.MustCompile(`(?i)document\.cookie\s*=`)
	postMessageWildcardPattern  = regexp.MustCompile(`(?i)\bpostMessage\s*\([^,]+,\s*['"]\*['"]\s*\)`)
	requestPattern              = regexp.MustCompile(`(?i)(?:fetch|axios(?:\.(?:get|post|put|patch|delete|request))?|got(?:\.(?:get|post|put|delete))?|request|https?\.get)\s*\(`)
	redirectPattern             = regexp.MustCompile(`(?i)(?:res\.redirect\s*\(|(?:window\.)?location(?:\.href)?\s*=)`)
	fileAccessPattern           = regexp.MustCompile(`(?i)(?:fs\.(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync|open|openSync)|res\.sendFile)\s*\(`)
	mathRandomPattern           = regexp.MustCompile(`(?i)Math\.random\s*\(`)
	sensitiveNamePattern        = regexp.MustCompile(`(?i)(?:token|secret|session|nonce|csrf|otp|auth|password|reset|invite|api[_-]?key|code_verifier|state)`)
	sanitizerPattern            = regexp.MustCompile(`(?i)(?:DOMPurify\.sanitize|sanitizeHtml|xssFilters|escapeHtml|he\.encode)`)
	corsWildcardPattern         = regexp.MustCompile(`(?is)cors\s*\(\s*{[^}]*origin\s*:\s*['"]\*['"][^}]*credentials\s*:\s*true`)
	manualCorsPattern           = regexp.MustCompile(`(?is)Access-Control-Allow-Origin['"]?\s*[:=,]\s*['"]\*['"][\s\S]{0,200}Access-Control-Allow-Credentials['"]?\s*[:=,]\s*true`)
	// Security heuristics
	// Prototype pollution: bracket-access __proto__, or setPrototypeOf (not standard inheritance)
	prototypePollutionPattern = regexp.MustCompile(`(?i)(?:\[['"]__proto__['"]\]\s*=|Object\.setPrototypeOf\s*\(|Reflect\.setPrototypeOf\s*\()`)
	// ES5 standard inheritance: b.__proto__ = a; b.prototype = Object.create(a.prototype); .prototype.constructor = b
	es5InheritancePattern      = regexp.MustCompile(`(?:__proto__\s*=\s*[a-zA-Z_$][a-zA-Z0-9_$]*\s*[;,)\]}]|\.prototype\s*=\s*Object\.create\s*\(|\.prototype\.constructor\s*=\s*[a-zA-Z_$])`)
	templateInjectionPattern   = regexp.MustCompile(`(?i)(?:\{\{\s*[^}]*\s*\}\}|<%[^%]*%>|\$\{[^}]*\}.*render|nunjucks\.render|ejs\.render|pug\.render|handlebars\.compile|Mustache\.render)`)
	insecureDeserializePattern = regexp.MustCompile(`(?i)(?:unserialize\s*\(|pickle\.loads?\s*\(|yaml\.(?:load|unsafe_load)\s*\(|JSON\.parse\s*\([^)]*(?:localStorage|sessionStorage|req\.|request\.)|deserialize\s*\([^)]*(?:body|params|query))`)
	objectMergePattern         = regexp.MustCompile(`(?i)(?:Object\.assign\s*\([^,]*,\s*(?:req\.|request\.|params|body|query)|_\.merge\s*\(|lodash\.merge\s*\(|\$\.extend\s*\(true|deepmerge\s*\()`)
	massAssignmentPattern      = regexp.MustCompile(`(?i)(?:\.update\s*\(\s*(?:req\.body|params)|\.create\s*\(\s*(?:req\.body|params)|\bspread\s*\(\s*(?:req\.|props))`)
	jwtWeakAlgPattern          = regexp.MustCompile(`(?i)(?:algorithm\s*[:=]\s*['"](?:none|HS256)['"]|alg\s*[:=]\s*['"]none['"])`)
	hardcodedJWTSecretPattern  = regexp.MustCompile(`(?i)(?:jwt\.sign|jwt\.verify)\s*\([^)]*['"](secret|password|key123|test|sample|example|changeme)['"]\s*\)`)

	// Vendor filename patterns (pre-compiled for hot path)
	vendorHexFilePattern     = regexp.MustCompile(`^[a-f0-9]{8,}\.js$`)
	vendorHexDashFilePattern = regexp.MustCompile(`^[a-f0-9]+-[a-f0-9]+\.js$`)
	// Content-hashed webpack bundles: name.HASH.js or 1234.HASH.js (dot-separated hash)
	vendorHashedDotPattern = regexp.MustCompile(`\.[a-f0-9]{8,}\.js$`)

	// Phase 5: New heuristic detection patterns
	corsOriginReflectPattern = regexp.MustCompile(`(?i)(?:Access-Control-Allow-Origin['"]?\s*[:=,]\s*(?:req\.headers\.origin|request\.headers\.origin|origin)|origin\s*:\s*(?:true|req\.headers\.origin))`)

	// ReDoS detection: extract JS regex literals and new RegExp() calls
	jsRegexLiteralPattern = regexp.MustCompile(`(?:^|[=(:,;!&|?+\-~^])\s*/([^/\n]{4,})/[gimsuy]*`)
	newRegExpPattern      = regexp.MustCompile(`(?i)new\s+RegExp\s*\(\s*['"]([^'"\n]{4,})['"]`)
	// Dangerous quantifier patterns that cause catastrophic backtracking
	redosNestedQuantifier       = regexp.MustCompile(`\([^)]*[+*][^)]*\)[+*]`)                                                              // (a+)+ or (a*)*
	redosOverlappingAlts        = regexp.MustCompile(`\((?:[^|)]+\|){2,}[^)]*\)[+*]`)                                                       // (a|b|c)+ with 3+ alts
	redosQuantifiedOverlap      = regexp.MustCompile(`[.\\][*+].*[.\\][*+].*[.\\][*+]`)                                                     // .*.*.*  triple greedy
	redosNestedRepetition       = regexp.MustCompile(`\([^)]*\{\d+,?\d*\}[^)]*\)[+*{]`)                                                     // (a{1,})+
	redosStarStar               = regexp.MustCompile(`(?:\.[*+]|\[[^\]]+\][*+]|\\[wdsSbB][*+])\s*(?:\.[*+]|\[[^\]]+\][*+]|\\[wdsSbB][*+])`) // .*.+ patterns
	insecureCookiePattern       = regexp.MustCompile(`(?i)(?:set-cookie|res\.cookie|response\.cookie)`)
	secureCookieFlagPattern     = regexp.MustCompile(`(?i)(?:secure\s*:\s*true|httpOnly\s*:\s*true|__Host-|__Secure-)`)
	debugModePattern            = regexp.MustCompile(`(?i)(?:debug\s*[:=]\s*true|NODE_ENV\s*[:=!]=?\s*['"]development['"]|app\.debug\s*=\s*True|DEBUG\s*=\s*['"]?(?:True|1|yes)['"]?)`)
	graphqlIntrospectionPattern = regexp.MustCompile(`(?i)(?:introspection\s*:\s*true|__schema\s*{)`)
	exposedSourceMapPattern     = regexp.MustCompile(`(?i)//[#@]\s*sourceMappingURL\s*=\s*[^\s]+\.map\b`)
	nosqlInjectionPattern       = regexp.MustCompile(`(?i)(?:\$(?:gt|gte|lt|lte|ne|in|nin|regex|where|exists)\b|\bfind(?:One)?\s*\(\s*\{[^}]*(?:req\.|request\.|params|body|query))`)
	exposedStackTracePattern    = regexp.MustCompile(`(?i)(?:res\.(?:send|json)\s*\(\s*(?:err|error)\.stack|stack\s*:\s*(?:err|error)\.stack|stackTrace\s*[:=])`)
	npmConfigLeakPattern        = regexp.MustCompile(`(?i)(?:_auth\s*=\s*[A-Za-z0-9+/=]{10,}|_authToken\s*=\s*[A-Za-z0-9._-]{10,}|//registry\.npmjs\.org/:_authToken)`)

	// Phase 7: Additional heuristic patterns
	dangerousHTMLPattern   = regexp.MustCompile(`(?i)dangerouslySetInnerHTML\s*=\s*\{`)
	corsOriginTrustPattern = regexp.MustCompile(`(?i)(?:allowedOrigins|cors.*origin)\s*[:=]\s*\[.*(?:\*\.|\.\*)`)
	unsafeIframePattern    = regexp.MustCompile(`(?i)(?:iframe\.src|<iframe[^>]*src)\s*=\s*(?:req\.|request\.|params|query|location|document)`)
	webhookNoVerifyPattern = regexp.MustCompile(`(?i)(?:webhook|hook|callback)\s*(?:=|:)\s*\(?\s*(?:req|request|event|body)\b`)
	webhookHMACPattern     = regexp.MustCompile(`(?i)(?:hmac|verify|signature|createHmac|timingSafeEqual)`)
	dbErrorExposurePattern = regexp.MustCompile(`(?i)(?:res\.(?:send|json|status)\s*\([^)]*(?:err(?:or)?\.message|err(?:or)?\.stack|err(?:or)?\b|sqlMessage|originalError))`)
	headerInjectionPattern = regexp.MustCompile(`(?i)(?:res\.(?:setHeader|set|header|writeHead)\s*\()`)
	headerTaintPattern     = regexp.MustCompile(`(?i)(?:(?:req|request)\.(?:query|params|body|headers)|ctx\.(?:query|params)|ctx\.request\.body)`)
	unsafeRegexUserPattern = regexp.MustCompile(`(?i)new\s+RegExp\s*\(\s*(?:(?:req|request)\.(?:query|params|body)|ctx\.(?:query|params)|ctx\.request\.body)`)
	hardcodedIPAuthPattern = regexp.MustCompile(`(?i)(?:(?:allowedIPs?|whitelist|trusted(?:IPs?|Proxies))\s*[:=]\s*\[)`)
)

func scanContent(target, content string) []Result {
	return scanContentWithOptions(target, content, 0)
}

func scanContentWithOptions(target, content string, contextLines int) []Result {
	collector := resultCollector{
		target:       target,
		content:      content,
		contextLines: contextLines,
		seen:         make(map[string]struct{}),
	}

	collectSignatureFindings(target, content, collector.addWithLine)
	collectHeuristicFindings(target, content, collector.addHeuristicEvidence)

	return collector.results
}

// isLikelyTestOrMockFile returns true if the filename suggests test data, mocks, fixtures or examples
func isLikelyTestOrMockFile(target string) bool {
	lower := strings.ToLower(filepath.Base(target))
	markers := []string{
		".test.", ".spec.", "_test.", "_spec.",
		".mock.", "_mock.", ".fixture", "_fixture",
		".example.", "_example.", ".sample.", "_sample.",
		".fake.", "_fake.", ".stub.", "_stub.",
		"__tests__", "__mocks__", "__fixtures__",
	}
	for _, m := range markers {
		if strings.Contains(lower, m) {
			return true
		}
	}
	// Also check path components
	lowerPath := strings.ToLower(strings.ReplaceAll(target, "\\", "/"))
	pathMarkers := []string{
		"/test/", "/tests/", "/spec/", "/specs/",
		"/__tests__/", "/__mocks__/", "/__fixtures__/",
		"/fixtures/", "/mocks/", "/examples/", "/samples/",
		"/testdata/", "/test-data/",
	}
	for _, pm := range pathMarkers {
		if strings.Contains(lowerPath, pm) {
			return true
		}
	}
	return false
}

// isLikelyEnvExample returns true if the target is an env example/template file
func isLikelyEnvExample(target string) bool {
	base := strings.ToLower(filepath.Base(target))
	exampleFiles := []string{
		".env.example", ".env.sample", ".env.template",
		".env.development", ".env.test", ".env.local.example",
		"env.example", "env.sample", "env.template",
	}
	for _, ef := range exampleFiles {
		if base == ef {
			return true
		}
	}
	return false
}

// suppressedOnTestFiles lists signature names that are commonly false positives in test/mock files
var suppressedOnTestFiles = map[string]bool{
	"API Key in Variable":        true,
	"Secret in Variable":         true,
	"API Key Generic Detector":   true,
	"Base64 High Entropy String": true,
	"Session ID":                 true,
	"CSRF Token":                 true,
	"Bearer Token Generic":       true,
	"Cookie Name Generic":        true,
	"Basic Auth String":          true,
	"OAuth Client Secret":        true,
	"OAuth Client ID":            true,
	"JJARDEL (Legacy)":           true,
	"SEGREDOS WAR (Legacy)":      true,
}

func (c *resultCollector) add(name, priority, match string) {
	c.addWithLine(name, priority, match, 0)
}

// addHeuristicEvidence is used by collectHeuristicFindings. It extracts the line
// number from "line N: ..." evidence format.
func (c *resultCollector) addHeuristicEvidence(name, priority, match string) {
	line := extractLineNumberFromEvidence(match)
	c.addWithLine(name, priority, match, line)
}

func (c *resultCollector) addWithLine(name, priority, match string, line int) {
	cleanMatch := normalizeFinding(match)
	if cleanMatch == "" {
		return
	}

	key := priority + "\x00" + name + "\x00" + cleanMatch
	if _, exists := c.seen[key]; exists {
		return
	}

	c.seen[key] = struct{}{}
	r := Result{
		Target:   c.target,
		Name:     name,
		Match:    cleanMatch,
		Priority: priority,
		Line:     line,
	}

	// Enrich with provider, tags, confidence, context
	enrichResult(&r, c.content, c.target, c.contextLines)

	c.results = append(c.results, r)
}

// passwordNonSecretValues are common non-secret values assigned to password fields
var passwordNonSecretValues = map[string]bool{
	"true": true, "false": true, "null": true, "undefined": true,
	"none": true, "disabled": true, "enabled": true,
	"required": true, "optional": true, "password": true,
	"changeme": true, "xxxxxxxx": true, "12345678": true,
	"encrypted": true, "redacted": true, "hidden": true,
	"********": true, "[hidden]": true, "[redacted]": true,
}

// genericSignatures lists signature names that produce noise on UUIDs and pure numeric values
var genericSignatures = map[string]bool{
	"API Key in Variable":      true,
	"Secret in Variable":       true,
	"API Key Generic Detector": true,
	"Session ID":               true,
	"CSRF Token":               true,
	"OAuth Client Secret":      true,
	"OAuth Client ID":          true,
	"Loggly Token":             true,
}

func collectSignatureFindings(target, content string, addLine func(name, priority, match string, line int)) {
	vendorTarget := isLikelyVendorTarget(target)
	testTarget := isLikelyTestOrMockFile(target)
	envExample := isLikelyEnvExample(target)
	isMinified := strings.Count(content, "\n") < 8 && len(content) > 6000

	// Build line offset index for efficient line-number lookup
	lineOffsets := buildLineOffsets(content)

	for _, sig := range Signatures {
		if vendorTarget && suppressedOnVendor[sig.Name] {
			continue
		}

		// Suppress noise-prone generic signatures in test/mock files
		if testTarget && suppressedOnTestFiles[sig.Name] {
			continue
		}

		// Suppress generic signatures in .env.example/.sample/.template files
		if envExample && suppressedOnTestFiles[sig.Name] {
			continue
		}

		// Fast pre-filter: skip regex if required prefix is absent
		if sig.Prefix != "" && !strings.Contains(content, sig.Prefix) {
			continue
		}

		// Skip noise-prone sigs on minified content
		if isMinified && skipOnMinified[sig.Name] {
			continue
		}

		matches := sig.Regex.FindAllStringIndex(content, 50)
		for _, loc := range matches {
			match := content[loc[0]:loc[1]]
			lineNum := offsetToLine(lineOffsets, loc[0])
			_ = lineNum // used by addSigWithLine below
			value := normalizeMatchedValue(match)
			normalizedValue := strings.ToLower(value)

			// Skip known safe strings (common hashes, test values)
			normalizedMatch := strings.ToLower(strings.TrimSpace(match))
			if knownSafeStrings[normalizedMatch] {
				continue
			}
			if knownSafeStrings[normalizedValue] {
				continue
			}

			// Skip repeated-character strings (e.g. "aaaaaaa...")
			if hasRepeatedChars(normalizedValue) {
				continue
			}

			if sig.Name == "Base64 High Entropy String" && isHexString(value) {
				continue
			}

			if sig.Name == "Base64 High Entropy String" && isLikelyBase64Noise(value) {
				continue
			}

			// Skip values that look like variable references, not literal secrets
			if isLikelyCodeReference(match) {
				continue
			}
			if genericSignatures[sig.Name] && isLikelyCodeReference(value) {
				continue
			}

			// Skip UUID-like values for generic patterns (UUIDs are IDs, not secrets)
			if genericSignatures[sig.Name] && isLikelyUUID(value) {
				continue
			}

			// Skip pure numeric values for generic patterns (not real secrets)
			if genericSignatures[sig.Name] && isPureNumeric(value) {
				continue
			}

			// Skip placeholder/template values for generic patterns
			if genericSignatures[sig.Name] && isLikelyPlaceholderValue(value) {
				continue
			}

			if sig.Name == "Bearer Token Generic" {
				bearerValue := value
				if idx := strings.Index(strings.ToLower(bearerValue), "bearer "); idx >= 0 {
					bearerValue = strings.TrimSpace(bearerValue[idx+len("bearer "):])
				}
				if len(bearerValue) < 20 || isLikelyPlaceholderValue(bearerValue) {
					continue
				}
				if shannonEntropy(bearerValue) < 3.0 {
					continue
				}
			}

			if sig.Name == "CSRF Token" {
				hasLetter := false
				hasDigit := false
				for _, r := range value {
					if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' {
						hasLetter = true
					}
					if r >= '0' && r <= '9' {
						hasDigit = true
					}
				}
				if !hasLetter || !hasDigit {
					continue
				}
			}

			// For patterns prone to false positives, require minimum entropy
			if minEntropy, ok := lowEntropyPatterns[sig.Name]; ok {
				if shannonEntropy(value) < minEntropy {
					continue
				}
			}

			// For Password Assignment, filter out common non-secret values
			if sig.Name == "Password Assignment" {
				if passwordNonSecretValues[strings.ToLower(value)] || isLikelyNonSecretPasswordValue(value) {
					continue
				}
			}

			// Filter i18n translation keys that look like tr_word_word_word
			if sig.Name == "Trigger.dev API Key" && looksLikeTranslationKey(value) {
				continue
			}

			addLine(sig.Name, sig.Priority, match, lineNum)
		}
	}
}

func collectHeuristicFindings(target, content string, add func(name, priority, match string)) {
	if isLikelyVendorTarget(target) {
		return
	}

	if isLikelyBundledContent(content) {
		return
	}

	rawLines := splitCodeLines(content)
	for _, line := range rawLines {
		text := strings.TrimSpace(line.Text)
		if strings.Contains(text, "sourceMappingURL") && shouldFlagSourceMapReference(text) {
			add("Exposed Source Map Reference", "LOW", formatLineEvidence(line.Number, text))
		}
	}

	codeOnly := stripJSComments(content)
	lines := splitCodeLines(codeOnly)

	if corsWildcardPattern.MatchString(codeOnly) || manualCorsPattern.MatchString(codeOnly) {
		add("CORS Wildcard With Credentials", "HIGH", "origin: '*' with credentials: true")
	}

	if corsOriginReflectPattern.MatchString(codeOnly) {
		add("CORS Origin Reflection (Dynamic)", "HIGH", "Origin header reflected without validation")
	}

	for _, line := range lines {
		text := strings.TrimSpace(line.Text)
		if text == "" || len(text) < 8 {
			continue
		}

		if isLikelyMinifiedLine(text) {
			continue
		}

		// ── Keyword-gated heuristic checks ──
		// Instead of running 25+ regex per line, check cheap substrings first.

		if strings.Contains(text, "rejectUnauthorized") || strings.Contains(text, "strictSSL") || strings.Contains(text, "NODE_TLS") {
			if insecureTLSPattern.MatchString(text) {
				add("TLS Validation Disabled", "HIGH", formatLineEvidence(line.Number, text))
			}
		}

		if strings.Contains(text, "postMessage") {
			if postMessageWildcardPattern.MatchString(text) {
				add("Wildcard postMessage Target Origin", "HIGH", formatLineEvidence(line.Number, text))
			}
		}

		if strings.Contains(text, "eval") || strings.Contains(text, "Function(") || strings.Contains(text, "setTimeout") || strings.Contains(text, "setInterval") {
			if dynamicCodePattern.MatchString(text) {
				add("Dynamic Code Execution Sink", "HIGH", formatLineEvidence(line.Number, text))
			}
		}

		if strings.Contains(text, "exec") || strings.Contains(text, "spawn") || strings.Contains(text, "fork(") {
			if commandExecPattern.MatchString(text) {
				name := "Command Execution Sink"
				priority := "MEDIUM"
				if shellTruePattern.MatchString(text) || taintSourcePattern.MatchString(text) {
					name = "Potential Command Injection"
					priority = "HIGH"
				}
				add(name, priority, formatLineEvidence(line.Number, text))
			}
		}

		if strings.Contains(text, "createHash") || strings.Contains(text, "CryptoJS") || strings.Contains(text, "md5") || strings.Contains(text, "sha1") || strings.Contains(text, "createCipher") || strings.Contains(text, "DES") || strings.Contains(text, "RC4") || strings.Contains(text, "ECB") {
			if weakCryptoPattern.MatchString(text) {
				add("Weak Cryptography", "MEDIUM", formatLineEvidence(line.Number, text))
			}
		}

		if strings.Contains(text, "Math.random") {
			if mathRandomPattern.MatchString(text) && sensitiveNamePattern.MatchString(text) {
				add("Predictable Security Token Generation", "MEDIUM", formatLineEvidence(line.Number, text))
			}
		}

		if strings.Contains(text, "Storage") || strings.Contains(text, "localStorage") || strings.Contains(text, "sessionStorage") {
			if insecureStoragePattern.MatchString(text) {
				if storageKey := storageSetItemKey(text); storageKey != "" && sensitiveNamePattern.MatchString(storageKey) {
					add("Sensitive Data Stored In Web Storage", "MEDIUM", formatLineEvidence(line.Number, text))
				}
			}
		}

		if strings.Contains(text, "document.cookie") {
			if documentCookiePattern.MatchString(text) && sensitiveNamePattern.MatchString(text) {
				add("Sensitive Token Written To document.cookie", "MEDIUM", formatLineEvidence(line.Number, text))
			}
		}

		if strings.Contains(text, "fetch") || strings.Contains(text, "axios") || strings.Contains(text, "http") || strings.Contains(text, "request(") {
			if requestPattern.MatchString(text) && taintSourcePattern.MatchString(text) {
				add("Potential SSRF / Untrusted Outbound Request", "MEDIUM", formatLineEvidence(line.Number, text))
			}
		}

		if strings.Contains(text, "redirect") || strings.Contains(text, "location") {
			if shouldFlagOpenRedirect(text) {
				add("Potential Open Redirect", "MEDIUM", formatLineEvidence(line.Number, text))
			}
		}

		if strings.Contains(text, "fs.") || strings.Contains(text, "sendFile") || strings.Contains(text, "readFile") {
			if fileAccessPattern.MatchString(text) && taintSourcePattern.MatchString(text) {
				add("Potential Path Traversal", "MEDIUM", formatLineEvidence(line.Number, text))
			}
		}

		if strings.Contains(text, "__proto__") || strings.Contains(text, "prototype") {
			if prototypePollutionPattern.MatchString(text) && !es5InheritancePattern.MatchString(text) {
				add("Potential Prototype Pollution", "HIGH", formatLineEvidence(line.Number, text))
			}
		}

		if strings.Contains(text, "assign") || strings.Contains(text, "merge") || strings.Contains(text, "extend") || strings.Contains(text, "deepmerge") {
			if objectMergePattern.MatchString(text) {
				add("Object Merge With User Input", "MEDIUM", formatLineEvidence(line.Number, text))
			}
		}

		if strings.Contains(text, "render") || strings.Contains(text, "template") || strings.Contains(text, "compile") {
			if templateInjectionPattern.MatchString(text) && taintSourcePattern.MatchString(text) {
				add("Potential Template Injection", "HIGH", formatLineEvidence(line.Number, text))
			}
		}

		if strings.Contains(text, "unserialize") || strings.Contains(text, "deserialize") || strings.Contains(text, "fromJSON") || strings.Contains(text, "YAML") {
			if insecureDeserializePattern.MatchString(text) {
				add("Potential Insecure Deserialization", "HIGH", formatLineEvidence(line.Number, text))
			}
		}

		if strings.Contains(text, "update(") || strings.Contains(text, "create(") || strings.Contains(text, "body)") || strings.Contains(text, "req.body") {
			if massAssignmentPattern.MatchString(text) {
				add("Potential Mass Assignment", "MEDIUM", formatLineEvidence(line.Number, text))
			}
		}

		if strings.Contains(text, "algorithm") || strings.Contains(text, "none") {
			if jwtWeakAlgPattern.MatchString(text) {
				add("JWT Weak Algorithm", "HIGH", formatLineEvidence(line.Number, text))
			}
		}

		if strings.Contains(text, "sign(") || strings.Contains(text, "secret") || strings.Contains(text, "jwt") {
			if hardcodedJWTSecretPattern.MatchString(text) {
				add("Hardcoded JWT Secret", "CRITICAL", formatLineEvidence(line.Number, text))
			}
		}

		if strings.Contains(text, "cookie") || strings.Contains(text, "Cookie") {
			if shouldFlagInsecureCookie(text) {
				add("Insecure Cookie (Missing Secure/HttpOnly)", "MEDIUM", formatLineEvidence(line.Number, text))
			}
		}

		if strings.Contains(text, "debug") || strings.Contains(text, "DEBUG") || strings.Contains(text, "verbose") || strings.Contains(text, "NODE_ENV") || strings.Contains(text, "development") {
			if shouldFlagDebugMode(text) {
				add("Debug Mode Enabled In Production Code", "MEDIUM", formatLineEvidence(line.Number, text))
			}
		}

		if strings.Contains(text, "introspection") {
			if graphqlIntrospectionPattern.MatchString(text) {
				add("GraphQL Introspection Enabled", "MEDIUM", formatLineEvidence(line.Number, text))
			}
		}

		if strings.Contains(text, "$where") || strings.Contains(text, "$regex") || strings.Contains(text, "$gt") || strings.Contains(text, "$ne") {
			if nosqlInjectionPattern.MatchString(text) && taintSourcePattern.MatchString(text) {
				add("Potential NoSQL Injection", "HIGH", formatLineEvidence(line.Number, text))
			}
		}

		if strings.Contains(text, "stack") || strings.Contains(text, "Stack") || strings.Contains(text, "trace") {
			if exposedStackTracePattern.MatchString(text) {
				add("Exposed Stack Trace to Client", "MEDIUM", formatLineEvidence(line.Number, text))
			}
		}

		if strings.Contains(text, "_auth") || strings.Contains(text, "authToken") || strings.Contains(text, "npm") {
			if npmConfigLeakPattern.MatchString(text) {
				add("NPM Config Leak (_auth / _authToken)", "HIGH", formatLineEvidence(line.Number, text))
			}
		}

		// ReDoS: only check lines containing regex-like patterns
		if strings.Contains(text, "RegExp") || strings.ContainsAny(text, "/") {
			checkReDoS(line.Number, text, add)
		}

		if strings.Contains(text, "query") || strings.Contains(text, "execute") || strings.Contains(text, "Query") {
			if sqlExecutionPattern.MatchString(text) && sqlKeywordPattern.MatchString(text) && dynamicDataPattern.MatchString(text) {
				add("Potential SQL Injection", "HIGH", formatLineEvidence(line.Number, text))
			}
		}

		if strings.Contains(text, "innerHTML") || strings.Contains(text, "outerHTML") || strings.Contains(text, "write(") || strings.Contains(text, "insertAdjacentHTML") {
			if xssSinkPattern.MatchString(text) && shouldFlagHTMLSink(text) {
				name := "HTML Injection Sink"
				priority := "MEDIUM"
				if taintSourcePattern.MatchString(text) {
					name = "Potential DOM XSS"
					priority = "HIGH"
				}
				add(name, priority, formatLineEvidence(line.Number, text))
			}
		}

		// Phase 7: dangerouslySetInnerHTML (React XSS)
		if strings.Contains(text, "dangerouslySetInnerHTML") {
			if dangerousHTMLPattern.MatchString(text) && !sanitizerPattern.MatchString(text) {
				add("React dangerouslySetInnerHTML Usage", "MEDIUM", formatLineEvidence(line.Number, text))
			}
		}

		// Phase 7: CORS origin misconfiguration
		if strings.Contains(text, "allowedOrigins") || strings.Contains(text, "cors") {
			if corsOriginTrustPattern.MatchString(text) {
				add("Overly Permissive CORS Origin", "MEDIUM", formatLineEvidence(line.Number, text))
			}
		}

		// Phase 7: Unsafe iframe src from user input
		if strings.Contains(text, "iframe") {
			if unsafeIframePattern.MatchString(text) {
				add("Unsafe Iframe Source from User Input", "HIGH", formatLineEvidence(line.Number, text))
			}
		}

		// Phase 7: Webhook endpoint without HMAC verification
		if strings.Contains(text, "webhook") || strings.Contains(text, "hook") || strings.Contains(text, "callback") {
			if shouldFlagWebhookHandler(text) {
				add("Webhook Handler Without Signature Verification", "MEDIUM", formatLineEvidence(line.Number, text))
			}
		}

		// Phase 7: Database error exposed to client
		if strings.Contains(text, "err") && (strings.Contains(text, "res.") || strings.Contains(text, "response.")) {
			if dbErrorExposurePattern.MatchString(text) {
				add("Error Details Exposed to Client", "MEDIUM", formatLineEvidence(line.Number, text))
			}
		}

		// Phase 7: HTTP header injection from user input
		if strings.Contains(text, "setHeader") || strings.Contains(text, "writeHead") || strings.Contains(text, "set(") {
			if shouldFlagHeaderInjection(text) {
				add("HTTP Header Injection from User Input", "HIGH", formatLineEvidence(line.Number, text))
			}
		}

		// Phase 7: Regex from user input (ReDoS via user-controlled pattern)
		if strings.Contains(text, "RegExp") {
			if unsafeRegexUserPattern.MatchString(text) {
				add("User-Controlled Regex Pattern", "HIGH", formatLineEvidence(line.Number, text))
			}
		}

		// Phase 7: Hardcoded IP allowlist
		if strings.Contains(text, "allowedIP") || strings.Contains(text, "whitelist") || strings.Contains(text, "trustedIP") || strings.Contains(text, "trustedProx") {
			if hardcodedIPAuthPattern.MatchString(text) {
				add("Hardcoded IP-Based Authorization", "MEDIUM", formatLineEvidence(line.Number, text))
			}
		}

		if strings.ContainsAny(text, "=:") {
			collectSuspiciousAssignments(line.Number, text, add)
		}
	}
}

func collectSuspiciousAssignments(lineNumber int, line string, add func(name, priority, match string)) {
	matches := suspiciousAssignmentPattern.FindAllStringSubmatch(line, -1)
	for _, match := range matches {
		identifier := strings.ToLower(match[1])
		value := firstNonEmpty(match[2], match[3], match[4])
		if !looksCredentialLike(identifier, value) {
			continue
		}

		priority := "MEDIUM"
		if strings.Contains(identifier, "password") || strings.Contains(identifier, "secret") || strings.Contains(identifier, "private") {
			priority = "HIGH"
		}

		add("Potential Hardcoded Credential", priority, formatLineEvidence(lineNumber, line))
	}
}

func normalizeFinding(match string) string {
	match = strings.TrimSpace(match)
	if match == "" {
		return ""
	}

	if strings.HasPrefix(match, "line ") {
		if len(match) > 180 {
			return match[:180] + "..."
		}
		return match
	}

	match = strings.Join(strings.Fields(match), " ")
	if len(match) > 100 {
		return match[:100] + "..."
	}
	return match
}

func shouldFlagHTMLSink(line string) bool {
	if sanitizerPattern.MatchString(line) {
		return false
	}

	if taintSourcePattern.MatchString(line) {
		return true
	}

	switch {
	case strings.Contains(line, "dangerouslySetInnerHTML"):
		return strings.Contains(line, "${") || strings.Contains(line, "+") || !strings.Contains(line, "__html")
	case strings.Contains(line, "insertAdjacentHTML"):
		return hasDynamicFragment(argumentAfterNthComma(line, 1))
	case strings.Contains(line, "document.write"):
		return hasDynamicFragment(argumentInsideCall(line))
	case strings.Contains(line, ".innerHTML") || strings.Contains(line, ".outerHTML") || strings.Contains(line, ".srcdoc"):
		return hasDynamicFragment(textAfterFirstEquals(line))
	default:
		return false
	}
}

func shouldFlagWebhookHandler(line string) bool {
	if !webhookNoVerifyPattern.MatchString(line) || webhookHMACPattern.MatchString(line) {
		return false
	}

	hasHandlerShape := strings.Contains(line, "=>") || strings.Contains(line, "function")
	if !hasHandlerShape {
		return false
	}

	hasInboundPayload := strings.Contains(line, "req.body") || strings.Contains(line, "request.body") || strings.Contains(line, "event.body")
	return hasInboundPayload
}

func shouldFlagDebugMode(line string) bool {
	if !debugModePattern.MatchString(line) {
		return false
	}

	if strings.Contains(line, "==") || strings.Contains(line, "!=") {
		return false
	}

	return true
}

func shouldFlagHeaderInjection(line string) bool {
	if !headerInjectionPattern.MatchString(line) {
		return false
	}

	return headerTaintPattern.MatchString(line)
}

func shouldFlagOpenRedirect(line string) bool {
	if !redirectPattern.MatchString(line) {
		return false
	}

	lower := strings.ToLower(line)
	if strings.Contains(lower, "res.redirect") {
		return taintSourcePattern.MatchString(argumentInsideCall(line))
	}

	if strings.Contains(lower, "location") {
		return taintSourcePattern.MatchString(textAfterFirstEquals(line))
	}

	return false
}

func shouldFlagInsecureCookie(line string) bool {
	if secureCookieFlagPattern.MatchString(line) {
		return false
	}

	return insecureCookiePattern.MatchString(line)
}

func shouldFlagSourceMapReference(line string) bool {
	return exposedSourceMapPattern.MatchString(line)
}

func hasDynamicFragment(fragment string) bool {
	fragment = strings.TrimSpace(strings.TrimSuffix(fragment, ";"))
	if fragment == "" {
		return false
	}

	if taintSourcePattern.MatchString(fragment) {
		return true
	}

	if strings.Contains(fragment, "${") || strings.Contains(fragment, "+") || strings.Contains(fragment, ".concat(") {
		return true
	}

	return !isStaticStringExpression(fragment)
}

func isStaticStringExpression(fragment string) bool {
	fragment = strings.TrimSpace(strings.TrimSuffix(fragment, ";"))
	if len(fragment) < 2 {
		return false
	}

	if strings.HasPrefix(fragment, "'") && strings.HasSuffix(fragment, "'") {
		return true
	}
	if strings.HasPrefix(fragment, "\"") && strings.HasSuffix(fragment, "\"") {
		return true
	}
	if strings.HasPrefix(fragment, "`") && strings.HasSuffix(fragment, "`") && !strings.Contains(fragment, "${") {
		return true
	}

	return false
}

func textAfterFirstEquals(line string) string {
	idx := strings.Index(line, "=")
	if idx == -1 || idx+1 >= len(line) {
		return ""
	}
	return line[idx+1:]
}

func argumentInsideCall(line string) string {
	start := strings.Index(line, "(")
	end := strings.LastIndex(line, ")")
	if start == -1 || end == -1 || end <= start+1 {
		return ""
	}
	return line[start+1 : end]
}

func argumentAfterNthComma(line string, commaIndex int) string {
	args := splitArguments(argumentInsideCall(line))
	if commaIndex < 0 || commaIndex >= len(args) {
		return ""
	}
	return args[commaIndex]
}

func storageSetItemKey(line string) string {
	matches := storageSetItemPattern.FindStringSubmatch(line)
	if len(matches) < 2 {
		return ""
	}

	return trimLiteralValue(matches[1])
}

func splitArguments(input string) []string {
	var args []string
	var current strings.Builder
	inSingle := false
	inDouble := false
	inTemplate := false
	escapeNext := false
	depth := 0

	for i := 0; i < len(input); i++ {
		ch := input[i]

		if escapeNext {
			current.WriteByte(ch)
			escapeNext = false
			continue
		}

		switch ch {
		case '\\':
			if inSingle || inDouble || inTemplate {
				escapeNext = true
			}
		case '\'':
			if !inDouble && !inTemplate {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle && !inTemplate {
				inDouble = !inDouble
			}
		case '`':
			if !inSingle && !inDouble {
				inTemplate = !inTemplate
			}
		case '(':
			if !inSingle && !inDouble && !inTemplate {
				depth++
			}
		case ')':
			if !inSingle && !inDouble && !inTemplate && depth > 0 {
				depth--
			}
		case ',':
			if !inSingle && !inDouble && !inTemplate && depth == 0 {
				args = append(args, strings.TrimSpace(current.String()))
				current.Reset()
				continue
			}
		}

		current.WriteByte(ch)
	}

	if current.Len() > 0 {
		args = append(args, strings.TrimSpace(current.String()))
	}

	return args
}

func looksCredentialLike(identifier, value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || looksLikePlaceholder(value) {
		return false
	}

	if strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") || strings.HasPrefix(value, "data:") {
		return false
	}

	// Skip properly hashed passwords (bcrypt, argon2, scrypt) — these are safe
	if strings.HasPrefix(value, "$2a$") || strings.HasPrefix(value, "$2b$") || strings.HasPrefix(value, "$2y$") ||
		strings.HasPrefix(value, "$argon2id$") || strings.HasPrefix(value, "$argon2i$") || strings.HasPrefix(value, "$scrypt$") {
		return false
	}

	// Skip file paths and CSS/HTML class selectors
	if strings.HasPrefix(value, "/") || strings.HasPrefix(value, "./") || strings.HasPrefix(value, "../") {
		return false
	}
	if strings.HasPrefix(value, ".") && !strings.ContainsAny(value, " =:") {
		return false // CSS class names like ".btn-primary-outlined"
	}

	if strings.Contains(identifier, "password") || strings.Contains(identifier, "passwd") || strings.Contains(identifier, "pwd") {
		if isLikelyNonSecretPasswordValue(value) {
			return false
		}
		return len(value) >= 6
	}

	entropy := shannonEntropy(value)
	if len(value) >= 20 && entropy >= 3.2 {
		return true
	}

	if len(value) >= 12 && entropy >= 3.6 {
		return true
	}

	if strings.HasPrefix(value, "eyJ") && strings.Count(value, ".") >= 1 {
		return true
	}

	if strings.ContainsAny(value, "-_.+/=") && len(value) >= 16 {
		return true
	}

	return false
}

func isLikelyNonSecretPasswordValue(value string) bool {
	trimmed := trimLiteralValue(value)
	lower := strings.ToLower(trimmed)
	if trimmed == "" {
		return false
	}

	if passwordNonSecretValues[lower] {
		return true
	}

	if strings.ContainsAny(trimmed, " \t\r\n") {
		return true
	}

	if strings.HasPrefix(trimmed, "[") || strings.HasPrefix(trimmed, ".") || strings.HasPrefix(trimmed, "#") {
		return true
	}

	if strings.Contains(lower, "type=password") {
		return true
	}

	if looksLikeIdentifierLiteral(trimmed) && !containsDigit(trimmed) {
		if strings.Contains(trimmed, "_") || hasMixedCase(trimmed) || strings.Contains(lower, "password") {
			return true
		}
	}

	return false
}

func looksLikeIdentifierLiteral(value string) bool {
	for i, r := range value {
		isLetter := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z'
		isDigit := r >= '0' && r <= '9'
		if i == 0 {
			if !isLetter && r != '_' {
				return false
			}
			continue
		}
		if !isLetter && !isDigit && r != '_' {
			return false
		}
	}

	return len(value) >= 8
}

func hasMixedCase(value string) bool {
	hasLower := false
	hasUpper := false
	for _, r := range value {
		if r >= 'a' && r <= 'z' {
			hasLower = true
		}
		if r >= 'A' && r <= 'Z' {
			hasUpper = true
		}
	}
	return hasLower && hasUpper
}

func containsDigit(value string) bool {
	for _, r := range value {
		if r >= '0' && r <= '9' {
			return true
		}
	}
	return false
}

func looksLikePlaceholder(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	placeholders := []string{
		"changeme",
		"change-me",
		"change_me",
		"replace-me",
		"replace_me",
		"replace_this",
		"replaceme",
		"your_token_here",
		"your_secret_here",
		"your_key_here",
		"your_api_key",
		"your-api-key",
		"your-api-key-here",
		"your-secret",
		"your-token",
		"insert_token_here",
		"insert_key_here",
		"enter_your_key",
		"put_your_key_here",
		"example",
		"example123",
		"example_key",
		"example_secret",
		"example_token",
		"sample",
		"sample_key",
		"sample_secret",
		"dummy",
		"dummykey",
		"dummysecret",
		"placeholder",
		"foo",
		"bar",
		"baz",
		"foobar",
		"test",
		"testing",
		"test123",
		"testkey",
		"testsecret",
		"testtoken",
		"test_key",
		"test_secret",
		"test_token",
		"null",
		"undefined",
		"none",
		"empty",
		"n/a",
		"todo",
		"fixme",
		"xxx",
		"token_here",
		"secret_here",
		"key_here",
		"password_here",
		"default",
		"default_key",
		"default_secret",
		"my-secret",
		"my-token",
		"my-key",
		"mysecret",
		"mytoken",
		"mykey",
	}

	for _, placeholder := range placeholders {
		if lower == placeholder {
			return true
		}
	}

	// Patterns like <YOUR_KEY>, ${TOKEN}, {{SECRET}}
	if strings.HasPrefix(lower, "<") && strings.HasSuffix(lower, ">") {
		return true
	}
	if strings.HasPrefix(lower, "${") && strings.HasSuffix(lower, "}") {
		return true
	}
	if strings.HasPrefix(lower, "{{") && strings.HasSuffix(lower, "}}") {
		return true
	}

	return false
}

func shannonEntropy(value string) float64 {
	if value == "" {
		return 0
	}

	counts := make(map[rune]float64)
	total := 0.0
	for _, r := range value {
		counts[r]++
		total++
	}

	entropy := 0.0
	for _, count := range counts {
		p := count / total
		entropy -= p * math.Log2(p)
	}

	return entropy
}

func stripJSComments(content string) string {
	var out strings.Builder
	out.Grow(len(content))
	inSingle := false
	inDouble := false
	inTemplate := false
	inLineComment := false
	inBlockComment := false
	escapeNext := false

	for i := 0; i < len(content); i++ {
		ch := content[i]

		if inLineComment {
			if ch == '\n' {
				inLineComment = false
				out.WriteByte(ch)
			}
			continue
		}

		if inBlockComment {
			if ch == '\n' {
				out.WriteByte(ch)
				continue
			}
			if ch == '*' && i+1 < len(content) && content[i+1] == '/' {
				inBlockComment = false
				i++
			}
			continue
		}

		if escapeNext {
			out.WriteByte(ch)
			escapeNext = false
			continue
		}

		if inSingle || inDouble || inTemplate {
			out.WriteByte(ch)
			if ch == '\\' {
				escapeNext = true
				continue
			}

			switch ch {
			case '\'':
				if inSingle {
					inSingle = false
				}
			case '"':
				if inDouble {
					inDouble = false
				}
			case '`':
				if inTemplate {
					inTemplate = false
				}
			}
			continue
		}

		if ch == '/' && i+1 < len(content) {
			next := content[i+1]
			if next == '/' {
				inLineComment = true
				i++
				continue
			}
			if next == '*' {
				inBlockComment = true
				i++
				continue
			}
		}

		switch ch {
		case '\'':
			inSingle = true
		case '"':
			inDouble = true
		case '`':
			inTemplate = true
		}

		out.WriteByte(ch)
	}

	return out.String()
}

func splitCodeLines(content string) []struct {
	Number int
	Text   string
} {
	parts := strings.Split(content, "\n")
	lines := make([]struct {
		Number int
		Text   string
	}, 0, len(parts))

	for idx, part := range parts {
		lines = append(lines, struct {
			Number int
			Text   string
		}{
			Number: idx + 1,
			Text:   part,
		})
	}

	return lines
}

func formatLineEvidence(lineNumber int, text string) string {
	text = strings.Join(strings.Fields(strings.TrimSpace(text)), " ")
	if len(text) > 150 {
		text = text[:150] + "..."
	}
	return fmt.Sprintf("line %d: %s", lineNumber, text)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

// vendorExactBasenames are basenames that mark the file as vendor/library
var vendorExactBasenames = map[string]bool{
	"app.js": true, "all.js": true, "js.js": true,
	"fontawesome.js": true, "player.js": true,
	"runtime.js": true, "polyfills.js": true,
}

// vendorSubstringMarkers are substrings checked anywhere in the path
var vendorSubstringMarkers = []string{
	".min.js", ".chunk.js", ".xhtml.js",
	".umd.js", ".umd.cjs", ".pack.", "_prod.js", "_prod_",
	"jquery", "bootstrap", "react", "vue", "redux",
	"moment", "modernizr", "datatables", "fitvids",
	"cdnjs", "squarespace", "scripts-compressed",
	"okta-sign-in", "appsflyer",
	"pdf.js", "pdf.worker", "pdf_viewer",
	"migrate", "bxslider", "i18next", "richfaces",
	"chart", "vendor", "bundle", "chunk", "node_modules",
	"eclair", "aura_", "sentry", "polyfill",
}

func isLikelyVendorTarget(target string) bool {
	lower := strings.ToLower(target)
	base := strings.ToLower(filepath.Base(target))

	// Fast exact-match on basename
	if vendorExactBasenames[base] {
		return true
	}

	// Cross-platform base
	unixBase := base
	if strings.ContainsRune(target, '\\') {
		unixBase = strings.ToLower(path.Base(strings.ReplaceAll(target, "\\", "/")))
	}
	if unixBase != base && vendorExactBasenames[unixBase] {
		return true
	}

	for _, marker := range vendorSubstringMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}

	if vendorHexFilePattern.MatchString(base) || vendorHexFilePattern.MatchString(unixBase) {
		return true
	}

	if vendorHexDashFilePattern.MatchString(base) || vendorHexDashFilePattern.MatchString(unixBase) {
		return true
	}

	// Content-hashed bundles: anything ending in .<8+hexchars>.js  (e.g. chat-window.c4140ec3.js)
	if vendorHashedDotPattern.MatchString(base) || vendorHashedDotPattern.MatchString(unixBase) {
		return true
	}

	return false
}

func isLikelyMinifiedLine(line string) bool {
	l := len(line)
	if l < 300 {
		return false
	}

	spaces := 0
	semis := 0
	for i := 0; i < l; i++ {
		switch line[i] {
		case ' ', '\t':
			spaces++
		case ';':
			semis++
		}
	}

	// Primary: whitespace ratio < 8%  (spaces*12 < len avoids float)
	if spaces*12 < l {
		return true
	}

	// Secondary: high semicolon density (>1 per 40 chars) on long lines indicates minified code
	// ES5 minified code like EclairNG has many `var` keywords that inflate whitespace,
	// but also has very high semicolon density from statement concatenation.
	if l >= 400 && semis*40 > l {
		return true
	}

	return false
}

func isHexString(value string) bool {
	trimmed := strings.Trim(value, `"'`)
	if len(trimmed) < 16 {
		return false
	}

	for _, r := range trimmed {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}

	return true
}

func isLikelyBase64Noise(value string) bool {
	trimmed := strings.Trim(value, `"'`)
	if trimmed == "" {
		return true
	}

	if strings.Contains(trimmed, "http") {
		return true
	}

	if strings.HasPrefix(trimmed, "/") {
		return true
	}

	if strings.Contains(trimmed, "/") && !strings.ContainsAny(trimmed, "+=") {
		return true
	}

	if !strings.ContainsAny(trimmed, "+/=") {
		return true
	}

	if shannonEntropy(trimmed) < 4.2 {
		return true
	}

	return false
}

// checkReDoS extracts regex patterns from a JS line and flags those vulnerable to catastrophic backtracking
func checkReDoS(lineNumber int, text string, add func(name, priority, match string)) {
	var regexBodies []string

	// Extract /pattern/flags literals
	for _, m := range jsRegexLiteralPattern.FindAllStringSubmatch(text, 5) {
		if len(m) > 1 {
			regexBodies = append(regexBodies, m[1])
		}
	}

	// Extract new RegExp("pattern") calls
	for _, m := range newRegExpPattern.FindAllStringSubmatch(text, 5) {
		if len(m) > 1 {
			regexBodies = append(regexBodies, m[1])
		}
	}

	for _, body := range regexBodies {
		if isVulnerableRegex(body) {
			add("Potential ReDoS (Catastrophic Backtracking)", "MEDIUM", formatLineEvidence(lineNumber, text))
			return // one finding per line is enough
		}
	}
}

// isVulnerableRegex checks a regex body string for patterns known to cause catastrophic backtracking
func isVulnerableRegex(pattern string) bool {
	if redosNestedQuantifier.MatchString(pattern) {
		return true
	}
	if redosOverlappingAlts.MatchString(pattern) {
		return true
	}
	if redosQuantifiedOverlap.MatchString(pattern) {
		return true
	}
	if redosNestedRepetition.MatchString(pattern) {
		return true
	}
	if redosStarStar.MatchString(pattern) {
		return true
	}
	return false
}

func isLikelyBundledContent(content string) bool {
	// Only skip heuristics for known bundler signatures — not merely long single-line files,
	// which can be legitimate compact code with real vulnerabilities.
	if strings.Contains(content, "webpackChunk") || strings.Contains(content, "webpackJsonp") ||
		strings.Contains(content, "webpackJsonpRlms") {
		return true
	}

	// Parcel, Rollup, esbuild bundler signatures
	if strings.Contains(content, "parcelRequire") ||
		strings.Contains(content, "__rollupBundleStart") ||
		strings.Contains(content, "__esbuild_") {
		return true
	}

	newlines := strings.Count(content, "\n")

	// Webpack 5 / generic IIFE bundles: few lines, large content, starts with IIFE.
	// Some bundles start with a short var declaration before the IIFE
	// (e.g. `var client;(()=>{...`) so we check within the first 300 chars.
	if newlines < 10 && len(content) > 5000 {
		trimmed := strings.TrimSpace(content)
		first300 := content
		if len(first300) > 300 {
			first300 = content[:300]
		}
		if strings.Contains(first300, "(()=>{") ||
			strings.HasPrefix(trimmed, "!function(") ||
			strings.HasPrefix(trimmed, "(function(") {
			return true
		}
	}

	// Webpack numeric-ID module pattern: !function(){var X={DIGITS:function(
	if newlines < 10 && len(content) > 10000 {
		if strings.Contains(content[:min(500, len(content))], "function(t,e,n){") ||
			strings.Contains(content[:min(500, len(content))], "function(e,t,r){") {
			return true
		}
	}

	// UMD wrapper pattern in large content
	if len(content) > 20000 && strings.Contains(content[:min(200, len(content))], "(function(root") {
		return true
	}

	return false
}

// buildLineOffsets returns a slice where offsets[i] is the byte offset of the
// start of line i+1 (0-indexed). Used for O(log n) byte-offset → line mapping.
func buildLineOffsets(content string) []int {
	offsets := []int{0}
	for i := 0; i < len(content); i++ {
		if content[i] == '\n' && i+1 < len(content) {
			offsets = append(offsets, i+1)
		}
	}
	return offsets
}

// offsetToLine does a binary search on lineOffsets to return the 1-based line
// number for the given byte offset.
func offsetToLine(offsets []int, byteOffset int) int {
	lo, hi := 0, len(offsets)-1
	for lo <= hi {
		mid := (lo + hi) / 2
		if offsets[mid] <= byteOffset {
			lo = mid + 1
		} else {
			hi = mid - 1
		}
	}
	return lo // 1-based: lo is the count of offsets <= byteOffset
}

// extractLineNumberFromEvidence parses "line N: ..." format used by
// formatLineEvidence and returns N, or 0 if the format doesn't match.
func extractLineNumberFromEvidence(evidence string) int {
	if !strings.HasPrefix(evidence, "line ") {
		return 0
	}
	rest := evidence[5:]
	colonIdx := strings.Index(rest, ":")
	if colonIdx <= 0 {
		return 0
	}
	n := 0
	for _, ch := range rest[:colonIdx] {
		if ch < '0' || ch > '9' {
			return 0
		}
		n = n*10 + int(ch-'0')
	}
	return n
}
