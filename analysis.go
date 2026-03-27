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
	target  string
	seen    map[string]struct{}
	results []Result
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
	// config.something or settings.something
	if strings.Contains(v, ".") && !strings.Contains(v, " ") && !strings.Contains(v, "/") && len(v) < 60 {
		parts := strings.SplitN(v, ".", 2)
		if len(parts) == 2 && len(parts[0]) > 0 && parts[0][0] >= 'a' && parts[0][0] <= 'z' {
			return true
		}
	}
	return false
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
	prototypePollutionPattern  = regexp.MustCompile(`(?i)(?:__proto__\s*[:=]|\[['"]__proto__['"]\]\s*=|constructor\s*\.\s*prototype\s*[:=]|Object\.setPrototypeOf\s*\(|Reflect\.setPrototypeOf\s*\()`)
	templateInjectionPattern   = regexp.MustCompile(`(?i)(?:\{\{\s*[^}]*\s*\}\}|<%[^%]*%>|\$\{[^}]*\}.*render|nunjucks\.render|ejs\.render|pug\.render|handlebars\.compile|Mustache\.render)`)
	insecureDeserializePattern = regexp.MustCompile(`(?i)(?:unserialize\s*\(|pickle\.loads?\s*\(|yaml\.(?:load|unsafe_load)\s*\(|JSON\.parse\s*\([^)]*(?:localStorage|sessionStorage|req\.|request\.)|deserialize\s*\([^)]*(?:body|params|query))`)
	objectMergePattern         = regexp.MustCompile(`(?i)(?:Object\.assign\s*\([^,]*,\s*(?:req\.|request\.|params|body|query)|_\.merge\s*\(|lodash\.merge\s*\(|\$\.extend\s*\(true|deepmerge\s*\()`)
	massAssignmentPattern      = regexp.MustCompile(`(?i)(?:\.update\s*\(\s*(?:req\.body|params)|\.create\s*\(\s*(?:req\.body|params)|\bspread\s*\(\s*(?:req\.|props))`)
	jwtWeakAlgPattern          = regexp.MustCompile(`(?i)(?:algorithm\s*[:=]\s*['"](?:none|HS256)['"]|alg\s*[:=]\s*['"]none['"])`)
	hardcodedJWTSecretPattern  = regexp.MustCompile(`(?i)(?:jwt\.sign|jwt\.verify)\s*\([^)]*['"](secret|password|key123|test|sample|example|changeme)['"]\s*\)`)

	// Vendor filename patterns (pre-compiled for hot path)
	vendorHexFilePattern     = regexp.MustCompile(`^[a-f0-9]{8,}\.js$`)
	vendorHexDashFilePattern = regexp.MustCompile(`^[a-f0-9]+-[a-f0-9]+\.js$`)

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
	insecureCookiePattern       = regexp.MustCompile(`(?i)(?:set-cookie|res\.cookie|response\.cookie|cookie\s*[:=])`)
	secureCookieFlagPattern     = regexp.MustCompile(`(?i)(?:secure\s*:\s*true|httpOnly\s*:\s*true|__Host-|__Secure-)`)
	debugModePattern            = regexp.MustCompile(`(?i)(?:debug\s*[:=]\s*true|NODE_ENV\s*[:=!]=?\s*['"]development['"]|app\.debug\s*=\s*True|DEBUG\s*=\s*['"]?(?:True|1|yes)['"]?)`)
	graphqlIntrospectionPattern = regexp.MustCompile(`(?i)(?:introspection\s*:\s*true|__schema\s*{|IntrospectionQuery)`)
	exposedSourceMapPattern     = regexp.MustCompile(`(?i)(?://[#@]\s*sourceMappingURL\s*=|\.map['"]?\s*$)`)
	nosqlInjectionPattern       = regexp.MustCompile(`(?i)(?:\$(?:gt|gte|lt|lte|ne|in|nin|regex|where|exists)\b|\bfind(?:One)?\s*\(\s*\{[^}]*(?:req\.|request\.|params|body|query))`)
	exposedStackTracePattern    = regexp.MustCompile(`(?i)(?:res\.(?:send|json)\s*\(\s*(?:err|error)\.stack|stack\s*:\s*(?:err|error)\.stack|stackTrace\s*[:=])`)
	npmConfigLeakPattern        = regexp.MustCompile(`(?i)(?:_auth\s*=\s*[A-Za-z0-9+/=]{10,}|_authToken\s*=\s*[A-Za-z0-9._-]{10,}|//registry\.npmjs\.org/:_authToken)`)
)

func scanContent(target, content string) []Result {
	collector := resultCollector{
		target: target,
		seen:   make(map[string]struct{}),
	}

	collectSignatureFindings(target, content, collector.add)
	collectHeuristicFindings(target, content, collector.add)

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

// suppressedOnTestFiles lists signature names that are commonly false positives in test/mock files
var suppressedOnTestFiles = map[string]bool{
	"API Key in Variable":        true,
	"Secret in Variable":         true,
	"API Key Generic Detector":   true,
	"Base64 High Entropy String": true,
	"Session ID":                 true,
	"CSRF Token":                 true,
	"Bearer Token Generic":       true,
	"Basic Auth String":          true,
	"OAuth Client Secret":        true,
	"OAuth Client ID":            true,
}

func (c *resultCollector) add(name, priority, match string) {
	cleanMatch := normalizeFinding(match)
	if cleanMatch == "" {
		return
	}

	key := priority + "\x00" + name + "\x00" + cleanMatch
	if _, exists := c.seen[key]; exists {
		return
	}

	c.seen[key] = struct{}{}
	c.results = append(c.results, Result{
		Target:   c.target,
		Name:     name,
		Match:    cleanMatch,
		Priority: priority,
	})
}

func collectSignatureFindings(target, content string, add func(name, priority, match string)) {
	vendorTarget := isLikelyVendorTarget(target)
	testTarget := isLikelyTestOrMockFile(target)
	isMinified := strings.Count(content, "\n") < 8 && len(content) > 6000

	for _, sig := range Signatures {
		if vendorTarget && (sig.Name == "Base64 High Entropy String" || sig.Name == "Localhost Reference" || sig.Name == "Private IP (Internal)" || sig.Name == "Dev/Stage URL" || sig.Name == "Basic Auth String" || sig.Name == "OAuth Client Secret" || sig.Name == "OAuth Client ID" || sig.Name == "Helm Secret Value" || sig.Name == "API Key Generic Detector" || sig.Name == "Secret in Variable" || sig.Name == "API Key in Variable" || sig.Name == "Session ID" || sig.Name == "CSRF Token") {
			continue
		}

		// Suppress noise-prone generic signatures in test/mock files
		if testTarget && suppressedOnTestFiles[sig.Name] {
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

		matches := sig.Regex.FindAllString(content, -1)
		for _, match := range matches {
			// Skip known safe strings (common hashes, test values)
			normalizedMatch := strings.ToLower(strings.TrimSpace(match))
			if knownSafeStrings[normalizedMatch] {
				continue
			}

			// Skip repeated-character strings (e.g. "aaaaaaa...")
			if hasRepeatedChars(normalizedMatch) {
				continue
			}

			if sig.Name == "Base64 High Entropy String" && isHexString(normalizedMatch) {
				continue
			}

			if sig.Name == "Base64 High Entropy String" && isLikelyBase64Noise(normalizedMatch) {
				continue
			}

			// Skip values that look like variable references, not literal secrets
			if isLikelyCodeReference(match) {
				continue
			}

			// For patterns prone to false positives, require minimum entropy
			if minEntropy, ok := lowEntropyPatterns[sig.Name]; ok {
				if shannonEntropy(match) < minEntropy {
					continue
				}
			}

			add(sig.Name, sig.Priority, match)
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
		if text == "" {
			continue
		}

		if isLikelyMinifiedLine(text) {
			continue
		}

		if insecureTLSPattern.MatchString(text) {
			add("TLS Validation Disabled", "HIGH", formatLineEvidence(line.Number, text))
		}

		if postMessageWildcardPattern.MatchString(text) {
			add("Wildcard postMessage Target Origin", "HIGH", formatLineEvidence(line.Number, text))
		}

		if dynamicCodePattern.MatchString(text) {
			add("Dynamic Code Execution Sink", "HIGH", formatLineEvidence(line.Number, text))
		}

		if commandExecPattern.MatchString(text) {
			name := "Command Execution Sink"
			priority := "MEDIUM"
			if shellTruePattern.MatchString(text) || taintSourcePattern.MatchString(text) {
				name = "Potential Command Injection"
				priority = "HIGH"
			}
			add(name, priority, formatLineEvidence(line.Number, text))
		}

		if weakCryptoPattern.MatchString(text) {
			add("Weak Cryptography", "MEDIUM", formatLineEvidence(line.Number, text))
		}

		if mathRandomPattern.MatchString(text) && sensitiveNamePattern.MatchString(text) {
			add("Predictable Security Token Generation", "MEDIUM", formatLineEvidence(line.Number, text))
		}

		if insecureStoragePattern.MatchString(text) && sensitiveNamePattern.MatchString(text) {
			add("Sensitive Data Stored In Web Storage", "MEDIUM", formatLineEvidence(line.Number, text))
		}

		if documentCookiePattern.MatchString(text) && sensitiveNamePattern.MatchString(text) {
			add("Sensitive Token Written To document.cookie", "MEDIUM", formatLineEvidence(line.Number, text))
		}

		if requestPattern.MatchString(text) && taintSourcePattern.MatchString(text) {
			add("Potential SSRF / Untrusted Outbound Request", "MEDIUM", formatLineEvidence(line.Number, text))
		}

		if redirectPattern.MatchString(text) && taintSourcePattern.MatchString(text) {
			add("Potential Open Redirect", "MEDIUM", formatLineEvidence(line.Number, text))
		}

		if fileAccessPattern.MatchString(text) && taintSourcePattern.MatchString(text) {
			add("Potential Path Traversal", "MEDIUM", formatLineEvidence(line.Number, text))
		}

		if prototypePollutionPattern.MatchString(text) {
			add("Potential Prototype Pollution", "HIGH", formatLineEvidence(line.Number, text))
		}

		if objectMergePattern.MatchString(text) {
			add("Object Merge With User Input", "MEDIUM", formatLineEvidence(line.Number, text))
		}

		if templateInjectionPattern.MatchString(text) && taintSourcePattern.MatchString(text) {
			add("Potential Template Injection", "HIGH", formatLineEvidence(line.Number, text))
		}

		if insecureDeserializePattern.MatchString(text) {
			add("Potential Insecure Deserialization", "HIGH", formatLineEvidence(line.Number, text))
		}

		if massAssignmentPattern.MatchString(text) {
			add("Potential Mass Assignment", "MEDIUM", formatLineEvidence(line.Number, text))
		}

		if jwtWeakAlgPattern.MatchString(text) {
			add("JWT Weak Algorithm", "HIGH", formatLineEvidence(line.Number, text))
		}

		if hardcodedJWTSecretPattern.MatchString(text) {
			add("Hardcoded JWT Secret", "CRITICAL", formatLineEvidence(line.Number, text))
		}

		// ── Phase 5: New heuristic detections ──

		if insecureCookiePattern.MatchString(text) && !secureCookieFlagPattern.MatchString(text) {
			add("Insecure Cookie (Missing Secure/HttpOnly)", "MEDIUM", formatLineEvidence(line.Number, text))
		}

		if debugModePattern.MatchString(text) {
			add("Debug Mode Enabled In Production Code", "MEDIUM", formatLineEvidence(line.Number, text))
		}

		if graphqlIntrospectionPattern.MatchString(text) {
			add("GraphQL Introspection Enabled", "MEDIUM", formatLineEvidence(line.Number, text))
		}

		if exposedSourceMapPattern.MatchString(text) {
			add("Exposed Source Map Reference", "LOW", formatLineEvidence(line.Number, text))
		}

		if nosqlInjectionPattern.MatchString(text) && taintSourcePattern.MatchString(text) {
			add("Potential NoSQL Injection", "HIGH", formatLineEvidence(line.Number, text))
		}

		if exposedStackTracePattern.MatchString(text) {
			add("Exposed Stack Trace to Client", "MEDIUM", formatLineEvidence(line.Number, text))
		}

		if npmConfigLeakPattern.MatchString(text) {
			add("NPM Config Leak (_auth / _authToken)", "HIGH", formatLineEvidence(line.Number, text))
		}

		// ReDoS: check JS regex literals and new RegExp() on this line
		checkReDoS(line.Number, text, add)

		if sqlExecutionPattern.MatchString(text) && sqlKeywordPattern.MatchString(text) && dynamicDataPattern.MatchString(text) {
			add("Potential SQL Injection", "HIGH", formatLineEvidence(line.Number, text))
		}

		if xssSinkPattern.MatchString(text) && shouldFlagHTMLSink(text) {
			name := "HTML Injection Sink"
			priority := "MEDIUM"
			if taintSourcePattern.MatchString(text) {
				name = "Potential DOM XSS"
				priority = "HIGH"
			}
			add(name, priority, formatLineEvidence(line.Number, text))
		}

		collectSuspiciousAssignments(line.Number, text, add)
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

	if strings.Contains(identifier, "password") || strings.Contains(identifier, "passwd") {
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

func isLikelyVendorTarget(target string) bool {
	lower := strings.ToLower(target)
	base := strings.ToLower(filepath.Base(target))
	unixBase := strings.ToLower(path.Base(strings.ReplaceAll(target, "\\", "/")))

	vendorMarkers := []string{
		".min.js",
		".chunk.js",
		".xhtml.js",
		"jquery",
		"bootstrap",
		"react",
		"vue",
		"redux",
		"moment",
		"modernizr",
		"datatables",
		"fitvids",
		"migrate",
		"bxslider",
		"i18next",
		"richfaces",
		"chart",
		"vendor",
		"bundle",
		"chunk",
		"node_modules",
		"app.js",
		"all.js",
		"js.js",
		"fontawesome.js",
		"player.js",
		"runtime.js",
		"polyfills.js",
	}

	for _, marker := range vendorMarkers {
		if strings.Contains(lower, marker) || strings.Contains(base, marker) || strings.Contains(unixBase, marker) {
			return true
		}
	}

	if vendorHexFilePattern.MatchString(base) || vendorHexFilePattern.MatchString(unixBase) {
		return true
	}

	if vendorHexDashFilePattern.MatchString(base) || vendorHexDashFilePattern.MatchString(unixBase) {
		return true
	}

	return false
}

func isLikelyMinifiedLine(line string) bool {
	if len(line) < 600 {
		return false
	}

	spaces := 0
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case ' ', '\t':
			spaces++
		}
	}

	return float64(spaces)/float64(len(line)) < 0.02
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
	lower := strings.ToLower(content)
	if strings.Contains(lower, "webpackchunk") || strings.Contains(lower, "webpackjsonp") || strings.Contains(lower, "webpackjsonprlms") {
		return true
	}

	if strings.Count(content, "\n") < 8 && len(content) > 6000 {
		return true
	}

	return false
}
