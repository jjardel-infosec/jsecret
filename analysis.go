package main

import (
	"fmt"
	"math"
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
	// Sequential alphabets (common in charset definitions)
	"0123456789abcdefghijklmnopqrstuv":     true,
	"abcdefghijklmnopqrstuvwxyz012345":     true,
	"0123456789abcdef":                     true,
	"0123456789abcdefghijklmnopqrstuvwxyz": true,
	"abcdefghijklmnopqrstuvwxyz":           true,
	// Common test/example values
	"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx":         true,
	"00000000000000000000000000000000":         true,
	"11111111111111111111111111111111":         true,
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": true,
}

// lowEntropyPatterns are signature names that should require entropy validation
var lowEntropyPatterns = map[string]bool{
	"GitHub OAuth App Secret":    true,
	"Loggly Token":               true,
	"Base64 High Entropy String": true,
	"Mistral API Key":            true,
	"Together AI Key":            true,
	"Algolia API Key":            true,
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
)

func scanContent(target, content string) []Result {
	collector := resultCollector{
		target: target,
		seen:   make(map[string]struct{}),
	}

	collectSignatureFindings(content, collector.add)
	collectHeuristicFindings(target, content, collector.add)

	return collector.results
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

func collectSignatureFindings(content string, add func(name, priority, match string)) {
	for _, sig := range Signatures {
		matches := sig.Regex.FindAllString(content, -1)
		for _, match := range matches {
			// Skip known safe strings (common hashes, test values)
			normalizedMatch := strings.ToLower(strings.TrimSpace(match))
			if knownSafeStrings[normalizedMatch] {
				continue
			}

			if sig.Name == "Base64 High Entropy String" && isHexString(normalizedMatch) {
				continue
			}

			// For patterns prone to false positives, require minimum entropy
			if lowEntropyPatterns[sig.Name] {
				if shannonEntropy(match) < 3.5 {
					continue
				}
			}

			add(sig.Name, sig.Priority, match)
		}
	}
}

func collectHeuristicFindings(target, content string, add func(name, priority, match string)) {
	codeOnly := stripJSComments(content)
	lines := splitCodeLines(codeOnly)
	vendorContext := isLikelyVendorTarget(target)

	if corsWildcardPattern.MatchString(codeOnly) || manualCorsPattern.MatchString(codeOnly) {
		add("CORS Wildcard With Credentials", "HIGH", "origin: '*' with credentials: true")
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

		if vendorContext {
			continue
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
		"replace-me",
		"replace_this",
		"your_token_here",
		"your_secret_here",
		"example",
		"example123",
		"dummy",
		"placeholder",
		"null",
		"undefined",
		"token_here",
		"secret_here",
	}

	for _, placeholder := range placeholders {
		if lower == placeholder {
			return true
		}
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

	vendorMarkers := []string{
		".min.js",
		"jquery",
		"bootstrap",
		"react",
		"vue",
		"redux",
		"moment",
		"chart",
		"vendor",
		"bundle",
		"chunk",
		"node_modules",
	}

	for _, marker := range vendorMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
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
