package main

import (
	"strings"
	"testing"
)

func TestScanContentFindsHeuristicFindings(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		finding  string
		priority string
	}{
		{
			name:     "dom xss",
			content:  `element.innerHTML = location.hash;`,
			finding:  "Potential DOM XSS",
			priority: "HIGH",
		},
		{
			name:     "disabled tls validation",
			content:  `const agent = new https.Agent({ rejectUnauthorized: false });`,
			finding:  "TLS Validation Disabled",
			priority: "HIGH",
		},
		{
			name:     "sql injection",
			content:  "db.query(`SELECT * FROM users WHERE id = ${req.query.id}`);",
			finding:  "Potential SQL Injection",
			priority: "HIGH",
		},
		{
			name:     "hardcoded credential",
			content:  `const clientSecret = "3vOqAq9Jv7F0dS1YxW2Tn4Qp";`,
			finding:  "Potential Hardcoded Credential",
			priority: "HIGH",
		},
		{
			name:     "wildcard postmessage",
			content:  `window.postMessage(payload, "*");`,
			finding:  "Wildcard postMessage Target Origin",
			priority: "HIGH",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			results := scanContent("sample.js", tc.content)
			match := findResult(results, tc.finding)
			if match == nil {
				t.Fatalf("expected finding %q, got %#v", tc.finding, results)
			}
			if match.Priority != tc.priority {
				t.Fatalf("expected priority %q, got %q", tc.priority, match.Priority)
			}
			if tc.finding != "Wildcard postMessage Target Origin" && tc.finding != "CORS Wildcard With Credentials" && !strings.HasPrefix(match.Match, "line ") {
				t.Fatalf("expected line-aware evidence, got %q", match.Match)
			}
		})
	}
}

func TestScanContentAvoidsCommentAndStaticHTMLNoise(t *testing.T) {
	content := `
// eval(userInput)
const html = "<strong>safe</strong>";
element.innerHTML = "<em>trusted</em>";
`

	results := scanContent("sample.js", content)
	if findResult(results, "Dynamic Code Execution Sink") != nil {
		t.Fatalf("unexpected dynamic code execution finding: %#v", results)
	}
	if findResult(results, "Potential DOM XSS") != nil {
		t.Fatalf("unexpected DOM XSS finding: %#v", results)
	}
	if findResult(results, "HTML Injection Sink") != nil {
		t.Fatalf("unexpected HTML injection sink finding: %#v", results)
	}
}

func TestScanContentAvoidsRegexExecFalsePositive(t *testing.T) {
	content := `const results = regex.exec(src);`
	results := scanContent("sample.js", content)

	if findResult(results, "Command Execution Sink") != nil {
		t.Fatalf("unexpected command execution finding: %#v", results)
	}
	if findResult(results, "Potential Command Injection") != nil {
		t.Fatalf("unexpected command injection finding: %#v", results)
	}
}

func TestScanContentSkipsMinifiedHeuristicNoise(t *testing.T) {
	minified := strings.Repeat("a", 700) + " eval(userInput) " + strings.Repeat("b", 700)
	results := scanContent("sample.js", minified)

	if findResult(results, "Dynamic Code Execution Sink") != nil {
		t.Fatalf("unexpected dynamic code finding in minified line: %#v", results)
	}
}

func TestScanContentSkipsNoisyHeuristicsForVendorFiles(t *testing.T) {
	content := `
const r = regex.exec(src);
const x = Object.assign({}, req.body);
const y = value && value.constructor.prototype;
`

	results := scanContent("jquery-3.6.0.min.js", content)

	if findResult(results, "Command Execution Sink") != nil {
		t.Fatalf("unexpected command execution finding for vendor file: %#v", results)
	}
	if findResult(results, "Object Merge With User Input") != nil {
		t.Fatalf("unexpected object merge finding for vendor file: %#v", results)
	}
	if findResult(results, "Potential Prototype Pollution") != nil {
		t.Fatalf("unexpected prototype pollution finding for vendor file: %#v", results)
	}
}

func TestScanContentSkipsHeuristicsForXHTMLVendorFiles(t *testing.T) {
	content := `
window.postMessage(payload, "*");
element.innerHTML = location.hash;
eval(userInput);
`

	results := scanContent("jquery.fitvids.js.xhtml.js", content)
	if len(results) != 0 {
		t.Fatalf("expected no heuristic findings for xhtml vendor file, got %#v", results)
	}
}

func TestScanContentSkipsHeuristicsForWebpackBundles(t *testing.T) {
	content := `(self.webpackChunk=self.webpackChunk||[]).push([[1],{1:function(){eval(userInput);window.postMessage(payload,"*");}}]);`
	results := scanContent("app.js", content)
	if len(results) != 0 {
		t.Fatalf("expected no heuristic findings for webpack bundle, got %#v", results)
	}
}

func TestScanContentSkipsBase64AlphabetNoise(t *testing.T) {
	content := `const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";`
	results := scanContent("vendor.js", content)
	if findResult(results, "Base64 High Entropy String") != nil {
		t.Fatalf("unexpected base64 noise finding: %#v", results)
	}
}

func TestScanContentSkipsNoisySignaturesForLinuxVendorPath(t *testing.T) {
	content := `
"username":"john",
"password":"12345678",
"client_secret":"40bd001563085fc35165329ea1ff5c5ecbdbbeef",
"client_id":"40bd001563085fc35165329ea1ff5c5ecbdbbeef"
`

	results := scanContent("/home/kali/tools/recon-web/data/runs/x/06-JS_DOWNLOAD/site/main.4c3332c6.chunk.js", content)

	if findResult(results, "Basic Auth String") != nil {
		t.Fatalf("unexpected basic auth finding for vendor linux path: %#v", results)
	}
	if findResult(results, "OAuth Client Secret") != nil {
		t.Fatalf("unexpected oauth secret finding for vendor linux path: %#v", results)
	}
	if findResult(results, "OAuth Client ID") != nil {
		t.Fatalf("unexpected oauth id finding for vendor linux path: %#v", results)
	}
}

func findResult(results []Result, name string) *Result {
	for i := range results {
		if results[i].Name == name {
			return &results[i]
		}
	}
	return nil
}

func assertFinding(t *testing.T, results []Result, name string) {
	t.Helper()
	if findResult(results, name) == nil {
		t.Errorf("expected finding %q, got none", name)
	}
}

// ── Signature Detection Tests ──

func TestSignatureDetectsAWSAccessKeyID(t *testing.T) {
	content := `const key = "AKIAIOSFODNN7EXAMPLE";`
	results := scanContent("config.js", content)
	if findResult(results, "AWS Access Key ID") == nil {
		t.Fatalf("expected AWS Access Key ID finding, got %#v", results)
	}
}

func TestSignatureDetectsGitHubToken(t *testing.T) {
	content := `const token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234";`
	results := scanContent("deploy.js", content)
	if findResult(results, "GitHub Token") == nil {
		t.Fatalf("expected GitHub Token finding, got %#v", results)
	}
}

func TestSignatureDetectsSlackWebhook(t *testing.T) {
	content := `const webhook = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXX";`
	results := scanContent("notify.js", content)
	if findResult(results, "Slack Webhook URL") == nil {
		t.Fatalf("expected Slack Webhook URL finding, got %#v", results)
	}
}

func TestSignatureDetectsOpenAIProjectKey(t *testing.T) {
	content := `const key = "sk-proj-` + strings.Repeat("a1B2c3D4", 11) + `";`
	results := scanContent("ai.js", content)
	if findResult(results, "OpenAI Project Key") == nil {
		t.Fatalf("expected OpenAI Project Key finding, got %#v", results)
	}
}

func TestSignatureDetectsTerraformCloudToken(t *testing.T) {
	content := `const tf = "atlasv1.` + strings.Repeat("abcdef12", 8) + `";`
	results := scanContent("infra.js", content)
	if findResult(results, "Terraform Cloud Token") == nil {
		t.Fatalf("expected Terraform Cloud Token finding, got %#v", results)
	}
}

func TestSignatureDetectsPrivateKey(t *testing.T) {
	content := `const pk = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAK...";`
	results := scanContent("keys.js", content)
	if findResult(results, "Private Key Block") == nil {
		t.Fatalf("expected Private Key Block finding, got %#v", results)
	}
}

func TestSignatureDetectsJWT(t *testing.T) {
	content := `const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";`
	results := scanContent("auth.js", content)
	if findResult(results, "JWT Token") == nil {
		t.Fatalf("expected JWT Token finding, got %#v", results)
	}
}

func TestSignatureDetectsMongoDBURI(t *testing.T) {
	content := `const uri = "mongodb+srv://admin:secret@cluster0.abc.mongodb.net/mydb";`
	results := scanContent("db.js", content)
	if findResult(results, "MongoDB Connection URI") == nil {
		t.Fatalf("expected MongoDB Connection URI finding, got %#v", results)
	}
}

func TestSignatureDetectsxAIGrokKey(t *testing.T) {
	content := `const key = "xai-` + strings.Repeat("abcdefAB", 6) + `";`
	results := scanContent("ai.js", content)
	if findResult(results, "xAI Grok API Key") == nil {
		t.Fatalf("expected xAI Grok API Key finding, got %#v", results)
	}
}

func TestSignatureDetectsPineconeKey(t *testing.T) {
	content := `const key = "pcsk_` + strings.Repeat("aBcDeFgH", 6) + `";`
	results := scanContent("vector.js", content)
	if findResult(results, "Pinecone API Key") == nil {
		t.Fatalf("expected Pinecone API Key finding, got %#v", results)
	}
}

// ── False Positive Regression Tests ──

func TestFPSkipsPlaceholderValues(t *testing.T) {
	content := `const apiSecret = "changeme";`
	results := scanContent("config.js", content)
	if findResult(results, "Potential Hardcoded Credential") != nil {
		t.Fatalf("should skip placeholder 'changeme', got %#v", results)
	}
}

func TestFPSkipsTemplateExpressions(t *testing.T) {
	content := `const apiSecret = "${API_SECRET}";`
	results := scanContent("config.js", content)
	if findResult(results, "Potential Hardcoded Credential") != nil {
		t.Fatalf("should skip template expression, got %#v", results)
	}
}

func TestFPSkipsProcessEnvReferences(t *testing.T) {
	content := `const secret = process.env.SECRET_KEY;`
	results := scanContent("config.js", content)
	// Should NOT detect "Potential Hardcoded Credential" for process.env references
	for _, r := range results {
		if r.Name == "Potential Hardcoded Credential" && strings.Contains(r.Match, "process.env") {
			t.Fatalf("should skip process.env references, got %#v", results)
		}
	}
}

func TestFPSkipsRepeatedCharStrings(t *testing.T) {
	content := `const token = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";`
	results := scanContent("config.js", content)
	// Should not trigger hardcoded credential for all-a string
	if findResult(results, "Potential Hardcoded Credential") != nil {
		t.Fatalf("should skip repeated char strings, got %#v", results)
	}
}

func TestFPSkipsKnownSafeHashes(t *testing.T) {
	content := `const hash = "da39a3ee5e6b4b0d3255bfef95601890afd80709";`
	results := scanContent("utils.js", content)
	if findResult(results, "GitHub OAuth App Secret") != nil {
		t.Fatalf("should skip known safe SHA1 hash, got %#v", results)
	}
}

func TestFPSkipsKnownSafeQuotedBase64(t *testing.T) {
	content := `const encoded = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz0123456789+/=";`
	results := scanContent("bundle.js", content)
	if findResult(results, "Base64 High Entropy String") != nil {
		t.Fatalf("should skip known safe quoted base64-like string, got %#v", results)
	}
}

func TestFPSkipsPlaceholderSecretValues(t *testing.T) {
	content := `const secret = "replace_me_in_production";`
	results := scanContent("config.js", content)
	if findResult(results, "Secret in Variable") != nil {
		t.Fatalf("should skip placeholder secret value, got %#v", results)
	}
	if findResult(results, "API Key Generic Detector") != nil {
		t.Fatalf("should skip placeholder generic secret value, got %#v", results)
	}
}

func TestFPSkipsPlaceholderSessionID(t *testing.T) {
	content := `const session_id = "sample_session_id_value";`
	results := scanContent("config.js", content)
	if findResult(results, "Session ID") != nil {
		t.Fatalf("should skip placeholder session id value, got %#v", results)
	}
}

// ── New Heuristic Tests ──

func TestHeuristicDetectsHardcodedJWTSecret(t *testing.T) {
	content := `const token = jwt.sign(payload, "secret");`
	results := scanContent("auth.js", content)
	if findResult(results, "Hardcoded JWT Secret") == nil {
		t.Fatalf("expected Hardcoded JWT Secret finding, got %#v", results)
	}
}

func TestHeuristicDetectsCORSOriginReflection(t *testing.T) {
	content := `res.setHeader("Access-Control-Allow-Origin", req.headers.origin);`
	results := scanContent("server.js", content)
	if findResult(results, "CORS Origin Reflection (Dynamic)") == nil {
		t.Fatalf("expected CORS Origin Reflection finding, got %#v", results)
	}
}

func TestHeuristicDetectsDebugMode(t *testing.T) {
	content := `const mode = NODE_ENV = "development";`
	results := scanContent("server.js", content)
	if findResult(results, "Debug Mode Enabled In Production Code") == nil {
		t.Fatalf("expected Debug Mode finding, got %#v", results)
	}
}

func TestHeuristicSkipsDebugModeComparisons(t *testing.T) {
	content := `if (NODE_ENV === "development") { console.log("dev only"); }`
	results := scanContent("server.js", content)
	if findResult(results, "Debug Mode Enabled In Production Code") != nil {
		t.Fatalf("should not flag debug mode comparisons, got %#v", results)
	}
}

func TestHeuristicDetectsExposedStackTrace(t *testing.T) {
	content := `app.use((err, req, res, next) => { res.json(err.stack); });`
	results := scanContent("errors.js", content)
	if findResult(results, "Exposed Stack Trace to Client") == nil {
		t.Fatalf("expected Exposed Stack Trace finding, got %#v", results)
	}
}

func TestHeuristicDetectsPrototypePollution(t *testing.T) {
	content := `obj.__proto__ = malicious;`
	results := scanContent("util.js", content)
	if findResult(results, "Potential Prototype Pollution") == nil {
		t.Fatalf("expected Prototype Pollution finding, got %#v", results)
	}
}

func TestHeuristicDetectsGraphQLIntrospection(t *testing.T) {
	content := `const schema = { introspection: true };`
	results := scanContent("graphql.js", content)
	if findResult(results, "GraphQL Introspection Enabled") == nil {
		t.Fatalf("expected GraphQL Introspection finding, got %#v", results)
	}
}

func TestHeuristicSkipsGraphQLIntrospectionQueryReferences(t *testing.T) {
	content := `import { IntrospectionQuery } from "graphql"; const queryName = IntrospectionQuery;`
	results := scanContent("graphql.js", content)
	if findResult(results, "GraphQL Introspection Enabled") != nil {
		t.Fatalf("should not flag GraphQL IntrospectionQuery references alone, got %#v", results)
	}
}

func TestHeuristicDetectsNPMConfigLeak(t *testing.T) {
	content := `const npmrc = "_authToken=npm_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456";`
	results := scanContent("config.js", content)
	if findResult(results, "NPM Config Leak (_auth / _authToken)") == nil {
		t.Fatalf("expected NPM Config Leak finding, got %#v", results)
	}
}

// ── Prefix Pre-filtering Test ──

func TestPrefixPreFilterSkipsRegexWhenPrefixAbsent(t *testing.T) {
	// Content with no "AKIA" prefix → AWS Access Key ID regex should be skipped
	content := `const x = "notanawskey_but_has_16_chars";`
	results := scanContent("test.js", content)
	if findResult(results, "AWS Access Key ID") != nil {
		t.Fatalf("expected no AWS finding when prefix absent, got %#v", results)
	}
}

// ── ReDoS Detection Tests ──

func TestReDoSDetectsNestedQuantifierLiteral(t *testing.T) {
	content := `const re = /(a+)+$/;`
	results := scanContent("validator.js", content)
	if findResult(results, "Potential ReDoS (Catastrophic Backtracking)") == nil {
		t.Fatalf("expected ReDoS finding for (a+)+, got %#v", results)
	}
}

func TestReDoSDetectsNewRegExpNestedQuantifier(t *testing.T) {
	content := `const re = new RegExp("(\\d+)+");`
	results := scanContent("parser.js", content)
	if findResult(results, "Potential ReDoS (Catastrophic Backtracking)") == nil {
		t.Fatalf("expected ReDoS finding for new RegExp nested quantifier, got %#v", results)
	}
}

func TestReDoSDetectsTripleGreedy(t *testing.T) {
	content := `const re = /.*a.*b.*c/;`
	results := scanContent("search.js", content)
	if findResult(results, "Potential ReDoS (Catastrophic Backtracking)") == nil {
		t.Fatalf("expected ReDoS finding for triple greedy .*.*.*,  got %#v", results)
	}
}

func TestReDoSDetectsStarStar(t *testing.T) {
	content := `const email = new RegExp("[a-z]+.*[a-z]+@example.com");`
	results := scanContent("form.js", content)
	if findResult(results, "Potential ReDoS (Catastrophic Backtracking)") == nil {
		t.Fatalf("expected ReDoS finding for overlapping quantifiers, got %#v", results)
	}
}

func TestReDoSSkipsSafeRegex(t *testing.T) {
	content := `const re = /^[a-z0-9]+$/;`
	results := scanContent("util.js", content)
	if findResult(results, "Potential ReDoS (Catastrophic Backtracking)") != nil {
		t.Fatalf("should not flag safe regex, got %#v", results)
	}
}

// ── New Signature Tests (v3.0 expansion) ──

func TestSignatureDetectsSquareAccessToken(t *testing.T) {
	content := `const token = "sq0atp-AbCdEfGhIjKlMnOpQrStUv";`
	results := scanContent("payment.js", content)
	if findResult(results, "Square Access Token") == nil {
		t.Fatalf("expected Square Access Token finding, got %#v", results)
	}
}

func TestSignatureDetectsRabbitMQURI(t *testing.T) {
	content := `const uri = "amqps://user:pass@rabbit.example.com:5671/vhost";`
	results := scanContent("queue.js", content)
	if findResult(results, "RabbitMQ URI") == nil {
		t.Fatalf("expected RabbitMQ URI finding, got %#v", results)
	}
}

func TestSignatureDetectsMailchimpKey(t *testing.T) {
	content := `const mc = "abcdef1234567890abcdef1234567890-us14";`
	results := scanContent("newsletter.js", content)
	if findResult(results, "Mailchimp API Key") == nil {
		t.Fatalf("expected Mailchimp API Key finding, got %#v", results)
	}
}

func TestSignatureDetectsLaunchDarklySDKKey(t *testing.T) {
	content := `const ld = "sdk-a1b2c3d4-e5f6-7890-abcd-ef1234567890";`
	results := scanContent("flags.js", content)
	if findResult(results, "LaunchDarkly SDK Key") == nil {
		t.Fatalf("expected LaunchDarkly SDK Key finding, got %#v", results)
	}
}

func TestSignatureDetectsDynatraceToken(t *testing.T) {
	content := `const dt = "dt0c01.ST2EY72KQINMH574WMNVI7YN.` + strings.Repeat("G3DFPBEJYMODIDAEX454M7YWBUVEFOWKPRVMWFSS324FHH", 2)[:64] + `";`
	results := scanContent("monitoring.js", content)
	if findResult(results, "Dynatrace API Token") == nil {
		t.Fatalf("expected Dynatrace API Token finding, got %#v", results)
	}
}

func TestSignatureDetectsBuildkiteAgentToken(t *testing.T) {
	content := `const bk = "bkagent_` + strings.Repeat("aBcDeFgH", 6) + `";`
	results := scanContent("ci.js", content)
	if findResult(results, "Buildkite Agent Token") == nil {
		t.Fatalf("expected Buildkite Agent Token finding, got %#v", results)
	}
}

func TestSignatureDetects1PasswordToken(t *testing.T) {
	content := `const op = "ops_` + strings.Repeat("A1b2C3d4E5", 5) + `";`
	results := scanContent("secrets.js", content)
	if findResult(results, "1Password Connect Token") == nil {
		t.Fatalf("expected 1Password Connect Token finding, got %#v", results)
	}
}

func TestSignatureDetectsNeonDBToken(t *testing.T) {
	content := `const db = "neon_` + strings.Repeat("aBcDeFgH", 5) + `";`
	results := scanContent("db.js", content)
	if findResult(results, "Neon Database Token") == nil {
		t.Fatalf("expected Neon Database Token finding, got %#v", results)
	}
}

func TestSignatureDetectsSentryDSN(t *testing.T) {
	content := `const dsn = "https://abc123def456@o123456.ingest.sentry.io/789012";`
	results := scanContent("error.js", content)
	if findResult(results, "Sentry DSN") == nil {
		t.Fatalf("expected Sentry DSN finding, got %#v", results)
	}
}

func TestSignatureDetectsStripeSecretKey(t *testing.T) {
	content := `const key = "sk_live_abcdefghijklmnopqrstuvwx";`
	results := scanContent("billing.js", content)
	if findResult(results, "Stripe Secret Key") == nil {
		t.Fatalf("expected Stripe Secret Key finding, got %#v", results)
	}
}

// ── Test/Mock File FP Suppression ──

func TestSuppressGenericSigsOnTestFiles(t *testing.T) {
	content := `const apiKey = "sk_test_abcdefghijklmnopqrstuvwx";`
	// In a test file, generic signatures should be suppressed
	results := scanContent("src/__tests__/auth.test.js", content)
	if findResult(results, "API Key Generic Detector") != nil {
		t.Fatalf("expected generic API key sig to be suppressed in test file, got %#v", results)
	}
}

func TestSpecificSigsStillFireOnTestFiles(t *testing.T) {
	// Real provider-specific tokens should still be detected in test files
	content := `const key = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234";`
	results := scanContent("tests/integration.spec.js", content)
	if findResult(results, "GitHub Token") == nil {
		t.Fatalf("expected GitHub Token to still fire in test file, got %#v", results)
	}
}

func TestSuppressLegacySigsOnTestFiles(t *testing.T) {
	content := `{"Authorization":"bearer abcdefghijklmnopqrstuvwxyz1234567890"}`
	results := scanContent("fixtures/auth.mock.js", content)
	if findResult(results, "JJARDEL (Legacy)") != nil {
		t.Fatalf("expected JJARDEL legacy sig to be suppressed in test file, got %#v", results)
	}
}

func TestSuppressLegacySigsOnEnvExample(t *testing.T) {
	content := "AKIAABCDEFGHIJKLMNOP\nconst secret = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\";"
	results := scanContent(".env.example", content)
	if findResult(results, "SEGREDOS WAR (Legacy)") != nil {
		t.Fatalf("expected SEGREDOS WAR legacy sig to be suppressed in env example, got %#v", results)
	}
}

// ── Bcrypt/Argon2 Hash FP Suppression ──

func TestFPSkipsBcryptHashedPasswords(t *testing.T) {
	content := `const passwordHash = "$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy";`
	results := scanContent("auth.js", content)
	if findResult(results, "Potential Hardcoded Credential") != nil {
		t.Fatalf("expected bcrypt hash to be skipped, got %#v", results)
	}
}

func TestFPSkipsArgon2HashedPasswords(t *testing.T) {
	content := `const passwordHash = "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+daw";`
	results := scanContent("auth.js", content)
	if findResult(results, "Potential Hardcoded Credential") != nil {
		t.Fatalf("expected argon2 hash to be skipped, got %#v", results)
	}
}

// ── File Path / CSS FP Suppression ──

func TestFPSkipsFilePathValues(t *testing.T) {
	content := `const secretPath = "/usr/local/etc/secrets/config.json";`
	results := scanContent("config.js", content)
	if findResult(results, "Potential Hardcoded Credential") != nil {
		t.Fatalf("expected file path to be skipped, got %#v", results)
	}
}

// ── Benchmark ──

// ── Phase 2: False Positive Regression Tests ──

func TestFPSkipsUUIDInGenericPatterns(t *testing.T) {
	content := `const apiKey = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";`
	results := scanContent("config.js", content)
	if findResult(results, "API Key Generic Detector") != nil {
		t.Fatalf("should skip UUID-like value in generic pattern, got %#v", results)
	}
}

func TestFPSkipsPureNumericInGenericPatterns(t *testing.T) {
	content := `const token = "12345678901234567890";`
	results := scanContent("config.js", content)
	if findResult(results, "API Key Generic Detector") != nil {
		t.Fatalf("should skip pure numeric value in generic pattern, got %#v", results)
	}
}

func TestFPSkipsEnvExampleFiles(t *testing.T) {
	content := `const apiKey = "sk_test_abcdefghijklmnopqrstuvwx";`
	results := scanContent(".env.example", content)
	if findResult(results, "API Key Generic Detector") != nil {
		t.Fatalf("should suppress generic sigs in .env.example, got %#v", results)
	}
}

func TestFPSkipsImportMetaEnv(t *testing.T) {
	content := `const key = import.meta.env.VITE_API_KEY;`
	results := scanContent("config.js", content)
	for _, r := range results {
		if r.Name == "Potential Hardcoded Credential" && strings.Contains(r.Match, "import.meta.env") {
			t.Fatalf("should skip import.meta.env references, got %#v", results)
		}
	}
}

func TestFPPasswordAssignmentSkipsCommonWords(t *testing.T) {
	tests := []string{
		`password: "disabled"`,
		`password = "required"`,
		`pwd: "optional"`,
		`password: "undefined"`,
	}
	for _, tc := range tests {
		results := scanContent("config.js", tc)
		if findResult(results, "Password Assignment") != nil {
			t.Fatalf("should skip common word in password assignment %q, got %#v", tc, results)
		}
	}
}

func TestPasswordAssignmentStillDetectsRealPasswords(t *testing.T) {
	content := `const password = "SuperS3cr3t!Pass";`
	results := scanContent("config.js", content)
	if findResult(results, "Password Assignment") == nil {
		t.Fatalf("expected Password Assignment finding for real password, got %#v", results)
	}
}

func TestFPTinybirdNowRequiresContext(t *testing.T) {
	// Bare "p.something" should NOT match without tinybird context
	content := `const version = "p.abcdefghijklmnopqrstuvwxyz";`
	results := scanContent("config.js", content)
	if findResult(results, "Tinybird API Token") != nil {
		t.Fatalf("should not flag bare p. string as Tinybird, got %#v", results)
	}
}

func TestTinybirdDetectsWithContext(t *testing.T) {
	content := `const TINYBIRD_TOKEN = "p.abcdefghijklmnopqrstuvwxyz";`
	results := scanContent("config.js", content)
	if findResult(results, "Tinybird API Token") == nil {
		t.Fatalf("expected Tinybird finding with context, got %#v", results)
	}
}

func TestFPResendRequiresLongerMatch(t *testing.T) {
	// Short "re_" prefixed strings should not match
	content := `const re_matchPattern = "something";`
	results := scanContent("utils.js", content)
	if findResult(results, "Resend API Key") != nil {
		t.Fatalf("should not flag short re_ strings, got %#v", results)
	}
}

func TestResendDetectsRealKey(t *testing.T) {
	content := `const key = "re_` + strings.Repeat("aBcDeFgH", 4) + `x1";`
	results := scanContent("email.js", content)
	if findResult(results, "Resend API Key") == nil {
		t.Fatalf("expected Resend API Key finding for real key, got %#v", results)
	}
}

func TestFPVaultLegacyNowHasPrefix(t *testing.T) {
	// A minified JS path like "module.s.abcdefghijklmnopqrstuvwx" should not match
	content := `module.s.abcdefghijklmnopqrstuvwxyz1234`
	results := scanContent("bundle.js", content)
	if findResult(results, "Vault Token (Legacy)") != nil {
		t.Fatalf("should not flag dotted access as Vault token, got %#v", results)
	}
}

func TestSpecificSigsStillFireOnEnvExample(t *testing.T) {
	// Real provider-specific tokens should still be detected in .env.example
	content := `GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234`
	results := scanContent(".env.example", content)
	if findResult(results, "GitHub Token") == nil {
		t.Fatalf("expected GitHub Token to still fire in .env.example, got %#v", results)
	}
}

func TestBearerTokenGenericSkipsPlaceholder(t *testing.T) {
	content := `Authorization: Bearer token`
	results := scanContent("headers.txt", content)
	if findResult(results, "Bearer Token Generic") != nil {
		t.Fatalf("should skip placeholder bearer token, got %#v", results)
	}
}

func TestBearerTokenGenericDetectsLongToken(t *testing.T) {
	content := `Authorization: Bearer abcdef1234567890qrstuvwxyzABCD`
	results := scanContent("headers.txt", content)
	assertFinding(t, results, "Bearer Token Generic")
}

func TestCookieNameGenericSkipsNonAuthCookie(t *testing.T) {
	content := `Set-Cookie: theme=dark; Path=/; SameSite=Lax`
	results := scanContent("headers.txt", content)
	if findResult(results, "Cookie Name Generic") != nil {
		t.Fatalf("should skip non-auth cookie names, got %#v", results)
	}
}

func TestCookieNameGenericDetectsSessionCookie(t *testing.T) {
	content := `Set-Cookie: sessionid=abc123xyz789; Path=/; HttpOnly`
	results := scanContent("headers.txt", content)
	assertFinding(t, results, "Cookie Name Generic")
}

func TestCSRFSkipsUnquotedReference(t *testing.T) {
	content := `const csrfToken = csrfValueFromMeta`
	results := scanContent("config.js", content)
	if findResult(results, "CSRF Token") != nil {
		t.Fatalf("should skip csrf variable reference, got %#v", results)
	}
}

func TestCSRFDetectsQuotedLiteral(t *testing.T) {
	content := `const csrfToken = "AbcDef123456Xyz"`
	results := scanContent("config.js", content)
	assertFinding(t, results, "CSRF Token")
}

// ── Phase 3: Bug Bounty Recon Detection Tests ──

func TestSignatureDetectsCredentialsInURL(t *testing.T) {
	content := `const db = "https://admin:s3cret@db.example.com:5432/mydb";`
	results := scanContent("config.js", content)
	if findResult(results, "Credentials in URL") == nil {
		t.Fatalf("expected Credentials in URL finding, got %#v", results)
	}
}

func TestSignatureDetectsAWSMetadataEndpoint(t *testing.T) {
	content := `fetch("http://169.254.169.254/latest/meta-data/iam/security-credentials/");`
	results := scanContent("ssrf.js", content)
	if findResult(results, "Cloud Metadata Endpoint (AWS)") == nil {
		t.Fatalf("expected Cloud Metadata Endpoint (AWS) finding, got %#v", results)
	}
}

func TestSignatureDetectsGCPMetadataEndpoint(t *testing.T) {
	content := `const url = "http://metadata.google.internal/computeMetadata/v1/project/project-id";`
	results := scanContent("gcp.js", content)
	if findResult(results, "Cloud Metadata Endpoint (GCP)") == nil {
		t.Fatalf("expected Cloud Metadata Endpoint (GCP) finding, got %#v", results)
	}
}

func TestSignatureDetectsS3BucketURL(t *testing.T) {
	content := `const bucket = "https://my-bucket.s3.us-east-1.amazonaws.com/data.csv";`
	results := scanContent("upload.js", content)
	if findResult(results, "AWS S3 Bucket URL (HTTP)") == nil {
		t.Fatalf("expected AWS S3 Bucket URL (HTTP) finding, got %#v", results)
	}
}

func TestSignatureDetectsGCSBucketURL(t *testing.T) {
	content := `const url = "https://storage.googleapis.com/my-public-bucket/file.zip";`
	results := scanContent("storage.js", content)
	if findResult(results, "GCS Bucket URL") == nil {
		t.Fatalf("expected GCS Bucket URL finding, got %#v", results)
	}
}

func TestSignatureDetectsAzureBlobURL(t *testing.T) {
	content := `const blob = "https://myaccount.blob.core.windows.net/container/file";`
	results := scanContent("azure.js", content)
	if findResult(results, "Azure Blob Storage URL") == nil {
		t.Fatalf("expected Azure Blob Storage URL finding, got %#v", results)
	}
}

func TestSignatureDetectsExposedSwagger(t *testing.T) {
	tests := []string{
		`const docs = "/swagger-ui";`,
		`fetch("/api-docs")`,
		`const endpoint = "swagger.json";`,
		`route("/graphiql")`,
	}
	for _, tc := range tests {
		results := scanContent("routes.js", tc)
		if findResult(results, "Exposed Swagger/OpenAPI") == nil {
			t.Fatalf("expected Exposed Swagger/OpenAPI finding for %q, got %#v", tc, results)
		}
	}
}

func TestSignatureDetectsWebSocketWithToken(t *testing.T) {
	content := `const ws = new WebSocket("wss://api.example.com/ws?token=eyJhbGciOiJIUzI1NiJ9");`
	results := scanContent("realtime.js", content)
	if findResult(results, "WebSocket URL with Token") == nil {
		t.Fatalf("expected WebSocket URL with Token finding, got %#v", results)
	}
}

func TestSignatureDetectsInternalEmail(t *testing.T) {
	content := `const admin = "admin@internal.corp";`
	results := scanContent("config.js", content)
	if findResult(results, "Internal Email Address") == nil {
		t.Fatalf("expected Internal Email Address finding, got %#v", results)
	}
}

func TestSignatureDetectsInternalDebugPath(t *testing.T) {
	tests := []string{
		`fetch("/internal/config")`,
		`app.get("/debug/pprof")`,
		`route("/metrics")`,
		`path: "/actuator/health"`,
		`app.get("/admin/users")`,
	}
	for _, tc := range tests {
		results := scanContent("routes.js", tc)
		if findResult(results, "Internal/Debug Path") == nil {
			t.Fatalf("expected Internal/Debug Path finding for %q, got %#v", tc, results)
		}
	}
}

func TestSignatureDetectsOIDCRedirectToLocalhost(t *testing.T) {
	content := `redirect_uri = "http://localhost:3000/callback";`
	results := scanContent("oauth.js", content)
	if findResult(results, "Hardcoded OIDC/OAuth Redirect URI") == nil {
		t.Fatalf("expected Hardcoded OIDC/OAuth Redirect URI finding, got %#v", results)
	}
}

func TestSignatureDetectsCerebrasKey(t *testing.T) {
	content := `const key = "csk-` + strings.Repeat("aBcDeFgH", 6) + `";`
	results := scanContent("ai.js", content)
	if findResult(results, "Cerebras API Key") == nil {
		t.Fatalf("expected Cerebras API Key finding, got %#v", results)
	}
}

func TestSignatureDetectsOpenRouterKey(t *testing.T) {
	content := `const key = "sk-or-v1-` + strings.Repeat("ab12cd34", 8) + `";`
	results := scanContent("ai.js", content)
	if findResult(results, "OpenRouter API Key") == nil {
		t.Fatalf("expected OpenRouter API Key finding, got %#v", results)
	}
}

func TestSignatureDetectsLangchainKey(t *testing.T) {
	content := `const key = "ls__` + strings.Repeat("ab12cd34", 4) + `";`
	results := scanContent("langchain.js", content)
	if findResult(results, "Langchain API Key") == nil {
		t.Fatalf("expected Langchain API Key finding, got %#v", results)
	}
}

func TestCredentialsInURLSkipsPlainHTTPS(t *testing.T) {
	// Normal HTTPS URLs without credentials should not match
	content := `const url = "https://api.example.com/v1/users";`
	results := scanContent("api.js", content)
	if findResult(results, "Credentials in URL") != nil {
		t.Fatalf("should not flag plain URLs as credentials in URL, got %#v", results)
	}
}

func TestInternalEmailSkipsPublicDomains(t *testing.T) {
	content := `const email = "user@example.com";`
	results := scanContent("contact.js", content)
	if findResult(results, "Internal Email Address") != nil {
		t.Fatalf("should not flag public domain emails, got %#v", results)
	}
}

// ── Additional heuristic coverage tests ──

func TestHeuristicDetectsInsecureCookie(t *testing.T) {
	content := `res.cookie("session", token, { maxAge: 3600 });`
	results := scanContent("auth.js", content)
	if findResult(results, "Insecure Cookie (Missing Secure/HttpOnly)") == nil {
		t.Fatalf("expected Insecure Cookie finding, got %#v", results)
	}
}

func TestHeuristicSkipsSecureCookie(t *testing.T) {
	content := `res.cookie("session", token, { httpOnly: true, secure: true });`
	results := scanContent("auth.js", content)
	if findResult(results, "Insecure Cookie (Missing Secure/HttpOnly)") != nil {
		t.Fatalf("should skip secure cookie, got %#v", results)
	}
}

func TestHeuristicDetectsNoSQLInjection(t *testing.T) {
	content := `db.find({ $where: req.body.filter });`
	results := scanContent("api.js", content)
	if findResult(results, "Potential NoSQL Injection") == nil {
		t.Fatalf("expected NoSQL Injection finding, got %#v", results)
	}
}

func TestHeuristicDetectsWildcardPostMessage(t *testing.T) {
	content := `window.postMessage(data, "*");`
	results := scanContent("messaging.js", content)
	if findResult(results, "Wildcard postMessage Target Origin") == nil {
		t.Fatalf("expected postMessage finding, got %#v", results)
	}
}

func TestHeuristicDetectsWeakCrypto(t *testing.T) {
	content := `const hash = crypto.createHash("md5").update(data).digest("hex");`
	results := scanContent("crypto.js", content)
	if findResult(results, "Weak Cryptography") == nil {
		t.Fatalf("expected Weak Crypto finding, got %#v", results)
	}
}

func TestHeuristicDetectsTemplateInjection(t *testing.T) {
	content := `const output = nunjucks.render(req.query.template);`
	results := scanContent("views.js", content)
	if findResult(results, "Potential Template Injection") == nil {
		t.Fatalf("expected Template Injection finding, got %#v", results)
	}
}

func TestHeuristicDetectsExposedSourceMap(t *testing.T) {
	content := `//# sourceMappingURL=app.bundle.js.map`
	results := scanContent("config.js", content)
	if findResult(results, "Exposed Source Map Reference") == nil {
		t.Fatalf("expected Source Map finding, got %#v", results)
	}
}

func TestHeuristicSkipsGenericMapStringReferences(t *testing.T) {
	content := `const mapFile = "app.bundle.js.map"`
	results := scanContent("config.js", content)
	if findResult(results, "Exposed Source Map Reference") != nil {
		t.Fatalf("should not flag generic .map string references, got %#v", results)
	}
}

func TestHeuristicDetectsMassAssignment(t *testing.T) {
	content := `User.update(req.body);`
	results := scanContent("users.js", content)
	if findResult(results, "Potential Mass Assignment") == nil {
		t.Fatalf("expected Mass Assignment finding, got %#v", results)
	}
}

func TestVendorDetectionSkipsGenericSigs(t *testing.T) {
	// Generic sigs like Base64 High Entropy should be suppressed on vendor paths
	content := `const x = "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODkw";`
	results := scanContent("vendor/jquery.min.js", content)
	if findResult(results, "Base64 High Entropy String") != nil {
		t.Fatalf("should suppress generic sigs in vendor files, got %#v", results)
	}
}

func TestSarifLevel(t *testing.T) {
	tests := []struct {
		priority string
		expected string
	}{
		{"CRITICAL", "error"},
		{"HIGH", "error"},
		{"MEDIUM", "warning"},
		{"LOW", "note"},
		{"UNKNOWN", "note"},
	}
	for _, tt := range tests {
		got := sarifLevel(tt.priority)
		if got != tt.expected {
			t.Errorf("sarifLevel(%q) = %q, want %q", tt.priority, got, tt.expected)
		}
	}
}

func TestSanitizeRuleID(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"Potential DOM XSS", "Potential-DOM-XSS"},
		{"Insecure Cookie (Missing Secure/HttpOnly)", "Insecure-Cookie-Missing-Secure/HttpOnly"},
		{"Simple", "Simple"},
	}
	for _, tt := range tests {
		got := sanitizeRuleID(tt.input)
		if got != tt.expected {
			t.Errorf("sanitizeRuleID(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

// ── extractLineNumber tests ──

func TestExtractLineNumber(t *testing.T) {
	tests := []struct {
		input    string
		expected int
	}{
		{"line 42: element.innerHTML = location.hash;", 42},
		{"line 1: const x = 1;", 1},
		{"line 999: foo", 999},
		{"AKIA1234567890ABCDEF", 0},
		{"mongodb+srv://admin:pass@host/db", 0},
		{"", 0},
	}
	for _, tt := range tests {
		got := extractLineNumber(tt.input)
		if got != tt.expected {
			t.Errorf("extractLineNumber(%q) = %d, want %d", tt.input, got, tt.expected)
		}
	}
}

// ── Benchmark ──

func BenchmarkScanContent(b *testing.B) {
	content := `
const dbUrl = "mongodb+srv://admin:P@ssw0rd123@cluster0.abc.mongodb.net/prod";
const ghToken = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234";
const apiKey = "AIzaSyA1234567890abcdefghijklmnopq-rstuvw";
element.innerHTML = location.hash;
const agent = new https.Agent({ rejectUnauthorized: false });
db.query("SELECT * FROM users WHERE id = " + req.query.id);
const secret = jwt.sign(payload, "secret");
obj.__proto__ = malicious;
const config = { debug: true, introspection: true };
`
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanContent("sample.js", content)
	}
}

// === Phase 7: New Signature Tests ===

func TestSignatureLDAPConnectionString(t *testing.T) {
	results := scanContent("config.js", `const ldapURL = "ldap://dc01.corp.local:389/DC=corp,DC=local";`)
	assertFinding(t, results, "LDAP Connection String")
}

func TestSignatureAzureServiceBus(t *testing.T) {
	results := scanContent("config.js", `const sbConn = "Endpoint=sb://mynamespace.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=abc123def456";`)
	assertFinding(t, results, "Azure Service Bus Connection")
}

func TestSignatureAWSSQSQueueURL(t *testing.T) {
	results := scanContent("config.js", `const queueUrl = "https://sqs.us-east-1.amazonaws.com/123456789012/my-queue";`)
	assertFinding(t, results, "AWS SQS Queue URL")
}

func TestSignatureAWSSNSTopicARN(t *testing.T) {
	results := scanContent("config.js", `const topic = "arn:aws:sns:us-east-1:123456789012:my-topic";`)
	assertFinding(t, results, "AWS SNS Topic ARN")
}

func TestSignatureGraphQLEndpoint(t *testing.T) {
	results := scanContent("routes.js", `const endpoint = "https://api.example.com/graphql";`)
	assertFinding(t, results, "GraphQL Endpoint")
}

func TestSignatureSpringBootActuator(t *testing.T) {
	results := scanContent("config.js", `const healthUrl = "/actuator/health";`)
	assertFinding(t, results, "Spring Boot Actuator Endpoint")
}

func TestSignatureAdminPanelPath(t *testing.T) {
	results := scanContent("routes.js", `router.get("/admin/dashboard", requireAuth, dashboardHandler);`)
	assertFinding(t, results, "Admin Panel Path")
}

func TestSignatureWebhookSecret(t *testing.T) {
	results := scanContent("config.js", `const webhookSecret = "whsec_abcdef1234567890abcdef1234567890";`)
	assertFinding(t, results, "Webhook Secret Key")
}

func TestSignatureMapboxSecretToken(t *testing.T) {
	results := scanContent("map.js", `mapboxgl.accessToken = "sk.eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9_YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4";`)
	assertFinding(t, results, "Mapbox Secret Token")
}

func TestSignatureTwilioAccountSID(t *testing.T) {
	results := scanContent("sms.js", `const accountSid = "AC1234567890abcdef1234567890abcdef";`)
	assertFinding(t, results, "Twilio Account SID")
}

func TestSignatureSendGridKey(t *testing.T) {
	results := scanContent("mail.js", `const sgKey = "SG.aBcDeFgHiJkLmNoPqRsTuV.aBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgHiJkLmNoPq";`)
	assertFinding(t, results, "SendGrid API Key")
}

// === Phase 7: New Heuristic Tests ===

func TestHeuristicDetectsDangerouslySetInnerHTML(t *testing.T) {
	results := scanContent("app.jsx", `<div dangerouslySetInnerHTML = { {__html: userInput} } />`)
	assertFinding(t, results, "React dangerouslySetInnerHTML Usage")
}

func TestHeuristicSkipsSanitizedDangerouslySetInnerHTML(t *testing.T) {
	results := scanContent("app.jsx", `<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userInput) }} />`)
	if findResult(results, "React dangerouslySetInnerHTML Usage") != nil {
		t.Fatalf("should not flag sanitized dangerouslySetInnerHTML usage, got %#v", results)
	}
	if findResult(results, "Potential DOM XSS") != nil || findResult(results, "HTML Injection Sink") != nil {
		t.Fatalf("should not flag sanitized HTML sink usage, got %#v", results)
	}
}

func TestHeuristicDetectsOverlyPermissiveCORS(t *testing.T) {
	results := scanContent("server.js", `const allowedOrigins = [*.example.com, "https://*.test.local"]`)
	assertFinding(t, results, "Overly Permissive CORS Origin")
}

func TestHeuristicSkipsExplicitLocalCORSOrigins(t *testing.T) {
	results := scanContent("server.js", `const allowedOrigins = ["https://api.test.local", "http://localhost:3000"]`)
	if findResult(results, "Overly Permissive CORS Origin") != nil {
		t.Fatalf("should not flag explicit local/test origins without wildcard, got %#v", results)
	}
}

func TestHeuristicDetectsUnsafeIframeSrc(t *testing.T) {
	results := scanContent("widget.js", `iframe.src = req.query.url;`)
	assertFinding(t, results, "Unsafe Iframe Source from User Input")
}

func TestHeuristicDetectsWebhookWithoutVerification(t *testing.T) {
	results := scanContent("hooks.js", `const webhook = (req, res) => { processPayment(req.body); };`)
	assertFinding(t, results, "Webhook Handler Without Signature Verification")
}

func TestHeuristicSkipsNonHandlerWebhookAssignments(t *testing.T) {
	results := scanContent("hooks.js", `const callback = req.body.callbackUrl; const webhook = req.body.webhook;`)
	if findResult(results, "Webhook Handler Without Signature Verification") != nil {
		t.Fatalf("should not flag non-handler webhook assignments, got %#v", results)
	}
}

func TestHeuristicSkipsWebhookWithHMAC(t *testing.T) {
	code := `app.post("/webhook", (req, res) => { const sig = createHmac('sha256', secret).update(req.body).digest('hex'); });`
	results := scanContent("hooks.js", code)
	for _, r := range results {
		if r.Name == "Webhook Handler Without Signature Verification" {
			t.Error("should not flag webhook handler that uses HMAC verification")
		}
	}
}

func TestHeuristicDetectsErrorExposure(t *testing.T) {
	results := scanContent("api.js", `app.get("/user", (req, res) => { db.find().catch(err => res.json(err.message)); });`)
	assertFinding(t, results, "Error Details Exposed to Client")
}

func TestHeuristicSkipsGenericCatchResponses(t *testing.T) {
	results := scanContent("api.js", `try { run(); } catch (err) { const message = "request failed"; res.json(message); }`)
	if findResult(results, "Error Details Exposed to Client") != nil {
		t.Fatalf("should not flag generic catch responses without error details, got %#v", results)
	}
}

func TestHeuristicDetectsHeaderInjection(t *testing.T) {
	results := scanContent("server.js", `res.setHeader("X-Custom", req.query.header);`)
	assertFinding(t, results, "HTTP Header Injection from User Input")
}

func TestHeuristicSkipsNonTaintedHeaderValues(t *testing.T) {
	results := scanContent("server.js", `res.setHeader("X-Trace", response.body);`)
	if findResult(results, "HTTP Header Injection from User Input") != nil {
		t.Fatalf("should not flag non-request-derived header values, got %#v", results)
	}
}

func TestHeuristicDetectsUserControlledRegex(t *testing.T) {
	results := scanContent("search.js", `const pattern = new RegExp(req.query.search);`)
	assertFinding(t, results, "User-Controlled Regex Pattern")
}

func TestHeuristicSkipsRegexBuiltFromLocalUserVariable(t *testing.T) {
	results := scanContent("search.js", `const user = "[a-z]+"; const pattern = new RegExp(user);`)
	if findResult(results, "User-Controlled Regex Pattern") != nil {
		t.Fatalf("should not flag regex built from a generic local variable, got %#v", results)
	}
}

func TestHeuristicDetectsHardcodedIPAllowlist(t *testing.T) {
	results := scanContent("auth.js", `const allowedIPs = ["10.0.0.1", "192.168.1.100"];`)
	assertFinding(t, results, "Hardcoded IP-Based Authorization")
}

func BenchmarkScanContentLargeFile(b *testing.B) {
	// Simulate a realistic 500-line file with a mix of clean code and a few findings
	var sb strings.Builder
	for i := 0; i < 100; i++ {
		sb.WriteString("const handler" + strings.Repeat("x", i%10) + " = async (req, res) => {\n")
		sb.WriteString("  const data = await db.find({ id: req.params.id });\n")
		sb.WriteString("  return res.json(data);\n")
		sb.WriteString("};\n")
		sb.WriteString("// This is a regular comment line\n")
	}
	// Inject a few real findings
	sb.WriteString(`const dbUrl = "mongodb+srv://admin:P@ssw0rd123@cluster0.abc.mongodb.net/prod";` + "\n")
	sb.WriteString(`element.innerHTML = location.hash;` + "\n")
	sb.WriteString(`const secret = jwt.sign(payload, "secret");` + "\n")
	sb.WriteString(`db.query("SELECT * FROM users WHERE id = " + req.query.id);` + "\n")
	content := sb.String()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanContent("src/handlers.js", content)
	}
}
