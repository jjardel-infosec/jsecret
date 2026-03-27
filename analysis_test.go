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
