package main

import (
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"
)

// ValidationResult holds the outcome of a provider-specific format check
type ValidationResult struct {
	Valid           bool
	Provider        string
	ConfidenceBoost int
}

// ValidateFormat runs provider-specific format validators against
// the raw matched value and returns a ValidationResult.
func ValidateFormat(sigName, rawValue string) ValidationResult {
	if fn, ok := formatValidators[sigName]; ok {
		return fn(rawValue)
	}
	return ValidationResult{}
}

// formatValidators maps signature names to validation functions.
var formatValidators = map[string]func(string) ValidationResult{
	// ── CRITICAL ─────────────────────────────────────────
	"AWS Access Key ID":         validateAWSAccessKey,
	"AWS Secret Access Key":     validateAWSSecretKey,
	"Google API Key":            validateGoogleAPIKey,
	"Google AI Studio Key":      validateGoogleAPIKey,
	"Stripe Secret Key":         validateStripeSecret,
	"OpenAI API Key":            validateOpenAIKey,
	"OpenAI Project Key":        validateOpenAIProjectKey,
	"Anthropic API Key":         validateAnthropicKey,
	"Cloudflare API Token":      validateCloudflareToken,
	"Terraform Cloud Token":     validateTerraformToken,
	"Alibaba Cloud Access Key":  validateAlibabaKey,
	"Azure Storage Account Key": validateAzureStorageKey,
	"Private Key Block":         validatePrivateKeyBlock,
	"PGP Private Key Block":     validatePGPPrivateKey,
	"Firebase URL":              validateFirebaseURL,

	// ── HIGH ─────────────────────────────────────────────
	"GitHub Token (Classic PAT)": validateGitHubClassicPAT,
	"GitHub Fine-Grained PAT":    validateGitHubFineGrainedPAT,
	"Slack Bot Token":            validateSlackToken,
	"Slack User Token":           validateSlackToken,
	"Slack Workspace Token":      validateSlackToken,
	"SendGrid API Key":           validateSendGridKey,
	"Twilio API Key SID":         validateTwilioKey,
	"DigitalOcean Token":         validateDigitalOceanToken,
	"Heroku API Key":             validateHerokuKey,
	"Hugging Face Token":         validateHuggingFaceToken,
	"Replicate API Token":        validateReplicateToken,
	"Groq API Key":               validateGroqKey,
	"Pinecone API Key":           validatePineconeKey,

	// ── MEDIUM ───────────────────────────────────────────
	"JWT Token":                 validateJWT,
	"Supabase Service Role JWT": validateJWT,
	"Bearer Token Generic":      validateBearerToken,
}

// ─── AWS ─────────────────────────────────────────────────────────────────────

var awsAccessKeyRe = regexp.MustCompile(`^AKIA[0-9A-Z]{16}$`)

func validateAWSAccessKey(value string) ValidationResult {
	v := trimQuotes(value)
	if awsAccessKeyRe.MatchString(v) {
		return ValidationResult{Valid: true, Provider: "aws", ConfidenceBoost: 25}
	}
	return ValidationResult{Provider: "aws"}
}

func validateAWSSecretKey(value string) ValidationResult {
	v := extractSecretValue(value)
	if len(v) == 40 && isBase64Charset(v) {
		return ValidationResult{Valid: true, Provider: "aws", ConfidenceBoost: 20}
	}
	return ValidationResult{Provider: "aws"}
}

// ─── Google ──────────────────────────────────────────────────────────────────

var googleAPIKeyRe = regexp.MustCompile(`^AIza[0-9A-Za-z\-_]{35}$`)

func validateGoogleAPIKey(value string) ValidationResult {
	v := trimQuotes(value)
	if googleAPIKeyRe.MatchString(v) {
		return ValidationResult{Valid: true, Provider: "google", ConfidenceBoost: 25}
	}
	return ValidationResult{Provider: "google"}
}

// ─── Stripe ──────────────────────────────────────────────────────────────────

func validateStripeSecret(value string) ValidationResult {
	v := trimQuotes(value)
	if strings.HasPrefix(v, "sk_live_") && len(v) >= 32 {
		return ValidationResult{Valid: true, Provider: "stripe", ConfidenceBoost: 25}
	}
	if strings.HasPrefix(v, "sk_test_") {
		return ValidationResult{Valid: true, Provider: "stripe", ConfidenceBoost: 5}
	}
	return ValidationResult{Provider: "stripe"}
}

// ─── OpenAI ──────────────────────────────────────────────────────────────────

func validateOpenAIKey(value string) ValidationResult {
	v := trimQuotes(value)
	if strings.HasPrefix(v, "sk-") && strings.Contains(v, "T3BlbkFJ") && len(v) >= 40 {
		return ValidationResult{Valid: true, Provider: "openai", ConfidenceBoost: 25}
	}
	return ValidationResult{Provider: "openai"}
}

func validateOpenAIProjectKey(value string) ValidationResult {
	v := trimQuotes(value)
	if strings.HasPrefix(v, "sk-proj-") && len(v) >= 80 {
		return ValidationResult{Valid: true, Provider: "openai", ConfidenceBoost: 25}
	}
	return ValidationResult{Provider: "openai"}
}

// ─── Anthropic ───────────────────────────────────────────────────────────────

func validateAnthropicKey(value string) ValidationResult {
	v := trimQuotes(value)
	if strings.HasPrefix(v, "sk-ant-") && len(v) >= 90 {
		return ValidationResult{Valid: true, Provider: "anthropic", ConfidenceBoost: 25}
	}
	return ValidationResult{Provider: "anthropic"}
}

// ─── GitHub ──────────────────────────────────────────────────────────────────

var ghClassicRe = regexp.MustCompile(`^ghp_[A-Za-z0-9]{36}$`)

func validateGitHubClassicPAT(value string) ValidationResult {
	v := trimQuotes(value)
	if ghClassicRe.MatchString(v) {
		return ValidationResult{Valid: true, Provider: "github", ConfidenceBoost: 25}
	}
	// Also accept other gh prefixes
	for _, prefix := range []string{"ghp_", "gho_", "ghs_", "ghr_"} {
		if strings.HasPrefix(v, prefix) && len(v) >= 36 {
			return ValidationResult{Valid: true, Provider: "github", ConfidenceBoost: 20}
		}
	}
	return ValidationResult{Provider: "github"}
}

var ghFineGrainedRe = regexp.MustCompile(`^github_pat_[A-Za-z0-9_]{82}$`)

func validateGitHubFineGrainedPAT(value string) ValidationResult {
	v := trimQuotes(value)
	if ghFineGrainedRe.MatchString(v) {
		return ValidationResult{Valid: true, Provider: "github", ConfidenceBoost: 25}
	}
	if strings.HasPrefix(v, "github_pat_") && len(v) >= 80 {
		return ValidationResult{Valid: true, Provider: "github", ConfidenceBoost: 20}
	}
	return ValidationResult{Provider: "github"}
}

// ─── Slack ───────────────────────────────────────────────────────────────────

func validateSlackToken(value string) ValidationResult {
	v := trimQuotes(value)
	for _, prefix := range []string{"xoxb-", "xoxp-", "xoxs-", "xoxa-", "xoxr-"} {
		if strings.HasPrefix(v, prefix) && len(v) >= 20 {
			return ValidationResult{Valid: true, Provider: "slack", ConfidenceBoost: 25}
		}
	}
	return ValidationResult{Provider: "slack"}
}

// ─── SendGrid ────────────────────────────────────────────────────────────────

func validateSendGridKey(value string) ValidationResult {
	v := trimQuotes(value)
	if strings.HasPrefix(v, "SG.") && len(v) >= 50 {
		return ValidationResult{Valid: true, Provider: "sendgrid", ConfidenceBoost: 25}
	}
	return ValidationResult{Provider: "sendgrid"}
}

// ─── Twilio ──────────────────────────────────────────────────────────────────

var twilioRe = regexp.MustCompile(`^SK[0-9a-f]{32}$`)

func validateTwilioKey(value string) ValidationResult {
	v := trimQuotes(value)
	if twilioRe.MatchString(v) {
		return ValidationResult{Valid: true, Provider: "twilio", ConfidenceBoost: 25}
	}
	return ValidationResult{Provider: "twilio"}
}

// ─── DigitalOcean ────────────────────────────────────────────────────────────

func validateDigitalOceanToken(value string) ValidationResult {
	v := trimQuotes(value)
	if strings.HasPrefix(v, "dop_v1_") && len(v) >= 71 {
		return ValidationResult{Valid: true, Provider: "digitalocean", ConfidenceBoost: 25}
	}
	return ValidationResult{Provider: "digitalocean"}
}

// ─── Heroku ──────────────────────────────────────────────────────────────────

var herokuRe = regexp.MustCompile(`^[0-9a-f]{32}$`)

func validateHerokuKey(value string) ValidationResult {
	v := trimQuotes(value)
	if herokuRe.MatchString(v) && len(v) == 32 {
		return ValidationResult{Valid: true, Provider: "heroku", ConfidenceBoost: 20}
	}
	return ValidationResult{Provider: "heroku"}
}

// ─── Cloudflare ──────────────────────────────────────────────────────────────

func validateCloudflareToken(value string) ValidationResult {
	v := extractSecretValue(value)
	if len(v) >= 40 && isAlphanumDashUnderscore(v) {
		return ValidationResult{Valid: true, Provider: "cloudflare", ConfidenceBoost: 20}
	}
	return ValidationResult{Provider: "cloudflare"}
}

// ─── Terraform ───────────────────────────────────────────────────────────────

func validateTerraformToken(value string) ValidationResult {
	v := trimQuotes(value)
	if strings.HasPrefix(v, "atlasv1.") && len(v) >= 60 {
		return ValidationResult{Valid: true, Provider: "terraform", ConfidenceBoost: 25}
	}
	return ValidationResult{Provider: "terraform"}
}

// ─── Alibaba Cloud ───────────────────────────────────────────────────────────

var alibabaRe = regexp.MustCompile(`^LTAI[A-Za-z0-9]{12,20}$`)

func validateAlibabaKey(value string) ValidationResult {
	v := trimQuotes(value)
	if alibabaRe.MatchString(v) {
		return ValidationResult{Valid: true, Provider: "alibaba", ConfidenceBoost: 25}
	}
	return ValidationResult{Provider: "alibaba"}
}

// ─── Azure Storage ───────────────────────────────────────────────────────────

func validateAzureStorageKey(value string) ValidationResult {
	v := extractSecretValue(value)
	if len(v) >= 86 && strings.HasSuffix(v, "==") {
		return ValidationResult{Valid: true, Provider: "azure", ConfidenceBoost: 20}
	}
	return ValidationResult{Provider: "azure"}
}

// ─── Private Keys ────────────────────────────────────────────────────────────

func validatePrivateKeyBlock(value string) ValidationResult {
	if strings.Contains(value, "-----BEGIN") && strings.Contains(value, "PRIVATE KEY") {
		return ValidationResult{Valid: true, Provider: "pki", ConfidenceBoost: 25}
	}
	return ValidationResult{Provider: "pki"}
}

func validatePGPPrivateKey(value string) ValidationResult {
	if strings.Contains(value, "-----BEGIN PGP PRIVATE KEY") {
		return ValidationResult{Valid: true, Provider: "pgp", ConfidenceBoost: 25}
	}
	return ValidationResult{Provider: "pgp"}
}

// ─── Firebase ────────────────────────────────────────────────────────────────

func validateFirebaseURL(value string) ValidationResult {
	v := trimQuotes(value)
	if strings.Contains(v, ".firebaseio.com") || strings.Contains(v, ".firebaseapp.com") {
		return ValidationResult{Valid: true, Provider: "firebase", ConfidenceBoost: 20}
	}
	return ValidationResult{Provider: "firebase"}
}

// ─── HuggingFace ─────────────────────────────────────────────────────────────

func validateHuggingFaceToken(value string) ValidationResult {
	v := trimQuotes(value)
	if strings.HasPrefix(v, "hf_") && len(v) >= 34 {
		return ValidationResult{Valid: true, Provider: "huggingface", ConfidenceBoost: 25}
	}
	return ValidationResult{Provider: "huggingface"}
}

// ─── Replicate ───────────────────────────────────────────────────────────────

func validateReplicateToken(value string) ValidationResult {
	v := trimQuotes(value)
	if strings.HasPrefix(v, "r8_") && len(v) >= 37 {
		return ValidationResult{Valid: true, Provider: "replicate", ConfidenceBoost: 25}
	}
	return ValidationResult{Provider: "replicate"}
}

// ─── Groq ────────────────────────────────────────────────────────────────────

func validateGroqKey(value string) ValidationResult {
	v := trimQuotes(value)
	if strings.HasPrefix(v, "gsk_") && len(v) >= 52 {
		return ValidationResult{Valid: true, Provider: "groq", ConfidenceBoost: 25}
	}
	return ValidationResult{Provider: "groq"}
}

// ─── Pinecone ────────────────────────────────────────────────────────────────

func validatePineconeKey(value string) ValidationResult {
	v := trimQuotes(value)
	if strings.HasPrefix(v, "pcsk_") && len(v) >= 42 {
		return ValidationResult{Valid: true, Provider: "pinecone", ConfidenceBoost: 25}
	}
	return ValidationResult{Provider: "pinecone"}
}

// ─── JWT ─────────────────────────────────────────────────────────────────────

func validateJWT(value string) ValidationResult {
	v := trimQuotes(value)

	// A JWT has 3 base64url-encoded parts separated by dots
	parts := strings.SplitN(v, ".", 4)
	if len(parts) != 3 {
		return ValidationResult{Provider: "jwt"}
	}
	if parts[0] == "" || parts[1] == "" {
		return ValidationResult{Provider: "jwt"}
	}

	// Decode header and check for "alg" field
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return ValidationResult{Provider: "jwt"}
	}

	var header map[string]interface{}
	if json.Unmarshal(headerBytes, &header) != nil {
		return ValidationResult{Provider: "jwt"}
	}

	if _, hasAlg := header["alg"]; !hasAlg {
		return ValidationResult{Provider: "jwt"}
	}

	return ValidationResult{Valid: true, Provider: "jwt", ConfidenceBoost: 20}
}

// ─── Bearer Token ────────────────────────────────────────────────────────────

func validateBearerToken(value string) ValidationResult {
	v := trimQuotes(value)
	if idx := strings.Index(strings.ToLower(v), "bearer "); idx >= 0 {
		v = strings.TrimSpace(v[idx+len("bearer "):])
	}
	if len(v) >= 20 && shannonEntropy(v) >= 3.0 {
		return ValidationResult{Valid: true, Provider: "", ConfidenceBoost: 10}
	}
	return ValidationResult{}
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func trimQuotes(v string) string {
	return strings.Trim(strings.TrimSpace(v), `'"`+"`")
}

func extractSecretValue(match string) string {
	v := normalizeMatchedValue(match)
	return trimQuotes(v)
}

func isBase64Charset(s string) bool {
	for _, r := range s {
		if !((r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '+' || r == '/' || r == '=') {
			return false
		}
	}
	return true
}

func isAlphanumDashUnderscore(s string) bool {
	for _, r := range s {
		if !((r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_') {
			return false
		}
	}
	return true
}
