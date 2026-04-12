package main

import (
	"net/url"
	"strings"
)

// computeConfidence calculates a dynamic confidence score (0–100) for a finding.
// It starts at base 50 and adjusts based on multiple signal factors.
func computeConfidence(r *Result, content, target string) int {
	score := 50

	value := normalizeMatchedValue(r.Match)

	// ── Entropy signal ───────────────────────────────────────────────────
	entropy := shannonEntropy(value)
	r.Entropy = entropy
	switch {
	case entropy >= 4.0:
		score += 15
	case entropy >= 3.5:
		score += 10
	case entropy >= 3.0:
		score += 5
	case entropy < 2.5 && len(value) > 4:
		score -= 20
	}

	// ── Format validation signal ─────────────────────────────────────────
	vr := ValidateFormat(r.Name, r.Match)
	if vr.Valid {
		score += vr.ConfidenceBoost
	}
	if vr.Provider != "" && r.Provider == "" {
		r.Provider = vr.Provider
	}

	// ── Placeholder signal ───────────────────────────────────────────────
	if isLikelyPlaceholderValue(value) || looksLikePlaceholder(value) {
		score -= 30
	} else {
		score += 10
	}

	// ── Test/mock file signal ────────────────────────────────────────────
	if isLikelyTestOrMockFile(target) || isLikelyEnvExample(target) {
		score -= 15
	} else {
		score += 5
	}

	// ── Vendor/minified signal ───────────────────────────────────────────
	if isLikelyVendorTarget(target) {
		score -= 10
	} else {
		score += 5
	}

	// ── Value length signal ──────────────────────────────────────────────
	if len(value) >= 20 {
		score += 5
	} else if len(value) < 8 && len(value) > 0 {
		score -= 10
	}

	// ── Proximity to auth code signal ────────────────────────────────────
	if hasAuthContext(r.Context) {
		score += 10
	}

	// ── Clamp ────────────────────────────────────────────────────────────
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	return score
}

// hasAuthContext checks if surrounding code context contains auth-related patterns
func hasAuthContext(context string) bool {
	if context == "" {
		return false
	}
	lower := strings.ToLower(context)
	markers := []string{
		"authorization", "bearer", "authenticate",
		"fetch(", "axios.", "http.get", "request(",
		"x-api-key", "api-key", "apikey",
		"credentials", "oauth", "token",
	}
	for _, m := range markers {
		if strings.Contains(lower, m) {
			return true
		}
	}
	return false
}

// ─── Provider Identification ─────────────────────────────────────────────────

// providerMap maps signature names to provider identifiers.
// Validators also set providers, but this covers signatures without validators.
var providerMap = map[string]string{
	// Cloud providers
	"AWS Access Key ID":          "aws",
	"AWS Secret Access Key":      "aws",
	"AWS Session Token":          "aws",
	"AWS RDS Hostname":           "aws",
	"AWS S3 Bucket URL":          "aws",
	"AWS S3 Bucket Path-Style":   "aws",
	"AWS Metadata Endpoint":      "aws",
	"AWS IAM ARN":                "aws",
	"Google API Key":             "google",
	"Google AI Studio Key":       "google",
	"Google OAuth Refresh Token": "google",
	"GCP Service Account JSON":   "google",
	"Google OAuth Secret":        "google",
	"GCP Metadata Endpoint":      "google",
	"Cloud SQL URI (GCP)":        "google",
	"GCS Bucket URL":             "google",
	"Azure Storage Account Key":  "azure",
	"Azure Client Secret":        "azure",
	"Azure SAS Token":            "azure",
	"Azure Blob Storage URL":     "azure",
	"Azure Metadata Endpoint":    "azure",
	"Azure DevOps Token":         "azure",
	"Alibaba Cloud Access Key":   "alibaba",

	// Payment
	"Stripe Secret Key":      "stripe",
	"Stripe Publishable Key": "stripe",
	"Square Access Token":    "square",
	"PayPal Client Secret":   "paypal",
	"Braintree Access Token": "braintree",
	"Adyen API Key":          "adyen",
	"Coinbase API Key":       "coinbase",

	// VCS / CI/CD
	"GitHub Token (Classic PAT)": "github",
	"GitHub Fine-Grained PAT":    "github",
	"GitLab Token":               "gitlab",
	"Bitbucket App Password":     "bitbucket",
	"CircleCI Token":             "circleci",
	"Travis CI Token":            "travisci",
	"Jenkins API Token":          "jenkins",
	"Buildkite Token":            "buildkite",

	// Communication
	"Slack Bot Token":         "slack",
	"Slack User Token":        "slack",
	"Slack Workspace Token":   "slack",
	"Slack Webhook URL":       "slack",
	"Twilio API Key SID":      "twilio",
	"Twilio Account SID":      "twilio",
	"SendGrid API Key":        "sendgrid",
	"Mailgun API Key":         "mailgun",
	"Telegram Bot Token":      "telegram",
	"Microsoft Teams Webhook": "microsoft",
	"Postmark Server Token":   "postmark",
	"Mailchimp API Key":       "mailchimp",
	"Vonage / Nexmo API Key":  "vonage",

	// Database
	"MongoDB Connection URI": "mongodb",
	"PostgreSQL URI":         "postgresql",
	"MySQL URI":              "mysql",
	"Redis URI":              "redis",
	"Elasticsearch URI":      "elasticsearch",
	"Snowflake URI":          "snowflake",
	"CockroachDB URI":        "cockroachdb",
	"ClickHouse URI":         "clickhouse",
	"Cassandra URI":          "cassandra",
	"JDBC URL":               "jdbc",
	"Supabase DB Key":        "supabase",

	// AI/ML
	"OpenAI API Key":      "openai",
	"OpenAI Project Key":  "openai",
	"Anthropic API Key":   "anthropic",
	"DeepSeek API Key":    "deepseek",
	"xAI Grok API Key":    "xai",
	"Perplexity API Key":  "perplexity",
	"Fireworks AI Key":    "fireworks",
	"Hugging Face Token":  "huggingface",
	"Replicate API Token": "replicate",
	"Groq API Key":        "groq",
	"Cohere API Key":      "cohere",
	"Mistral API Key":     "mistral",
	"Together AI Key":     "togetherai",
	"Pinecone API Key":    "pinecone",
	"Weaviate API Key":    "weaviate",
	"Qdrant API Key":      "qdrant",

	// Hosting / PaaS
	"DigitalOcean Token": "digitalocean",
	"Heroku API Key":     "heroku",
	"Vercel Token":       "vercel",
	"Netlify Token":      "netlify",
	"Fly.io Token":       "flyio",
	"Render Token":       "render",
	"Railway Token":      "railway",
	"Deno Deploy Token":  "deno",

	// Security / Auth
	"Cloudflare API Token":       "cloudflare",
	"Cloudflare KV Namespace":    "cloudflare",
	"Fastly API Token":           "fastly",
	"Okta API Token":             "okta",
	"Auth0 Management API Token": "auth0",

	// Firebase
	"Firebase URL":     "firebase",
	"Firebase API Key": "firebase",
	"Firebase Secret":  "firebase",

	// Monitoring / Logging
	"Sentry DSN":               "sentry",
	"Datadog API Key":          "datadog",
	"New Relic API Key":        "newrelic",
	"Splunk HEC Token":         "splunk",
	"Elastic APM Secret Token": "elastic",
	"Bugsnag API Key":          "bugsnag",
	"PagerDuty API Key":        "pagerduty",
	"Dynatrace Token":          "dynatrace",

	// IaC
	"Terraform Cloud Token": "terraform",
	"Pulumi Access Token":   "pulumi",
	"Vault Token":           "hashicorp",
	"Vault Unseal Key":      "hashicorp",

	// Other SaaS
	"Shopify Access Token":    "shopify",
	"Dropbox Access Token":    "dropbox",
	"Figma Access Token":      "figma",
	"Notion API Key":          "notion",
	"Airtable API Key":        "airtable",
	"Algolia API Key":         "algolia",
	"Mapbox Token":            "mapbox",
	"LaunchDarkly API Key":    "launchdarkly",
	"Grafana Service Account": "grafana",
	"Postman API Key":         "postman",
	"NPM Token":               "npm",
	"PyPI Token":              "pypi",
}

// resolveProvider returns the provider for a given signature name.
func resolveProvider(sigName string) string {
	if p, ok := providerMap[sigName]; ok {
		return p
	}
	return ""
}

// ─── Tag Classification ─────────────────────────────────────────────────────

// classifyTags returns classification tags for a finding.
func classifyTags(r *Result, target string) []string {
	var tags []string

	name := strings.ToLower(r.Name)
	match := strings.ToLower(r.Match)

	// Auth-related
	if containsAny(name, "token", "key", "secret", "password", "passwd", "jwt",
		"oauth", "bearer", "credential", "auth", "session", "csrf") {
		tags = append(tags, "auth-related")
	}

	// Third-party provider identified
	if r.Provider != "" {
		tags = append(tags, "third-party")
	}

	// Internal API / infrastructure
	if containsAny(name, "private ip", "localhost", "internal", "debug") ||
		containsAny(match, "127.0.0.1", "10.0.", "172.16.", "192.168.", "localhost", "internal") {
		tags = append(tags, "internal-api")
	}

	// Tracking / analytics
	if containsAny(name, "amplitude", "mixpanel", "segment", "heap", "keen",
		"analytics", "google analytics", "tracking", "ga_") {
		tags = append(tags, "tracking")
	}

	// Config leak
	if containsAny(name, "source map", "debug mode", "env", "config") ||
		containsAny(match, ".env", "source map", "debug: true") {
		tags = append(tags, "config-leak")
	}

	// Database
	if containsAny(name, "mongodb", "postgresql", "mysql", "redis", "elasticsearch",
		"snowflake", "cockroach", "clickhouse", "cassandra", "jdbc", "rds") {
		tags = append(tags, "database")
	}

	// Crypto / PKI
	if containsAny(name, "private key", "pgp", "pem", "certificate") {
		tags = append(tags, "crypto")
	}

	return tags
}

// extractDomain returns the domain from a URL target, or empty string for file paths.
func extractDomain(target string) string {
	if !isUrl(target) {
		return ""
	}
	parsed, err := url.Parse(target)
	if err != nil {
		return ""
	}
	host := parsed.Hostname()
	return host
}

// extractCodeContext returns surrounding lines (±contextRadius) for a given line number.
func extractCodeContext(content string, lineNumber, contextRadius int) string {
	if lineNumber <= 0 || contextRadius <= 0 {
		return ""
	}

	lines := strings.Split(content, "\n")
	if lineNumber > len(lines) {
		return ""
	}

	start := lineNumber - 1 - contextRadius
	if start < 0 {
		start = 0
	}
	end := lineNumber - 1 + contextRadius + 1
	if end > len(lines) {
		end = len(lines)
	}

	snippet := strings.Join(lines[start:end], "\n")
	// Truncate long context
	if len(snippet) > 500 {
		snippet = snippet[:500] + "..."
	}
	return snippet
}

// enrichResult populates Provider, Tags, Confidence, and optionally Context on a Result.
func enrichResult(r *Result, content, target string, contextLines int) {
	// Provider (from map if not already set by validator)
	if r.Provider == "" {
		r.Provider = resolveProvider(r.Name)
	}

	// Tags
	r.Tags = classifyTags(r, target)

	// Context snippet
	if contextLines > 0 && r.Line > 0 {
		r.Context = extractCodeContext(content, r.Line, contextLines)
	}

	// Confidence scoring (must be last — uses Provider, Entropy, Context)
	r.Confidence = computeConfidence(r, content, target)
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func containsAny(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
