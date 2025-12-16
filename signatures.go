package main

import "regexp"

type Signature struct {
	Name  string
	Regex *regexp.Regexp
}

var Signatures []Signature

func init() {
	// Raw patterns from the user and some legacy ones
	rawPatterns := map[string]string{
		// 🔑 API Keys & Tokens
		"AWS Access Key ID":       `AKIA[0-9A-Z]{16}`,
		"AWS Secret Access Key":   `(?i)aws(.{0,20})?(?-i)['\"][0-9a-zA-Z\/+]{40}['\"]`,
		"Google API Key":          `AIza[0-9A-Za-z\\-_]{35}`,
		"Firebase Secret":         `AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}`,
		"GitHub Token":            `ghp_[0-9a-zA-Z]{36}`,
		"GitLab Token":            `glpat-[0-9a-zA-Z-_]{20}`,
		"Slack Token":             `xox[baprs]-([0-9a-zA-Z]{10,48})?`,
		"Stripe Secret Key":       `sk_live_[0-9a-zA-Z]{24}`,
		"Stripe Publishable Key":  `pk_live_[0-9a-zA-Z]{24}`,
		"Twilio API Key":          `SK[0-9a-fA-F]{32}`,
		"SendGrid API Key":        `SG\.[\w\d\-_]{22}\.[\w\d\-_]{43}`,
		"Mailgun API Key":         `key-[0-9a-zA-Z]{32}`,
		"Dropbox Access Token":    `sl.[A-Za-z0-9_-]{20,100}`,
		"Shopify Access Token":    `shpat_[0-9a-fA-F]{32}`,
		"Facebook Access Token":   `EAACEdEose0cBA[0-9A-Za-z]+`,
		"Heroku API Key":          `[hH]eroku['\"][0-9a-f]{32}['\"]`,
		"DigitalOcean Token":      `dop_v1_[a-z0-9]{64}`,
		"Asana Personal Access Token": `0/[0-9a-z]{32}`,
		"Linear API Key":          `lin_api_[a-zA-Z0-9]{40}`,
		"Telegram Bot Token":      `\d{9}:[a-zA-Z0-9_-]{35}`,

		// 🔐 OAuth & JWT
		"OAuth Client Secret":     `(?i)client_secret['"\s:=]+[a-zA-Z0-9\-_.~]{10,100}`,
		"OAuth Client ID":         `(?i)client_id['"\s:=]+[a-zA-Z0-9\-_.~]{10,100}`,
		"JWT Token":               `eyJ[A-Za-z0-9-_=]+?\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*`,
		"Azure Client Secret":     `(?i)azure(.{0,20})?client.secret(.{0,20})?['\"][a-zA-Z0-9._%+-]{32,}['\"]`,
		"Microsoft Teams Webhook": `https:\/\/[a-z]+\.webhook\.office\.com\/webhookb2\/[a-zA-Z0-9@\-]+\/.*`,

		// 🔒 Credentials & Passwords
		"Basic Auth String":       `(?i)(username|user|email)['"\s:=]+[^\s'"@]{1,100}['"].*?(password|pwd)['"\s:=]+[^\s'"]{4,100}`,
		"Password Assignment":     `(?i)(password|pwd|pass)['"\s:=]+[^\s'"]{4,100}`,
		"API Key in Variable":     `(?i)(api[_-]?key)['"\s:=]+[a-zA-Z0-9\-_.]{8,100}`,
		"Secret in Variable":      `(?i)(secret|token)['"\s:=]+[a-zA-Z0-9\-_.]{8,100}`,
		"Authorization Bearer Token": `Bearer\s+[a-zA-Z0-9\-._~+/]+=*`,

		// 🛢️ Database URLs
		"MongoDB Connection URI":  `mongodb(\+srv)?:\/\/[^\s'"]+`,
		"PostgreSQL URI":          `postgres(?:ql)?:\/\/[^\s'"]+`,
		"MySQL URI":               `mysql:\/\/[^\s'"]+`,
		"Redis URI":               `redis:\/\/[^\s'"]+`,
		"Elasticsearch URI":       `elasticsearch:\/\/[^\s'"]+`,
		"Supabase DB Key":         `supabase\.co\/[a-z0-9]{15,}`,
		"Firebase URL":            `https:\/\/[a-z0-9-]+\.firebaseio\.com`,
		"JDBC URL":                `jdbc:\w+:\/\/[^\s'"]+`,
		"AWS RDS Hostname":        `[a-z0-9-]+\.rds\.amazonaws\.com`,
		"Cloud SQL URI (GCP)":     `googleapis\.com\/sql\/v1beta4\/projects\/`,

		// 🛰️ Other Service Credentials
		"Algolia API Key":         `(?i)(algolia|application)_?key['"\s:=]+[a-zA-Z0-9]{10,}`,
		"Firebase API Key":        `firebaseConfig\s*=\s*{[^}]*apiKey\s*:\s*['"][^'"]+['"]`,
		"Cloudinary URL":          `cloudinary:\/\/[0-9]{15}:[a-zA-Z0-9]+@[a-zA-Z]+`,
		"Sentry DSN":              `https:\/\/[a-zA-Z0-9]+@[a-z]+\.ingest\.sentry\.io\/\d+`,
		"Netlify Token":           `netlifyAuthToken\s*=\s*['"][a-z0-9]{40}['"]`,
		"GitHub OAuth App Secret": `[a-f0-9]{40}`,
		"Segment API Key":         `(?i)segment(.{0,20})?key['"\s:=]+[a-zA-Z0-9]{10,}`,
		"Intercom Access Token":   `(?i)intercom(.{0,20})?token['"\s:=]+[a-zA-Z0-9-_]{20,}`,
		"Amplitude API Key":       `apiKey['"]?\s*:\s*['"][a-z0-9\-]{32,64}['"]`,
		"Plaid Client Secret":     `plaid(.{0,20})?(client)?secret['"\s:=]+[a-z0-9-_]{30,}`,

		// 📦 Container & Deployment Secrets
		"Docker Hub Password":     `(?i)docker(.{0,20})?password['"\s:=]+[^\s'"]{8,}`,
		"AWS IAM Role ARN":        `arn:aws:iam::[0-9]{12}:role\/[A-Za-z0-9_+=,.@\-_/]+`,
		"AWS S3 Bucket URL":       `s3:\/\/[a-z0-9\-\.]{3,63}`,
		"Kubernetes Secret Name":  `(?i)secretName:\s*['"]?[a-z0-9\-]+['"]?`,
		"Helm Secret Value":       `(?i)secret\s*:\s*['"][^'"]+['"]`,
		"GitHub Actions Secret Reference": `secrets\.[A-Z0-9_]+`,
		"GitHub Actions Encrypted Value": `encrypted_value:\s*['"][a-zA-Z0-9+/=]{10,}['"]`,
		"K8s Service Account Token": `eyJhbGciOiJSUzI1NiIsImtpZCI6`,
		"Vault Token":             `s\.[a-zA-Z0-9]{8,}`,
		"Hashicorp Vault URL":     `https:\/\/vault\.[a-z0-9\-_\.]+\.com`,

		// 🧰 DevOps & CI/CD Credentials
		"CircleCI Token":          `circle-token=[a-z0-9]{40}`,
		"Travis CI Token":         `(?i)travis(.{0,20})?token['"\s:=]+[a-z0-9]{30,}`,
		"Jenkins Crumb Token":     `Jenkins-Crumb:\s*[a-z0-9]{30,}`,
		"Azure DevOps Token":      `[a-z0-9]{52}`,
		"GitHub Personal Access Token": `ghp_[a-zA-Z0-9]{36}`,
		"GitHub Fine-Grained Token": `github_pat_[0-9a-zA-Z_]{20,}`,
		"Bitbucket OAuth Key":     `bitbucket(.{0,20})?key['"\s:=]+[a-zA-Z0-9]{20,}`,
		"Bitbucket OAuth Secret":  `bitbucket(.{0,20})?secret['"\s:=]+[a-zA-Z0-9]{20,}`,
		"GitLab Runner Token":     `glrt-[a-zA-Z0-9_-]{20}`,
		"Netlify Access Token":    `netlifyAuthToken\s*=\s*['"][a-z0-9]{40}['"]`,

		// 🛠️ SDKs & Tooling Keys
		"Bugsnag API Key":         `[a-f0-9]{32}`,
		"Datadog API Key":         `[a-z0-9]{32}`,
		"Loggly Token":            `[a-z0-9]{30}-[a-z0-9]{10}`,
		"New Relic Key":           `NRII-[a-zA-Z0-9]{20,}`,
		"Mixpanel Token":          `(?i)mixpanel(.{0,20})?token['"\s:=]+[a-z0-9]{32}`,
		"Heap Analytics App ID":   `heapSettings\.appId\s*=\s*['"][a-z0-9]{8,12}['"]`,
		"Keen IO Project ID":      `projectId['"]?\s*:\s*['"][a-f0-9]{24}['"]`,
		"Keen IO Write Key":       `writeKey['"]?\s*:\s*['"][a-zA-Z0-9]{64}['"]`,
		"Snyk Token":              `snyk_token\s*=\s*[a-f0-9\-]{36}`,
		"Rollbar Access Token":    `access_token['"]?\s*:\s*['"][a-z0-9]{32}['"]`,

		// 🎮 App & Game APIs
		"Twitch API Key":          `(?i)twitch(.{0,20})?key['"\s:=]+[a-zA-Z0-9]{20,}`,
		"Discord Bot Token":       `[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}`,
		"Discord Webhook URL":     `https:\/\/discord(?:app)?\.com\/api\/webhooks\/[0-9]+\/[a-zA-Z0-9_-]+`,
		"Steam Web API Key":       `(?i)steam(.{0,20})?key['"\s:=]+[a-zA-Z0-9]{32}`,
		"Riot Games API Key":      `RGAPI-[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`,

		// 🌐 URL Leaks & Internal Endpoints
		"Private IP (Internal)":   `\b(10\.\d{1,3}|\b192\.168|\b172\.(1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}`,
		"Localhost Reference":     `localhost:[0-9]{2,5}`,
		"Dev/Stage URL":           `(dev|staging|test)\.[a-z0-9.-]+\.(com|net|io)`,
		"Internal Subdomain URL":  `https?:\/\/[a-z0-9.-]+\.internal\.[a-z]{2,}`,
		"Preprod URLs":            `https:\/\/preprod\.[a-z0-9-]+\.[a-z]{2,}`,

		// 🧪 Miscellaneous & Generic
		"Private Key Block":       `-----BEGIN (RSA|DSA|EC|OPENSSH)? PRIVATE KEY-----`,
		"PEM File Content":        `-----BEGIN CERTIFICATE-----`,
		"PGP Private Key Block":   `-----BEGIN PGP PRIVATE KEY BLOCK-----`,
		"Base64 High Entropy String": `['\"][A-Za-z0-9+\/]{40,}={0,2}['\"]`,
		"API Key Generic Detector": `(?i)(apikey|api_key|secret|token)['"\s:=]+[a-zA-Z0-9\-._]{8,}`,
		"Bearer Token Generic":    `(?i)authorization:\s*Bearer\s+[a-zA-Z0-9\-._~+/]+=*`,
		"Session ID":              `(?i)(sessionid|session_id)['"\s:=]+[a-zA-Z0-9]{10,}`,
		"Cookie Name Generic":     `(?i)set-cookie:\s*[a-zA-Z0-9_-]+=`,
		"CSRF Token":              `(?i)csrf(token)?['"\s:=]+[a-zA-Z0-9-_]{8,}`,
		"JWT in Local Storage":    `localStorage\.setItem\(['"]token['"],\s*['"]eyJ[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+['"]\)`,
		
		// Legacy/Custom patterns
		"JJARDEL": `(?:"?[a-z0-9_\-]*(?:key|secret|password|dependencies|auth|aws_secret|api|token)[a-z0-9_\-]*"?\\s*(?::|=)\\s*"?!(null|true|false)([a-z0-9+_:\.\-\/]+)|"Authorization":"[a-z0-9+:_\-\/]+\s(.*?(?<!\\)(?=")))`,
		"SEGREDOS WAR": `(('|")((?:ASIA|AKIA|AROA|AIDA)([A-Z0-9]{16}))('|").*?(\n^.*?){0,4}(('|")[a-zA-Z0-9+/]{40}('|"))+|('|")[a-zA-Z0-9+/]{40}('|").*?(\n^.*?){0,3}(('|")(?:ASIA|AKIA|AROA|AIDA)([A-Z0-9]{16})('|"))+)`,
	}

	for name, pattern := range rawPatterns {
		re, err := regexp.Compile(pattern)
		if err == nil {
			Signatures = append(Signatures, Signature{Name: name, Regex: re})
		}
	}
}
