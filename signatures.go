package main

import "regexp"

type Signature struct {
	Name     string
	Regex    *regexp.Regexp
	Priority string
}

var Signatures []Signature

type RawSig struct {
	Name     string
	Pattern  string
	Priority string
}

func init() {
	rawPatterns := []RawSig{
		// 🔑 Critical: APIs de Serviços de Nuvem, AWS, DBs e Pagamentos
		{"AWS Access Key ID", `AKIA[0-9A-Z]{16}`, "CRITICAL"},
		{"AWS Secret Access Key", `(?i)aws(.{0,20})?(?-i)['\"][0-9a-zA-Z\/+]{40}['\"]`, "CRITICAL"},
		{"Google API Key", `AIza[0-9A-Za-z\\-_]{35}`, "CRITICAL"},
		{"Stripe Secret Key", `sk_live_[0-9a-zA-Z]{24}`, "CRITICAL"},
		{"DigitalOcean Token", `dop_v1_[a-z0-9]{64}`, "CRITICAL"},
		{"Heroku API Key", `[hH]eroku['\"][0-9a-f]{32}['\"]`, "CRITICAL"},
		{"MongoDB Connection URI", `mongodb(\+srv)?:\/\/[^\s'"]+`, "CRITICAL"},
		{"PostgreSQL URI", `postgres(?:ql)?:\/\/[^\s'"]+`, "CRITICAL"},
		{"MySQL URI", `mysql:\/\/[^\s'"]+`, "CRITICAL"},
		{"Redis URI", `redis:\/\/[^\s'"]+`, "CRITICAL"},
		{"Elasticsearch URI", `elasticsearch:\/\/[^\s'"]+`, "CRITICAL"},
		{"Supabase DB Key", `supabase\.co\/[a-z0-9]{15,}`, "CRITICAL"},
		{"Firebase URL", `https:\/\/[a-z0-9-]+\.firebaseio\.com`, "CRITICAL"},
		{"JDBC URL", `jdbc:\w+:\/\/[^\s'"]+`, "CRITICAL"},
		{"AWS RDS Hostname", `[a-z0-9-]+\.rds\.amazonaws\.com`, "CRITICAL"},
		{"Cloud SQL URI (GCP)", `googleapis\.com\/sql\/v1beta4\/projects\/`, "CRITICAL"},
		{"Private Key Block", `-----BEGIN (RSA|DSA|EC|OPENSSH)? PRIVATE KEY-----`, "CRITICAL"},
		{"PGP Private Key Block", `-----BEGIN PGP PRIVATE KEY BLOCK-----`, "CRITICAL"},
		{"Basic Auth String", `(?i)(username|user|email)['"\s:=]+[^\s'"@]{1,100}['"].*?(password|pwd)['"\s:=]+[^\s'"]{4,100}`, "CRITICAL"},
		{"Password Assignment", `(?i)\b(?:password|passwd|pwd)\b\s*[:=]\s*['"][^'"\s<>]{8,100}['"]`, "CRITICAL"},

		// 🔑 High: Plataformas, Git de Repos, Comunicação e SaaS
		{"GitHub Token", `ghp_[0-9a-zA-Z]{36}`, "HIGH"},
		{"GitHub Fine-Grained PAT", `github_pat_[0-9a-zA-Z_]{22,}`, "HIGH"},
		{"GitLab Token", `glpat-[0-9a-zA-Z-_]{20}`, "HIGH"},
		{"Slack Token", `xox[baprs]-[0-9a-zA-Z]{10,48}`, "HIGH"},
		{"Twilio API Key", `SK[0-9a-fA-F]{32}`, "HIGH"},
		{"SendGrid API Key", `SG\.[\w\d\-_]{22}\.[\w\d\-_]{43}`, "HIGH"},
		{"Mailgun API Key", `key-[0-9a-zA-Z]{32}`, "HIGH"},
		{"Dropbox Access Token", `sl\.[A-Za-z0-9_-]{130,}`, "HIGH"},
		{"Shopify Access Token", `shpat_[0-9a-fA-F]{32}`, "HIGH"},
		{"Facebook Access Token", `EAACEdEose0cBA[0-9A-Za-z]+`, "HIGH"},
		{"Stripe Publishable Key", `pk_live_[0-9a-zA-Z]{24}`, "HIGH"},
		{"Netlify Token", `netlifyAuthToken\s*=\s*['"][a-z0-9]{40}['"]`, "HIGH"},
		{"Firebase Secret", `AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}`, "HIGH"},
		{"Asana Personal Access Token", `\b0/[0-9a-f]{32}\b`, "HIGH"},
		{"Linear API Key", `lin_api_[a-zA-Z0-9]{40}`, "HIGH"},
		{"Telegram Bot Token", `\b\d{8,10}:[a-zA-Z0-9_-]{35}\b`, "HIGH"},
		{"Docker Hub Password", `(?i)docker(.{0,20})?password['"\s:=]+[^\s'"]{8,}`, "HIGH"},
		{"AWS IAM Role ARN", `arn:aws:iam::[0-9]{12}:role\/[A-Za-z0-9_+=,.@\-_/]+`, "HIGH"},
		{"Kubernetes Secret Name", `(?i)secretName:\s*['"]?[a-z0-9\-]+['"]?`, "HIGH"},
		{"Helm Secret Value", `(?i)secret\s*:\s*['"][^'"]+['"]`, "HIGH"},
		{"GitHub Actions Secret Reference", `secrets\.[A-Z0-9_]+`, "HIGH"},
		{"GitHub Actions Encrypted Value", `encrypted_value:\s*['"][a-zA-Z0-9+/=]{10,}['"]`, "HIGH"},
		{"K8s Service Account Token", `eyJhbGciOiJSUzI1NiIsImtpZCI6`, "HIGH"},
		{"Vault Token", `\bhvs\.[a-zA-Z0-9_-]{20,}`, "HIGH"},
		{"Vault Token (Legacy)", `\bs\.[a-zA-Z0-9]{24,}(?![a-zA-Z0-9_(.])`, "HIGH"},
		{"Hashicorp Vault URL", `https:\/\/vault\.[a-z0-9\-_\.]+\.com`, "HIGH"},
		{"CircleCI Token", `circle-token=[a-z0-9]{40}`, "HIGH"},
		{"Travis CI Token", `(?i)travis(.{0,20})?token['"\s:=]+[a-z0-9]{30,}`, "HIGH"},
		{"Jenkins Crumb Token", `Jenkins-Crumb:\s*[a-z0-9]{30,}`, "HIGH"},
		{"Azure DevOps PAT", `(?i)(?:azure|devops|ado)[_\-\s.]*(?:pat|token|password)['": \t=]+[a-z0-9]{52}`, "HIGH"},

		{"Bitbucket OAuth Key", `bitbucket(.{0,20})?key['"\s:=]+[a-zA-Z0-9]{20,}`, "HIGH"},
		{"Bitbucket OAuth Secret", `bitbucket(.{0,20})?secret['"\s:=]+[a-zA-Z0-9]{20,}`, "HIGH"},
		{"GitLab Runner Token", `glrt-[a-zA-Z0-9_-]{20}`, "HIGH"},
		{"Sentry DSN", `https:\/\/[a-zA-Z0-9]+@[a-z]+\.ingest\.sentry\.io\/\d+`, "HIGH"},

		// 🤖 AI/ML Providers
		{"OpenAI API Key", `sk-[a-zA-Z0-9]{20,}T3BlbkFJ[a-zA-Z0-9]{20,}`, "CRITICAL"},
		{"OpenAI Project Key", `sk-proj-[a-zA-Z0-9_-]{80,}`, "CRITICAL"},
		{"Anthropic API Key", `sk-ant-[a-zA-Z0-9_-]{90,}`, "CRITICAL"},
		{"Hugging Face Token", `hf_[a-zA-Z0-9]{34}`, "HIGH"},
		{"Replicate API Token", `r8_[a-zA-Z0-9]{37}`, "HIGH"},
		{"Google AI Studio Key", `AIzaSy[a-zA-Z0-9_-]{33}`, "CRITICAL"},
		{"Mistral API Key", `(?i)(?:mistral(?:api)?(?:key|token)?|MISTRAL_API_KEY)\b[^\n]{0,40}[:=]\s*['"][a-z0-9]{32}['"]`, "MEDIUM"},
		{"Groq API Key", `gsk_[a-zA-Z0-9]{52}`, "HIGH"},
		{"Together AI Key", `(?i)(?:together(?:api)?(?:key|token)?|TOGETHER_API_KEY)\b[^\n]{0,40}[:=]\s*['"][a-f0-9]{64}['"]`, "MEDIUM"},

		// ☁️ Modern Cloud/SaaS
		{"Supabase API Key", `sbp_[a-f0-9]{40}`, "HIGH"},
		{"Vercel Token", `vercel_[a-zA-Z0-9]{24}`, "HIGH"},
		{"NPM Token", `npm_[a-zA-Z0-9]{36}`, "HIGH"},
		{"PyPI Token", `pypi-[a-zA-Z0-9_-]{36,}`, "HIGH"},
		{"Clerk Secret Key", `sk_live_[a-zA-Z0-9]{40,}`, "HIGH"},
		{"Clerk Publishable Key", `pk_live_[a-zA-Z0-9]{40,}`, "MEDIUM"},
		{"Azure SAS Token", `(?i)sv=\d{4}-\d{2}-\d{2}&s[a-z]=.*&sig=[a-zA-Z0-9%/+=]+`, "HIGH"},
		{"Planetscale Token", `pscale_tkn_[a-zA-Z0-9_]{32,}`, "HIGH"},
		{"Neon Database Token", `neon_[a-zA-Z0-9_]{32,}`, "HIGH"},
		{"Railway Token", `railway_[a-zA-Z0-9_]{32,}`, "HIGH"},
		{"Render API Key", `rnd_[a-zA-Z0-9]{32,}`, "HIGH"},
		{"Google OAuth Client Secret", `GOCSPX-[a-zA-Z0-9_-]{28}`, "HIGH"},
		{"Grafana API Key", `glc_[a-zA-Z0-9_]{32,}`, "HIGH"},
		{"Grafana Service Account", `glsa_[a-zA-Z0-9_]{32,}`, "HIGH"},
		{"Postman API Key", `PMAK-[a-f0-9]{24}-[a-f0-9]{34}`, "HIGH"},
		{"Doppler Token", `dp\.(?:st|ct|sa|scim|audit)\.[a-zA-Z0-9_]{40,}`, "HIGH"},
		{"Figma Token", `figd_[a-zA-Z0-9_-]{40,}`, "HIGH"},
		{"Notion API Key", `secret_[a-zA-Z0-9]{43}`, "HIGH"},
		{"Airtable API Key", `(?i)(?:airtable(?:api)?(?:key|token)?)\b[^\n]{0,40}[:=]\s*['"]key[a-zA-Z0-9]{14}['"]`, "HIGH"},
		{"Contentful API Key", `CFPAT-[a-zA-Z0-9_-]{43}`, "HIGH"},
		{"Algolia API Key", `(?i)(?:algolia(?:api)?(?:key|token)?|x-algolia-api-key)\b[^\n]{0,40}[:=]\s*['"][a-f0-9]{32}['"]`, "MEDIUM"},
		{"Mapbox Token", `pk\.[a-zA-Z0-9]{60,}`, "MEDIUM"},
		{"Mapbox Secret", `sk\.[a-zA-Z0-9]{60,}`, "HIGH"},

		// 🔐 Medium: Tokens de Baixo Risco, Analytics e Oauth Incompleto
		{"Firebase API Key", `firebaseConfig\s*=\s*{[^}]*apiKey\s*:\s*['"][^'"]+['"]`, "MEDIUM"},
		{"OAuth Client Secret", `(?i)client_secret['"\s:=]+[a-zA-Z0-9\-_.~]{10,100}`, "MEDIUM"},
		{"OAuth Client ID", `(?i)client_id['"\s:=]+[a-zA-Z0-9\-_.~]{10,100}`, "MEDIUM"},
		{"Azure Client Secret", `(?i)azure(.{0,20})?client.secret(.{0,20})?['\"][a-zA-Z0-9._%+-]{32,}['\"]`, "MEDIUM"},
		{"Microsoft Teams Webhook", `https:\/\/[a-z]+\.webhook\.office\.com\/webhookb2\/[a-zA-Z0-9@\-]+\/.*`, "MEDIUM"},
		{"API Key in Variable", `(?i)(api[_-]?key)['"\s:=]+(?![a-zA-Z]\.[a-zA-Z])[a-zA-Z0-9\-_]{8,100}`, "MEDIUM"},
		{"Secret in Variable", `(?i)(secret|token)['"\s:=]+(?![a-zA-Z]\.[a-zA-Z])[a-zA-Z0-9\-_]{8,100}`, "MEDIUM"},
		{"Authorization Bearer Token", `Bearer\s+[a-zA-Z0-9\-._~+/]+=*`, "MEDIUM"},
		{"Cloudinary URL", `cloudinary:\/\/[0-9]{15}:[a-zA-Z0-9]+@[a-zA-Z]+`, "MEDIUM"},
		{"Segment API Key", `(?i)segment(.{0,20})?key['"\s:=]+[a-zA-Z0-9]{10,}`, "MEDIUM"},
		{"Intercom Access Token", `(?i)intercom(.{0,20})?token['"\s:=]+[a-zA-Z0-9-_]{20,}`, "MEDIUM"},
		{"Amplitude API Key", `apiKey['"]?\s*:\s*['"][a-z0-9\-]{32,64}['"]`, "MEDIUM"},
		{"Plaid Client Secret", `plaid(.{0,20})?(client)?secret['"\s:=]+[a-z0-9-_]{30,}`, "MEDIUM"},
		{"Bugsnag API Key", `(?i)(?:bugsnag|notifier)[_\-\s.]*(?:api)?[_\-\s.]*key['": \t=]+[a-f0-9]{32}(?![a-f0-9])`, "MEDIUM"},
		{"Datadog API Key", `(?i)(?:DD_API_KEY|DD_CLIENT_TOKEN|datadog[_\-\s.]*(?:api|client)[_\-\s.]*(?:key|token))['": \t=]+[a-z0-9]{32}(?![a-z0-9])`, "MEDIUM"},
		{"Loggly Token", `[a-z0-9]{30}-[a-z0-9]{10}`, "MEDIUM"},
		{"New Relic Key", `NRII-[a-zA-Z0-9]{20,}`, "MEDIUM"},
		{"Mixpanel Token", `(?i)mixpanel(.{0,20})?token['"\s:=]+[a-z0-9]{32}`, "MEDIUM"},
		{"Heap Analytics App ID", `heapSettings\.appId\s*=\s*['"][a-z0-9]{8,12}['"]`, "MEDIUM"},
		{"Keen IO Project ID", `projectId['"]?\s*:\s*['"][a-f0-9]{24}['"]`, "MEDIUM"},
		{"Keen IO Write Key", `writeKey['"]?\s*:\s*['"][a-zA-Z0-9]{64}['"]`, "MEDIUM"},
		{"Snyk Token", `snyk_token\s*=\s*[a-f0-9\-]{36}`, "MEDIUM"},
		{"Rollbar Access Token", `access_token['"]?\s*:\s*['"][a-z0-9]{32}['"]`, "MEDIUM"},
		{"Twitch API Key", `(?i)twitch(.{0,20})?key['"\s:=]+[a-zA-Z0-9]{20,}`, "MEDIUM"},
		{"Discord Bot Token", `[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}`, "MEDIUM"},
		{"Discord Webhook URL", `https:\/\/discord(?:app)?\.com\/api\/webhooks\/[0-9]+\/[a-zA-Z0-9_-]+`, "MEDIUM"},
		{"Steam Web API Key", `(?i)steam(.{0,20})?key['"\s:=]+[a-zA-Z0-9]{32}`, "MEDIUM"},
		{"Riot Games API Key", `RGAPI-[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`, "MEDIUM"},
		{"GitHub OAuth App Secret", `(?i)(?:github|client[_-]?secret|oauth[_-]?(?:token|secret)|access_token)['": \t=]+(?<![a-f0-9])[a-f0-9]{40}(?![a-f0-9])`, "MEDIUM"},
		{"JWT Token", `eyJ[A-Za-z0-9-_=]+?\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*`, "MEDIUM"},
		{"JWT in Local Storage", `localStorage\.setItem\(['"]token['"],\s*['"]eyJ[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+['"]\)`, "MEDIUM"},

		// 📉 Low / Noise: Detecções genéricas ou propensas a falso-positivos
		{"AWS S3 Bucket URL", `s3:\/\/[a-z0-9\-\.]{3,63}`, "LOW"},
		{"Private IP (Internal)", `\b(10\.\d{1,3}|\b192\.168|\b172\.(1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}`, "LOW"},
		{"Localhost Reference", `localhost:[0-9]{2,5}`, "LOW"},
		{"Dev/Stage URL", `(dev|staging|test)\.[a-z0-9.-]+\.(com|net|io)`, "LOW"},
		{"Internal Subdomain URL", `https?:\/\/[a-z0-9.-]+\.internal\.[a-z]{2,}`, "LOW"},
		{"Preprod URLs", `https:\/\/preprod\.[a-z0-9-]+\.[a-z]{2,}`, "LOW"},
		{"PEM File Content", `-----BEGIN CERTIFICATE-----`, "LOW"},
		{"Base64 High Entropy String", `['\"][A-Za-z0-9+\/]{40,}={0,2}['\"]`, "LOW"},
		{"API Key Generic Detector", `(?i)(apikey|api_key|secret|token)['"\s:=]+(?![a-zA-Z]\.[a-zA-Z])[a-zA-Z0-9\-_]{8,}`, "LOW"},
		{"Bearer Token Generic", `(?i)authorization:\s*Bearer\s+[a-zA-Z0-9\-._~+/]+=*`, "LOW"},
		{"Session ID", `(?i)(sessionid|session_id)['"\s:=]+[a-zA-Z0-9]{10,}`, "LOW"},
		{"Cookie Name Generic", `(?i)set-cookie:\s*[a-zA-Z0-9_-]+=`, "LOW"},
		{"CSRF Token", `(?i)csrf(token)?['"\s:=]+[a-zA-Z0-9-_]{8,}`, "LOW"},
		{"JJARDEL (Legacy)", `(?:"?[a-z0-9_\-]*(?:key|secret|password|dependencies|auth|aws_secret|api|token)[a-z0-9_\-]*"?\s*(?::|=)\s*"?!(null|true|false)([a-z0-9+_:\.\-\/]+)|"Authorization":"[a-z0-9+:_\-\/]+\s(.*?(?<!\\)(?=")))`, "LOW"},
		{"SEGREDOS WAR (Legacy)", `(('|")((?:ASIA|AKIA|AROA|AIDA)([A-Z0-9]{16}))('|").*?(\n^.*?){0,4}(('|")[a-zA-Z0-9+/]{40}('|"))+|('|")[a-zA-Z0-9+/]{40}('|").*?(\n^.*?){0,3}(('|")(?:ASIA|AKIA|AROA|AIDA)([A-Z0-9]{16})('|"))+)`, "LOW"},
	}

	for _, sig := range rawPatterns {
		re, err := regexp.Compile(sig.Pattern)
		if err == nil {
			Signatures = append(Signatures, Signature{Name: sig.Name, Regex: re, Priority: sig.Priority})
		}
	}
}
