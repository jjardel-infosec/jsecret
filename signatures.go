package main

import "regexp"

type Signature struct {
	Name     string
	Regex    *regexp.Regexp
	Priority string
	Prefix   string // Static prefix for fast pre-filtering (skip regex if absent)
}

var Signatures []Signature

type RawSig struct {
	Name     string
	Pattern  string
	Priority string
	Prefix   string // Optional: static substring that MUST appear for this pattern to match
}

func init() {
	rawPatterns := []RawSig{
		// ═══════════════════════════════════════════════════════════════════
		// 🔑 CRITICAL: Cloud APIs, AWS, DBs, Payments, Private Keys
		// ═══════════════════════════════════════════════════════════════════
		{"AWS Access Key ID", `AKIA[0-9A-Z]{16}`, "CRITICAL", "AKIA"},
		{"AWS Secret Access Key", `(?i)aws(.{0,20})?(?-i)['\"][0-9a-zA-Z\/+]{40}['\"]`, "CRITICAL", ""},
		{"AWS Session Token", `(?i)aws_session_token['"\s:=]+[A-Za-z0-9/+=]{100,}`, "CRITICAL", ""},
		{"Google API Key", `AIza[0-9A-Za-z\\-_]{35}`, "CRITICAL", "AIza"},
		{"Google AI Studio Key", `AIzaSy[a-zA-Z0-9_-]{33}`, "CRITICAL", "AIzaSy"},
		{"Google OAuth Refresh Token", `1//[a-zA-Z0-9_-]{40,}`, "CRITICAL", "1//"},
		{"GCP Service Account JSON", `(?s)"type"\s*:\s*"service_account"[\s\S]{0,500}"private_key"\s*:\s*"-----BEGIN`, "CRITICAL", "service_account"},
		{"Stripe Secret Key", `sk_live_[0-9a-zA-Z]{24}`, "CRITICAL", "sk_live_"},
		{"DigitalOcean Token", `dop_v1_[a-z0-9]{64}`, "CRITICAL", "dop_v1_"},
		{"Heroku API Key", `[hH]eroku['\"][0-9a-f]{32}['\"]`, "CRITICAL", "eroku"},
		{"MongoDB Connection URI", `mongodb(\+srv)?:\/\/[^\s'"]+`, "CRITICAL", "mongodb"},
		{"PostgreSQL URI", `postgres(?:ql)?:\/\/[^\s'"]+`, "CRITICAL", "postgres"},
		{"MySQL URI", `mysql:\/\/[^\s'"]+`, "CRITICAL", "mysql://"},
		{"Redis URI", `redis:\/\/[^\s'"]+`, "CRITICAL", "redis://"},
		{"Elasticsearch URI", `elasticsearch:\/\/[^\s'"]+`, "CRITICAL", "elasticsearch://"},
		{"Snowflake URI", `snowflake:\/\/[^\s'"]+`, "CRITICAL", "snowflake://"},
		{"CockroachDB URI", `cockroachdb:\/\/[^\s'"]+`, "CRITICAL", "cockroachdb://"},
		{"ClickHouse URI", `clickhouse:\/\/[^\s'"]+`, "CRITICAL", "clickhouse://"},
		{"Cassandra URI", `cassandra:\/\/[^\s'"]+`, "CRITICAL", "cassandra://"},
		{"Supabase DB Key", `supabase\.co\/[a-z0-9]{15,}`, "CRITICAL", "supabase.co"},
		{"Firebase URL", `https:\/\/[a-z0-9-]+\.firebaseio\.com`, "CRITICAL", "firebaseio.com"},
		{"JDBC URL", `jdbc:\w+:\/\/[^\s'"]+`, "CRITICAL", "jdbc:"},
		{"AWS RDS Hostname", `[a-z0-9-]+\.rds\.amazonaws\.com`, "CRITICAL", ".rds.amazonaws.com"},
		{"Cloud SQL URI (GCP)", `googleapis\.com\/sql\/v1beta4\/projects\/`, "CRITICAL", "googleapis.com/sql"},
		{"Private Key Block", `-----BEGIN (RSA|DSA|EC|OPENSSH)? PRIVATE KEY-----`, "CRITICAL", "-----BEGIN"},
		{"PGP Private Key Block", `-----BEGIN PGP PRIVATE KEY BLOCK-----`, "CRITICAL", "-----BEGIN PGP"},
		{"Basic Auth String", `(?is)(?:['"](?:username|user|email)['"]\s*:\s*['"][^'"\s@]{3,100}['"][\s\S]{0,120}['"](?:password|passwd|pwd)['"]\s*:\s*['"][^'"\s<>]{8,100}['"]|['"](?:password|passwd|pwd)['"]\s*:\s*['"][^'"\s<>]{8,100}['"][\s\S]{0,120}['"](?:username|user|email)['"]\s*:\s*['"][^'"\s@]{3,100}['"])`, "CRITICAL", ""},
		{"Password Assignment", `(?i)\b(?:password|passwd|pwd)\b\s*[:=]\s*['"][^'"\s<>]{8,100}['"]`, "CRITICAL", ""},
		{"Cloudflare API Token", `(?i)(?:CF_API_TOKEN|cloudflare[_\-\s.]*(?:api)?[_\-\s.]*(?:token|key))['": \t=]+[A-Za-z0-9_-]{40}`, "CRITICAL", ""},
		{"Terraform Cloud Token", `atlasv1\.[a-zA-Z0-9_-]{60,}`, "CRITICAL", "atlasv1."},
		{"Pulumi Access Token", `pul-[a-f0-9]{40}`, "CRITICAL", "pul-"},
		{"Alibaba Cloud Access Key", `LTAI[A-Za-z0-9]{12,20}`, "CRITICAL", "LTAI"},
		{"Azure Storage Account Key", `(?i)AccountKey\s*=\s*[A-Za-z0-9+/]{86,88}==`, "CRITICAL", "AccountKey"},

		// ═══════════════════════════════════════════════════════════════════
		// 🤖 AI/ML Providers (expanded for 2024-2026 landscape)
		// ═══════════════════════════════════════════════════════════════════
		{"OpenAI API Key", `sk-[a-zA-Z0-9]{20,}T3BlbkFJ[a-zA-Z0-9]{20,}`, "CRITICAL", "T3BlbkFJ"},
		{"OpenAI Project Key", `sk-proj-[a-zA-Z0-9_-]{80,}`, "CRITICAL", "sk-proj-"},
		{"Anthropic API Key", `sk-ant-[a-zA-Z0-9_-]{90,}`, "CRITICAL", "sk-ant-"},
		{"DeepSeek API Key", `(?i)(?:deepseek|DEEPSEEK_API_KEY)\b[^\n]{0,40}[:=]\s*['"]sk-[a-f0-9]{48}['"]`, "CRITICAL", "deepseek"},
		{"xAI Grok API Key", `xai-[a-zA-Z0-9]{40,}`, "CRITICAL", "xai-"},
		{"Perplexity API Key", `pplx-[a-f0-9]{48}`, "HIGH", "pplx-"},
		{"Fireworks AI Key", `fw_[a-zA-Z0-9]{40,}`, "HIGH", "fw_"},
		{"Hugging Face Token", `hf_[a-zA-Z0-9]{34}`, "HIGH", "hf_"},
		{"Replicate API Token", `r8_[a-zA-Z0-9]{37}`, "HIGH", "r8_"},
		{"Groq API Key", `gsk_[a-zA-Z0-9]{52}`, "HIGH", "gsk_"},
		{"Cohere API Key", `(?i)(?:cohere|CO_API_KEY|COHERE_API_KEY)\b[^\n]{0,40}[:=]\s*['"][a-zA-Z0-9]{40}['"]`, "HIGH", ""},
		{"Mistral API Key", `(?i)(?:mistral(?:api)?(?:key|token)?|MISTRAL_API_KEY)\b[^\n]{0,40}[:=]\s*['"][a-z0-9]{32}['"]`, "MEDIUM", ""},
		{"Together AI Key", `(?i)(?:together(?:api)?(?:key|token)?|TOGETHER_API_KEY)\b[^\n]{0,40}[:=]\s*['"][a-f0-9]{64}['"]`, "MEDIUM", ""},
		{"Pinecone API Key", `pcsk_[a-zA-Z0-9_]{42,}`, "HIGH", "pcsk_"},
		{"Weaviate API Key", `(?i)(?:weaviate|WCS_API_KEY)\b[^\n]{0,40}[:=]\s*['"][a-zA-Z0-9-]{36,}['"]`, "HIGH", ""},
		{"Qdrant API Key", `(?i)(?:qdrant|QDRANT_API_KEY)\b[^\n]{0,40}[:=]\s*['"][a-zA-Z0-9_-]{20,}['"]`, "MEDIUM", ""},

		// ═══════════════════════════════════════════════════════════════════
		// 🔑 HIGH: Git Platforms, Communication, CI/CD, SaaS
		// ═══════════════════════════════════════════════════════════════════
		{"GitHub Token", `ghp_[0-9a-zA-Z]{36}`, "HIGH", "ghp_"},
		{"GitHub Fine-Grained PAT", `github_pat_[0-9a-zA-Z_]{22,}`, "HIGH", "github_pat_"},
		{"GitLab Token", `glpat-[0-9a-zA-Z-_]{20}`, "HIGH", "glpat-"},
		{"Slack Token", `xox[baprs]-[0-9a-zA-Z]{10,48}`, "HIGH", "xox"},
		{"Slack Webhook URL", `https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+`, "HIGH", "hooks.slack.com"},
		{"Twilio API Key", `SK[0-9a-fA-F]{32}`, "HIGH", "SK"},
		{"SendGrid API Key", `SG\.[\w\d\-_]{22}\.[\w\d\-_]{43}`, "HIGH", "SG."},
		{"Mailgun API Key", `key-[0-9a-zA-Z]{32}`, "HIGH", "key-"},
		{"Dropbox Access Token", `sl\.[A-Za-z0-9_-]{130,}`, "HIGH", "sl."},
		{"Shopify Access Token", `shpat_[0-9a-fA-F]{32}`, "HIGH", "shpat_"},
		{"Facebook Access Token", `EAACEdEose0cBA[0-9A-Za-z]+`, "HIGH", "EAACEdEose0cBA"},
		{"Stripe Publishable Key", `pk_live_[0-9a-zA-Z]{24}`, "HIGH", "pk_live_"},
		{"Netlify Token", `netlifyAuthToken\s*=\s*['"][a-z0-9]{40}['"]`, "HIGH", "netlifyAuthToken"},
		{"Firebase Secret", `AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}`, "HIGH", "AAAA"},
		{"Asana Personal Access Token", `\b0/[0-9a-f]{32}\b`, "HIGH", "0/"},
		{"Linear API Key", `lin_api_[a-zA-Z0-9]{40}`, "HIGH", "lin_api_"},
		{"Linear OAuth Token", `lin_oauth_[a-zA-Z0-9]{40}`, "HIGH", "lin_oauth_"},
		{"Telegram Bot Token", `\b\d{8,10}:[a-zA-Z0-9_-]{35}\b`, "HIGH", ""},
		{"Docker Hub Password", `(?i)docker(.{0,20})?password['"\s:=]+[^\s'"]{8,}`, "HIGH", ""},
		{"AWS IAM Role ARN", `arn:aws:iam::[0-9]{12}:role\/[A-Za-z0-9_+=,.@\-_/]+`, "HIGH", "arn:aws:iam::"},
		{"Kubernetes Secret Name", `(?i)secretName:\s*['"]?[a-z0-9\-]+['"]?`, "HIGH", ""},
		{"Helm Secret Value", `(?is)apiVersion\s*:\s*v\d+[^\n]*[\s\S]{0,250}kind\s*:\s*Secret[\s\S]{0,500}\b(?:data|stringData)\b[\s\S]{0,500}\bsecret\s*:\s*['"][^'"]+['"]`, "HIGH", ""},
		{"GitHub Actions Secret Reference", `secrets\.[A-Z0-9_]+`, "HIGH", "secrets."},
		{"GitHub Actions Encrypted Value", `encrypted_value:\s*['"][a-zA-Z0-9+/=]{10,}['"]`, "HIGH", "encrypted_value"},
		{"K8s Service Account Token", `eyJhbGciOiJSUzI1NiIsImtpZCI6`, "HIGH", "eyJhbGciOiJSUzI1NiIsImtpZCI6"},
		{"Vault Token", `\bhvs\.[a-zA-Z0-9_-]{20,}`, "HIGH", "hvs."},
		{"Vault Token (Legacy)", `(?:^|[\s'";=])s\.[a-zA-Z0-9]{24,}(?![a-zA-Z0-9_(./])`, "HIGH", "s."},
		{"Hashicorp Vault URL", `https:\/\/vault\.[a-z0-9\-_\.]+\.com`, "HIGH", "vault."},
		{"CircleCI Token", `circle-token=[a-z0-9]{40}`, "HIGH", "circle-token="},
		{"Travis CI Token", `(?i)travis(.{0,20})?token['"\s:=]+[a-z0-9]{30,}`, "HIGH", ""},
		{"Jenkins Crumb Token", `Jenkins-Crumb:\s*[a-z0-9]{30,}`, "HIGH", "Jenkins-Crumb"},
		{"Azure DevOps PAT", `(?i)(?:azure|devops|ado)[_\-\s.]*(?:pat|token|password)['": \t=]+[a-z0-9]{52}`, "HIGH", ""},
		{"Bitbucket OAuth Key", `bitbucket(.{0,20})?key['"\s:=]+[a-zA-Z0-9]{20,}`, "HIGH", "bitbucket"},
		{"Bitbucket OAuth Secret", `bitbucket(.{0,20})?secret['"\s:=]+[a-zA-Z0-9]{20,}`, "HIGH", "bitbucket"},
		{"GitLab Runner Token", `glrt-[a-zA-Z0-9_-]{20}`, "HIGH", "glrt-"},
		{"Sentry DSN", `https:\/\/[a-zA-Z0-9]+@[a-z0-9]+\.ingest\.sentry\.io\/\d+`, "HIGH", "sentry.io"},
		{"Google OAuth Client Secret", `GOCSPX-[a-zA-Z0-9_-]{28}`, "HIGH", "GOCSPX-"},

		// ═══════════════════════════════════════════════════════════════════
		// ☁️ Modern Cloud/SaaS (expanded for 2024-2026 services)
		// ═══════════════════════════════════════════════════════════════════
		{"Supabase API Key", `sbp_[a-f0-9]{40}`, "HIGH", "sbp_"},
		{"Supabase Service Role JWT", `(?i)(?:service_role|SUPABASE_SERVICE_ROLE)\b[^\n]{0,40}[:=]\s*['"]eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+['"]`, "CRITICAL", "service_role"},
		{"Vercel Token", `vercel_[a-zA-Z0-9]{24}`, "HIGH", "vercel_"},
		{"NPM Token", `npm_[a-zA-Z0-9]{36}`, "HIGH", "npm_"},
		{"PyPI Token", `pypi-[a-zA-Z0-9_-]{36,}`, "HIGH", "pypi-"},
		{"Clerk Secret Key", `sk_live_[a-zA-Z0-9]{40,}`, "HIGH", "sk_live_"},
		{"Clerk Publishable Key", `pk_live_[a-zA-Z0-9]{40,}`, "MEDIUM", "pk_live_"},
		{"Azure SAS Token", `(?i)sv=\d{4}-\d{2}-\d{2}&s[a-z]=.*&sig=[a-zA-Z0-9%/+=]+`, "HIGH", "sv="},
		{"Planetscale Token", `pscale_tkn_[a-zA-Z0-9_]{32,}`, "HIGH", "pscale_tkn_"},
		{"Planetscale OAuth Token", `pscale_oauthtkn_[a-zA-Z0-9_]{32,}`, "HIGH", "pscale_oauthtkn_"},
		{"Neon Database Token", `neon_[a-zA-Z0-9_]{32,}`, "HIGH", "neon_"},
		{"Railway Token", `railway_[a-zA-Z0-9_]{32,}`, "HIGH", "railway_"},
		{"Render API Key", `rnd_[a-zA-Z0-9]{32,}`, "HIGH", "rnd_"},
		{"Grafana API Key", `glc_[a-zA-Z0-9_]{32,}`, "HIGH", "glc_"},
		{"Grafana Service Account", `glsa_[a-zA-Z0-9_]{32,}`, "HIGH", "glsa_"},
		{"Postman API Key", `PMAK-[a-f0-9]{24}-[a-f0-9]{34}`, "HIGH", "PMAK-"},
		{"Doppler Token", `dp\.(?:st|ct|sa|scim|audit)\.[a-zA-Z0-9_]{40,}`, "HIGH", "dp."},
		{"Figma Token", `figd_[a-zA-Z0-9_-]{40,}`, "HIGH", "figd_"},
		{"Notion API Key", `secret_[a-zA-Z0-9]{43}`, "HIGH", "secret_"},
		{"Airtable API Key", `(?i)(?:airtable(?:api)?(?:key|token)?)\b[^\n]{0,40}[:=]\s*['"]key[a-zA-Z0-9]{14}['"]`, "HIGH", ""},
		{"Contentful API Key", `CFPAT-[a-zA-Z0-9_-]{43}`, "HIGH", "CFPAT-"},
		{"Fly.io Token", `fo1_[a-zA-Z0-9_-]{40,}`, "HIGH", "fo1_"},
		{"Deno Deploy Token", `ddp_[a-zA-Z0-9]{40}`, "HIGH", "ddp_"},
		{"Resend API Key", `re_[a-zA-Z0-9]{30,}`, "HIGH", "re_"},
		{"Trigger.dev API Key", `tr_(?:dev|prod|live|test|stg)_[a-zA-Z0-9]{16,}`, "HIGH", "tr_"},
		{"Tinybird API Token", `(?i)(?:tinybird|TINYBIRD_TOKEN|TB_TOKEN)\b[^\n]{0,40}[:=]\s*['"]p\.[a-zA-Z0-9]{20,}['"]`, "HIGH", "p."},
		{"Arcjet API Key", `ajkey_[a-zA-Z0-9_-]{30,}`, "HIGH", "ajkey_"},
		{"Expo Access Token", `expo_[a-zA-Z0-9]{20,}`, "HIGH", "expo_"},
		{"Infisical Token", `st\.[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}`, "HIGH", "st."},
		{"Algolia API Key", `(?i)(?:algolia(?:api)?(?:key|token)?|x-algolia-api-key)\b[^\n]{0,40}[:=]\s*['"][a-f0-9]{32}['"]`, "MEDIUM", ""},
		{"Mapbox Token", `pk\.[a-zA-Z0-9]{60,}`, "MEDIUM", "pk."},
		{"Mapbox Secret", `sk\.[a-zA-Z0-9]{60,}`, "HIGH", "sk."},

		// ═══════════════════════════════════════════════════════════════════
		// 🛡️ Infrastructure & Secrets Management
		// ═══════════════════════════════════════════════════════════════════
		{"Okta API Token", `(?i)(?:okta|OKTA_API_TOKEN)\b[^\n]{0,40}[:=]\s*['"][a-zA-Z0-9_-]{42}['"]`, "HIGH", ""},
		{"Auth0 Management Token", `(?i)(?:auth0|AUTH0_API_TOKEN)\b[^\n]{0,40}[:=]\s*['"]eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+['"]`, "HIGH", "auth0"},
		{"Confluent / Kafka API Key", `(?i)(?:confluent|kafka)[_\-\s.]*(?:api)?[_\-\s.]*(?:key|secret)['": \t=]+[a-zA-Z0-9]{16,}`, "HIGH", ""},
		{"RabbitMQ URI", `amqps?:\/\/[^\s'"]+`, "CRITICAL", "amqp"},
		{"Memcached URI", `memcached:\/\/[^\s'"]+`, "HIGH", "memcached://"},
		{"InfluxDB Token", `(?i)(?:influx|INFLUXDB_TOKEN)\b[^\n]{0,40}[:=]\s*['"][a-zA-Z0-9_=-]{40,}['"]`, "HIGH", ""},
		{"Vault Unseal Key", `(?i)unseal[_\-\s]*key['": \t=]+[a-zA-Z0-9+/=]{44}`, "CRITICAL", "unseal"},
		{"1Password Connect Token", `ops_[a-zA-Z0-9]{40,}`, "HIGH", "ops_"},
		{"Doppler Service Token", `dp\.st\.[a-zA-Z0-9_]{40,}`, "HIGH", "dp.st."},

		// ═══════════════════════════════════════════════════════════════════
		// 💳 Payments & Financial
		// ═══════════════════════════════════════════════════════════════════
		{"Square Access Token", `sq0atp-[a-zA-Z0-9_-]{22}`, "CRITICAL", "sq0atp-"},
		{"Square OAuth Secret", `sq0csp-[a-zA-Z0-9_-]{43}`, "CRITICAL", "sq0csp-"},
		{"Braintree Access Token", `access_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32}`, "CRITICAL", "access_token$production$"},
		{"PayPal Client Secret", `(?i)paypal(.{0,20})?secret['"\s:=]+[a-zA-Z0-9_-]{40,}`, "HIGH", "paypal"},
		{"Adyen API Key", `(?i)(?:adyen|ADYEN_API_KEY)\b[^\n]{0,40}[:=]\s*['"]AQE[a-zA-Z0-9_.-]+['"]`, "HIGH", "AQE"},
		{"Coinbase API Key", `(?i)(?:coinbase|cb)[_\-\s.]*(?:api)?[_\-\s.]*(?:key|secret)['": \t=]+[a-zA-Z0-9]{16,}`, "HIGH", ""},

		// ═══════════════════════════════════════════════════════════════════
		// 📧 Email & Communication Services
		// ═══════════════════════════════════════════════════════════════════
		{"Postmark Server Token", `(?i)(?:postmark|POSTMARK_SERVER_TOKEN)\b[^\n]{0,40}[:=]\s*['"][a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}['"]`, "HIGH", "postmark"},
		{"Mailchimp API Key", `[a-f0-9]{32}-us\d{1,2}`, "HIGH", "-us"},
		{"SparkPost API Key", `(?i)(?:sparkpost|SPARKPOST_API_KEY)\b[^\n]{0,40}[:=]\s*['"][a-f0-9]{40}['"]`, "HIGH", "sparkpost"},
		{"Vonage / Nexmo API Key", `(?i)(?:nexmo|vonage)[_\-\s.]*(?:api)?[_\-\s.]*(?:key|secret)['": \t=]+[a-zA-Z0-9]{8,}`, "HIGH", ""},
		{"Pusher App Secret", `(?i)pusher(.{0,20})?secret['"\s:=]+[a-zA-Z0-9]{20,}`, "MEDIUM", "pusher"},
		{"Ably API Key", `(?i)(?:ably|ABLY_API_KEY)\b[^\n]{0,40}[:=]\s*['"][a-zA-Z0-9._-]{10,}:[a-zA-Z0-9._-]{10,}['"]`, "HIGH", "ably"},

		// ═══════════════════════════════════════════════════════════════════
		// 🧪 Testing / Monitoring / Observability
		// ═══════════════════════════════════════════════════════════════════
		{"LaunchDarkly SDK Key", `sdk-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}`, "HIGH", "sdk-"},
		{"LaunchDarkly API Key", `api-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}`, "HIGH", "api-"},
		{"PagerDuty API Key", `(?i)(?:pagerduty|PD_API_KEY)\b[^\n]{0,40}[:=]\s*['"][a-zA-Z0-9+_-]{20,}['"]`, "HIGH", ""},
		{"Elastic APM Secret Token", `(?i)(?:elastic|apm)[_\-\s.]*(?:secret)?[_\-\s.]*token['": \t=]+[a-zA-Z0-9_-]{20,}`, "HIGH", ""},
		{"Honeycomb API Key", `(?i)(?:honeycomb|HONEYCOMB_API_KEY)\b[^\n]{0,40}[:=]\s*['"][a-zA-Z0-9]{22,}['"]`, "MEDIUM", ""},
		{"Dynatrace API Token", `dt0c01\.[a-zA-Z0-9]{24}\.[a-zA-Z0-9]{64}`, "HIGH", "dt0c01."},
		{"Splunk HEC Token", `(?i)(?:splunk|HEC)[_\-\s.]*token['": \t=]+[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}`, "HIGH", ""},
		{"Logz.io Token", `(?i)(?:logzio|LOGZIO_TOKEN)\b[^\n]{0,40}[:=]\s*['"][a-zA-Z0-9]{32,}['"]`, "MEDIUM", ""},

		// ═══════════════════════════════════════════════════════════════════
		// 🗺️ Maps / Geolocation / CDN
		// ═══════════════════════════════════════════════════════════════════
		{"HERE Maps API Key", `(?i)(?:here|HERE_API_KEY)\b[^\n]{0,40}[:=]\s*['"][a-zA-Z0-9_-]{40,}['"]`, "MEDIUM", ""},
		{"Fastly API Token", `(?i)(?:fastly|FASTLY_API_TOKEN)\b[^\n]{0,40}[:=]\s*['"][a-zA-Z0-9_-]{32,}['"]`, "HIGH", "fastly"},
		{"Cloudflare Workers KV Token", `(?i)(?:CF_KV|cloudflare[_\-\s.]*kv)[_\-\s.]*(?:token|key)['": \t=]+[a-zA-Z0-9_-]{40,}`, "HIGH", ""},

		// ═══════════════════════════════════════════════════════════════════
		// 🏗️ DevOps / Build / Deployment
		// ═══════════════════════════════════════════════════════════════════
		{"Buildkite Agent Token", `bkagent_[a-zA-Z0-9]{40,}`, "HIGH", "bkagent_"},
		{"Buildkite API Token", `bkp_[a-zA-Z0-9]{40,}`, "HIGH", "bkp_"},
		{"Pulumi State Passphrase", `(?i)PULUMI_CONFIG_PASSPHRASE['": \t=]+[^\s'"]{8,}`, "HIGH", "PULUMI_CONFIG_PASSPHRASE"},
		{"Terraform Workspace Token", `(?i)TF_TOKEN_[a-z_]+['": \t=]+[a-zA-Z0-9._-]{14,}`, "HIGH", "TF_TOKEN_"},
		{"Scaleway API Key", `scw[a-zA-Z0-9_]{32,}`, "HIGH", "scw"},
		{"Hetzner API Token", `(?i)(?:hetzner|HETZNER_API_TOKEN)\b[^\n]{0,40}[:=]\s*['"][a-zA-Z0-9]{64}['"]`, "HIGH", "hetzner"},
		{"Linode API Token", `(?i)(?:linode|LINODE_TOKEN)\b[^\n]{0,40}[:=]\s*['"][a-f0-9]{64}['"]`, "HIGH", "linode"},
		{"Vultr API Key", `(?i)(?:vultr|VULTR_API_KEY)\b[^\n]{0,40}[:=]\s*['"][a-zA-Z0-9]{36}['"]`, "HIGH", "vultr"},

		// ═══════════════════════════════════════════════════════════════════
		// 🔐 MEDIUM: Analytics, OAuth, Webhooks, Messaging
		// ═══════════════════════════════════════════════════════════════════
		{"Firebase API Key", `firebaseConfig\s*=\s*{[^}]*apiKey\s*:\s*['"][^'"]+['"]`, "MEDIUM", "firebaseConfig"},
		{"OAuth Client Secret", `(?i)\bclient_secret\b\s*[:=]\s*['"](?=[A-Za-z0-9._~\-]{24,100}['"])(?=[^'"]*[A-Za-z])(?=[^'"]*\d)[A-Za-z0-9._~\-]{24,100}['"]`, "MEDIUM", ""},
		{"OAuth Client ID", `(?i)\bclient_id\b\s*[:=]\s*['"](?=[A-Za-z0-9._~\-]{16,100}['"])(?=[^'"]*[A-Za-z])(?=[^'"]*\d)[A-Za-z0-9._~\-]{16,100}['"]`, "MEDIUM", ""},
		{"Azure Client Secret", `(?i)azure(.{0,20})?client.secret(.{0,20})?['\"][a-zA-Z0-9._%+-]{32,}['\"]`, "MEDIUM", ""},
		{"Microsoft Teams Webhook", `https:\/\/[a-z]+\.webhook\.office\.com\/webhookb2\/[a-zA-Z0-9@\-]+\/.*`, "MEDIUM", "webhook.office.com"},
		{"API Key in Variable", `(?i)(api[_-]?key)['"\s:=]+(?![a-zA-Z]\.[a-zA-Z])[a-zA-Z0-9\-_]{8,100}`, "MEDIUM", ""},
		{"Secret in Variable", `(?i)(secret|token)['"\s:=]+(?![a-zA-Z]\.[a-zA-Z])[a-zA-Z0-9\-_]{8,100}`, "MEDIUM", ""},
		{"Authorization Bearer Token", `Bearer\s+[a-zA-Z0-9\-._~+/]{20,}=*`, "MEDIUM", "Bearer"},
		{"Cloudinary URL", `cloudinary:\/\/[0-9]{15}:[a-zA-Z0-9]+@[a-zA-Z]+`, "MEDIUM", "cloudinary://"},
		{"Segment API Key", `(?i)segment(.{0,20})?key['"\s:=]+[a-zA-Z0-9]{10,}`, "MEDIUM", ""},
		{"Intercom Access Token", `(?i)intercom(.{0,20})?token['"\s:=]+[a-zA-Z0-9-_]{20,}`, "MEDIUM", ""},
		{"Amplitude API Key", `apiKey['"]?\s*:\s*['"][a-z0-9\-]{32,64}['"]`, "MEDIUM", "apiKey"},
		{"Plaid Client Secret", `plaid(.{0,20})?(client)?secret['"\s:=]+[a-z0-9-_]{30,}`, "MEDIUM", "plaid"},
		{"Bugsnag API Key", `(?i)(?:bugsnag|notifier)[_\-\s.]*(?:api)?[_\-\s.]*key['": \t=]+[a-f0-9]{32}(?![a-f0-9])`, "MEDIUM", ""},
		{"Datadog API Key", `(?i)(?:DD_API_KEY|DD_CLIENT_TOKEN|datadog[_\-\s.]*(?:api|client)[_\-\s.]*(?:key|token))['": \t=]+[a-z0-9]{32}(?![a-z0-9])`, "MEDIUM", ""},
		{"Loggly Token", `[a-z0-9]{30}-[a-z0-9]{10}`, "MEDIUM", ""},
		{"New Relic Key", `NRII-[a-zA-Z0-9]{20,}`, "MEDIUM", "NRII-"},
		{"Mixpanel Token", `(?i)mixpanel(.{0,20})?token['"\s:=]+[a-z0-9]{32}`, "MEDIUM", ""},
		{"Heap Analytics App ID", `heapSettings\.appId\s*=\s*['"][a-z0-9]{8,12}['"]`, "MEDIUM", "heapSettings"},
		{"Keen IO Project ID", `projectId['"]?\s*:\s*['"][a-f0-9]{24}['"]`, "MEDIUM", "projectId"},
		{"Keen IO Write Key", `writeKey['"]?\s*:\s*['"][a-zA-Z0-9]{64}['"]`, "MEDIUM", "writeKey"},
		{"Snyk Token", `snyk_token\s*=\s*[a-f0-9\-]{36}`, "MEDIUM", "snyk_token"},
		{"Rollbar Access Token", `access_token['"]?\s*:\s*['"][a-z0-9]{32}['"]`, "MEDIUM", "access_token"},
		{"Twitch API Key", `(?i)twitch(.{0,20})?key['"\s:=]+[a-zA-Z0-9]{20,}`, "MEDIUM", ""},
		{"Discord Bot Token", `[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}`, "MEDIUM", ""},
		{"Discord Webhook URL", `https:\/\/discord(?:app)?\.com\/api\/webhooks\/[0-9]+\/[a-zA-Z0-9_-]+`, "MEDIUM", "discord"},
		{"Steam Web API Key", `(?i)steam(.{0,20})?key['"\s:=]+[a-zA-Z0-9]{32}`, "MEDIUM", ""},
		{"Riot Games API Key", `RGAPI-[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`, "MEDIUM", "RGAPI-"},
		{"GitHub OAuth App Secret", `(?i)(?:github|client[_-]?secret|oauth[_-]?(?:token|secret)|access_token)['": \t=]+(?<![a-f0-9])[a-f0-9]{40}(?![a-f0-9])`, "MEDIUM", ""},
		{"JWT Token", `eyJ[A-Za-z0-9-_=]+?\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*`, "MEDIUM", "eyJ"},
		{"JWT in Local Storage", `localStorage\.setItem\(['"]token['"],\s*['"]eyJ[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+['"]\)`, "MEDIUM", "localStorage.setItem"},

		// ═══════════════════════════════════════════════════════════════════
		// 🎯 Bug Bounty Recon: URLs, Endpoints, Metadata, Cloud Storage
		// ═══════════════════════════════════════════════════════════════════
		{"Credentials in URL", `https?://[^\s'"/:@]+:[^\s'"@]{3,100}@[^\s'"]+`, "CRITICAL", "://"},
		{"Cloud Metadata Endpoint (AWS)", `169\.254\.169\.254`, "HIGH", "169.254.169.254"},
		{"Cloud Metadata Endpoint (GCP)", `metadata\.google\.internal`, "HIGH", "metadata.google.internal"},
		{"Cloud Metadata Endpoint (Azure)", `169\.254\.169\.254/metadata`, "HIGH", "169.254.169.254/metadata"},
		{"AWS S3 Bucket URL (HTTP)", `https?://[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]\.s3[.-](?:us|eu|ap|sa|ca|me|af|cn)-[a-z]+-\d\.amazonaws\.com`, "MEDIUM", ".s3"},
		{"AWS S3 Bucket Path-Style", `https?://s3[.-](?:us|eu|ap|sa|ca|me|af|cn)-[a-z]+-\d\.amazonaws\.com/[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]`, "MEDIUM", "s3"},
		{"GCS Bucket URL", `https?://storage\.googleapis\.com/[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]`, "MEDIUM", "storage.googleapis.com"},
		{"Azure Blob Storage URL", `https?://[a-z0-9]{3,24}\.blob\.core\.windows\.net`, "MEDIUM", ".blob.core.windows.net"},
		{"Exposed Swagger/OpenAPI", `(?i)(?:swagger-ui|swagger\.json|openapi\.json|api-docs|\/swagger\/|\/api\/docs|graphiql|\/graphql\/playground|altair|\/redoc)`, "MEDIUM", ""},
		{"WebSocket URL with Token", `wss?://[^\s'"]*[\?&](?:token|key|auth|session|api_key)=[^\s'"&]+`, "MEDIUM", "ws"},
		{"Internal Email Address", `[a-zA-Z0-9._%+-]+@(?:internal|corp|local|private|intra|dev)\.[a-zA-Z]{2,}`, "LOW", "@"},
		{"Internal/Debug Path", `(?i)['"]\/(?:internal|debug|metrics|healthcheck|admin(?:istrator)?|actuator|_debug|__debug|phpinfo|server-(?:status|info)|elmah\.axd)(?:\/|['"])`, "MEDIUM", ""},
		{"Hardcoded OIDC/OAuth Redirect URI", `(?i)redirect_uri['"\s:=]+https?://(?:localhost|127\.0\.0\.1)[:\d/]*`, "MEDIUM", "redirect_uri"},

		// ═══════════════════════════════════════════════════════════════════
		// 🤖 AI/ML Provider Keys (2025 additions)
		// ═══════════════════════════════════════════════════════════════════
		{"Google Gemini API Key", `(?i)(?:gemini|GEMINI_API_KEY)\b[^\n]{0,40}[:=]\s*['"]AIzaSy[a-zA-Z0-9_-]{33}['"]`, "CRITICAL", "AIzaSy"},
		{"Cerebras API Key", `csk-[a-zA-Z0-9]{40,}`, "HIGH", "csk-"},
		{"Sambanova API Key", `(?i)(?:sambanova|SAMBANOVA_API_KEY)\b[^\n]{0,40}[:=]\s*['"][a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}['"]`, "HIGH", "sambanova"},
		{"Voyage AI Key", `pa-[a-zA-Z0-9_-]{40,}`, "HIGH", "pa-"},
		{"AI21 Labs API Key", `(?i)(?:ai21|AI21_API_KEY)\b[^\n]{0,40}[:=]\s*['"][a-zA-Z0-9]{40,}['"]`, "HIGH", "ai21"},
		{"Stability AI Key", `sk-[a-zA-Z0-9]{48,}`, "HIGH", "sk-"},
		{"OpenRouter API Key", `sk-or-v1-[a-f0-9]{64}`, "HIGH", "sk-or-v1-"},
		{"Langchain API Key", `ls__[a-f0-9]{32,}`, "HIGH", "ls__"},
		{"Unify AI Key", `(?i)(?:unify|UNIFY_API_KEY)\b[^\n]{0,40}[:=]\s*['"][a-zA-Z0-9_-]{40,}['"]`, "HIGH", "unify"},

		// ═══════════════════════════════════════════════════════════════════
		// 🎯 Bug Bounty Recon: Infrastructure & Misconfiguration (Phase 7)
		// ═══════════════════════════════════════════════════════════════════
		{"LDAP Connection String", `ldaps?:\/\/[a-zA-Z0-9._:@\/-]+`, "MEDIUM", "ldap"},
		{"Azure Service Bus Connection", `Endpoint=sb:\/\/[a-zA-Z0-9.-]+\.servicebus\.windows\.net`, "HIGH", "sb://"},
		{"Azure SQL Connection String", `Server=tcp:[a-zA-Z0-9.-]+\.database\.windows\.net`, "HIGH", ".database.windows.net"},
		{"AWS SQS Queue URL", `https:\/\/sqs\.[a-z0-9-]+\.amazonaws\.com\/\d{12}\/`, "MEDIUM", "sqs."},
		{"AWS SNS Topic ARN", `arn:aws:sns:[a-z0-9-]+:\d{12}:[a-zA-Z0-9_-]+`, "MEDIUM", "arn:aws:sns:"},
		{"GraphQL Endpoint", `(?i)['"]https?://[a-z0-9._-]+(?:/[a-z0-9._-]+)*/graphql['"]`, "LOW", "graphql"},
		{"Spring Boot Actuator Endpoint", `(?i)['"](?:https?://[a-z0-9._-]+)?/actuator(?:/[a-z]+)?['"]`, "MEDIUM", "actuator"},
		{"Admin Panel Path", `(?i)['"](?:https?://[a-z0-9._-]+)?/(?:admin|_admin|dashboard/admin|wp-admin|phpmyadmin)(?:/[a-z0-9_-]*)?['"]`, "LOW", "admin"},
		{"Hardcoded Feature Flag", `(?i)(?:feature_flag|featureFlag|enableFeature|FEATURE_TOGGLE)['"\s:=]+['"]?(?:true|false|on|off|enabled|disabled)['"]?`, "LOW", ""},
		{"Webhook Secret Key", `(?i)(?:webhook[_\s-]?secret|signing[_\s-]?secret|whsec_)['":\s=]+['"]?[a-zA-Z0-9_\-]{20,}['"]?`, "HIGH", ""},
		{"Mapbox Secret Token", `sk\.eyJ[a-zA-Z0-9_-]{50,}`, "HIGH", "sk.eyJ"},
		{"Twilio Account SID", `AC[a-f0-9]{32}`, "MEDIUM", "AC"},

		// ═══════════════════════════════════════════════════════════════════
		// 📉 LOW: Generic / Noise-prone detections
		// ═══════════════════════════════════════════════════════════════════
		{"AWS S3 Bucket URL", `s3:\/\/[a-z0-9\-\.]{3,63}`, "LOW", "s3://"},
		{"Private IP (Internal)", `\b(10\.\d{1,3}|\b192\.168|\b172\.(1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}`, "LOW", ""},
		{"Localhost Reference", `localhost:[0-9]{2,5}`, "LOW", "localhost:"},
		{"Dev/Stage URL", `(dev|staging|test)\.[a-z0-9.-]+\.(com|net|io)`, "LOW", ""},
		{"Internal Subdomain URL", `https?:\/\/[a-z0-9.-]+\.internal\.[a-z]{2,}`, "LOW", ".internal."},
		{"Preprod URLs", `https:\/\/preprod\.[a-z0-9-]+\.[a-z]{2,}`, "LOW", "preprod."},
		{"PEM File Content", `-----BEGIN CERTIFICATE-----`, "LOW", "-----BEGIN CERTIFICATE"},
		{"Base64 High Entropy String", `['\"](?=[A-Za-z0-9+\/]{40,}={0,2}['\"])(?=[^'\"]*[+/=])[A-Za-z0-9+\/]{40,}={0,2}['\"]`, "LOW", ""},
		{"API Key Generic Detector", `(?i)(apikey|api_key|secret|token)['"\s:=]+(?![a-zA-Z]\.[a-zA-Z])[a-zA-Z0-9\-_]{8,}`, "LOW", ""},
		{"Bearer Token Generic", `(?i)authorization:\s*Bearer\s+[a-zA-Z0-9\-._~+/=]{20,}`, "LOW", ""},
		{"Session ID", `(?i)(sessionid|session_id)['"\s:=]+[a-zA-Z0-9]{10,}`, "LOW", ""},
		{"Cookie Name Generic", `(?i)set-cookie:\s*(?:session(?:id)?|sess(?:ion)?|auth(?:token)?|access[_-]?token|refresh[_-]?token|jwt|sid|connect\.sid)=`, "LOW", ""},
		{"CSRF Token", `(?i)csrf(token)?['"\s:=]+\s*['"][A-Za-z0-9_-]{12,}['"]`, "LOW", ""},
		{"JJARDEL (Legacy)", `(?:"?[a-z0-9_\-]*(?:key|secret|password|dependencies|auth|aws_secret|api|token)[a-z0-9_\-]*"?\s*(?::|=)\s*"?!(null|true|false)([a-z0-9+_:\.\-\/]+)|"Authorization":"[a-z0-9+:_\-\/]+\s(.*?(?<!\\)(?=")))`, "LOW", ""},
		{"SEGREDOS WAR (Legacy)", `(('|")((?:ASIA|AKIA|AROA|AIDA)([A-Z0-9]{16}))('|").*?(\n^.*?){0,4}(('|")[a-zA-Z0-9+/]{40}('|"))+|('|")[a-zA-Z0-9+/]{40}('|").*?(\n^.*?){0,3}(('|")(?:ASIA|AKIA|AROA|AIDA)([A-Z0-9]{16})('|"))+)`, "LOW", ""},
	}

	for _, sig := range rawPatterns {
		re, err := regexp.Compile(sig.Pattern)
		if err == nil {
			Signatures = append(Signatures, Signature{
				Name:     sig.Name,
				Regex:    re,
				Priority: sig.Priority,
				Prefix:   sig.Prefix,
			})
		}
	}
}
