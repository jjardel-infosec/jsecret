package main

import "testing"

func TestValidateFormat_AWS(t *testing.T) {
	v := ValidateFormat("AWS Access Key ID", `AKIAIOSFODNN7EXAMPLE`)
	if !v.Valid {
		t.Error("expected valid for AKIA-prefixed 20-char key")
	}
	if v.Provider != "aws" {
		t.Errorf("expected provider 'aws', got %q", v.Provider)
	}
}

func TestValidateFormat_AWSInvalid(t *testing.T) {
	v := ValidateFormat("AWS Access Key ID", `AKIASHORT`)
	if v.Valid {
		t.Error("expected invalid for short AKIA key")
	}
}

func TestValidateFormat_GoogleAPIKey(t *testing.T) {
	// 39 chars total: AIza + 35 alphanumeric chars
	v := ValidateFormat("Google API Key", `AIzaSyC-abcDEF1234567890123456789012345`)
	if !v.Valid {
		t.Error("expected valid for AIza-prefixed 39-char key")
	}
	if v.Provider != "google" {
		t.Errorf("expected provider 'google', got %q", v.Provider)
	}
}

func TestValidateFormat_StripeSecretKey(t *testing.T) {
	v := ValidateFormat("Stripe Secret Key", `sk_live_51H2bQf3Kj7Lm9Np0Rs2Tu4Vw`)
	if !v.Valid {
		t.Error("expected valid for sk_live_ prefixed key")
	}
	if v.Provider != "stripe" {
		t.Errorf("expected provider 'stripe', got %q", v.Provider)
	}
}

func TestValidateFormat_GitHubPAT(t *testing.T) {
	v := ValidateFormat("GitHub Token (Classic PAT)", `ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh`)
	if !v.Valid {
		t.Error("expected valid for ghp_ prefixed token")
	}
	if v.Provider != "github" {
		t.Errorf("expected provider 'github', got %q", v.Provider)
	}
}

func TestValidateFormat_SlackBot(t *testing.T) {
	v := ValidateFormat("Slack Bot Token", `xoxb-1234567890-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx`)
	if !v.Valid {
		t.Error("expected valid for xoxb- prefixed token")
	}
}

func TestValidateFormat_SendGrid(t *testing.T) {
	v := ValidateFormat("SendGrid API Key", `SG.abcdefghijklmnop.qrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUV`)
	if !v.Valid {
		t.Error("expected valid for SG. prefixed key with dot")
	}
}

func TestValidateFormat_JWT(t *testing.T) {
	// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
	v := ValidateFormat("JWT Token", token)
	if !v.Valid {
		t.Error("expected valid for well-formed JWT")
	}
	if v.Provider != "jwt" {
		t.Errorf("expected provider 'jwt', got %q", v.Provider)
	}
}

func TestValidateFormat_UnknownSig(t *testing.T) {
	v := ValidateFormat("SomeUnknownSignature", "random_value_here")
	if v.Valid {
		t.Error("expected invalid for unknown signature name")
	}
	if v.ConfidenceBoost != 0 {
		t.Errorf("expected 0 confidence boost, got %d", v.ConfidenceBoost)
	}
}

func TestTrimQuotes(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{`"hello"`, "hello"},
		{`'world'`, "world"},
		{"  `backtick`  ", "backtick"},
		{"noQuotes", "noQuotes"},
	}
	for _, tt := range tests {
		got := trimQuotes(tt.input)
		if got != tt.want {
			t.Errorf("trimQuotes(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestExtractSecretValue(t *testing.T) {
	tests := []struct {
		match string
		want  string
	}{
		{`api_key = "sk_live_abc123"`, "sk_live_abc123"},
		{`token: 'ghp_abcdef1234567890'`, "ghp_abcdef1234567890"},
		{"just_a_value", "just_a_value"},
	}
	for _, tt := range tests {
		got := extractSecretValue(tt.match)
		if got == "" {
			t.Errorf("extractSecretValue(%q) returned empty", tt.match)
		}
	}
}
