package main

import "testing"

func TestComputeConfidence_HighEntropy(t *testing.T) {
	r := &Result{
		Name:  "AWS Secret Access Key",
		Match: `secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`,
	}
	score := computeConfidence(r, "", "app.js")
	if score < 50 {
		t.Errorf("expected confidence >= 50 for high-entropy AWS key, got %d", score)
	}
}

func TestComputeConfidence_PlaceholderLowersScore(t *testing.T) {
	r := &Result{
		Name:  "API Key in Variable",
		Match: `api_key = "your_api_key_here"`,
	}
	score := computeConfidence(r, "", "config.js")
	if score > 40 {
		t.Errorf("expected confidence <= 40 for placeholder value, got %d", score)
	}
}

func TestComputeConfidence_TestFilePenalty(t *testing.T) {
	r := &Result{
		Name:  "Stripe Secret Key",
		Match: `sk_test_4eC39HqLyjWDarjtT1zdp7dc`,
	}
	scoreNormal := computeConfidence(r, "", "payments.js")
	scoreTest := computeConfidence(r, "", "payments.test.js")
	if scoreTest >= scoreNormal {
		t.Errorf("expected test file score (%d) < normal score (%d)", scoreTest, scoreNormal)
	}
}

func TestComputeConfidence_VendorPenalty(t *testing.T) {
	r := &Result{
		Name:  "API Key in Variable",
		Match: `apiKey = "abc123def456ghi789jkl012"`,
	}
	scoreNormal := computeConfidence(r, "", "src/auth.js")
	scoreVendor := computeConfidence(r, "", "jquery.min.js")
	if scoreVendor >= scoreNormal {
		t.Errorf("expected vendor score (%d) < normal score (%d)", scoreVendor, scoreNormal)
	}
}

func TestComputeConfidence_ClampsBounds(t *testing.T) {
	r := &Result{
		Name:  "API Key in Variable",
		Match: `key = "x"`,
	}
	score := computeConfidence(r, "", "test.example.js")
	if score < 0 || score > 100 {
		t.Errorf("expected score clamped between 0 and 100, got %d", score)
	}
}

func TestHasAuthContext(t *testing.T) {
	tests := []struct {
		context string
		want    bool
	}{
		{"const token = fetchData(url, { headers: { Authorization: 'Bearer ...' } })", true},
		{"const x = 42;", false},
		{"", false},
		{"fetch('/api/users', { credentials: 'include' })", true},
	}
	for _, tt := range tests {
		got := hasAuthContext(tt.context)
		if got != tt.want {
			t.Errorf("hasAuthContext(%q) = %v, want %v", tt.context, got, tt.want)
		}
	}
}

func TestClassifyTags(t *testing.T) {
	r := &Result{
		Name:     "AWS Secret Access Key",
		Provider: "aws",
	}
	tags := classifyTags(r, "https://example.com/app.js")
	if len(tags) == 0 {
		t.Errorf("expected at least one tag, got none")
	}
	found := false
	for _, tag := range tags {
		if tag == "third-party" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'third-party' tag for AWS provider, got %v", tags)
	}
}

func TestExtractDomain(t *testing.T) {
	tests := []struct {
		target string
		want   string
	}{
		{"https://cdn.example.com/app.js", "cdn.example.com"},
		{"http://localhost:3000/bundle.js", "localhost"},
		{"/path/to/local/file.js", ""},
		{"", ""},
	}
	for _, tt := range tests {
		got := extractDomain(tt.target)
		if got != tt.want {
			t.Errorf("extractDomain(%q) = %q, want %q", tt.target, got, tt.want)
		}
	}
}

func TestExtractCodeContext(t *testing.T) {
	content := "line1\nline2\nline3\nline4\nline5\nline6\nline7"
	ctx := extractCodeContext(content, 4, 1)
	if ctx == "" {
		t.Error("expected non-empty context")
	}
	if !contains(ctx, "line3") || !contains(ctx, "line4") || !contains(ctx, "line5") {
		t.Errorf("expected context to contain surrounding lines, got %q", ctx)
	}
}

func TestEnrichResult(t *testing.T) {
	r := &Result{
		Name:     "GitHub Token (Classic PAT)",
		Match:    "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		Priority: "CRITICAL",
	}
	enrichResult(r, "const token = 'ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx';\nfetch('/api');", "src/auth.js", 1)
	if r.Provider == "" {
		t.Error("expected provider to be set")
	}
	if r.Confidence == 0 {
		t.Error("expected confidence > 0")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && containsString(s, substr)
}

func containsString(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
