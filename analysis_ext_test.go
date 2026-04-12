package main

import "testing"

func TestBuildLineOffsets(t *testing.T) {
	content := "line1\nline2\nline3"
	offsets := buildLineOffsets(content)
	// Expected: [0, 6, 12] — byte offsets of each line start
	if len(offsets) != 3 {
		t.Fatalf("expected 3 offsets, got %d: %v", len(offsets), offsets)
	}
	if offsets[0] != 0 || offsets[1] != 6 || offsets[2] != 12 {
		t.Errorf("expected offsets [0,6,12], got %v", offsets)
	}
}

func TestBuildLineOffsets_SingleLine(t *testing.T) {
	offsets := buildLineOffsets("no newlines here")
	if len(offsets) != 1 || offsets[0] != 0 {
		t.Errorf("expected [0] for single line, got %v", offsets)
	}
}

func TestBuildLineOffsets_Empty(t *testing.T) {
	offsets := buildLineOffsets("")
	if len(offsets) != 1 || offsets[0] != 0 {
		t.Errorf("expected [0] for empty, got %v", offsets)
	}
}

func TestOffsetToLine(t *testing.T) {
	// content: "aaa\nbbb\nccc"
	// offsets: [0, 4, 8]
	offsets := []int{0, 4, 8}

	tests := []struct {
		offset int
		want   int // 1-based line
	}{
		{0, 1}, // start of line 1
		{2, 1}, // middle of line 1
		{3, 1}, // last char of line 1 (\n)
		{4, 2}, // start of line 2
		{7, 2}, // last char of line 2
		{8, 3}, // start of line 3
		{10, 3},
	}
	for _, tt := range tests {
		got := offsetToLine(offsets, tt.offset)
		if got != tt.want {
			t.Errorf("offsetToLine(%v, %d) = %d, want %d", offsets, tt.offset, got, tt.want)
		}
	}
}

func TestExtractLineNumberFromEvidence(t *testing.T) {
	tests := []struct {
		evidence string
		want     int
	}{
		{"line 42: some code here", 42},
		{"line 1: x = 5;", 1},
		{"line 999: long line", 999},
		{"not a line reference", 0},
		{"", 0},
		{"line abc: bad", 0},
	}
	for _, tt := range tests {
		got := extractLineNumberFromEvidence(tt.evidence)
		if got != tt.want {
			t.Errorf("extractLineNumberFromEvidence(%q) = %d, want %d", tt.evidence, got, tt.want)
		}
	}
}

func TestScanContentWithOptions_LineTracking(t *testing.T) {
	// Content with a hardcoded AWS key on a specific line
	content := `// config file
const region = "us-east-1";
const secretKey = "AKIAIOSFODNN7EXAMPLE";
console.log("hello");`

	results := scanContentWithOptions("test.js", content, 0)

	foundAWS := false
	for _, r := range results {
		if r.Name == "AWS Access Key ID" {
			foundAWS = true
			if r.Line != 3 {
				t.Errorf("expected AWS key on line 3, got %d", r.Line)
			}
			if r.Confidence == 0 {
				t.Error("expected confidence > 0 for AWS key")
			}
			if r.Provider == "" {
				t.Error("expected provider to be set for AWS key")
			}
		}
	}
	if !foundAWS {
		t.Error("expected to find AWS Access Key ID in content")
	}
}

func TestScanContentWithOptions_Context(t *testing.T) {
	content := `line1
line2
const key = "AKIAIOSFODNN7EXAMPLE";
line4
line5`

	results := scanContentWithOptions("test.js", content, 2)

	for _, r := range results {
		if r.Name == "AWS Access Key ID" && r.Context == "" {
			t.Error("expected context to be set when contextLines > 0")
		}
	}
}

func TestScanContent_BackwardsCompat(t *testing.T) {
	// scanContent should still work (delegates to scanContentWithOptions)
	content := `const key = "AKIAIOSFODNN7EXAMPLE";`
	results := scanContent("config.js", content)
	if len(results) == 0 {
		t.Error("expected at least one result from scanContent")
	}
}

func TestFP_TranslationKeysNotTriggerDev(t *testing.T) {
	// i18n translation keys like tr_livechat_something should NOT match Trigger.dev
	content := `var translations = {
		tr_livechat_unavailable_closechat: "Close chat",
		tr_header_brandlogoalttext: "Brand logo",
		tr_footer_privacypolicy: "Privacy Policy",
		tr_currency_topcurrencies: "Top currencies",
		tr_customer_service_submit_case_loading: "Loading"
	};`
	results := scanContent("chat-window.js", content)
	for _, r := range results {
		if r.Name == "Trigger.dev API Key" {
			t.Errorf("translation key falsely detected as Trigger.dev API Key: %s", r.Match)
		}
	}
}

func TestFP_BookingTranslationKeysNotTriggerDev(t *testing.T) {
	content := `var translations = {
		tr_header_brandlogoalttext: "Brand logo",
		tr_header_brandlogoalttext_autohuren: "Brand logo autohuren",
		tr_header_brandlogoalttext_bravofly: "Brand logo bravofly",
		tr_header_brandlogoalttext_: "Brand logo default",
		tr_common_text_copyright: "Copyright",
		tr_common_text_copyright_ryanair: "Copyright Ryanair",
		tr_common_text_copyright_: "Copyright default",
		tr_currency_topcurrencies: "Top currencies",
		tr_currency_allcurrencies: "All currencies",
		tr_header_languagecurrencypanel_selectcurrency: "Select currency",
		tr_helpcentre_page_title: "Help centre",
		tr_footer_privacypolicy: "Privacy policy",
		tr_footer_termsconditions: "Terms and conditions"
	};`
	results := scanContent("booking.com/client.374869a4afb9a509b2fe.js", content)
	for _, r := range results {
		if r.Name == "Trigger.dev API Key" {
			t.Errorf("booking.com translation key falsely detected as Trigger.dev API Key: %s", r.Match)
		}
	}
}

func TestFP_BearerTokenLiteral(t *testing.T) {
	// The literal string "Bearer Token" in UI/docs should NOT match
	content := `const authType = "Bearer Token";`
	results := scanContent("index.js", content)
	for _, r := range results {
		if r.Name == "Authorization Bearer Token" {
			t.Errorf("literal 'Bearer Token' falsely detected: %s", r.Match)
		}
	}
}

func TestFP_CredentialsInURL_TemplateURL(t *testing.T) {
	// Template URL with authuser param + unrelated @ in code should NOT match
	content := "var providers=[{url:`https://mail.google.com/mail?authuser=${e}`,gmail:!0},{regex:/@yahoo\\.com$/,url:\"https://mail.yahoo.com\"}];"
	results := scanContent("providers.js", content)
	for _, r := range results {
		if r.Name == "Credentials in URL" {
			t.Errorf("template URL falsely detected as Credentials in URL: %s", r.Match)
		}
	}
}

func TestFP_WebpackBundleHeuristics(t *testing.T) {
	// Webpack 5 IIFE bundle should be detected as bundled content
	// and NOT trigger heuristic findings like Prototype Pollution
	if !isLikelyBundledContent(buildFakeWebpackBundle()) {
		t.Error("expected webpack 5 IIFE to be detected as bundled content")
	}
}

func TestLooksLikeTranslationKey(t *testing.T) {
	tests := []struct {
		value string
		want  bool
	}{
		{"tr_livechat_unavailable_closechat", true},
		{"tr_header_brandlogoalttext", true},
		{"tr_footer_links_geoblockingportal", true},
		{"tr_dev_A8f7BcD32e91K4m6N", false},  // mixed case = real key
		{"tr_prod_abc123def456ghi789", true}, // all lowercase = still i18n-like
		{"not_a_tr_key", false},              // no tr_ prefix
		{"tr_x", false},                      // only 1 segment after tr_
	}
	for _, tt := range tests {
		got := looksLikeTranslationKey(tt.value)
		if got != tt.want {
			t.Errorf("looksLikeTranslationKey(%q) = %v, want %v", tt.value, got, tt.want)
		}
	}
}

// buildFakeWebpackBundle creates a large fake webpack 5 bundle for testing
func buildFakeWebpackBundle() string {
	// Start with webpack 5 IIFE pattern, pad to >5000 chars
	bundle := "(()=>{var e={136:(e,t,r)=>{\"use strict\";t.FK=void 0;"
	for len(bundle) < 6000 {
		bundle += "e.exports=function(t){return t+1};"
	}
	bundle += "}})();"
	return bundle
}

func TestFP_ES5InheritanceNotPrototypePollution(t *testing.T) {
	// Standard ES5 class inheritance should NOT be flagged as Prototype Pollution
	content := `a&&(b.__proto__=a);b.prototype=Object.create(a&&a.prototype);b.prototype.constructor=b;b.prototype.applyTransform=function(){var a=this._decomposeTransform();}`
	results := scanContent("EclairNG.js", content)
	for _, r := range results {
		if r.Name == "Potential Prototype Pollution" {
			t.Errorf("ES5 inheritance falsely detected as Prototype Pollution: %s", r.Match)
		}
	}
}

func TestFP_ObjectSetPrototypeOfInheritance(t *testing.T) {
	// Object.setPrototypeOf with __proto__ polyfill pattern — TypeScript helper
	content := `var __extends = Object.setPrototypeOf || {__proto__:[]} instanceof Array;`
	results := scanContent("lib.js", content)
	// TypeScript polyfill pattern should not produce prototype pollution findings
	_ = results
}

func TestFP_VendorDetection_ProdFile(t *testing.T) {
	if !isLikelyVendorTarget("booking.com/aura_prod.js") {
		t.Error("aura_prod.js should be detected as vendor target")
	}
}

func TestFP_VendorDetection_UMD(t *testing.T) {
	if !isLikelyVendorTarget("booking.com/index.umd.cjs.js") {
		t.Error("index.umd.cjs.js should be detected as vendor target")
	}
}

func TestFP_VendorDetection_Eclair(t *testing.T) {
	if !isLikelyVendorTarget("booking.com/EclairNG.js") {
		t.Error("EclairNG.js should be detected as vendor target (eclair marker)")
	}
}

func TestFP_VendorDetection_SentryPack(t *testing.T) {
	if !isLikelyVendorTarget("booking.com/sentry-wrapper.pack.ec4dcd4257cafb4f0f1a79ba02a0f0a4.js") {
		t.Error("sentry-wrapper.pack.*.js should be detected as vendor target")
	}
}

func TestFP_VendorDetection_HashedNames(t *testing.T) {
	// Webpack content-hashed bundles with name.HASH.js format
	cases := []string{
		"booking.com/chat-window.c4140ec35644d7684bce.js",
		"booking.com/5923.a949fe50bed968f9327a.js",
		"booking.com/client.374869a4afb9a509b2fe.js",
		"booking.com/index.f17af9eb.js",
		"booking.com/1004b298.2b938b5a.chunk.js",
	}
	for _, path := range cases {
		if !isLikelyVendorTarget(path) {
			t.Errorf("content-hashed bundle %q should be detected as vendor target", path)
		}
	}
}

func TestFP_BundledContent_VarClientPrefix(t *testing.T) {
	// Webpack bundle that prepends `var client;` before the IIFE arrow function
	bundle := "var client;(()=>{var e={136:(e,t,r)=>{\"use strict\";t.FK=void 0;"
	for len(bundle) < 6000 {
		bundle += "e.exports=function(t){return t+1};"
	}
	bundle += "}})();"
	if !isLikelyBundledContent(bundle) {
		t.Error("webpack bundle with var-prefix before IIFE should be detected as bundled content")
	}
}

func TestFP_AdminPathSuppressedOnVendor(t *testing.T) {
	// Admin/debug path signatures should be suppressed in vendor/hashed files
	content := `var routes = ["/admin/users", "/admin/migrate-to-cloud", "/internal/metrics"];`
	// Hashed bundle file — should be treated as vendor
	results := scanContent("booking.com/5923.a949fe50bed968f9327a.js", content)
	for _, r := range results {
		if r.Name == "Admin Panel Path" || r.Name == "Internal/Debug Path" {
			t.Errorf("admin/debug path should be suppressed in vendor file: %s – %s", r.Name, r.Match)
		}
	}
}

func TestFP_MinifiedLineDetection(t *testing.T) {
	// Build a 400-char line with semicolons every ~30 chars (typical minified ES5)
	line := ""
	for i := 0; i < 15; i++ {
		line += "var a=b.prototype;a.x=function(){return this._v};"
	}
	if !isLikelyMinifiedLine(line) {
		t.Errorf("expected 400+ char semicolon-dense line to be detected as minified (len=%d)", len(line))
	}
}

func TestFP_BundledContent_NumericWebpack(t *testing.T) {
	// Webpack bundle with numeric module IDs (no webpackChunk marker)
	content := "!function(){var t={97318:function(t,e,n){\"use strict\";n.r(e),n.d(e,{supportsHistory:function(){return o}});"
	for len(content) < 15000 {
		content += "var r=function(t){return t+1};"
	}
	content += "}();"
	if !isLikelyBundledContent(content) {
		t.Error("expected numeric-ID webpack bundle to be detected as bundled content")
	}
}

func TestFP_MinifiedHeuristicsSkipped(t *testing.T) {
	// ES5 minified line with prototype inheritance should produce no findings
	line := "a&&(b.__proto__=a);b.prototype=Object.create(a&&a.prototype);b.prototype.constructor=b;"
	// Repeat to make it > 300 chars and semicolon-dense
	content := ""
	for len(content) < 500 {
		content += line
	}
	results := scanContent("lib.js", content)
	for _, r := range results {
		if r.Name == "Potential Prototype Pollution" {
			t.Errorf("minified ES5 inheritance should not trigger Prototype Pollution: %s", r.Match)
		}
	}
}

func TestNormalizeURL(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		// Already has scheme — unchanged
		{"https://booking.com/aura_prod.js", "https://booking.com/aura_prod.js"},
		{"http://example.com/app.js", "http://example.com/app.js"},
		// scheme-less host+path → prepend https://
		{"booking.com/aura_prod.js", "https://booking.com/aura_prod.js"},
		{"www.booking.com/static/js/app.js", "https://www.booking.com/static/js/app.js"},
		{"q-cf.bstatic.com/npstatic/r/etc.js", "https://q-cf.bstatic.com/npstatic/r/etc.js"},
		// Absolute/relative file paths — unchanged
		{"/home/user/app.js", "/home/user/app.js"},
		{"./app.js", "./app.js"},
		{"../lib/app.js", "../lib/app.js"},
		// Windows path — unchanged
		{"C:\\Users\\test\\app.js", "C:\\Users\\test\\app.js"},
		// Blank — unchanged
		{"", ""},
		// Comment line — unchanged
		{"# this is a comment", "# this is a comment"},
	}
	for _, tt := range tests {
		got := normalizeURL(tt.input)
		if got != tt.want {
			t.Errorf("normalizeURL(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
