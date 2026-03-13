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

func findResult(results []Result, name string) *Result {
	for i := range results {
		if results[i].Name == name {
			return &results[i]
		}
	}
	return nil
}
