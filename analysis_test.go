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

func findResult(results []Result, name string) *Result {
	for i := range results {
		if results[i].Name == name {
			return &results[i]
		}
	}
	return nil
}
