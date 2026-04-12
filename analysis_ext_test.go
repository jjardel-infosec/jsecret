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
