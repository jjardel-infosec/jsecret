package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// loadIgnorePatterns reads a .jsecretignore file and returns the patterns (glob-style).
// Blank lines and lines starting with '#' are skipped.
func loadIgnorePatterns(root string) []string {
	f, err := os.Open(filepath.Join(root, ".jsecretignore"))
	if err != nil {
		return nil
	}
	defer f.Close()

	var patterns []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		patterns = append(patterns, line)
	}
	return patterns
}

// shouldIgnore returns true if relPath matches any of the ignore patterns.
func shouldIgnore(relPath string, patterns []string) bool {
	// Normalise to forward slashes for consistent matching
	norm := filepath.ToSlash(relPath)
	for _, pat := range patterns {
		pat = filepath.ToSlash(pat)
		// Match against the full relative path
		if matched, _ := filepath.Match(pat, norm); matched {
			return true
		}
		// Match against the basename only
		if matched, _ := filepath.Match(pat, filepath.Base(norm)); matched {
			return true
		}
		// Support directory prefix patterns like "test/" → skip anything under test/
		if strings.HasSuffix(pat, "/") && strings.HasPrefix(norm, pat) {
			return true
		}
		// Support **/ prefix for recursive patterns (simplified)
		if strings.HasPrefix(pat, "**/") {
			rest := pat[3:]
			if matched, _ := filepath.Match(rest, filepath.Base(norm)); matched {
				return true
			}
			if strings.Contains(norm, "/"+rest) || strings.HasSuffix(norm, rest) {
				return true
			}
		}
	}
	return false
}

var (
	// Hashes dos conteudos para não baixar/escanear scripts duplicados
	SeenHashes sync.Map // O(1) de tempo de acesso e lock-free pra Concorrência

	// Default scannable extensions for directory mode
	defaultExtensions = []string{".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".vue", ".svelte"}

	// Priority levels ordered by severity
	priorityLevels = map[string]int{
		"CRITICAL": 4,
		"HIGH":     3,
		"MEDIUM":   2,
		"LOW":      1,
	}
)

// JSONResult is the structured output for -json flag
type JSONResult struct {
	Target   string `json:"target"`
	Priority string `json:"priority"`
	Finding  string `json:"finding"`
	Evidence string `json:"evidence"`
	Category string `json:"category"`
}

// SARIFLog is the top-level SARIF v2.1.0 structure
type SARIFLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

// SARIFRun represents a single analysis run
type SARIFRun struct {
	Tool    SARIFTool     `json:"tool"`
	Results []SARIFResult `json:"results"`
}

// SARIFTool describes the analysis tool
type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

// SARIFDriver describes the tool driver
type SARIFDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []SARIFRule `json:"rules"`
}

// SARIFRule describes a detection rule
type SARIFRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	ShortDescription SARIFMessage   `json:"shortDescription"`
	DefaultConfig    SARIFRuleLevel `json:"defaultConfiguration"`
}

// SARIFRuleLevel contains the level for a rule
type SARIFRuleLevel struct {
	Level string `json:"level"`
}

// SARIFResult is a single finding in SARIF format
type SARIFResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   SARIFMessage    `json:"message"`
	Locations []SARIFLocation `json:"locations,omitempty"`
}

// SARIFMessage is a text message
type SARIFMessage struct {
	Text string `json:"text"`
}

// SARIFLocation represents a location in a file
type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

// SARIFPhysicalLocation is the physical file location
type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
}

// SARIFArtifactLocation represents a file URI
type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

func main() {
	// Define flags
	var urlFlag string
	var fileFlag string
	var dirFlag string
	var outputFlag string
	var csvFlag string
	var jsonFlag string
	var sarifFlag string
	var minFlag string
	var proxyFlag string
	var extFlag string
	var concurrency int
	var helpFlag bool
	var silentFlag bool
	var strictFlag bool

	flag.StringVar(&urlFlag, "u", "", "Single URL to scan")
	flag.StringVar(&fileFlag, "f", "", "File containing list of URLs")
	flag.StringVar(&dirFlag, "d", "", "Directory to scan for script files (recursive)")
	flag.StringVar(&outputFlag, "o", "", "Output file to save results (TXT format)")
	flag.StringVar(&csvFlag, "csv", "", "Output file to save results (CSV format)")
	flag.StringVar(&jsonFlag, "json", "", "Output file to save results (JSON format)")
	flag.StringVar(&sarifFlag, "sarif", "", "Output file to save results (SARIF v2.1.0 format)")
	flag.StringVar(&minFlag, "min", "", "Minimum severity to report: CRITICAL, HIGH, MEDIUM, LOW")
	flag.StringVar(&proxyFlag, "proxy", "", "HTTP/HTTPS proxy URL (e.g., http://127.0.0.1:8080)")
	flag.StringVar(&extFlag, "ext", "", "Custom file extensions for directory scan (comma-separated, e.g., .js,.ts,.jsx)")
	flag.IntVar(&concurrency, "t", 50, "Number of concurrent threads")
	flag.BoolVar(&helpFlag, "h", false, "Show help message")
	flag.BoolVar(&silentFlag, "s", false, "Silent mode (no banner/summary)")
	flag.BoolVar(&strictFlag, "strict", false, "Exit with code 1 if CRITICAL or HIGH findings are found")

	// Custom usage message
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  jsecret [flags]\n\n")
		fmt.Fprintf(os.Stderr, "Examples:\n")
		fmt.Fprintf(os.Stderr, "  cat urls.txt | jsecret\n")
		fmt.Fprintf(os.Stderr, "  jsecret -u http://example.com/script.js\n")
		fmt.Fprintf(os.Stderr, "  jsecret -f urls.txt -t 100 -o results.txt -csv report.csv\n")
		fmt.Fprintf(os.Stderr, "  jsecret -d /path/to/project -json findings.json\n")
		fmt.Fprintf(os.Stderr, "  jsecret -d . -min HIGH -strict\n")
		fmt.Fprintf(os.Stderr, "  jsecret -f urls.txt -sarif report.sarif\n")
		fmt.Fprintf(os.Stderr, "  jsecret -d . -ext .js,.ts,.jsx,.vue\n")
		fmt.Fprintf(os.Stderr, "  jsecret -u https://example.com/app.js -proxy http://127.0.0.1:8080\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	if helpFlag {
		flag.Usage()
		os.Exit(0)
	}

	if !silentFlag {
		printBanner()
	}

	// Configure proxy
	if proxyFlag != "" {
		configureProxy(proxyFlag)
	}

	// Parse minimum severity filter
	minLevel := 0
	if minFlag != "" {
		upper := strings.ToUpper(minFlag)
		if level, ok := priorityLevels[upper]; ok {
			minLevel = level
		} else {
			fmt.Fprintf(os.Stderr, "Invalid -min value: %s (use CRITICAL, HIGH, MEDIUM, or LOW)\n", minFlag)
			os.Exit(1)
		}
	}

	// Parse custom extensions
	scanExtensions := defaultExtensions
	if extFlag != "" {
		scanExtensions = nil
		for _, ext := range strings.Split(extFlag, ",") {
			ext = strings.TrimSpace(ext)
			if ext != "" {
				if !strings.HasPrefix(ext, ".") {
					ext = "." + ext
				}
				scanExtensions = append(scanExtensions, ext)
			}
		}
	}

	// Check if we have any input source
	hasInput := false
	if urlFlag != "" || fileFlag != "" || dirFlag != "" {
		hasInput = true
	} else {
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			hasInput = true
		}
	}

	if !hasInput {
		flag.Usage()
		os.Exit(0)
	}

	startTime := time.Now()

	// Counters for summary statistics
	var filesScanned int64
	var criticalCount, highCount, mediumCount, lowCount int64

	// Worker pool setup
	var wg sync.WaitGroup
	jobs := make(chan string, 1000)
	results := make(chan Result, 500)

	// Collect all results for JSON/SARIF output
	var allResults []Result
	var resultsMu sync.Mutex

	// Output Handler
	var wgOutput sync.WaitGroup
	wgOutput.Add(1)
	go func() {
		defer wgOutput.Done()

		var f *os.File
		if outputFlag != "" {
			var err error
			f, err = os.Create(outputFlag)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
			} else {
				defer f.Close()
			}
		}

		var csvF *os.File
		var csvWriter *csv.Writer
		if csvFlag != "" {
			var err error
			csvF, err = os.Create(csvFlag)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error creating CSV output file: %v\n", err)
			} else {
				defer csvF.Close()
				csvWriter = csv.NewWriter(csvF)
				defer csvWriter.Flush()

				// Write Header
				csvWriter.Write([]string{"Target", "Priority", "Finding Type", "Evidence"})
			}
		}

		for res := range results {
			// Apply severity filter
			if minLevel > 0 {
				resLevel := priorityLevels[res.Priority]
				if resLevel < minLevel {
					continue
				}
			}

			// Update counters
			switch res.Priority {
			case "CRITICAL":
				atomic.AddInt64(&criticalCount, 1)
			case "HIGH":
				atomic.AddInt64(&highCount, 1)
			case "MEDIUM":
				atomic.AddInt64(&mediumCount, 1)
			case "LOW":
				atomic.AddInt64(&lowCount, 1)
			}

			// Collect for JSON/SARIF
			if jsonFlag != "" || sarifFlag != "" {
				resultsMu.Lock()
				allResults = append(allResults, res)
				resultsMu.Unlock()
			}

			// Select Color for Terminal
			var consoleColor string
			switch res.Priority {
			case "CRITICAL":
				consoleColor = "\033[1;31m" // Bold Red
			case "HIGH":
				consoleColor = "\033[31m" // Red
			case "MEDIUM":
				consoleColor = "\033[33m" // Yellow
			case "LOW":
				consoleColor = "\033[34m" // Blue
			default:
				consoleColor = "\033[32m" // Green
			}

			// Console Output (Format: [TARGET] [PRIORITY] FINDING : MATCH)
			fmt.Printf("\033[36m[%s]\033[0m %s[%s]\033[0m \033[32m%s\033[0m : %s\n", res.Target, consoleColor, res.Priority, res.Name, res.Match)

			// File Output
			if f != nil {
				fmt.Fprintf(f, "[%s] [%s] %s : %s\n", res.Target, res.Priority, res.Name, res.Match)
			}

			// CSV Output
			if csvWriter != nil {
				csvWriter.Write([]string{res.Target, res.Priority, res.Name, res.Match})
			}
		}
	}()

	// Start workers
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range jobs {
				atomic.AddInt64(&filesScanned, 1)
				matcher(target, results)
			}
		}()
	}

	// Input handling in a separate goroutine
	go func() {
		defer close(jobs)

		// 1. Single URL Mode
		if urlFlag != "" {
			if isUrl(urlFlag) || isScannable(urlFlag, scanExtensions) {
				jobs <- urlFlag
			}
			return
		}

		// 2. Directory Mode
		if dirFlag != "" {
			if !silentFlag {
				fmt.Printf("[*] Scanning directory: %s (extensions: %s)\n", dirFlag, strings.Join(scanExtensions, ", "))
			}
			ignorePatterns := loadIgnorePatterns(dirFlag)
			if len(ignorePatterns) > 0 && !silentFlag {
				fmt.Printf("[*] Loaded %d ignore patterns from .jsecretignore\n", len(ignorePatterns))
			}
			err := filepath.Walk(dirFlag, func(fpath string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				// Compute relative path for ignore matching
				relPath, _ := filepath.Rel(dirFlag, fpath)
				if relPath == "" {
					relPath = fpath
				}
				// Skip hidden directories and node_modules
				if info.IsDir() {
					base := filepath.Base(fpath)
					if strings.HasPrefix(base, ".") || base == "node_modules" || base == "dist" || base == "build" || base == ".git" {
						return filepath.SkipDir
					}
					// Check .jsecretignore for directory patterns
					if len(ignorePatterns) > 0 && shouldIgnore(relPath+"/", ignorePatterns) {
						return filepath.SkipDir
					}
					return nil
				}
				if isScannable(info.Name(), scanExtensions) {
					if len(ignorePatterns) > 0 && shouldIgnore(relPath, ignorePatterns) {
						return nil
					}
					jobs <- fpath
				}
				return nil
			})
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error walking directory: %v\n", err)
			}
			return
		}

		// 3. File Input Mode
		if fileFlag != "" {
			file, err := os.Open(fileFlag)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error opening file: %v\n", err)
				return
			}
			defer file.Close()

			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := scanner.Text()
				if line != "" {
					jobs <- line
				}
			}
			return
		}

		// 4. Stdin Mode
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			line := scanner.Text()
			if line != "" {
				jobs <- line
			}
		}
	}()

	wg.Wait()
	close(results)
	wgOutput.Wait()

	// Write JSON output
	if jsonFlag != "" {
		writeJSONOutput(jsonFlag, allResults)
	}

	// Write SARIF output
	if sarifFlag != "" {
		writeSARIFOutput(sarifFlag, allResults)
	}

	// Print summary
	elapsed := time.Since(startTime)
	total := atomic.LoadInt64(&criticalCount) + atomic.LoadInt64(&highCount) + atomic.LoadInt64(&mediumCount) + atomic.LoadInt64(&lowCount)
	if !silentFlag {
		fmt.Printf("\n\033[1;37m─── Scan Summary ───\033[0m\n")
		fmt.Printf("  Files scanned : %d\n", atomic.LoadInt64(&filesScanned))
		fmt.Printf("  Total findings: %d\n", total)
		fmt.Printf("    \033[1;31mCRITICAL\033[0m: %d\n", atomic.LoadInt64(&criticalCount))
		fmt.Printf("    \033[31mHIGH\033[0m    : %d\n", atomic.LoadInt64(&highCount))
		fmt.Printf("    \033[33mMEDIUM\033[0m  : %d\n", atomic.LoadInt64(&mediumCount))
		fmt.Printf("    \033[34mLOW\033[0m     : %d\n", atomic.LoadInt64(&lowCount))
		fmt.Printf("  Elapsed       : %s\n", elapsed.Round(time.Millisecond))
	}

	// Exit with code 1 if strict mode and critical/high findings
	if strictFlag && (atomic.LoadInt64(&criticalCount) > 0 || atomic.LoadInt64(&highCount) > 0) {
		os.Exit(1)
	}
}

// isScannable checks if a filename has a scannable extension
func isScannable(name string, extensions []string) bool {
	lower := strings.ToLower(name)
	for _, ext := range extensions {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

// writeJSONOutput writes results in structured JSON format
func writeJSONOutput(path string, results []Result) {
	jsonResults := make([]JSONResult, 0, len(results))
	for _, r := range results {
		category := "signature"
		if strings.HasPrefix(r.Match, "line ") {
			category = "heuristic"
		}
		jsonResults = append(jsonResults, JSONResult{
			Target:   r.Target,
			Priority: r.Priority,
			Finding:  r.Name,
			Evidence: r.Match,
			Category: category,
		})
	}

	data, err := json.MarshalIndent(jsonResults, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
		return
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing JSON output: %v\n", err)
	}
}

// writeSARIFOutput writes results in SARIF v2.1.0 format
func writeSARIFOutput(path string, results []Result) {
	ruleMap := make(map[string]int)
	var rules []SARIFRule
	var sarifResults []SARIFResult

	for _, r := range results {
		ruleID := sanitizeRuleID(r.Name)
		if _, exists := ruleMap[ruleID]; !exists {
			ruleMap[ruleID] = len(rules)
			rules = append(rules, SARIFRule{
				ID:               ruleID,
				Name:             r.Name,
				ShortDescription: SARIFMessage{Text: r.Name},
				DefaultConfig:    SARIFRuleLevel{Level: sarifLevel(r.Priority)},
			})
		}

		sr := SARIFResult{
			RuleID:  ruleID,
			Level:   sarifLevel(r.Priority),
			Message: SARIFMessage{Text: r.Match},
		}
		if r.Target != "" {
			sr.Locations = []SARIFLocation{
				{PhysicalLocation: SARIFPhysicalLocation{
					ArtifactLocation: SARIFArtifactLocation{URI: r.Target},
				}},
			}
		}
		sarifResults = append(sarifResults, sr)
	}

	log := SARIFLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFDriver{
						Name:           "jsecret",
						Version:        "3.1.0",
						InformationURI: "https://github.com/jjardel-infosec/jsecret",
						Rules:          rules,
					},
				},
				Results: sarifResults,
			},
		},
	}

	data, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling SARIF: %v\n", err)
		return
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing SARIF output: %v\n", err)
	}
}

func sarifLevel(priority string) string {
	switch priority {
	case "CRITICAL", "HIGH":
		return "error"
	case "MEDIUM":
		return "warning"
	default:
		return "note"
	}
}

func sanitizeRuleID(name string) string {
	return strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(name, " ", "-"), "(", ""), ")", "")
}

func printBanner() {
	fmt.Println(`
       _                         _ 
      (_)                       | |
       _ ___  ___  ___ _ __ ___ | |_ 
      | / __|/ _ \/ __| '__/ _ \| __|
      | \__ \  __/ (__| | |  __/| |_ 
      | |___/\___|\___|_|  \___| \__|
     _/ |                            
    |__/   v3.0 - @jjardel-infosec (Ultimate JS Security Scanner)
	`)
}
