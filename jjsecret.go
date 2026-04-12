package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const VERSION = "4.0.3"

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

func normalizeIgnoreValue(value string) string {
	normalized := filepath.ToSlash(strings.TrimSpace(value))
	normalized = strings.TrimPrefix(normalized, "./")
	return strings.TrimPrefix(normalized, "/")
}

func matchIgnoreSegments(patternSegments, pathSegments []string, requireFullMatch bool) bool {
	if len(patternSegments) == 0 {
		return !requireFullMatch || len(pathSegments) == 0
	}

	if patternSegments[0] == "**" {
		for offset := 0; offset <= len(pathSegments); offset++ {
			if matchIgnoreSegments(patternSegments[1:], pathSegments[offset:], requireFullMatch) {
				return true
			}
		}
		return false
	}

	if len(pathSegments) == 0 {
		return false
	}

	matched, err := path.Match(patternSegments[0], pathSegments[0])
	if err != nil || !matched {
		return false
	}

	return matchIgnoreSegments(patternSegments[1:], pathSegments[1:], requireFullMatch)
}

func matchesIgnorePattern(relPath string, isDir bool, pattern string) bool {
	pattern = filepath.ToSlash(strings.TrimSpace(pattern))
	if pattern == "" || strings.HasPrefix(pattern, "#") {
		return false
	}

	rootAnchored := strings.HasPrefix(pattern, "/")
	directoryPattern := strings.HasSuffix(pattern, "/")
	pattern = normalizeIgnoreValue(strings.TrimSuffix(pattern, "/"))
	if pattern == "" {
		return false
	}

	pathValue := normalizeIgnoreValue(strings.TrimSuffix(relPath, "/"))
	if pathValue == "" {
		return false
	}

	pathSegments := strings.Split(pathValue, "/")
	if !strings.Contains(pattern, "/") {
		if rootAnchored {
			matched, err := path.Match(pattern, pathSegments[0])
			if err != nil || !matched {
				return false
			}
			if directoryPattern {
				return true
			}
			return len(pathSegments) == 1
		}

		if directoryPattern {
			for _, segment := range pathSegments {
				matched, err := path.Match(pattern, segment)
				if err == nil && matched {
					return true
				}
			}
			return false
		}

		matched, err := path.Match(pattern, path.Base(pathValue))
		return err == nil && matched
	}

	patternSegments := strings.Split(pattern, "/")
	requireFullMatch := !directoryPattern
	if rootAnchored {
		return matchIgnoreSegments(patternSegments, pathSegments, requireFullMatch)
	}

	for start := 0; start < len(pathSegments); start++ {
		if matchIgnoreSegments(patternSegments, pathSegments[start:], requireFullMatch) {
			return true
		}
	}

	return isDir && directoryPattern && matchIgnoreSegments(patternSegments, pathSegments, false)
}

// shouldIgnore returns true if relPath matches any of the ignore patterns.
func shouldIgnore(relPath string, patterns []string) bool {
	isDir := strings.HasSuffix(filepath.ToSlash(relPath), "/")
	for _, pattern := range patterns {
		if matchesIgnorePattern(relPath, isDir, pattern) {
			return true
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

type ScanStats struct {
	SignatureCount  int
	HeuristicCount  int
	UniqueTypeCount int
}

type ScanCounters struct {
	FilesScanned int64
	Critical     int64
	High         int64
	Medium       int64
	Low          int64
	Total        int64
}

type SeverityBreakdown struct {
	Critical int
	High     int
	Medium   int
	Low      int
}

type MarkdownTargetGroup struct {
	Target  string
	Results []Result
}

type MarkdownSeverityGroup struct {
	Severity string
	Icon     string
	Results  []Result
	Targets  []MarkdownTargetGroup
}

func snapshotScanCounters(filesScanned, critical, high, medium, low *int64) ScanCounters {
	snapshot := ScanCounters{
		FilesScanned: atomic.LoadInt64(filesScanned),
		Critical:     atomic.LoadInt64(critical),
		High:         atomic.LoadInt64(high),
		Medium:       atomic.LoadInt64(medium),
		Low:          atomic.LoadInt64(low),
	}
	snapshot.Total = snapshot.Critical + snapshot.High + snapshot.Medium + snapshot.Low
	return snapshot
}

func countResultsBySeverity(results []Result) SeverityBreakdown {
	breakdown := SeverityBreakdown{}
	for _, result := range results {
		switch result.Priority {
		case "CRITICAL":
			breakdown.Critical++
		case "HIGH":
			breakdown.High++
		case "MEDIUM":
			breakdown.Medium++
		case "LOW":
			breakdown.Low++
		}
	}
	return breakdown
}

func markdownSeverityIcon(severity string) string {
	switch severity {
	case "CRITICAL":
		return "🔴"
	case "HIGH":
		return "🟠"
	case "MEDIUM":
		return "🟡"
	case "LOW":
		return "🔵"
	default:
		return "ℹ️"
	}
}

func groupMarkdownResults(results []Result) []MarkdownSeverityGroup {
	sorted := sortedResultsCopy(results)
	var groups []MarkdownSeverityGroup

	for _, severity := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} {
		group := MarkdownSeverityGroup{
			Severity: severity,
			Icon:     markdownSeverityIcon(severity),
		}

		for _, result := range sorted {
			if result.Priority != severity {
				continue
			}
			group.Results = append(group.Results, result)
			if len(group.Targets) == 0 || group.Targets[len(group.Targets)-1].Target != result.Target {
				group.Targets = append(group.Targets, MarkdownTargetGroup{Target: result.Target})
			}
			lastIndex := len(group.Targets) - 1
			group.Targets[lastIndex].Results = append(group.Targets[lastIndex].Results, result)
		}

		if len(group.Results) > 0 {
			groups = append(groups, group)
		}
	}

	return groups
}

func renderScanSummary(filesScanned, total, critical, high, medium, low int64, stats ScanStats, elapsed time.Duration) string {
	var sb strings.Builder
	sb.WriteString("\n\033[1;37m─── Scan Summary ───\033[0m\n")
	sb.WriteString(fmt.Sprintf("  Files scanned : %d\n", filesScanned))
	sb.WriteString(fmt.Sprintf("  Total findings: %d (%d signature, %d heuristic)\n", total, stats.SignatureCount, stats.HeuristicCount))
	sb.WriteString(fmt.Sprintf("  Unique types  : %d\n", stats.UniqueTypeCount))
	sb.WriteString(fmt.Sprintf("    \033[1;31mCRITICAL\033[0m: %d\n", critical))
	sb.WriteString(fmt.Sprintf("    \033[31mHIGH\033[0m    : %d\n", high))
	sb.WriteString(fmt.Sprintf("    \033[33mMEDIUM\033[0m  : %d\n", medium))
	sb.WriteString(fmt.Sprintf("    \033[34mLOW\033[0m     : %d\n", low))
	sb.WriteString(fmt.Sprintf("  Elapsed       : %s\n", elapsed.Round(time.Millisecond)))
	return sb.String()
}

func shouldExitStrict(critical, high int64) bool {
	return critical > 0 || high > 0
}

func resultCategory(result Result) string {
	if strings.HasPrefix(result.Match, "line ") {
		return "heuristic"
	}
	return "signature"
}

func sortResults(results []Result) {
	sort.Slice(results, func(i, j int) bool {
		pi := priorityLevels[results[i].Priority]
		pj := priorityLevels[results[j].Priority]
		if pi != pj {
			return pi > pj
		}
		if results[i].Target != results[j].Target {
			return results[i].Target < results[j].Target
		}
		if results[i].Name != results[j].Name {
			return results[i].Name < results[j].Name
		}
		return results[i].Match < results[j].Match
	})
}

func sortedResultsCopy(results []Result) []Result {
	cloned := append([]Result(nil), results...)
	sortResults(cloned)
	return cloned
}

func summarizeResults(results []Result) ScanStats {
	stats := ScanStats{}
	uniqueTypes := make(map[string]struct{})
	for _, result := range results {
		uniqueTypes[result.Name] = struct{}{}
		if resultCategory(result) == "heuristic" {
			stats.HeuristicCount++
		} else {
			stats.SignatureCount++
		}
	}
	stats.UniqueTypeCount = len(uniqueTypes)
	return stats
}

// JSONResult is the structured output for -json flag
type JSONResult struct {
	Target     string   `json:"target"`
	Priority   string   `json:"priority"`
	Finding    string   `json:"finding"`
	Evidence   string   `json:"evidence"`
	Category   string   `json:"category"`
	Line       int      `json:"line,omitempty"`
	Confidence int      `json:"confidence"`
	Provider   string   `json:"provider,omitempty"`
	Tags       []string `json:"tags,omitempty"`
	Entropy    float64  `json:"entropy,omitempty"`
	Context    string   `json:"context,omitempty"`
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
	Region           *SARIFRegion          `json:"region,omitempty"`
}

// SARIFArtifactLocation represents a file URI
type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

// SARIFRegion represents a line/column range in a file
type SARIFRegion struct {
	StartLine int `json:"startLine"`
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
	var insecureTLSFlag bool
	var versionFlag bool

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
	flag.BoolVar(&silentFlag, "s", false, "Silent mode (no banner, summary, or fetch warnings)")
	flag.BoolVar(&versionFlag, "version", false, "Show version and exit")
	var mdFlag string
	flag.StringVar(&mdFlag, "md", "", "Output file to save results (Markdown bug bounty report)")
	flag.BoolVar(&strictFlag, "strict", false, "Exit with code 1 if CRITICAL or HIGH findings are found")
	flag.BoolVar(&insecureTLSFlag, "k", false, "Skip TLS certificate verification for HTTPS requests")

	// v4.0 flags
	var confidenceMin int
	var providersFilter string
	var tagsFilter string
	var contextLines int
	flag.IntVar(&confidenceMin, "confidence-min", 0, "Minimum confidence score (0-100) to report findings")
	flag.StringVar(&providersFilter, "providers", "", "Comma-separated list of providers to include (e.g., aws,github,stripe)")
	flag.StringVar(&tagsFilter, "tags", "", "Comma-separated list of tags to include (e.g., auth-related,third-party)")
	flag.IntVar(&contextLines, "context", 0, "Number of surrounding code lines to include (0-10)")

	// Custom usage message
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  jsecret [flags]\n\n")
		fmt.Fprintf(os.Stderr, "Examples:\n")
		fmt.Fprintf(os.Stderr, "  cat urls.txt | jsecret\n")
		fmt.Fprintf(os.Stderr, "  jsecret -u http://example.com/script.js\n")
		fmt.Fprintf(os.Stderr, "  jsecret -f urls.txt -t 100 -o results.txt -csv report.csv\n")
		fmt.Fprintf(os.Stderr, "  jsecret -d /path/to/project -json findings.json\n")
		fmt.Fprintf(os.Stderr, "  jsecret -d . -md report.md\n")
		fmt.Fprintf(os.Stderr, "  jsecret -d . -min HIGH -strict\n")
		fmt.Fprintf(os.Stderr, "  jsecret -f urls.txt -sarif report.sarif\n")
		fmt.Fprintf(os.Stderr, "  jsecret -d . -ext .js,.ts,.jsx,.vue\n")
		fmt.Fprintf(os.Stderr, "  jsecret -u https://example.com/app.js -proxy http://127.0.0.1:8080\n")
		fmt.Fprintf(os.Stderr, "  jsecret -d . -confidence-min 70 -providers aws,github\n")
		fmt.Fprintf(os.Stderr, "  jsecret -d . -tags auth-related -context 3\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	if versionFlag {
		fmt.Printf("jsecret %s\n", VERSION)
		os.Exit(0)
	}

	if helpFlag {
		flag.Usage()
		os.Exit(0)
	}

	if !silentFlag {
		printBanner()
	}
	configureDiagnostics(!silentFlag)

	if concurrency < 1 {
		fmt.Fprintf(os.Stderr, "Invalid -t value: %d (use a value >= 1)\n", concurrency)
		os.Exit(1)
	}

	if insecureTLSFlag {
		configureTLSVerification(true)
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

	// Parse v4.0 filters
	if contextLines < 0 {
		contextLines = 0
	} else if contextLines > 10 {
		contextLines = 10
	}

	var providerSet map[string]bool
	if providersFilter != "" {
		providerSet = make(map[string]bool)
		for _, p := range strings.Split(providersFilter, ",") {
			p = strings.TrimSpace(strings.ToLower(p))
			if p != "" {
				providerSet[p] = true
			}
		}
	}

	var tagSet map[string]bool
	if tagsFilter != "" {
		tagSet = make(map[string]bool)
		for _, t := range strings.Split(tagsFilter, ",") {
			t = strings.TrimSpace(strings.ToLower(t))
			if t != "" {
				tagSet[t] = true
			}
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

	// Set context lines for scanContentWithOptions
	scanContextLines = contextLines

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
				csvWriter.Write([]string{"Target", "Priority", "Finding Type", "Evidence", "Confidence", "Provider", "Line"})
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

			// Apply confidence filter
			if confidenceMin > 0 && res.Confidence < confidenceMin {
				continue
			}

			// Apply provider filter
			if providerSet != nil && !providerSet[strings.ToLower(res.Provider)] {
				continue
			}

			// Apply tag filter
			if tagSet != nil {
				matched := false
				for _, t := range res.Tags {
					if tagSet[strings.ToLower(t)] {
						matched = true
						break
					}
				}
				if !matched {
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

			// Collect for JSON/SARIF/Markdown
			if jsonFlag != "" || sarifFlag != "" || mdFlag != "" {
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
				lineStr := ""
				if res.Line > 0 {
					lineStr = strconv.Itoa(res.Line)
				}
				csvWriter.Write([]string{res.Target, res.Priority, res.Name, res.Match, strconv.Itoa(res.Confidence), res.Provider, lineStr})
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
				// Skip hidden directories, VCS metadata, and dependency trees.
				if info.IsDir() {
					base := filepath.Base(fpath)
					if strings.HasPrefix(base, ".") || base == "node_modules" || base == ".git" {
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
				line := normalizeURL(scanner.Text())
				if line != "" {
					jobs <- line
				}
			}
			return
		}

		// 4. Stdin Mode
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			line := normalizeURL(scanner.Text())
			if line != "" {
				jobs <- line
			}
		}
	}()

	wg.Wait()
	close(results)
	wgOutput.Wait()

	// Sort collected results by severity (descending), then by target
	sortResults(allResults)

	// Write JSON output
	if jsonFlag != "" {
		writeJSONOutput(jsonFlag, allResults)
	}

	// Write SARIF output
	if sarifFlag != "" {
		writeSARIFOutput(sarifFlag, allResults)
	}

	// Write Markdown report
	if mdFlag != "" {
		writeMarkdownOutput(mdFlag, allResults)
	}

	// Print summary
	elapsed := time.Since(startTime)
	counters := snapshotScanCounters(&filesScanned, &criticalCount, &highCount, &mediumCount, &lowCount)
	if !silentFlag {
		stats := summarizeResults(allResults)
		fmt.Print(renderScanSummary(counters.FilesScanned, counters.Total, counters.Critical, counters.High, counters.Medium, counters.Low, stats, elapsed))
	}

	// Exit with code 1 if strict mode and critical/high findings
	if strictFlag && shouldExitStrict(counters.Critical, counters.High) {
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

// extractLineNumber parses "line N: ..." evidence strings and returns the line number (0 if none).
var lineNumberRe = regexp.MustCompile(`^line (\d+):`)

func extractLineNumber(evidence string) int {
	m := lineNumberRe.FindStringSubmatch(evidence)
	if m == nil {
		return 0
	}
	n, _ := strconv.Atoi(m[1])
	return n
}

// writeJSONOutput writes results in structured JSON format
func writeJSONOutput(path string, results []Result) {
	results = sortedResultsCopy(results)
	jsonResults := make([]JSONResult, 0, len(results))
	for _, r := range results {
		category := resultCategory(r)
		lineNum := r.Line
		if lineNum == 0 && category == "heuristic" {
			lineNum = extractLineNumber(r.Match)
		}
		jsonResults = append(jsonResults, JSONResult{
			Target:     r.Target,
			Priority:   r.Priority,
			Finding:    r.Name,
			Evidence:   r.Match,
			Category:   category,
			Line:       lineNum,
			Confidence: r.Confidence,
			Provider:   r.Provider,
			Tags:       r.Tags,
			Entropy:    r.Entropy,
			Context:    r.Context,
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
	results = sortedResultsCopy(results)
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
			Message: SARIFMessage{Text: fmt.Sprintf("[confidence:%d] %s", r.Confidence, r.Match)},
		}
		if r.Target != "" {
			lineNum := r.Line
			if lineNum == 0 {
				lineNum = extractLineNumber(r.Match)
			}
			loc := SARIFLocation{
				PhysicalLocation: SARIFPhysicalLocation{
					ArtifactLocation: SARIFArtifactLocation{URI: r.Target},
				},
			}
			if lineNum > 0 {
				loc.PhysicalLocation.Region = &SARIFRegion{StartLine: lineNum}
			}
			sr.Locations = []SARIFLocation{loc}
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
						Version:        VERSION,
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

// writeMarkdownOutput writes a bug-bounty-style markdown report grouped by severity.
func writeMarkdownOutput(path string, results []Result) {
	var sb strings.Builder
	sb.WriteString("# jsecret Security Scan Report\n\n")
	sb.WriteString(fmt.Sprintf("**Generated:** %s\n\n", time.Now().UTC().Format(time.RFC3339)))

	counts := countResultsBySeverity(results)
	groups := groupMarkdownResults(results)
	sb.WriteString("## Summary\n\n")
	sb.WriteString(fmt.Sprintf("| Severity | Count |\n|----------|-------|\n"))
	for _, row := range []struct {
		Severity string
		Count    int
	}{
		{Severity: "CRITICAL", Count: counts.Critical},
		{Severity: "HIGH", Count: counts.High},
		{Severity: "MEDIUM", Count: counts.Medium},
		{Severity: "LOW", Count: counts.Low},
	} {
		if row.Count > 0 {
			sb.WriteString(fmt.Sprintf("| %s | %d |\n", row.Severity, row.Count))
		}
	}
	sb.WriteString("\n")

	for _, group := range groups {
		sb.WriteString(fmt.Sprintf("## %s %s (%d)\n\n", group.Icon, group.Severity, len(group.Results)))
		for _, targetGroup := range group.Targets {
			sb.WriteString(fmt.Sprintf("### `%s`\n\n", targetGroup.Target))
			for _, r := range targetGroup.Results {
				ln := r.Line
				if ln == 0 {
					ln = extractLineNumber(r.Match)
				}
				label := r.Name
				if r.Provider != "" {
					label = fmt.Sprintf("%s [%s]", r.Name, r.Provider)
				}
				if ln > 0 {
					sb.WriteString(fmt.Sprintf("- **%s** (line %d, confidence: %d%%)\n", label, ln, r.Confidence))
				} else {
					sb.WriteString(fmt.Sprintf("- **%s** (confidence: %d%%)\n", label, r.Confidence))
				}
				sb.WriteString(fmt.Sprintf("  > `%s`\n\n", r.Match))
			}
		}
	}

	if err := os.WriteFile(path, []byte(sb.String()), 0600); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing Markdown output: %v\n", err)
	}
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
    |__/   v4.0.3 - @jjardel-infosec (Ultimate JS Security Scanner)
	`)
}
