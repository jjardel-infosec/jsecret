package main

import (
	"bufio"
	"encoding/csv"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

var (
	// Hashes dos conteudos para não baixar/escanear scripts duplicados
	SeenHashes sync.Map // O(1) de tempo de acesso e lock-free pra Concorrência
)

func main() {
	// Define flags
	var urlFlag string
	var fileFlag string
	var dirFlag string
	var outputFlag string
	var csvFlag string
	var concurrency int
	var helpFlag bool
	var silentFlag bool

	flag.StringVar(&urlFlag, "u", "", "Single URL to scan")
	flag.StringVar(&fileFlag, "f", "", "File containing list of URLs")
	flag.StringVar(&dirFlag, "d", "", "Directory to scan for .js files (recursive)")
	flag.StringVar(&outputFlag, "o", "", "Output file to save results (TXT format)")
	flag.StringVar(&csvFlag, "csv", "", "Output file to save results (CSV format)")
	flag.IntVar(&concurrency, "t", 50, "Number of concurrent threads")
	flag.BoolVar(&helpFlag, "h", false, "Show help message")
	flag.BoolVar(&silentFlag, "s", false, "Silent mode (no banner)")

	// Custom usage message
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  jsecret [flags]\n\n")
		fmt.Fprintf(os.Stderr, "Examples:\n")
		fmt.Fprintf(os.Stderr, "  cat urls.txt | jsecret\n")
		fmt.Fprintf(os.Stderr, "  jsecret -u http://example.com/script.js\n")
		fmt.Fprintf(os.Stderr, "  jsecret -f urls.txt -t 100 -o results.txt -csv report.csv\n")
		fmt.Fprintf(os.Stderr, "  jsecret -d /path/to/js/files\n")
		fmt.Fprintf(os.Stderr, "  jsecret -d .\n\n")
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

	// Worker pool setup
	var wg sync.WaitGroup
	jobs := make(chan string)
	results := make(chan Result)

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
				matcher(target, results)
			}
		}()
	}

	// Input handling in a separate goroutine
	go func() {
		defer close(jobs)

		// 1. Single URL Mode
		if urlFlag != "" {
			if isUrl(urlFlag) || strings.HasSuffix(urlFlag, ".js") {
				jobs <- urlFlag
			}
			return
		}

		// 2. Directory Mode
		if dirFlag != "" {
			if !silentFlag {
				fmt.Printf("[*] Scanning directory: %s\n", dirFlag)
			}
			err := filepath.Walk(dirFlag, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if !info.IsDir() && strings.HasSuffix(info.Name(), ".js") {
					jobs <- path
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
    |__/   v2.3 - @jjardel-infosec (Hybrid JS Security Scan)
	`)
}
