package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// Maximum response body size: 10MB
const maxBodySize = 10 * 1024 * 1024

type Result struct {
	Target   string
	Name     string
	Match    string
	Priority string
}

// Shared HTTP client with connection pooling (created once, reused by all workers)
var sharedClient = &http.Client{
	Transport: newHTTPTransport(nil, false),
	Timeout:   15 * time.Second,
}

var (
	sharedProxyURL     *url.URL
	sharedInsecureTLS  bool
	diagnosticsEnabled bool
	diagnosticWriter   io.Writer = os.Stderr
	diagnosticWarnings sync.Map
)

func configureDiagnostics(enabled bool) {
	diagnosticsEnabled = enabled
	diagnosticWarnings = sync.Map{}
}

func emitDiagnosticWarning(message string) {
	if !diagnosticsEnabled || message == "" {
		return
	}
	if _, loaded := diagnosticWarnings.LoadOrStore(message, struct{}{}); loaded {
		return
	}
	fmt.Fprintf(diagnosticWriter, "Warning: %s\n", message)
}

func describeNetworkError(err error) string {
	if err == nil {
		return "unknown error"
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return fmt.Sprintf("request timed out: %v", err)
	}

	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		var netInnerErr net.Error
		if errors.As(urlErr.Err, &netInnerErr) && netInnerErr.Timeout() {
			return fmt.Sprintf("request timed out: %v", urlErr.Err)
		}
		return urlErr.Err.Error()
	}

	return err.Error()
}

func newHTTPTransport(proxyURL *url.URL, insecureTLS bool) *http.Transport {
	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: insecureTLS},
		MaxIdleConns:        200,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     30 * time.Second,
	}
	if proxyURL != nil {
		transport.Proxy = http.ProxyURL(proxyURL)
	}
	return transport
}

func refreshHTTPTransport() {
	sharedClient.Transport = newHTTPTransport(sharedProxyURL, sharedInsecureTLS)
}

func configureTLSVerification(insecureTLS bool) {
	sharedInsecureTLS = insecureTLS
	refreshHTTPTransport()
}

// configureProxy sets the proxy URL on the shared HTTP client
func configureProxy(proxyURL string) {
	parsed, err := url.Parse(proxyURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid proxy URL: %v\n", err)
		os.Exit(1)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" && parsed.Scheme != "socks5" {
		fmt.Fprintf(os.Stderr, "Invalid proxy scheme %q (use http, https, or socks5)\n", parsed.Scheme)
		os.Exit(1)
	}
	if parsed.Host == "" {
		fmt.Fprintf(os.Stderr, "Proxy URL missing host\n")
		os.Exit(1)
	}
	sharedProxyURL = parsed
	refreshHTTPTransport()
}

func matcher(target string, results chan<- Result) {
	content, err := fetchContent(target)
	if err != nil {
		emitDiagnosticWarning(fmt.Sprintf("failed to read %s: %s", target, describeNetworkError(err)))
		return
	}
	if content == "" {
		return
	}

	hash, err := createHashSum(content)
	if err != nil {
		return
	}

	// Map de Hashes Global (O(1)) para evitar processamento duplicado
	if _, loaded := SeenHashes.LoadOrStore(hash, struct{}{}); loaded {
		return // Já escaneamos esse mesmo conteúdo/arquivo anteriormente!
	}

	for _, result := range scanContent(target, content) {
		results <- result
	}

	// Source map resolution: scan original sources if available
	if isUrl(target) {
		resolveAndScanSourceMap(target, content, results)
	}
}

func fetchContent(target string) (string, error) {
	if isUrl(target) {
		return requester(target)
	}
	content, err := os.ReadFile(target)
	if err != nil {
		return "", err
	}
	return string(content), nil
}

func createHashSum(input string) (string, error) {
	hasher := sha256.New()
	_, err := hasher.Write([]byte(input))
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func isUrl(rawURL string) bool {
	return strings.HasPrefix(rawURL, "http://") || strings.HasPrefix(rawURL, "https://")
}

func requester(targetURL string) (string, error) {
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; JSecret/3.3.0; +https://github.com/jjardel-infosec/jsecret)")

	resp, err := sharedClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return "", fmt.Errorf("unexpected HTTP status %s", resp.Status)
	}

	// Limit response body to prevent OOM on huge files
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// sourceMap represents the minimal structure of a JS source map
type sourceMap struct {
	Sources        []string `json:"sources"`
	SourcesContent []string `json:"sourcesContent"`
}

// resolveAndScanSourceMap attempts to find and scan original sources from a source map
func resolveAndScanSourceMap(jsURL, content string, results chan<- Result) {
	mapURL := ""

	// Check for sourceMappingURL comment in the JS content
	for _, prefix := range []string{"//# sourceMappingURL=", "//@ sourceMappingURL="} {
		idx := strings.LastIndex(content, prefix)
		if idx != -1 {
			rest := content[idx+len(prefix):]
			end := strings.IndexAny(rest, " \n\r\t")
			if end == -1 {
				end = len(rest)
			}
			candidate := strings.TrimSpace(rest[:end])
			if candidate != "" {
				if isUrl(candidate) {
					mapURL = candidate
				} else {
					// Relative URL resolution
					lastSlash := strings.LastIndex(jsURL, "/")
					if lastSlash != -1 {
						mapURL = jsURL[:lastSlash+1] + candidate
					}
				}
			}
			break
		}
	}

	// Fallback: try appending .map to the JS URL
	if mapURL == "" {
		mapURL = jsURL + ".map"
	}

	mapContent, err := requester(mapURL)
	if err != nil {
		if mapURL != jsURL+".map" {
			emitDiagnosticWarning(fmt.Sprintf("failed to fetch source map %s: %s", mapURL, describeNetworkError(err)))
		}
		return
	}
	if mapContent == "" {
		return
	}

	var sm sourceMap
	if err := json.Unmarshal([]byte(mapContent), &sm); err != nil {
		emitDiagnosticWarning(fmt.Sprintf("failed to parse source map %s: %v", mapURL, err))
		return
	}

	// Scan each original source from the source map
	for i, src := range sm.SourcesContent {
		if src == "" {
			continue
		}

		sourceName := "sourcemap"
		if i < len(sm.Sources) {
			sourceName = sm.Sources[i]
		}

		sourceTarget := jsURL + " → " + sourceName

		hash, err := createHashSum(src)
		if err != nil {
			continue
		}
		if _, loaded := SeenHashes.LoadOrStore(hash, struct{}{}); loaded {
			continue
		}

		for _, result := range scanContent(sourceTarget, src) {
			results <- result
		}
	}
}
