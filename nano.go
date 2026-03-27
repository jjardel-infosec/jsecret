package main

import (
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
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
	Transport: &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:        200,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     30 * time.Second,
	},
	Timeout: 15 * time.Second,
}

// configureProxy sets the proxy URL on the shared HTTP client
func configureProxy(proxyURL string) {
	parsed, err := url.Parse(proxyURL)
	if err != nil {
		return
	}
	sharedClient.Transport = &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:        200,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     30 * time.Second,
		Proxy:               http.ProxyURL(parsed),
	}
}

func matcher(target string, results chan<- Result) {
	content := fetchContent(target)
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

func fetchContent(target string) string {
	if isUrl(target) {
		return requester(target)
	}
	content, err := os.ReadFile(target)
	if err == nil {
		return string(content)
	}
	return ""
}

func createHashSum(input string) (string, error) {
	hasher := md5.New()
	_, err := hasher.Write([]byte(input))
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func isUrl(rawURL string) bool {
	return strings.HasPrefix(rawURL, "http://") || strings.HasPrefix(rawURL, "https://")
}

func requester(targetURL string) string {
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return ""
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; JSecret/3.0; +https://github.com/jjardel-infosec/jsecret)")

	resp, err := sharedClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	// Limit response body to prevent OOM on huge files
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	if err != nil {
		return ""
	}
	return string(body)
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

	mapContent := requester(mapURL)
	if mapContent == "" {
		return
	}

	var sm sourceMap
	if err := json.Unmarshal([]byte(mapContent), &sm); err != nil {
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
