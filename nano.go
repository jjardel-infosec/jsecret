package main

import (
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type Result struct {
	Target   string
	Name     string
	Match    string
	Priority string
}

func matcher(target string, results chan<- Result) {
	content := fetchContent(target)
	if content != "" {
		Hach, err := CreatHashSum(content)
		if err != nil {
			return
		}

		// Map de Hashes Global (O(1)) para evitar processamento duplicado
		if _, loaded := SeenHashes.LoadOrStore(Hach, struct{}{}); loaded {
			return // Já escaneamos esse mesmo conteúdo/arquivo anteriormente!
		}

		for _, result := range scanContent(target, content) {
			results <- result
		}
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

func CreatHashSum(input string) (string, error) {
	hasher := md5.New()
	_, err := hasher.Write([]byte(input))
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func isUrl(url string) bool {
	if strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://") {
		return true
	}
	return false
}

func requester(url string) string {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   10 * time.Second,
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return ""
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; JSecret/2.3; +https://github.com/jjardel-infosec/jsecret)")

	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}
	return string(body)
}
