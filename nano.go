package main

import (
	"crypto/md5"
	"encoding/hex"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

type Result struct {
	Target string
	Name   string
	Match  string
}

func matcher(target string, results chan<- Result) {
	content := fetchContent(target)
	if content != "" {
		Hach, _ := CreatHashSum(content)
		
		mu.Lock()
		seen := contains(HashList, Hach)
		if !seen {
			HashList = append(HashList, Hach)
		}
		mu.Unlock()

		if !seen {
			for _, sig := range Signatures {
				if sig.Regex.MatchString(content) {
					matches := sig.Regex.FindStringSubmatch(content)
					if len(matches) > 0 {
						match := matches[0]
						// Truncate match if it's too long
						if len(match) > 100 {
							match = match[:100] + "..."
						}
						results <- Result{
							Target: target,
							Name:   sig.Name,
							Match:  match,
						}
					}
				}
			}
		}
	}
}

func fetchContent(target string) string {
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		return requester(target)
	}
	// Try to read as local file
	content, err := ioutil.ReadFile(target)
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

func contains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}
	return false
}

func isUrl(url string) bool {
	if strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://") {
		if len(strings.Split(url, "/")) > 2 {
			return true
		}
	}
	return false
}

func requester(url string) string {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return ""
	}
	
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; JSecret/1.0; +https://github.com/user/jsecret)")

	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return ""
	}
	return string(body)
}
