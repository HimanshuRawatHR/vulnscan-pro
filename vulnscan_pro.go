package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Vulnerability struct {
	ID              string    `json:"id"`
	Type            string    `json:"type"`
	Severity        string    `json:"severity"`
	CVSS            float32   `json:"cvss_score"`
	CWE             string    `json:"cwe"`
	URL             string    `json:"url"`
	Parameter       string    `json:"parameter"`
	Payload         string    `json:"payload"`
	Evidence        string    `json:"evidence"`
	Description     string    `json:"description"`
	Impact          string    `json:"impact"`
	Remediation     string    `json:"remediation"`
	Timestamp       time.Time `json:"timestamp"`
	ReproductionURL string    `json:"reproduction_url"`
	ProofOfConcept  string    `json:"proof_of_concept"`
}

type ScanStats struct {
	TotalRequests   int64
	VulnFound       int64
	StartTime       time.Time
	EndTime         time.Time
	CriticalCount   int64
	HighCount       int64
	MediumCount     int64
	LowCount        int64
	TotalVulns      int64
}

type Scanner struct {
	targetURL   string
	results     []Vulnerability
	client      *http.Client
	mu          sync.Mutex
	concurrency int
	timeout     time.Duration
	stats       ScanStats
	verbose     bool
}

func NewScanner(targetURL string, concurrency int, timeout time.Duration, verbose bool) *Scanner {
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			MaxIdleConns:       100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:    90 * time.Second,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	return &Scanner{
		targetURL:   targetURL,
		client:      client,
		concurrency: concurrency,
		timeout:     timeout,
		results:     []Vulnerability{},
		verbose:     verbose,
		stats: ScanStats{
			StartTime: time.Now(),
		},
	}
}

func (s *Scanner) ScanSQLInjection(parameter string) {
	sqlPayloads := []struct {
		payload string
		desc    string
		type_   string
	}{
		{"' OR '1'='1", "Boolean-based SQLi", "Boolean"},
		{"1' OR '1'='1", "Boolean-based SQLi", "Boolean"},
		{"' OR 1=1 --", "Boolean-based SQLi", "Boolean"},
	}

	for _, payload := range sqlPayloads {
		testURL := s.buildURL(parameter, payload.payload)
		resp, err := s.client.Get(testURL)
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		atomic.AddInt64(&s.stats.TotalRequests, 1)
		body, _ := io.ReadAll(resp.Body)
		bodyStr := string(body)

		if s.detectSQLError(bodyStr) {
			s.addVuln(Vulnerability{
				ID:              fmt.Sprintf("SQLi_%d", time.Now().UnixNano()),
				Type:            fmt.Sprintf("SQL Injection (%s)", payload.type_),
				Severity:        "Critical",
				CVSS:            9.9,
				CWE:             "89",
				URL:             testURL,
				Parameter:       parameter,
				Payload:         payload.payload,
				Evidence:        "SQL error detected",
				Description:     "SQL Injection vulnerability detected",
				Impact:          "Database compromise, data theft",
				Remediation:     "Use parameterized queries",
				Timestamp:       time.Now(),
				ReproductionURL: testURL,
				ProofOfConcept:  fmt.Sprintf("curl '%s'", testURL),
			})
			return
		}
	}
}

func (s *Scanner) ScanXSS(parameter string) {
	xssPayloads := []string{
		"<script>alert('XSS')</script>",
		"<img src=x onerror=alert('XSS')>",
	}

	for _, payload := range xssPayloads {
		testURL := s.buildURL(parameter, payload)
		resp, err := s.client.Get(testURL)
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		atomic.AddInt64(&s.stats.TotalRequests, 1)
		body, _ := io.ReadAll(resp.Body)
		bodyStr := string(body)

		if strings.Contains(bodyStr, payload) {
			s.addVuln(Vulnerability{
				ID:              fmt.Sprintf("XSS_%d", time.Now().UnixNano()),
				Type:            "Cross-Site Scripting (XSS)",
				Severity:        "High",
				CVSS:            7.5,
				CWE:             "79",
				URL:             testURL,
				Parameter:       parameter,
				Payload:         payload,
				Evidence:        "Payload reflected",
				Description:     "XSS vulnerability detected",
				Impact:          "Session hijacking, credential theft",
				Remediation:     "HTML encode output, use CSP",
				Timestamp:       time.Now(),
				ReproductionURL: testURL,
				ProofOfConcept:  fmt.Sprintf("curl '%s'", testURL),
			})
			return
		}
	}
}

func (s *Scanner) ScanCSRF() {
	resp, err := s.client.Get(s.targetURL)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)
	atomic.AddInt64(&s.stats.TotalRequests, 1)

	hasForm := containsFormWithPost(bodyStr)
	hasToken := strings.Contains(bodyStr, "csrf") || strings.Contains(bodyStr, "_token")

	if hasForm && !hasToken {
		s.addVuln(Vulnerability{
			ID:              fmt.Sprintf("CSRF_%d", time.Now().UnixNano()),
			Type:            "CSRF",
			Severity:        "High",
			CVSS:            6.5,
			CWE:             "352",
			URL:             s.targetURL,
			Parameter:       "Forms",
			Payload:         "No CSRF token",
			Evidence:        "POST form without CSRF",
			Description:     "CSRF vulnerability detected",
			Impact:          "Unauthorized actions",
			Remediation:     "Add CSRF tokens",
			Timestamp:       time.Now(),
			ReproductionURL: s.targetURL,
			ProofOfConcept:  "Check forms",
		})
	}
}

func (s *Scanner) ScanBrokenAuth() {
	resp, err := s.client.Get(s.targetURL)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	atomic.AddInt64(&s.stats.TotalRequests, 1)

	cookie := resp.Header.Get("Set-Cookie")
	if cookie != "" && !strings.Contains(cookie, "Secure") {
		s.addVuln(Vulnerability{
			ID:              fmt.Sprintf("AUTH_%d", time.Now().UnixNano()),
			Type:            "Insecure Cookie",
			Severity:        "High",
			CVSS:            7.5,
			CWE:             "614",
			URL:             s.targetURL,
			Parameter:       "Cookie",
			Payload:         "Missing Secure",
			Evidence:        "No Secure flag",
			Description:     "Insecure cookie transmission",
			Impact:          "Session hijacking",
			Remediation:     "Add Secure flag",
			Timestamp:       time.Now(),
			ReproductionURL: s.targetURL,
			ProofOfConcept:  "curl -I",
		})
	}
}

func (s *Scanner) ScanSensitiveDataExposure() {
	resp, err := s.client.Get(s.targetURL)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	atomic.AddInt64(&s.stats.TotalRequests, 1)

	if !strings.HasPrefix(s.targetURL, "https://") {
		s.addVuln(Vulnerability{
			ID:              fmt.Sprintf("DATA_%d", time.Now().UnixNano()),
			Type:            "Unencrypted Connection",
			Severity:        "Critical",
			CVSS:            9.8,
			CWE:             "295",
			URL:             s.targetURL,
			Parameter:       "Protocol",
			Payload:         "HTTP",
			Evidence:        "Uses HTTP",
			Description:     "No encryption",
			Impact:          "Data interception",
			Remediation:     "Use HTTPS",
			Timestamp:       time.Now(),
			ReproductionURL: s.targetURL,
			ProofOfConcept:  "curl -v",
		})
	}

	headers := []string{"Strict-Transport-Security", "Content-Security-Policy", "X-Content-Type-Options"}
	for _, h := range headers {
		if resp.Header.Get(h) == "" {
			s.addVuln(Vulnerability{
				ID:              fmt.Sprintf("HDR_%d", time.Now().UnixNano()),
				Type:            "Missing Header: " + h,
				Severity:        "Medium",
				CVSS:            4.3,
				CWE:             "693",
				URL:             s.targetURL,
				Parameter:       "Headers",
				Payload:         h,
				Evidence:        "Missing",
				Description:     "Security header missing",
				Impact:          "Increased attack surface",
				Remediation:     "Add " + h,
				Timestamp:       time.Now(),
				ReproductionURL: s.targetURL,
				ProofOfConcept:  "curl -i",
			})
		}
	}
}

func (s *Scanner) ScanXXE(parameter string) {
	payload := `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`
	testURL := s.buildURL(parameter, payload)
	resp, err := s.client.Get(testURL)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	atomic.AddInt64(&s.stats.TotalRequests, 1)
	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	if strings.Contains(bodyStr, "root:") {
		s.addVuln(Vulnerability{
			ID:              fmt.Sprintf("XXE_%d", time.Now().UnixNano()),
			Type:            "XXE Injection",
			Severity:        "Critical",
			CVSS:            9.8,
			CWE:             "611",
			URL:             testURL,
			Parameter:       parameter,
			Payload:         payload,
			Evidence:        "File disclosed",
			Description:     "XXE found",
			Impact:          "File access",
			Remediation:     "Disable entities",
			Timestamp:       time.Now(),
			ReproductionURL: testURL,
			ProofOfConcept:  "XXE",
		})
	}
}

func (s *Scanner) ScanSSRF(parameter string) {
	payloads := []string{"http://localhost:8080", "http://127.0.0.1:8080"}
	
	for _, payload := range payloads {
		testURL := s.buildURL(parameter, payload)
		resp, err := s.client.Get(testURL)
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		atomic.AddInt64(&s.stats.TotalRequests, 1)
		body, _ := io.ReadAll(resp.Body)
		bodyStr := string(body)

		// FIXED: Only flag if we see actual SSRF evidence
		if strings.Contains(bodyStr, "root:") || strings.Contains(bodyStr, "<!DOCTYPE") && strings.Contains(bodyStr, "127.0.0.1") {
			s.addVuln(Vulnerability{
				ID:              fmt.Sprintf("SSRF_%d", time.Now().UnixNano()),
				Type:            "SSRF",
				Severity:        "High",
				CVSS:            8.6,
				CWE:             "918",
				URL:             testURL,
				Parameter:       parameter,
				Payload:         payload,
				Evidence:        "Server accessed internal URL",
				Description:     "SSRF found",
				Impact:          "Internal access",
				Remediation:     "Validate URLs",
				Timestamp:       time.Now(),
				ReproductionURL: testURL,
				ProofOfConcept:  payload,
			})
			return
		}
	}
}

func (s *Scanner) ScanCommandInjection(parameter string) {
	payloads := []string{"; whoami", "| whoami"}
	
	for _, payload := range payloads {
		testURL := s.buildURL(parameter, payload)
		resp, err := s.client.Get(testURL)
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		atomic.AddInt64(&s.stats.TotalRequests, 1)
		body, _ := io.ReadAll(resp.Body)
		bodyStr := string(body)

		if strings.Contains(bodyStr, "uid=") {
			s.addVuln(Vulnerability{
				ID:              fmt.Sprintf("RCE_%d", time.Now().UnixNano()),
				Type:            "RCE",
				Severity:        "Critical",
				CVSS:            9.8,
				CWE:             "78",
				URL:             testURL,
				Parameter:       parameter,
				Payload:         payload,
				Evidence:        "Command output",
				Description:     "RCE found",
				Impact:          "System compromise",
				Remediation:     "Parameterized APIs",
				Timestamp:       time.Now(),
				ReproductionURL: testURL,
				ProofOfConcept:  payload,
			})
			return
		}
	}
}

func (s *Scanner) ScanPathTraversal(parameter string) {
	payloads := []string{"../etc/passwd", "../../etc/passwd"}
	
	for _, payload := range payloads {
		testURL := s.buildURL(parameter, payload)
		resp, err := s.client.Get(testURL)
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		atomic.AddInt64(&s.stats.TotalRequests, 1)
		body, _ := io.ReadAll(resp.Body)
		bodyStr := string(body)

		if strings.Contains(bodyStr, "root:") {
			s.addVuln(Vulnerability{
				ID:              fmt.Sprintf("PATH_%d", time.Now().UnixNano()),
				Type:            "Path Traversal",
				Severity:        "High",
				CVSS:            7.5,
				CWE:             "22",
				URL:             testURL,
				Parameter:       parameter,
				Payload:         payload,
				Evidence:        "File content",
				Description:     "Path traversal found",
				Impact:          "File access",
				Remediation:     "Sanitize paths",
				Timestamp:       time.Now(),
				ReproductionURL: testURL,
				ProofOfConcept:  payload,
			})
			return
		}
	}
}

func (s *Scanner) buildURL(parameter, payload string) string {
	if strings.Contains(s.targetURL, "?") {
		return fmt.Sprintf("%s&%s=%s", s.targetURL, parameter, url.QueryEscape(payload))
	}
	return fmt.Sprintf("%s?%s=%s", s.targetURL, parameter, url.QueryEscape(payload))
}

func (s *Scanner) addVuln(vuln Vulnerability) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.results = append(s.results, vuln)
	atomic.AddInt64(&s.stats.TotalVulns, 1)
	switch vuln.Severity {
	case "Critical":
		atomic.AddInt64(&s.stats.CriticalCount, 1)
	case "High":
		atomic.AddInt64(&s.stats.HighCount, 1)
	case "Medium":
		atomic.AddInt64(&s.stats.MediumCount, 1)
	}
}

func (s *Scanner) detectSQLError(response string) bool {
	errors := []string{"SQL syntax", "mysql_fetch", "ORA-", "PostgreSQL", "syntax error", "Unclosed"}
	for _, err := range errors {
		if strings.Contains(response, err) {
			return true
		}
	}
	return false
}

func (s *Scanner) RunFullScan() {
	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Println("STARTING SCAN")
	fmt.Println(strings.Repeat("=", 80))
	fmt.Printf("Target: %s | Threads: %d\n\n", s.targetURL, s.concurrency)

	params := []string{"id", "search", "q", "page", "user", "email", "name", "data", "file", "param"}
	var wg sync.WaitGroup
	sem := make(chan struct{}, s.concurrency)

	headerFuncs := []func(){s.ScanCSRF, s.ScanBrokenAuth, s.ScanSensitiveDataExposure}
	for _, f := range headerFuncs {
		wg.Add(1)
		go func(fn func()) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			fn()
		}(f)
	}

	paramFuncs := []func(string){s.ScanSQLInjection, s.ScanXSS, s.ScanXXE, s.ScanSSRF, s.ScanCommandInjection, s.ScanPathTraversal}
	for _, p := range params {
		for _, f := range paramFuncs {
			wg.Add(1)
			go func(param string, fn func(string)) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				fn(param)
			}(p, f)
		}
	}

	wg.Wait()
	s.stats.EndTime = time.Now()
}

func (s *Scanner) PrintResults() {
	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Println("RESULTS")
	fmt.Println(strings.Repeat("=", 80))

	if len(s.results) == 0 {
		fmt.Println("No vulnerabilities found!")
		return
	}

	groups := make(map[string][]Vulnerability)
	for _, v := range s.results {
		groups[v.Severity] = append(groups[v.Severity], v)
	}

	order := []string{"Critical", "High", "Medium"}
	for _, sev := range order {
		if vulns, ok := groups[sev]; ok {
			fmt.Printf("\n[%s] %d found\n", sev, len(vulns))
			for i, v := range vulns {
				fmt.Printf("%d. %s (CWE: %s) - %s\n", i+1, v.Type, v.CWE, v.ReproductionURL)
			}
		}
	}

	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Printf("Total: %d | Requests: %d | Time: %.2fs\n", len(s.results), atomic.LoadInt64(&s.stats.TotalRequests), s.stats.EndTime.Sub(s.stats.StartTime).Seconds())
	fmt.Println(strings.Repeat("=", 80))
}

func (s *Scanner) GenerateReports(base string) {
	ts := time.Now().Unix()
	txt := fmt.Sprintf("%s_%d.txt", base, ts)
	js := fmt.Sprintf("%s_%d.json", base, ts)

	var report string
	report = fmt.Sprintf("SCAN REPORT\nTarget: %s\nTotal: %d\n\n", s.targetURL, len(s.results))
	for _, v := range s.results {
		report += fmt.Sprintf("[%s] %s\n%s\n\n", v.Severity, v.Type, v.ReproductionURL)
	}
	os.WriteFile(txt, []byte(report), 0644)

	type Rep struct {
		Target string          `json:"target"`
		Vulns  []Vulnerability `json:"vulnerabilities"`
	}
	data, _ := json.MarshalIndent(Rep{s.targetURL, s.results}, "", "  ")
	os.WriteFile(js, data, 0644)

	fmt.Printf("Saved: %s, %s\n", txt, js)
}

func containsFormWithPost(html string) bool {
	return strings.Contains(html, "<form") && (strings.Contains(html, `method="post"`) || strings.Contains(html, `method='post'`))
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func showMenu() {
	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Println("VulnScan Pro v2.0 - Fixed")
	fmt.Println(strings.Repeat("=", 80))
	fmt.Println("1. Quick  2. Fast  3. Stealthy  4. Verbose  5. Custom  6. Exit")
	fmt.Println(strings.Repeat("=", 80))
}

func getUserInput(prompt string) string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print(prompt)
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
}

func runScan(targetURL string, threads int, timeout time.Duration, verbose bool) {
	if !strings.HasPrefix(targetURL, "http") {
		targetURL = "https://" + targetURL
	}

	fmt.Printf("\nConnecting to %s...\n", targetURL)
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Head(targetURL)
	if err != nil {
		fmt.Printf("Failed: %v\n", err)
		return
	}
	resp.Body.Close()

	fmt.Printf("Connected! Status: %d\n\n", resp.StatusCode)
	scanner := NewScanner(targetURL, threads, timeout, verbose)
	scanner.RunFullScan()
	scanner.PrintResults()

	if getUserInput("\nGenerate reports? (y/n): ") == "y" {
		scanner.GenerateReports("Report")
	}
}

func main() {
	for {
		showMenu()
		choice := getUserInput("\nSelect: ")

		switch choice {
		case "1":
			url := getUserInput("URL: ")
			if url != "" {
				runScan(url, 10, 10*time.Second, false)
			}
		case "2":
			url := getUserInput("URL: ")
			if url != "" {
				runScan(url, 30, 5*time.Second, false)
			}
		case "3":
			url := getUserInput("URL: ")
			if url != "" {
				runScan(url, 2, 20*time.Second, false)
			}
		case "4":
			url := getUserInput("URL: ")
			if url != "" {
				runScan(url, 10, 10*time.Second, true)
			}
		case "5":
			url := getUserInput("URL: ")
			if url != "" {
				t := 10
				to := 10
				fmt.Sscanf(getUserInput("Threads (10): "), "%d", &t)
				fmt.Sscanf(getUserInput("Timeout (10): "), "%d", &to)
				runScan(url, t, time.Duration(to)*time.Second, false)
			}
		case "6":
			fmt.Println("Goodbye!")
			return
		}
	}
}
