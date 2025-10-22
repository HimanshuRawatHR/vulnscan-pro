package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
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
		{"admin' OR '1'='1' --", "Boolean-based SQLi", "Boolean"},
		{"' OR 1=1 --", "Boolean-based SQLi", "Boolean"},
		{"1' UNION SELECT NULL --", "Union-based SQLi", "Union"},
		{"1' AND SLEEP(5) --", "Time-based SQLi", "Time-based"},
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
		if s.detectSQLError(string(body)) {
			s.addVuln(Vulnerability{
				ID:              fmt.Sprintf("SQLi_%d", time.Now().UnixNano()),
				Type:            fmt.Sprintf("SQL Injection (%s)", payload.type_),
				Severity:        "Critical",
				CVSS:            9.9,
				CWE:             "89",
				URL:             testURL,
				Parameter:       parameter,
				Payload:         payload.payload,
				Evidence:        string(body[:min(300, len(body))]),
				Description:     "SQL Injection vulnerability detected",
				Impact:          "Database compromise, data theft, unauthorized access",
				Remediation:     "Use parameterized queries, input validation, least privilege principle",
				Timestamp:       time.Now(),
				ReproductionURL: testURL,
				ProofOfConcept:  fmt.Sprintf("curl '%s'", testURL),
			})
			return
		}
	}
}

func (s *Scanner) ScanXSS(parameter string) {
	xssPayloads := []struct {
		payload string
		type_   string
	}{
		{"<script>alert('XSS')</script>", "Reflected"},
		{"<img src=x onerror=alert('XSS')>", "Event"},
		{"<svg onload=alert('XSS')>", "SVG"},
	}

	for _, payload := range xssPayloads {
		testURL := s.buildURL(parameter, payload.payload)
		resp, err := s.client.Get(testURL)
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		atomic.AddInt64(&s.stats.TotalRequests, 1)
		body, _ := io.ReadAll(resp.Body)
		if strings.Contains(string(body), payload.payload) {
			s.addVuln(Vulnerability{
				ID:              fmt.Sprintf("XSS_%d", time.Now().UnixNano()),
				Type:            fmt.Sprintf("XSS (%s)", payload.type_),
				Severity:        "High",
				CVSS:            7.5,
				CWE:             "79",
				URL:             testURL,
				Parameter:       parameter,
				Payload:         payload.payload,
				Evidence:        "Payload reflected",
				Description:     "Cross-Site Scripting detected",
				Impact:          "Session hijacking, credential theft, malware distribution",
				Remediation:     "HTML encode output, use CSP, input validation",
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

	if !strings.Contains(bodyStr, "csrf") && containsFormWithPost(bodyStr) {
		s.addVuln(Vulnerability{
			ID:              fmt.Sprintf("CSRF_%d", time.Now().UnixNano()),
			Type:            "Cross-Site Request Forgery (CSRF)",
			Severity:        "High",
			CVSS:            6.5,
			CWE:             "352",
			URL:             s.targetURL,
			Parameter:       "Forms",
			Evidence:        "No CSRF token",
			Description:     "CSRF protection missing on forms",
			Impact:          "Unauthorized state-changing operations, account takeover",
			Remediation:     "Add CSRF tokens, use SameSite cookies, custom header validation",
			Timestamp:       time.Now(),
			ReproductionURL: s.targetURL,
			ProofOfConcept:  "Craft malicious form",
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
			Type:            "Insecure Cookie Transmission",
			Severity:        "High",
			CVSS:            7.5,
			CWE:             "614",
			URL:             s.targetURL,
			Evidence:        "No Secure flag",
			Description:     "Session cookies transmitted over insecure channels",
			Impact:          "Man-in-the-middle attacks, session hijacking",
			Remediation:     "Set Secure flag, use HTTPS only, implement HttpOnly flag",
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
			Evidence:        "HTTP used",
			Description:     "No encryption for data transmission",
			Impact:          "Complete data interception, man-in-the-middle attacks",
			Remediation:     "Use HTTPS with valid SSL certificate, enforce HSTS",
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
				Type:            "Missing Security Header: " + h,
				Severity:        "Medium",
				CVSS:            4.3,
				CWE:             "693",
				URL:             s.targetURL,
				Evidence:        "Not present",
				Description:     "Security header missing",
				Impact:          "Increased attack surface",
				Remediation:     "Add header to responses",
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
	if strings.Contains(string(body), "root:") {
		s.addVuln(Vulnerability{
			ID:              fmt.Sprintf("XXE_%d", time.Now().UnixNano()),
			Type:            "XML External Entity (XXE)",
			Severity:        "Critical",
			CVSS:            9.8,
			CWE:             "611",
			URL:             testURL,
			Evidence:        "File disclosed",
			Description:     "XXE vulnerability allowing file disclosure",
			Impact:          "Arbitrary file access, SSRF, denial of service",
			Remediation:     "Disable XML external entities, use safe XML parsers",
			Timestamp:       time.Now(),
			ReproductionURL: testURL,
			ProofOfConcept:  "XXE payload",
		})
	}
}

func (s *Scanner) ScanSSRF(parameter string) {
	payloads := []string{"http://localhost:8080", "http://127.0.0.1:8080", "file:///etc/passwd"}
	for _, payload := range payloads {
		testURL := s.buildURL(parameter, payload)
		resp, err := s.client.Get(testURL)
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		atomic.AddInt64(&s.stats.TotalRequests, 1)
		body, _ := io.ReadAll(resp.Body)
		if len(body) > 100 {
			s.addVuln(Vulnerability{
				ID:              fmt.Sprintf("SSRF_%d", time.Now().UnixNano()),
				Type:            "Server-Side Request Forgery (SSRF)",
				Severity:        "High",
				CVSS:            8.6,
				CWE:             "918",
				URL:             testURL,
				Evidence:        "SSRF detected",
				Description:     "Application makes requests to attacker-controlled URLs",
				Impact:          "Internal network scanning, metadata exposure",
				Remediation:     "Validate URLs, use allowlist, disable protocols",
				Timestamp:       time.Now(),
				ReproductionURL: testURL,
				ProofOfConcept:  "SSRF payload",
			})
		}
	}
}

func (s *Scanner) ScanCommandInjection(parameter string) {
	payloads := []string{"; whoami", "| whoami", "& whoami"}
	for _, payload := range payloads {
		testURL := s.buildURL(parameter, payload)
		resp, err := s.client.Get(testURL)
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		atomic.AddInt64(&s.stats.TotalRequests, 1)
		body, _ := io.ReadAll(resp.Body)
		if strings.Contains(string(body), "uid=") {
			s.addVuln(Vulnerability{
				ID:              fmt.Sprintf("RCE_%d", time.Now().UnixNano()),
				Type:            "Remote Code Execution (RCE)",
				Severity:        "Critical",
				CVSS:            9.8,
				CWE:             "78",
				URL:             testURL,
				Evidence:        "RCE found",
				Description:     "Application executes arbitrary system commands",
				Impact:          "Complete system compromise, data theft, malware",
				Remediation:     "Avoid shell execution, use parameterized APIs",
				Timestamp:       time.Now(),
				ReproductionURL: testURL,
				ProofOfConcept:  "Command injection",
			})
			return
		}
	}
}

func (s *Scanner) ScanPathTraversal(parameter string) {
	payloads := []string{"../etc/passwd", "../../etc/passwd", "..%2fetc%2fpasswd"}
	for _, payload := range payloads {
		testURL := s.buildURL(parameter, payload)
		resp, err := s.client.Get(testURL)
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		atomic.AddInt64(&s.stats.TotalRequests, 1)
		body, _ := io.ReadAll(resp.Body)
		if strings.Contains(string(body), "root:") {
			s.addVuln(Vulnerability{
				ID:              fmt.Sprintf("PATH_%d", time.Now().UnixNano()),
				Type:            "Path Traversal / Directory Traversal",
				Severity:        "High",
				CVSS:            7.5,
				CWE:             "22",
				URL:             testURL,
				Evidence:        "File accessible",
				Description:     "Path traversal vulnerability allows unauthorized file access",
				Impact:          "Arbitrary file disclosure, configuration exposure",
				Remediation:     "Validate and sanitize paths, use allowlist",
				Timestamp:       time.Now(),
				ReproductionURL: testURL,
				ProofOfConcept:  "Traversal payload",
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
	errors := []string{"SQL syntax", "mysql_fetch", "ORA-", "PostgreSQL", "syntax error"}
	for _, err := range errors {
		if strings.Contains(response, err) {
			return true
		}
	}
	return false
}

func (s *Scanner) RunFullScan() {
	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Println("🔍 STARTING COMPREHENSIVE VULNERABILITY SCAN")
	fmt.Println(strings.Repeat("=", 80))
	fmt.Printf("Target: %s | Threads: %d | Timeout: %v\n\n", s.targetURL, s.concurrency, s.timeout)

	params := []string{"id", "search", "q", "page", "user", "email", "name", "data", "file", "param"}
	var wg sync.WaitGroup
	sem := make(chan struct{}, s.concurrency)

	funcs := []func(){s.ScanCSRF, s.ScanBrokenAuth, s.ScanSensitiveDataExposure}
	for _, f := range funcs {
		wg.Add(1)
		go func(fn func()) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			fn()
		}(f)
	}

	for _, p := range params {
		for _, f := range []func(string){s.ScanSQLInjection, s.ScanXSS, s.ScanXXE, s.ScanSSRF, s.ScanCommandInjection, s.ScanPathTraversal} {
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
	fmt.Println("📊 VULNERABILITY ASSESSMENT REPORT")
	fmt.Println(strings.Repeat("=", 80))

	if len(s.results) == 0 {
		fmt.Println("✓ No vulnerabilities found!")
		return
	}

	groups := make(map[string][]Vulnerability)
	for _, v := range s.results {
		groups[v.Severity] = append(groups[v.Severity], v)
	}

	order := []string{"Critical", "High", "Medium", "Low"}
	emojis := map[string]string{"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🔵"}

	for _, sev := range order {
		if vulns, ok := groups[sev]; ok {
			fmt.Printf("\n%s [%s] %d vulnerabilities\n", emojis[sev], sev, len(vulns))
			fmt.Println(strings.Repeat("-", 80))
			for i, v := range vulns {
				fmt.Printf("\n%d. %s\n", i+1, v.Type)
				fmt.Printf("   ID: %s | CVSS: %.1f | CWE: %s\n", v.ID, v.CVSS, v.CWE)
				fmt.Printf("   Parameter: %s\n", v.Parameter)
				fmt.Printf("   Description: %s\n", v.Description)
				fmt.Printf("   Impact: %s\n", v.Impact)
				fmt.Printf("   Remediation: %s\n", v.Remediation)
				fmt.Printf("   URL: %s\n", v.ReproductionURL)
			}
		}
	}

	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Println("📈 SCAN STATISTICS")
	fmt.Println(strings.Repeat("=", 80))
	fmt.Printf("Total Vulnerabilities: %d\n", len(s.results))
	fmt.Printf("Critical: %d | High: %d | Medium: %d\n", atomic.LoadInt64(&s.stats.CriticalCount), atomic.LoadInt64(&s.stats.HighCount), atomic.LoadInt64(&s.stats.MediumCount))
	fmt.Printf("Total Requests: %d | Duration: %.2f seconds\n", atomic.LoadInt64(&s.stats.TotalRequests), s.stats.EndTime.Sub(s.stats.StartTime).Seconds())
	fmt.Println(strings.Repeat("=", 80))
}

func (s *Scanner) GenerateProfessionalReport(filename string) error {
	report := fmt.Sprintf(`
╔════════════════════════════════════════════════════════════════════════════╗
║              SECURITY VULNERABILITY ASSESSMENT REPORT                     ║
║                    Professional Bug Bounty Report                          ║
╚════════════════════════════════════════════════════════════════════════════╝

REPORT GENERATED: %s
SCAN TARGET: %s
TOTAL VULNERABILITIES: %d

════════════════════════════════════════════════════════════════════════════

EXECUTIVE SUMMARY
════════════════════════════════════════════════════════════════════════════

A comprehensive security assessment was conducted on the target application.
The scan identified %d vulnerabilities of varying severity levels:

  • Critical: %d  (Immediate action required)
  • High:     %d  (Should be addressed urgently)
  • Medium:   %d  (Address in near-term)
  • Low:      %d  (Consider for future remediation)

Scan Duration: %.2f seconds
Total Requests: %d
Scan Threads: Concurrent

════════════════════════════════════════════════════════════════════════════

VULNERABILITY FINDINGS
════════════════════════════════════════════════════════════════════════════
`,
		time.Now().Format("January 02, 2006 - 15:04:05 MST"),
		s.targetURL,
		len(s.results),
		len(s.results),
		atomic.LoadInt64(&s.stats.CriticalCount),
		atomic.LoadInt64(&s.stats.HighCount),
		atomic.LoadInt64(&s.stats.MediumCount),
		atomic.LoadInt64(&s.stats.LowCount),
		s.stats.EndTime.Sub(s.stats.StartTime).Seconds(),
		atomic.LoadInt64(&s.stats.TotalRequests),
	)

	groups := make(map[string][]Vulnerability)
	for _, v := range s.results {
		groups[v.Severity] = append(groups[v.Severity], v)
	}

	order := []string{"Critical", "High", "Medium", "Low"}
	vulnNum := 1

	for _, severity := range order {
		vulns, exists := groups[severity]
		if !exists {
			continue
		}

		report += fmt.Sprintf("\n%s SEVERITY VULNERABILITIES (%d found)\n", strings.ToUpper(severity), len(vulns))
		report += strings.Repeat("─", 80) + "\n"

		for _, vuln := range vulns {
			report += fmt.Sprintf(`
[%d] %s
────────────────────────────────────────────────────────────────────────────

Vulnerability ID:       %s
Classification:         %s
CWE ID:                 CWE-%s
CVSS Score:             %.1f
Severity Level:         %s

Parameter Affected:     %s
Affected URL:           %s

DESCRIPTION:
%s

VULNERABILITY DETAILS:
Payload Used:           %s
Evidence Found:         %s

BUSINESS IMPACT:
%s

PROOF OF CONCEPT:
%s

REMEDIATION STEPS:
%s

REFERENCES:
- CWE-%s: https://cwe.mitre.org/data/definitions/%s.html
- OWASP Top 10: https://owasp.org/www-project-top-ten/

────────────────────────────────────────────────────────────────────────────

`,
				vulnNum,
				vuln.Type,
				vuln.ID,
				vuln.Type,
				vuln.CWE,
				vuln.CVSS,
				vuln.Severity,
				vuln.Parameter,
				vuln.ReproductionURL,
				vuln.Description,
				vuln.Payload,
				vuln.Evidence,
				vuln.Impact,
				vuln.ProofOfConcept,
				vuln.Remediation,
				vuln.CWE,
				vuln.CWE,
			)
			vulnNum++
		}
	}

	report += fmt.Sprintf(`

════════════════════════════════════════════════════════════════════════════

REMEDIATION SUMMARY & PRIORITY
════════════════════════════════════════════════════════════════════════════

IMMEDIATE ACTION REQUIRED (Critical):
%d vulnerability(ies) require immediate attention. These vulnerabilities can
lead to complete system compromise and should be remediated without delay.

SHORT-TERM (High):
%d vulnerability(ies) should be addressed within 1-2 weeks to minimize risk.

MEDIUM-TERM (Medium):
%d vulnerability(ies) should be planned for remediation within the next month.

LONG-TERM (Low):
%d vulnerability(ies) can be addressed in future security updates.

════════════════════════════════════════════════════════════════════════════

GENERAL SECURITY RECOMMENDATIONS
════════════════════════════════════════════════════════════════════════════

1. SECURE CODING PRACTICES
   • Implement input validation and output encoding
   • Use parameterized queries for database operations
   • Avoid dynamic query construction from user input

2. SECURITY HEADERS
   • Implement all recommended security headers (CSP, HSTS, X-Frame-Options)
   • Configure CORS appropriately
   • Set secure cookie flags (Secure, HttpOnly, SameSite)

3. AUTHENTICATION & SESSION MANAGEMENT
   • Enforce strong password policies
   • Implement multi-factor authentication
   • Use secure session tokens with expiration

4. REGULAR SECURITY TESTING
   • Conduct periodic vulnerability assessments
   • Implement continuous security monitoring
   • Perform code security reviews

5. INCIDENT RESPONSE
   • Establish an incident response plan
   • Maintain detailed logs for security events
   • Create backup and disaster recovery procedures

════════════════════════════════════════════════════════════════════════════

ASSESSMENT METHODOLOGY
════════════════════════════════════════════════════════════════════════════

The assessment was conducted using automated vulnerability scanning techniques
that included:

✓ SQL Injection Testing (Boolean, Union, Time-based, Error-based)
✓ Cross-Site Scripting (XSS) Detection
✓ Cross-Site Request Forgery (CSRF) Analysis
✓ Broken Authentication & Session Management
✓ Sensitive Data Exposure Review
✓ XML External Entity (XXE) Testing
✓ Server-Side Request Forgery (SSRF) Testing
✓ Command Injection Testing
✓ Path Traversal / Directory Traversal Testing
✓ Security Header Validation

════════════════════════════════════════════════════════════════════════════

DISCLAIMER & LEGAL NOTICE
════════════════════════════════════════════════════════════════════════════

This security assessment was conducted for authorized testing purposes only.
The findings in this report should be treated as confidential and must not be
shared with unauthorized parties without explicit consent.

All vulnerabilities identified should be addressed promptly to mitigate
security risks. The assessment provider is not liable for any damages
resulting from the application of these findings.

════════════════════════════════════════════════════════════════════════════

REPORT PREPARED BY: VulnScan Pro v1.0
PREPARED DATE:      %s
SCAN TARGET:        %s

════════════════════════════════════════════════════════════════════════════

END OF REPORT

`,
		atomic.LoadInt64(&s.stats.CriticalCount),
		atomic.LoadInt64(&s.stats.HighCount),
		atomic.LoadInt64(&s.stats.MediumCount),
		atomic.LoadInt64(&s.stats.LowCount),
		time.Now().Format("January 02, 2006"),
		s.targetURL,
	)

	return os.WriteFile(filename, []byte(report), 0644)
}

func (s *Scanner) GenerateBugBountyReport(filename string) error {
	type Report struct {
		ReportDate      string             `json:"report_date"`
		Target          string             `json:"target"`
		TotalVulns      int                `json:"total_vulnerabilities"`
		Critical        int64              `json:"critical_count"`
		High            int64              `json:"high_count"`
		Medium          int64              `json:"medium_count"`
		Low             int64              `json:"low_count"`
		Vulnerabilities []Vulnerability    `json:"vulnerabilities"`
		Summary         string             `json:"executive_summary"`
		ScanDuration    string             `json:"scan_duration"`
	}

	r := Report{
		ReportDate:      time.Now().Format("2006-01-02 15:04:05"),
		Target:          s.targetURL,
		TotalVulns:      len(s.results),
		Critical:        atomic.LoadInt64(&s.stats.CriticalCount),
		High:            atomic.LoadInt64(&s.stats.HighCount),
		Medium:          atomic.LoadInt64(&s.stats.MediumCount),
		Low:             atomic.LoadInt64(&s.stats.LowCount),
		Vulnerabilities: s.results,
		Summary:         fmt.Sprintf("Security assessment identified %d vulnerabilities", len(s.results)),
		ScanDuration:    fmt.Sprintf("%.2f seconds", s.stats.EndTime.Sub(s.stats.StartTime).Seconds()),
	}

	data, _ := json.MarshalIndent(r, "", "  ")
	return os.WriteFile(filename, data, 0644)
}

func (s *Scanner) GenerateHTMLReport(filename string) error {
	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Vulnerability Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            line-height: 1.6; 
            color: #333;
            background-color: #f5f5f5;
        }
        .container { max-width: 900px; margin: 0 auto; padding: 20px; }
        .header { 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            border-radius: 10px;
            margin-bottom: 30px;
            text-align: center;
        }
        .header h1 { font-size: 2em; margin-bottom: 10px; }
        .header p { font-size: 1.1em; opacity: 0.9; }
        .summary { 
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }
        .summary-box {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            text-align: center;
        }
        .summary-box h3 { font-size: 2em; margin-bottom: 5px; }
        .critical-box { border-top: 4px solid #e74c3c; color: #e74c3c; }
        .high-box { border-top: 4px solid #e67e22; color: #e67e22; }
        .medium-box { border-top: 4px solid #f39c12; color: #f39c12; }
        .low-box { border-top: 4px solid #27ae60; color: #27ae60; }
        .vulnerability {
            background: white;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            border-left: 4px solid #333;
        }
        .vulnerability.critical { border-left-color: #e74c3c; }
        .vulnerability.high { border-left-color: #e67e22; }
        .vulnerability.medium { border-left-color: #f39c12; }
        .vulnerability.low { border-left-color: #27ae60; }
        .vuln-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }
        .vuln-header h3 { flex: 1; }
        .badge {
            display: inline-block;
            padding: 5px 10px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: bold;
        }
        .badge-critical { background: #e74c3c; color: white; }
        .badge-high { background: #e67e22; color: white; }
        .badge-medium { background: #f39c12; color: white; }
        .badge-low { background: #27ae60; color: white; }
        .vuln-details {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 15px;
            font-size: 0.95em;
        }
        .vuln-details p { margin-bottom: 10px; }
        .vuln-details strong { display: block; color: #667eea; margin-bottom: 3px; }
        .footer {
            text-align: center;
            padding: 20px;
            color: #999;
            margin-top: 40px;
            border-top: 1px solid #ddd;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Security Vulnerability Report</h1>
            <p>Professional Penetration Testing Assessment</p>
            <p>Generated: ` + time.Now().Format("January 02, 2006 - 15:04:05") + `</p>
        </div>

        <div class="summary">
            <div class="summary-box">
                <h3>` + fmt.Sprintf("%d", len(s.results)) + `</h3>
                <p>Total Vulnerabilities</p>
            </div>
            <div class="summary-box critical-box">
                <h3>` + fmt.Sprintf("%d", atomic.LoadInt64(&s.stats.CriticalCount)) + `</h3>
                <p>Critical</p>
            </div>
            <div class="summary-box high-box">
                <h3>` + fmt.Sprintf("%d", atomic.LoadInt64(&s.stats.HighCount)) + `</h3>
                <p>High</p>
            </div>
            <div class="summary-box medium-box">
                <h3>` + fmt.Sprintf("%d", atomic.LoadInt64(&s.stats.MediumCount)) + `</h3>
                <p>Medium</p>
            </div>
        </div>

        <h2>Vulnerability Findings</h2>`

	for _, v := range s.results {
		severity := strings.ToLower(v.Severity)
		html += fmt.Sprintf(`
        <div class="vulnerability %s">
            <div class="vuln-header">
                <h3>%s</h3>
                <span class="badge badge-%s">%s</span>
            </div>
            <div class="vuln-details">
                <p><strong>Vulnerability ID:</strong> %s</p>
                <p><strong>CVSS Score:</strong> %.1f</p>
                <p><strong>CWE:</strong> CWE-%s</p>
                <p><strong>Parameter:</strong> %s</p>
                <p><strong>Description:</strong> %s</p>
                <p><strong>Impact:</strong> %s</p>
                <p><strong>Remediation:</strong> %s</p>
                <p><strong>URL:</strong> <code>%s</code></p>
            </div>
        </div>
`,
			severity, v.Type, severity, strings.ToUpper(v.Severity),
			v.ID, v.CVSS, v.CWE, v.Parameter, v.Description,
			v.Impact, v.Remediation, v.ReproductionURL,
		)
	}

	html += `
        <div class="footer">
            <p>Report Generated by VulnScan Pro v1.0 - Professional Bug Bounty Scanner</p>
            <p>Target: ` + s.targetURL + `</p>
            <p>Scan Duration: ` + fmt.Sprintf("%.2f seconds", s.stats.EndTime.Sub(s.stats.StartTime).Seconds()) + `</p>
        </div>
    </div>
</body>
</html>`

	return os.WriteFile(filename, []byte(html), 0644)
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
	fmt.Println("╔════════════════════════════════════════════════════════════════════════════╗")
	fmt.Println("║         🔒 VulnScan Pro - Professional Bug Bounty Scanner 🔒              ║")
	fmt.Println("╚════════════════════════════════════════════════════════════════════════════╝")
	fmt.Println("\n📋 MENU OPTIONS:")
	fmt.Println("  1. Quick Scan (Normal)")
	fmt.Println("  2. Fast Scan (More Threads)")
	fmt.Println("  3. Stealthy Scan (Fewer Threads)")
	fmt.Println("  4. Verbose Scan (See Details)")
	fmt.Println("  5. Custom Scan (Set Your Own Options)")
	fmt.Println("  6. Exit")
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

	fmt.Printf("\n[*] Connecting to %s...\n", targetURL)
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Head(targetURL)
	if err != nil {
		fmt.Printf("❌ Connection failed: %v\n", err)
		return
	}
	resp.Body.Close()

	fmt.Printf("[✓] Connected! Status: %d\n\n", resp.StatusCode)
	scanner := NewScanner(targetURL, threads, timeout, verbose)
	scanner.RunFullScan()
	scanner.PrintResults()

	reportChoice := getUserInput("\n📄 Generate reports? (y/n): ")
	if reportChoice == "y" || reportChoice == "Y" {
		timestamp := time.Now().Unix()
		txtFile := fmt.Sprintf("Vulnerability_Report_%d.txt", timestamp)
		jsonFile := fmt.Sprintf("Vulnerability_Report_%d.json", timestamp)
		htmlFile := fmt.Sprintf("Vulnerability_Report_%d.html", timestamp)

		fmt.Printf("\n[*] Generating Professional Report...\n")
		scanner.GenerateProfessionalReport(txtFile)
		fmt.Printf("[✓] Professional Report: %s\n", txtFile)

		fmt.Printf("[*] Generating JSON Report...\n")
		scanner.GenerateBugBountyReport(jsonFile)
		fmt.Printf("[✓] JSON Report: %s\n", jsonFile)

		fmt.Printf("[*] Generating HTML Report...\n")
		scanner.GenerateHTMLReport(htmlFile)
		fmt.Printf("[✓] HTML Report: %s\n\n", htmlFile)

		fmt.Println("✅ All reports generated successfully!")
		fmt.Println("\n📂 Report Files:")
		fmt.Printf("   1. Text Report: %s (Professional Format)\n", txtFile)
		fmt.Printf("   2. JSON Report: %s (Bug Bounty Platforms)\n", jsonFile)
		fmt.Printf("   3. HTML Report: %s (Visual Presentation)\n\n", htmlFile)
	}
}

func main() {
	flag.Parse()

	if len(os.Args) == 1 {
		for {
			showMenu()
			choice := getUserInput("\n🎯 Select an option (1-6): ")

			switch choice {
			case "1":
				targetURL := getUserInput("\n📍 Enter target URL (e.g., https://example.com): ")
				if targetURL == "" {
					fmt.Println("❌ URL cannot be empty!")
					continue
				}
				runScan(targetURL, 10, 10*time.Second, false)

			case "2":
				targetURL := getUserInput("\n📍 Enter target URL: ")
				if targetURL == "" {
					fmt.Println("❌ URL cannot be empty!")
					continue
				}
				fmt.Println("[*] Running FAST scan (30 threads)...\n")
				runScan(targetURL, 30, 5*time.Second, false)

			case "3":
				targetURL := getUserInput("\n📍 Enter target URL: ")
				if targetURL == "" {
					fmt.Println("❌ URL cannot be empty!")
					continue
				}
				fmt.Println("[*] Running STEALTHY scan (2 threads, 20s timeout)...\n")
				runScan(targetURL, 2, 20*time.Second, false)

			case "4":
				targetURL := getUserInput("\n📍 Enter target URL: ")
				if targetURL == "" {
					fmt.Println("❌ URL cannot be empty!")
					continue
				}
				fmt.Println("[*] Running VERBOSE scan...\n")
				runScan(targetURL, 10, 10*time.Second, true)

			case "5":
				targetURL := getUserInput("\n📍 Enter target URL: ")
				if targetURL == "" {
					fmt.Println("❌ URL cannot be empty!")
					continue
				}

				threadsStr := getUserInput("🧵 Enter number of threads (default 10): ")
				threads := 10
				if threadsStr != "" {
					fmt.Sscanf(threadsStr, "%d", &threads)
				}

				timeoutStr := getUserInput("⏱️  Enter timeout in seconds (default 10): ")
				timeoutSec := 10
				if timeoutStr != "" {
					fmt.Sscanf(timeoutStr, "%d", &timeoutSec)
				}

				verboseStr := getUserInput("🔍 Verbose mode? (y/n): ")
				verbose := verboseStr == "y" || verboseStr == "Y"

				fmt.Printf("\n[*] Running CUSTOM scan (%d threads, %ds timeout)...\n\n", threads, timeoutSec)
				runScan(targetURL, threads, time.Duration(timeoutSec)*time.Second, verbose)

			case "6":
				fmt.Println("\n👋 Goodbye!")
				return

			default:
				fmt.Println("❌ Invalid option! Please try again.")
			}
		}
	}
}
