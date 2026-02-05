package fort

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// ReportGenerator generates structured analysis reports
type ReportGenerator struct {
	llm    *OpenAILLMClient
	config ReportConfig
}

// ReportProgressFn receives live phase progress updates during report generation.
type ReportProgressFn func(phase int, name string)

// ReportConfig configures report generation
type ReportConfig struct {
	IncludeFunctions  bool
	IncludeClasses    bool
	DetailedSecurity  bool
	CheckDependencies bool
}

// DefaultReportConfig returns default report configuration
func DefaultReportConfig() ReportConfig {
	return ReportConfig{
		IncludeFunctions:  true,
		IncludeClasses:    true,
		DetailedSecurity:  true,
		CheckDependencies: true,
	}
}

// NewReportGenerator creates a new report generator
func NewReportGenerator(llm *OpenAILLMClient, config ReportConfig) *ReportGenerator {
	return &ReportGenerator{
		llm:    llm,
		config: config,
	}
}

// GenerateReport generates a comprehensive analysis report
func (rg *ReportGenerator) GenerateReport(ctx context.Context, code string, opts ReportOptions) (*AnalysisReport, error) {
	return rg.GenerateReportWithProgress(ctx, code, opts, nil)
}

// GenerateReportWithProgress generates a report and emits phase progress updates.
func (rg *ReportGenerator) GenerateReportWithProgress(
	ctx context.Context,
	code string,
	opts ReportOptions,
	progress ReportProgressFn,
) (*AnalysisReport, error) {
	reportID := fmt.Sprintf("report_%d", time.Now().UnixNano())
	report := NewAnalysisReport(reportID)

	// Set input metadata
	report.Input = rg.buildInputMetadata(code, opts)

	// Phase 1: Code structure analysis
	rg.emitProgress(progress, 1, "Code structure analysis")
	codeAnalysis, err := rg.analyzeCodeStructure(ctx, code, opts)
	if err != nil {
		return nil, fmt.Errorf("code analysis failed: %w", err)
	}
	report.Code = *codeAnalysis

	// Phase 2: Security assessment
	rg.emitProgress(progress, 2, "Security assessment")
	securityAssessment, err := rg.analyzeSecurityWithPatterns(ctx, code, codeAnalysis)
	if err != nil {
		return nil, fmt.Errorf("security analysis failed: %w", err)
	}
	report.Security = *securityAssessment

	// Phase 3: Capability detection
	rg.emitProgress(progress, 3, "Capability detection")
	report.Capabilities = rg.detectCapabilities(code, codeAnalysis)

	// Phase 4: Dependency analysis
	rg.emitProgress(progress, 4, "Dependency analysis")
	report.Dependencies = rg.analyzeDependencies(codeAnalysis)

	// Phase 5: Execution recommendations
	rg.emitProgress(progress, 5, "Generating recommendations")
	report.Execution = rg.generateExecutionRecommendations(report)

	// Phase 6: Summary
	rg.emitProgress(progress, 6, "Summary generation")
	report.Summary = rg.generateSummary(report)

	return report, nil
}

func (rg *ReportGenerator) emitProgress(progress ReportProgressFn, phase int, name string) {
	if progress != nil {
		progress(phase, name)
	}
}

// ReportOptions contains options for report generation
type ReportOptions struct {
	Language string
	Purpose  string
}

func (rg *ReportGenerator) buildInputMetadata(code string, opts ReportOptions) ReportInput {
	hash := sha256.Sum256([]byte(code))
	lines := strings.Split(code, "\n")

	return ReportInput{
		SourceType: "inline",
		Language:   opts.Language,
		Purpose:    opts.Purpose,
		CodeSize:   len(code),
		LineCount:  len(lines),
		SHA256:     hex.EncodeToString(hash[:]),
	}
}

func (rg *ReportGenerator) analyzeCodeStructure(ctx context.Context, code string, opts ReportOptions) (*CodeAnalysis, error) {
	systemPrompt := `You are an expert code analyzer. Analyze the provided code and return a detailed JSON analysis.

Return ONLY a valid JSON object with this exact structure:
{
  "detected_language": "string - programming language",
  "language_version": "string - version if detectable, empty otherwise",
  "confidence": 0.95,
  "frameworks": ["list of frameworks/libraries used"],
  "entry_points": [
    {"name": "main", "type": "function|class|script", "location": "line X", "recommended": true}
  ],
  "functions": [
    {"name": "func_name", "parameters": ["param1", "param2"], "returns": "return_type", "location": "line X", "is_async": false}
  ],
  "classes": [
    {"name": "ClassName", "bases": ["BaseClass"], "methods": ["method1", "method2"], "location": "line X"}
  ],
  "imports": [
    {"module": "module_name", "alias": "alias_if_any", "items": ["imported_items"], "location": "line X", "is_stdlib": true}
  ],
  "complexity": {
    "level": "trivial|simple|moderate|complex|extreme",
    "score": 25,
    "cyclomatic_estimate": 5,
    "lines_of_code": 50,
    "comment_ratio": 0.1,
    "estimated_runtime": "< 1 second"
  },
  "summary": "Brief description of what the code does",
  "inferred_purpose": "What the code is trying to accomplish"
}

Be precise and thorough. Return ONLY the JSON, no markdown or explanation.`

	userPrompt := fmt.Sprintf("Analyze this code:\n\n```\n%s\n```", code)
	if opts.Language != "" {
		userPrompt += fmt.Sprintf("\n\nLanguage hint: %s", opts.Language)
	}
	if opts.Purpose != "" {
		userPrompt += fmt.Sprintf("\n\nStated purpose: %s", opts.Purpose)
	}

	content, err := rg.llm.generateText(ctx, systemPrompt, userPrompt, true)
	if err != nil {
		return nil, fmt.Errorf("LLM request failed: %w", err)
	}
	content = extractJSON(content)

	var result CodeAnalysis
	if err := json.Unmarshal([]byte(content), &result); err != nil {
		return nil, fmt.Errorf("failed to parse LLM response: %w", err)
	}

	return &result, nil
}

func (rg *ReportGenerator) analyzeSecurityWithPatterns(ctx context.Context, code string, codeAnalysis *CodeAnalysis) (*SecurityAssessment, error) {
	assessment := &SecurityAssessment{
		Findings: []SecurityIssue{},
		Patterns: PatternAnalysis{},
	}

	// Static pattern analysis first
	rg.runPatternAnalysis(code, assessment)

	// Obfuscation detection
	assessment.Obfuscation = rg.detectObfuscation(code)

	// LLM-based security analysis
	llmFindings, err := rg.llmSecurityAnalysis(ctx, code, codeAnalysis)
	if err != nil {
		// Don't fail entirely, just use pattern-based results
		assessment.Confidence = 0.5
	} else {
		// Merge LLM findings
		assessment.Findings = append(assessment.Findings, llmFindings...)
		assessment.Confidence = 0.85
	}

	// Calculate risk
	assessment.RiskLevel, assessment.RiskScore = rg.calculateRisk(assessment)
	assessment.Safe = assessment.RiskLevel == "none" || assessment.RiskLevel == "low"

	// Generate mitigations
	assessment.Mitigations = rg.generateMitigations(assessment)

	return assessment, nil
}

func (rg *ReportGenerator) runPatternAnalysis(code string, assessment *SecurityAssessment) {
	patterns := []struct {
		category string
		patterns []struct {
			regex    string
			severity string
			title    string
			cwe      string
		}
	}{
		{
			category: "command_execution",
			patterns: []struct {
				regex    string
				severity string
				title    string
				cwe      string
			}{
				{`os\.system\s*\(`, "high", "OS system command execution", "CWE-78"},
				{`subprocess\.(call|run|Popen)\s*\(`, "high", "Subprocess execution", "CWE-78"},
				{`exec\s*\(`, "high", "Exec function call", "CWE-78"},
				{`child_process\.(exec|spawn)`, "high", "Child process execution", "CWE-78"},
				{`Runtime\.getRuntime\(\)\.exec`, "high", "Java runtime exec", "CWE-78"},
			},
		},
		{
			category: "code_injection",
			patterns: []struct {
				regex    string
				severity string
				title    string
				cwe      string
			}{
				{`eval\s*\(`, "critical", "Eval function - code injection risk", "CWE-94"},
				{`exec\s*\(.*input|exec\s*\(.*request`, "critical", "Dynamic code execution with user input", "CWE-94"},
				{`Function\s*\(`, "high", "Dynamic function constructor", "CWE-94"},
				{`__import__\s*\(`, "medium", "Dynamic import", "CWE-94"},
				{`compile\s*\(.*exec`, "high", "Compile and execute pattern", "CWE-94"},
			},
		},
		{
			category: "network_access",
			patterns: []struct {
				regex    string
				severity string
				title    string
				cwe      string
			}{
				{`socket\.socket\s*\(`, "medium", "Raw socket creation", "CWE-284"},
				{`requests\.(get|post|put|delete)\s*\(`, "low", "HTTP request", ""},
				{`urllib\.request|http\.client`, "low", "HTTP client usage", ""},
				{`fetch\s*\(`, "low", "Fetch API call", ""},
				{`WebSocket\s*\(`, "medium", "WebSocket connection", ""},
			},
		},
		{
			category: "filesystem_access",
			patterns: []struct {
				regex    string
				severity string
				title    string
				cwe      string
			}{
				{`open\s*\([^)]*['"][wa]`, "medium", "File write operation", "CWE-73"},
				{`rm\s+-rf|rmdir|unlink`, "high", "File deletion", "CWE-73"},
				{`/etc/passwd|/etc/shadow`, "critical", "Sensitive file access", "CWE-200"},
				{`\.ssh/|id_rsa|authorized_keys`, "critical", "SSH key access", "CWE-200"},
				{`chmod\s+[0-7]*7`, "high", "Permission modification", "CWE-732"},
			},
		},
		{
			category: "reverse_shell",
			patterns: []struct {
				regex    string
				severity string
				title    string
				cwe      string
			}{
				{`/dev/tcp/`, "critical", "Bash reverse shell pattern", "CWE-506"},
				{`nc\s+-[el]|ncat\s+-[el]|netcat`, "critical", "Netcat reverse shell", "CWE-506"},
				{`bash\s+-i\s+>&`, "critical", "Interactive bash redirect", "CWE-506"},
				{`python.*socket.*connect.*sh`, "critical", "Python reverse shell pattern", "CWE-506"},
				{`pty\.spawn`, "high", "PTY spawn - potential shell", "CWE-506"},
			},
		},
		{
			category: "crypto_mining",
			patterns: []struct {
				regex    string
				severity string
				title    string
				cwe      string
			}{
				{`stratum\+tcp://|stratum://`, "critical", "Crypto mining pool connection", ""},
				{`xmrig|cpuminer|minerd`, "critical", "Crypto miner binary", ""},
				{`hashrate|mining.*pool`, "high", "Mining-related terms", ""},
				{`coinhive|cryptonight`, "critical", "Known mining service", ""},
			},
		},
	}

	issueID := 1
	for _, cat := range patterns {
		for _, p := range cat.patterns {
			re := regexp.MustCompile(`(?i)` + p.regex)
			matches := re.FindAllStringIndex(code, -1)
			for _, match := range matches {
				lineNum := strings.Count(code[:match[0]], "\n") + 1
				evidence := code[match[0]:min(match[1]+20, len(code))]
				if len(evidence) > 50 {
					evidence = evidence[:50] + "..."
				}

				issue := SecurityIssue{
					ID:          fmt.Sprintf("SEC-%03d", issueID),
					Category:    cat.category,
					Severity:    p.severity,
					Title:       p.title,
					Description: fmt.Sprintf("Pattern detected: %s", p.regex),
					Location:    fmt.Sprintf("line %d", lineNum),
					LineNumber:  lineNum,
					Evidence:    strings.TrimSpace(evidence),
					CWE:         p.cwe,
				}
				assessment.Findings = append(assessment.Findings, issue)

				// Add to pattern matches
				pm := PatternMatch{
					Pattern:    p.regex,
					Match:      evidence,
					Location:   fmt.Sprintf("line %d", lineNum),
					LineNumber: lineNum,
					Severity:   p.severity,
				}
				switch cat.category {
				case "command_execution":
					assessment.Patterns.CommandExecution = append(assessment.Patterns.CommandExecution, pm)
				case "code_injection":
					assessment.Patterns.CodeInjection = append(assessment.Patterns.CodeInjection, pm)
				case "network_access":
					assessment.Patterns.NetworkAccess = append(assessment.Patterns.NetworkAccess, pm)
				case "filesystem_access":
					assessment.Patterns.FileSystemAccess = append(assessment.Patterns.FileSystemAccess, pm)
				case "reverse_shell":
					assessment.Patterns.ReverseShell = append(assessment.Patterns.ReverseShell, pm)
				case "crypto_mining":
					assessment.Patterns.CryptoOperations = append(assessment.Patterns.CryptoOperations, pm)
				}
				issueID++
			}
		}
	}
}

func (rg *ReportGenerator) detectObfuscation(code string) ObfuscationAnalysis {
	result := ObfuscationAnalysis{}

	// Calculate entropy
	result.Entropy = calculateEntropy(code)

	// Check indicators
	if result.Entropy > 5.5 {
		result.Indicators = append(result.Indicators, "High entropy content")
	}

	// Hex encoding
	hexPattern := regexp.MustCompile(`\\x[0-9a-fA-F]{2}`)
	if len(hexPattern.FindAllString(code, -1)) > 10 {
		result.Indicators = append(result.Indicators, "Hex-encoded strings")
		result.EncodingTypes = append(result.EncodingTypes, "hex")
	}

	// Base64 patterns
	b64Pattern := regexp.MustCompile(`[A-Za-z0-9+/]{40,}={0,2}`)
	if len(b64Pattern.FindAllString(code, -1)) > 2 {
		result.Indicators = append(result.Indicators, "Base64-encoded content")
		result.EncodingTypes = append(result.EncodingTypes, "base64")
	}

	// Very long lines
	for _, line := range strings.Split(code, "\n") {
		if len(line) > 500 {
			result.Indicators = append(result.Indicators, "Very long lines (minified/obfuscated)")
			break
		}
	}

	// Unusual variable names
	varPattern := regexp.MustCompile(`\b[_O0Il]{5,}\b`)
	if len(varPattern.FindAllString(code, -1)) > 3 {
		result.Indicators = append(result.Indicators, "Confusing variable names")
	}

	result.IsObfuscated = len(result.Indicators) >= 2
	result.Confidence = float64(len(result.Indicators)) / 5.0
	if result.Confidence > 1.0 {
		result.Confidence = 1.0
	}

	return result
}

func (rg *ReportGenerator) llmSecurityAnalysis(ctx context.Context, code string, codeAnalysis *CodeAnalysis) ([]SecurityIssue, error) {
	systemPrompt := `You are an expert security analyst. Analyze the code for security vulnerabilities.

Return ONLY a JSON array of security findings:
[
  {
    "category": "category_name",
    "severity": "info|low|medium|high|critical",
    "title": "Brief title",
    "description": "Detailed description of the issue",
    "location": "line number or function name",
    "evidence": "Code snippet showing the issue",
    "cwe": "CWE-XXX if applicable",
    "mitigation": "How to fix or mitigate"
  }
]

Categories: command_injection, code_injection, sql_injection, xss, path_traversal,
insecure_deserialization, hardcoded_secrets, weak_crypto, race_condition,
buffer_overflow, integer_overflow, use_after_free, resource_leak, dos

Return empty array [] if no issues found. Return ONLY the JSON array.`

	userPrompt := fmt.Sprintf("Security analysis for %s code:\n\n```\n%s\n```", codeAnalysis.DetectedLanguage, code)

	content, err := rg.llm.generateText(ctx, systemPrompt, userPrompt, false)
	if err != nil {
		return nil, err
	}
	content = extractJSON(content)

	var findings []SecurityIssue
	if err := json.Unmarshal([]byte(content), &findings); err != nil {
		return nil, err
	}

	// Add IDs to LLM findings
	for i := range findings {
		findings[i].ID = fmt.Sprintf("LLM-%03d", i+1)
	}

	return findings, nil
}

func (rg *ReportGenerator) calculateRisk(assessment *SecurityAssessment) (string, int) {
	score := 0
	severityWeights := map[string]int{
		"info":     1,
		"low":      5,
		"medium":   15,
		"high":     30,
		"critical": 50,
	}

	for _, f := range assessment.Findings {
		score += severityWeights[f.Severity]
	}

	// Obfuscation adds risk
	if assessment.Obfuscation.IsObfuscated {
		score += 20
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	var level string
	switch {
	case score == 0:
		level = "none"
	case score < 15:
		level = "low"
	case score < 40:
		level = "medium"
	case score < 70:
		level = "high"
	default:
		level = "critical"
	}

	return level, score
}

func (rg *ReportGenerator) generateMitigations(assessment *SecurityAssessment) []string {
	mitigations := []string{}

	hasNetwork := len(assessment.Patterns.NetworkAccess) > 0
	hasFilesystem := len(assessment.Patterns.FileSystemAccess) > 0
	hasCommand := len(assessment.Patterns.CommandExecution) > 0

	if hasNetwork {
		mitigations = append(mitigations, "Disable network access with -allow-network=false")
	}
	if hasFilesystem {
		mitigations = append(mitigations, "Use read-only filesystem mode")
	}
	if hasCommand {
		mitigations = append(mitigations, "Review subprocess calls carefully before execution")
	}
	if assessment.Obfuscation.IsObfuscated {
		mitigations = append(mitigations, "Manual review recommended for obfuscated code")
	}

	mitigations = append(mitigations, "Execute in sandboxed container with resource limits")

	return mitigations
}

func (rg *ReportGenerator) detectCapabilities(code string, analysis *CodeAnalysis) CapabilityRequirements {
	caps := CapabilityRequirements{}

	// Network detection
	networkPatterns := []string{
		`requests\.|urllib|http\.client|aiohttp`,
		`socket\.socket|socket\.connect`,
		`fetch\(|XMLHttpRequest`,
		`net\.Dial|http\.Get|http\.Post`,
	}
	for _, p := range networkPatterns {
		if regexp.MustCompile(`(?i)` + p).MatchString(code) {
			caps.Network.Required = true
			caps.Network.Outbound = true
			caps.Network.Evidence = append(caps.Network.Evidence, p)
		}
	}

	// Detect protocols
	if regexp.MustCompile(`(?i)https?://`).MatchString(code) {
		caps.Network.Protocols = append(caps.Network.Protocols, "http", "https")
	}
	if regexp.MustCompile(`(?i)wss?://|WebSocket`).MatchString(code) {
		caps.Network.Protocols = append(caps.Network.Protocols, "websocket")
	}

	// Filesystem detection
	fsReadPatterns := []string{`open\(.*['"]r`, `read\(|ReadFile|readFileSync`}
	fsWritePatterns := []string{`open\(.*['"][wa]`, `write\(|WriteFile|writeFileSync`}

	for _, p := range fsReadPatterns {
		if regexp.MustCompile(`(?i)` + p).MatchString(code) {
			caps.Filesystem.ReadRequired = true
		}
	}
	for _, p := range fsWritePatterns {
		if regexp.MustCompile(`(?i)` + p).MatchString(code) {
			caps.Filesystem.WriteRequired = true
		}
	}

	// Temp files
	if regexp.MustCompile(`(?i)tempfile|mktemp|/tmp/|NamedTemporaryFile`).MatchString(code) {
		caps.Filesystem.TempRequired = true
	}

	// Process/subprocess detection
	processPatterns := []string{
		`subprocess\.|os\.system|exec\(`,
		`child_process|spawn\(|exec\(`,
		`Runtime\.exec|ProcessBuilder`,
	}
	for _, p := range processPatterns {
		if regexp.MustCompile(`(?i)` + p).MatchString(code) {
			caps.Process.SubprocessRequired = true
			caps.Process.Evidence = append(caps.Process.Evidence, p)
		}
	}

	// Environment variables
	envPattern := regexp.MustCompile(`(?i)os\.environ|process\.env|os\.Getenv|System\.getenv`)
	if envPattern.MatchString(code) {
		// Try to extract var names
		envVarPattern := regexp.MustCompile(`(?:environ|env|Getenv|getenv)\[?['"(\s]*([A-Z_][A-Z0-9_]*)`)
		matches := envVarPattern.FindAllStringSubmatch(code, -1)
		for _, m := range matches {
			if len(m) > 1 {
				caps.System.EnvironmentVars = append(caps.System.EnvironmentVars, m[1])
			}
		}
	}

	// Resource estimates based on analysis
	caps.Resources = rg.estimateResources(analysis)

	return caps
}

func (rg *ReportGenerator) estimateResources(analysis *CodeAnalysis) ResourceRequirements {
	res := ResourceRequirements{
		EstimatedMemoryMB: 128,
		EstimatedCPU:      0.5,
		EstimatedTimeoutS: 30,
	}

	// Adjust based on complexity
	switch analysis.Complexity.Level {
	case "trivial":
		res.EstimatedMemoryMB = 64
		res.EstimatedTimeoutS = 10
	case "simple":
		res.EstimatedMemoryMB = 128
		res.EstimatedTimeoutS = 30
	case "moderate":
		res.EstimatedMemoryMB = 256
		res.EstimatedTimeoutS = 60
	case "complex":
		res.EstimatedMemoryMB = 512
		res.EstimatedCPU = 1.0
		res.EstimatedTimeoutS = 120
	case "extreme":
		res.EstimatedMemoryMB = 1024
		res.EstimatedCPU = 2.0
		res.EstimatedTimeoutS = 300
	}

	// Check for data science libraries
	dataLibs := []string{"pandas", "numpy", "tensorflow", "pytorch", "torch", "sklearn"}
	for _, lib := range dataLibs {
		for _, imp := range analysis.Imports {
			if strings.Contains(strings.ToLower(imp.Module), lib) {
				res.EstimatedMemoryMB = max(res.EstimatedMemoryMB, 512)
				res.EstimatedCPU = maxFloat(res.EstimatedCPU, 1.0)
			}
		}
	}

	return res
}

func (rg *ReportGenerator) analyzeDependencies(analysis *CodeAnalysis) DependencyAnalysis {
	deps := DependencyAnalysis{
		Dependencies: []DependencyInfo{},
	}

	for _, imp := range analysis.Imports {
		if imp.IsStdLib {
			continue
		}

		dep := DependencyInfo{
			Name:     imp.Module,
			Source:   inferPackageSource(analysis.DetectedLanguage),
			Required: true,
		}

		// Basic risk assessment for known risky packages
		riskyPackages := map[string]string{
			"pickle":   "high",
			"marshal":  "high",
			"yaml":     "medium",
			"eval":     "critical",
			"exec":     "critical",
			"requests": "low",
		}

		for pkg, risk := range riskyPackages {
			if strings.Contains(strings.ToLower(imp.Module), pkg) {
				dep.RiskLevel = risk
				break
			}
		}

		deps.Dependencies = append(deps.Dependencies, dep)
	}

	deps.Count = len(deps.Dependencies)

	// Calculate risk score
	riskScore := 0
	for _, d := range deps.Dependencies {
		switch d.RiskLevel {
		case "low":
			riskScore += 5
		case "medium":
			riskScore += 15
		case "high":
			riskScore += 30
		case "critical":
			riskScore += 50
		}
	}
	deps.RiskScore = min(riskScore, 100)

	return deps
}

func inferPackageSource(language string) string {
	sources := map[string]string{
		"python":     "pip",
		"javascript": "npm",
		"typescript": "npm",
		"go":         "go",
		"rust":       "cargo",
		"ruby":       "gem",
		"java":       "maven",
		"php":        "composer",
	}
	if src, ok := sources[language]; ok {
		return src
	}
	return "unknown"
}

func (rg *ReportGenerator) generateExecutionRecommendations(report *AnalysisReport) ExecutionRecommendations {
	rec := ExecutionRecommendations{
		Recommended:    report.Security.Safe,
		RequiresReview: !report.Security.Safe || report.Security.Obfuscation.IsObfuscated,
		MemoryMB:       report.Capabilities.Resources.EstimatedMemoryMB,
		CPULimit:       report.Capabilities.Resources.EstimatedCPU,
		TimeoutSec:     report.Capabilities.Resources.EstimatedTimeoutS,
		MaxPIDs:        100,
		Runtime:        "runc",
	}

	// Determine network policy
	if report.Capabilities.Network.Required {
		if report.Security.RiskLevel == "high" || report.Security.RiskLevel == "critical" {
			rec.NetworkPolicy = "none"
			rec.ReviewReasons = append(rec.ReviewReasons, "Network access requested but code has security risks")
		} else {
			rec.NetworkPolicy = "restricted"
		}
	} else {
		rec.NetworkPolicy = "none"
	}

	// Determine filesystem mode
	if report.Capabilities.Filesystem.WriteRequired {
		rec.FilesystemMode = "restricted"
	} else {
		rec.FilesystemMode = "readonly"
	}

	// Select base image
	rec.BaseImage = selectBaseImage(report.Code.DetectedLanguage)

	// Entry point
	if len(report.Code.EntryPoints) > 0 {
		for _, ep := range report.Code.EntryPoints {
			if ep.Recommended {
				rec.EntryPoint = ep.Name
				break
			}
		}
		if rec.EntryPoint == "" {
			rec.EntryPoint = report.Code.EntryPoints[0].Name
		}
	}

	// Add review reasons
	if report.Security.Obfuscation.IsObfuscated {
		rec.ReviewReasons = append(rec.ReviewReasons, "Code appears to be obfuscated")
	}
	if report.Security.RiskScore > 30 {
		rec.ReviewReasons = append(rec.ReviewReasons, fmt.Sprintf("Security risk score is %d/100", report.Security.RiskScore))
	}
	if len(report.Security.Patterns.ReverseShell) > 0 {
		rec.ReviewReasons = append(rec.ReviewReasons, "Potential reverse shell patterns detected")
		rec.Recommended = false
	}
	if len(report.Security.Patterns.CryptoOperations) > 0 {
		rec.ReviewReasons = append(rec.ReviewReasons, "Potential crypto mining patterns detected")
		rec.Recommended = false
	}

	return rec
}

func selectBaseImage(language string) string {
	images := map[string]string{
		"python":     "python:3.11-slim-bookworm",
		"javascript": "node:20-slim",
		"typescript": "node:20-slim",
		"go":         "golang:1.22-alpine",
		"rust":       "rust:1.75-slim",
		"ruby":       "ruby:3.2-slim",
		"java":       "eclipse-temurin:21-jre-alpine",
		"c":          "gcc:13-bookworm",
		"cpp":        "gcc:13-bookworm",
		"php":        "php:8.3-cli-alpine",
	}
	if img, ok := images[language]; ok {
		return img
	}
	return "alpine:3.19"
}

func (rg *ReportGenerator) generateSummary(report *AnalysisReport) ReportSummary {
	summary := ReportSummary{
		Verdict:       VerdictFromRisk(report.Security.RiskLevel, report.Execution.RequiresReview),
		Confidence:    report.Security.Confidence,
		RiskFactors:   []string{},
		SecurityScore: 100 - report.Security.RiskScore,
		TrustScore:    100,
	}

	// Complexity score
	complexityScores := map[string]int{
		"trivial":  10,
		"simple":   25,
		"moderate": 50,
		"complex":  75,
		"extreme":  100,
	}
	summary.ComplexityScore = complexityScores[report.Code.Complexity.Level]

	// Build risk factors
	if report.Security.RiskScore > 0 {
		summary.RiskFactors = append(summary.RiskFactors, fmt.Sprintf("%d security findings", len(report.Security.Findings)))
	}
	if report.Security.Obfuscation.IsObfuscated {
		summary.RiskFactors = append(summary.RiskFactors, "Code obfuscation detected")
		summary.TrustScore -= 30
	}
	if report.Capabilities.Network.Required {
		summary.RiskFactors = append(summary.RiskFactors, "Requires network access")
	}
	if report.Capabilities.Process.SubprocessRequired {
		summary.RiskFactors = append(summary.RiskFactors, "Executes subprocesses")
		summary.TrustScore -= 10
	}

	// Recommendations
	if !report.Execution.Recommended {
		summary.Recommendations = append(summary.Recommendations, "Manual review strongly recommended before execution")
	}
	if report.Capabilities.Network.Required && report.Security.RiskLevel != "none" {
		summary.Recommendations = append(summary.Recommendations, "Consider running without network access")
	}
	summary.Recommendations = append(summary.Recommendations, "Execute in sandboxed environment with resource limits")

	// Verdict reason
	switch summary.Verdict {
	case "safe":
		summary.VerdictReason = "Code passed security analysis with no significant risks"
	case "caution":
		summary.VerdictReason = "Code has some risk factors that require attention"
	case "unsafe":
		summary.VerdictReason = "Code contains security risks and should not be executed without review"
	case "blocked":
		summary.VerdictReason = "Code contains critical security issues and execution is not recommended"
	}

	// Adjust trust score
	if summary.TrustScore < 0 {
		summary.TrustScore = 0
	}

	return summary
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func maxFloat(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}
