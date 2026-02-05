package fort

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sashabaranov/go-openai"
)

// SandboxExecutionReview is the LLM-generated interpretation of sandbox artifacts.
type SandboxExecutionReview struct {
	OverallAssessment string   `json:"overall_assessment"`
	RiskLevel         string   `json:"risk_level"`
	Confidence        float64  `json:"confidence"`
	Summary           string   `json:"summary"`
	PipelineFindings  []string `json:"pipeline_findings,omitempty"`
	LogFindings       []string `json:"log_findings,omitempty"`
	FileFindings      []string `json:"file_findings,omitempty"`
	ActivityFindings  []string `json:"activity_findings,omitempty"`
	Recommendations   []string `json:"recommendations,omitempty"`
}

// LLMClient abstracts LLM interactions for code analysis
type LLMClient interface {
	Analyze(ctx context.Context, code, language, purpose string) (*AnalysisResult, error)
	Synthesize(ctx context.Context, code string, analysis *AnalysisResult) (*SynthesisResult, error)
	SynthesizeProject(ctx context.Context, projectContext string, analysis *AnalysisResult) (*SynthesisResult, error)
	Validate(ctx context.Context, code string, analysis *AnalysisResult, synthesis *SynthesisResult, policy *SecurityPolicy) (*ValidationResult, error)
}

// OpenAILLMClient implements LLMClient using OpenAI API
type OpenAILLMClient struct {
	client  *openai.Client
	apiKey  string
	model   string
	baseURL string
	verbose bool
	dumpDir string
	dumpSeq uint64
	dumpMu  sync.Mutex
}

// NewOpenAILLMClient creates an OpenAI-based LLM client
func NewOpenAILLMClient(apiKey, model string) *OpenAILLMClient {
	cfg := openai.DefaultConfig(apiKey)
	return &OpenAILLMClient{
		client:  openai.NewClient(apiKey),
		apiKey:  apiKey,
		model:   model,
		baseURL: cfg.BaseURL,
	}
}

// NewOpenAILLMClientWithBaseURL creates an OpenAI-compatible LLM client with custom base URL
func NewOpenAILLMClientWithBaseURL(apiKey, model, baseURL string) *OpenAILLMClient {
	config := openai.DefaultConfig(apiKey)
	config.BaseURL = baseURL
	return &OpenAILLMClient{
		client:  openai.NewClientWithConfig(config),
		apiKey:  apiKey,
		model:   model,
		baseURL: baseURL,
	}
}

// SetDebugOptions enables verbose logs and optional JSON dumps of LLM requests/responses.
func (c *OpenAILLMClient) SetDebugOptions(verbose bool, dumpDir string) {
	c.verbose = verbose
	c.dumpDir = strings.TrimSpace(dumpDir)
}

func (c *OpenAILLMClient) logf(format string, args ...interface{}) {
	if !c.verbose {
		return
	}
	fmt.Fprintf(os.Stderr, "[LLM] "+format+"\n", args...)
}

func (c *OpenAILLMClient) dumpLLMJSON(kind string, payload map[string]interface{}) {
	dumpDir := strings.TrimSpace(c.dumpDir)
	if dumpDir == "" {
		return
	}

	c.dumpMu.Lock()
	defer c.dumpMu.Unlock()

	if err := os.MkdirAll(dumpDir, 0755); err != nil {
		c.logf("Failed to create LLM dump dir %q: %v", dumpDir, err)
		return
	}

	seq := atomic.AddUint64(&c.dumpSeq, 1)
	filename := fmt.Sprintf(
		"%s_%06d_%s.json",
		time.Now().UTC().Format("20060102T150405.000Z"),
		seq,
		sanitizeDumpToken(kind),
	)
	path := filepath.Join(dumpDir, filename)

	record := map[string]interface{}{
		"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
		"model":     c.model,
		"base_url":  c.baseURL,
		"kind":      kind,
		"payload":   payload,
	}

	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		c.logf("Failed to serialize LLM dump %q: %v", kind, err)
		return
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		c.logf("Failed to write LLM dump file %q: %v", path, err)
		return
	}
	c.logf("Wrote LLM dump: %s", path)
}

func sanitizeDumpToken(v string) string {
	v = strings.TrimSpace(strings.ToLower(v))
	if v == "" {
		return "llm"
	}
	var b strings.Builder
	b.Grow(len(v))
	for _, r := range v {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
			continue
		}
		b.WriteByte('_')
	}
	out := strings.Trim(b.String(), "_")
	if out == "" {
		return "llm"
	}
	return out
}

// Analyze performs code analysis using LLM
func (c *OpenAILLMClient) Analyze(ctx context.Context, code, language, purpose string) (*AnalysisResult, error) {
	systemPrompt := `You are an expert code analyzer. Analyze the provided code and return a JSON object with these fields:
- detected_language: the programming language
- detected_runtime: the runtime environment (e.g., python3.11, node18, go1.21)
- detected_frameworks: list of detected frameworks/libraries
- inferred_dependencies: list of {name, version, source} objects for required packages
- complexity: one of "trivial", "simple", "moderate", "complex", "extreme"
- estimated_runtime: human-readable estimate like "< 1 second", "1-5 seconds", etc.
- potential_risks: list of security/safety concerns
- requires_review: boolean if human review is recommended
- summary: brief description of what the code does
- detected_entry_points: list of possible entry points (main functions, etc.)
- recommended_entry: the recommended entry point to execute

Return ONLY valid JSON, no markdown or explanation.`

	userPrompt := fmt.Sprintf("Analyze this code:\n\n```\n%s\n```", code)
	if language != "" {
		userPrompt += fmt.Sprintf("\n\nLanguage hint: %s", language)
	}
	if purpose != "" {
		userPrompt += fmt.Sprintf("\n\nIntended purpose: %s", purpose)
	}

	content, err := c.generateText(ctx, systemPrompt, userPrompt, false)
	if err != nil {
		return nil, fmt.Errorf("LLM request failed: %w", err)
	}

	content = extractJSON(content)
	result, err := parseAnalysisResult(content)
	if err != nil {
		return nil, fmt.Errorf("failed to parse LLM response: %w", err)
	}

	return result, nil
}

// Synthesize generates container configuration using LLM
func (c *OpenAILLMClient) Synthesize(ctx context.Context, code string, analysis *AnalysisResult) (*SynthesisResult, error) {
	systemPrompt := `You are an expert at creating minimal, secure Docker containers for code execution.
Generate a JSON object with these fields:
- base_image: minimal base image (prefer alpine/slim variants, e.g., python:3.11-slim-bookworm)
- dockerfile: complete Dockerfile content with security best practices (non-root user, minimal packages)
- entry_script: optional shell script to run the code
- setup_script: optional script for any pre-execution setup
- run_command: array of command and arguments to execute the code
- work_dir: working directory in container
- environment_vars: map of environment variables
- build_args: list of build arguments
- recommended_memory_mb: suggested memory limit
- recommended_cpu: suggested CPU limit (1.0 = 1 core)
- recommended_timeout_sec: suggested timeout

Security requirements:
- Use non-root user
- Minimize installed packages
- Set appropriate file permissions
- Don't expose unnecessary ports

Return ONLY valid JSON, no markdown.`

	analysisJSON, _ := json.Marshal(analysis)
	userPrompt := fmt.Sprintf("Generate container config for this code:\n\n```\n%s\n```\n\nAnalysis:\n%s", code, string(analysisJSON))

	content, err := c.generateText(ctx, systemPrompt, userPrompt, false)
	if err != nil {
		return nil, fmt.Errorf("LLM request failed: %w", err)
	}

	var result SynthesisResult
	content = extractJSON(content)
	if err := json.Unmarshal([]byte(content), &result); err != nil {
		return nil, fmt.Errorf("failed to parse LLM response: %w", err)
	}

	return &result, nil
}

// SynthesizeProject generates container config for multi-file projects
func (c *OpenAILLMClient) SynthesizeProject(ctx context.Context, projectContext string, analysis *AnalysisResult) (*SynthesisResult, error) {
	systemPrompt := `You are an expert DevOps engineer creating production-quality Dockerfiles.
Given a multi-file project analysis, generate the optimal Docker configuration.

Requirements:
1. Use multi-stage builds to minimize final image size
2. Use appropriate base images (prefer alpine/slim variants)
3. Create a non-root user for security
4. Install only necessary dependencies
5. Copy files efficiently (use .dockerignore patterns mentally)
6. Set proper file permissions
7. Handle the detected build system correctly (npm, pip, cargo, go mod, maven, etc.)
8. Configure the correct entry point and run command

Return a JSON object with these fields:
- base_image: the base image to use
- dockerfile: complete Dockerfile content (multi-stage if beneficial)
- entry_script: optional shell script wrapper (if needed)
- setup_script: optional setup script (if needed)
- run_command: array of command and args to run the project
- work_dir: working directory in container
- environment_vars: map of environment variables
- build_args: list of build arguments
- recommended_memory_mb: memory limit suggestion
- recommended_cpu: CPU limit (1.0 = 1 core)
- recommended_timeout_sec: timeout suggestion

Important Dockerfile best practices:
- Order layers by change frequency (dependencies before code)
- Use specific version tags, not :latest
- Combine RUN commands to reduce layers
- Clean up package manager caches
- Don't store secrets in the image

Return ONLY valid JSON, no markdown.`

	userPrompt := fmt.Sprintf("Generate Docker configuration for this project:\n\n%s", projectContext)

	content, err := c.generateText(ctx, systemPrompt, userPrompt, false)
	if err != nil {
		return nil, fmt.Errorf("LLM request failed: %w", err)
	}

	var result SynthesisResult

	// Try to extract JSON from response (handle markdown code blocks)
	content = extractJSON(content)

	if err := json.Unmarshal([]byte(content), &result); err != nil {
		return nil, fmt.Errorf("failed to parse LLM response: %w", err)
	}

	return &result, nil
}

// extractJSON extracts JSON from a response that might be wrapped in markdown
func extractJSON(content string) string {
	// Remove markdown code blocks if present
	if strings.Contains(content, "```json") {
		start := strings.Index(content, "```json") + 7
		end := strings.LastIndex(content, "```")
		if end > start {
			content = content[start:end]
		}
	} else if strings.Contains(content, "```") {
		start := strings.Index(content, "```") + 3
		end := strings.LastIndex(content, "```")
		if end > start {
			content = content[start:end]
		}
	}
	return strings.TrimSpace(content)
}

// Validate performs security validation using LLM
func (c *OpenAILLMClient) Validate(ctx context.Context, code string, analysis *AnalysisResult, synthesis *SynthesisResult, policy *SecurityPolicy) (*ValidationResult, error) {
	systemPrompt := `You are an expert security analyst. Review the code for security issues.
Return a JSON object with these fields:
- safe: boolean indicating if the code is safe to execute
- risk_level: one of "none", "low", "medium", "high", "critical"
- confidence: 0.0-1.0 confidence in your assessment
- findings: list of {category, severity, description, location, evidence, mitigated, mitigation}
- policy_violations: list of {policy, description, severity} for policy violations
- recommendations: list of security recommendations
- rejection_reason: if not safe, explain why (empty string if safe)
- review_notes: any additional notes for human reviewers

Categories to check:
- Command injection, code injection
- File system access violations
- Network access violations
- Crypto mining indicators
- Data exfiltration attempts
- Reverse shells
- Privilege escalation
- Resource abuse

Return ONLY valid JSON, no markdown.`

	analysisJSON, _ := json.Marshal(analysis)
	policyJSON, _ := json.Marshal(policy)
	userPrompt := fmt.Sprintf("Validate this code:\n\n```\n%s\n```\n\nAnalysis:\n%s\n\nPolicy:\n%s", code, string(analysisJSON), string(policyJSON))

	content, err := c.generateText(ctx, systemPrompt, userPrompt, false)
	if err != nil {
		return nil, fmt.Errorf("LLM request failed: %w", err)
	}

	var result ValidationResult
	content = extractJSON(content)
	if err := json.Unmarshal([]byte(content), &result); err != nil {
		return nil, fmt.Errorf("failed to parse LLM response: %w", err)
	}

	return &result, nil
}

func (c *OpenAILLMClient) generateText(ctx context.Context, systemPrompt, userPrompt string, forceJSONObject bool) (string, error) {
	if isCodexModel(c.model) {
		c.logf("Routing model %q to /responses endpoint", c.model)
		content, err := c.createResponses(ctx, systemPrompt, userPrompt)
		if err == nil {
			return content, nil
		}

		// Fallback for providers that expose Codex-like models but don't support /responses.
		c.logf("/responses failed for model %q: %v; trying /completions fallback", c.model, err)
		fallbackContent, fallbackErr := c.createCompletion(ctx, systemPrompt, userPrompt)
		if fallbackErr == nil {
			return fallbackContent, nil
		}
		return "", fmt.Errorf("responses endpoint failed: %w; completions fallback failed: %v", err, fallbackErr)
	}

	if prefersCompletionsEndpoint(c.model) {
		c.logf("Routing model %q to /completions endpoint", c.model)
		content, err := c.createCompletion(ctx, systemPrompt, userPrompt)
		if err == nil {
			return content, nil
		}
		if shouldFallbackToChatEndpoint(err) && !isStrictCompletionsModel(c.model) {
			c.logf("/completions failed for model %q: %v; trying /chat/completions fallback", c.model, err)
			fallbackContent, fallbackErr := c.createChatCompletion(ctx, systemPrompt, userPrompt, forceJSONObject)
			if fallbackErr == nil {
				return fallbackContent, nil
			}
			return "", fmt.Errorf("completions endpoint failed: %w; chat fallback failed: %v", err, fallbackErr)
		}
		return "", err
	}

	c.logf("Routing model %q to /chat/completions endpoint", c.model)
	content, err := c.createChatCompletion(ctx, systemPrompt, userPrompt, forceJSONObject)
	if err == nil {
		return content, nil
	}
	if shouldFallbackToCompletionsEndpoint(err) {
		c.logf("/chat/completions failed for model %q: %v; trying /completions fallback", c.model, err)
		fallbackContent, fallbackErr := c.createCompletion(ctx, systemPrompt, userPrompt)
		if fallbackErr == nil {
			return fallbackContent, nil
		}
		return "", fmt.Errorf("chat endpoint failed: %w; completions fallback failed: %v", err, fallbackErr)
	}
	return "", err
}

func (c *OpenAILLMClient) createResponses(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	reqBody := map[string]interface{}{
		"model": c.model,
		"input": formatCompletionPrompt(systemPrompt, userPrompt),
	}

	payload, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to encode responses request: %w", err)
	}

	baseURL := strings.TrimRight(c.baseURL, "/")
	if baseURL == "" {
		baseURL = "https://api.openai.com/v1"
	}
	url := baseURL + "/responses"
	c.logf("POST %s", url)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		c.dumpLLMJSON("responses_error", map[string]interface{}{
			"endpoint": "responses",
			"url":      url,
			"request":  reqBody,
			"error":    fmt.Sprintf("failed to create request: %v", err),
		})
		return "", fmt.Errorf("failed to create responses request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if strings.TrimSpace(c.apiKey) != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.dumpLLMJSON("responses_error", map[string]interface{}{
			"endpoint": "responses",
			"url":      url,
			"request":  reqBody,
			"error":    err.Error(),
		})
		return "", fmt.Errorf("responses request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.dumpLLMJSON("responses_error", map[string]interface{}{
			"endpoint":    "responses",
			"url":         url,
			"request":     reqBody,
			"status_code": resp.StatusCode,
			"error":       fmt.Sprintf("failed to read response body: %v", err),
		})
		return "", fmt.Errorf("failed to read responses body: %w", err)
	}
	c.logf("/responses status=%d", resp.StatusCode)

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusBadRequest {
		msg := parseResponsesErrorMessage(body)
		c.dumpLLMJSON("responses_error", map[string]interface{}{
			"endpoint":      "responses",
			"url":           url,
			"request":       reqBody,
			"status_code":   resp.StatusCode,
			"status":        resp.Status,
			"error":         msg,
			"response_body": string(body),
		})
		return "", fmt.Errorf("error, status code: %d, status: %s, message: %s", resp.StatusCode, resp.Status, msg)
	}

	var response responsesAPIResponse
	if err := json.Unmarshal(body, &response); err != nil {
		c.dumpLLMJSON("responses_error", map[string]interface{}{
			"endpoint":      "responses",
			"url":           url,
			"request":       reqBody,
			"status_code":   resp.StatusCode,
			"error":         fmt.Sprintf("failed to decode response payload: %v", err),
			"response_body": string(body),
		})
		return "", fmt.Errorf("failed to decode responses payload: %w", err)
	}

	content := strings.TrimSpace(response.OutputText)
	if content != "" {
		c.dumpLLMJSON("responses_success", map[string]interface{}{
			"endpoint":        "responses",
			"url":             url,
			"request":         reqBody,
			"status_code":     resp.StatusCode,
			"response_output": response,
		})
		return content, nil
	}

	var chunks []string
	for _, out := range response.Output {
		for _, item := range out.Content {
			text := strings.TrimSpace(item.Text)
			if text != "" {
				chunks = append(chunks, text)
			}
		}
	}
	if len(chunks) > 0 {
		c.dumpLLMJSON("responses_success", map[string]interface{}{
			"endpoint":        "responses",
			"url":             url,
			"request":         reqBody,
			"status_code":     resp.StatusCode,
			"response_output": response,
		})
		return strings.Join(chunks, "\n"), nil
	}

	c.dumpLLMJSON("responses_error", map[string]interface{}{
		"endpoint":        "responses",
		"url":             url,
		"request":         reqBody,
		"status_code":     resp.StatusCode,
		"response_output": response,
		"error":           "no response from LLM",
	})
	return "", fmt.Errorf("no response from LLM")
}

type responsesAPIResponse struct {
	OutputText string                 `json:"output_text"`
	Output     []responsesOutputBlock `json:"output"`
}

type responsesOutputBlock struct {
	Content []responsesOutputContent `json:"content"`
}

type responsesOutputContent struct {
	Text string `json:"text"`
}

func parseResponsesErrorMessage(body []byte) string {
	var payload struct {
		Message string `json:"message"`
		Error   struct {
			Message string `json:"message"`
		} `json:"error"`
	}

	if err := json.Unmarshal(body, &payload); err == nil {
		if strings.TrimSpace(payload.Error.Message) != "" {
			return payload.Error.Message
		}
		if strings.TrimSpace(payload.Message) != "" {
			return payload.Message
		}
	}

	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return "unknown error"
	}
	return trimmed
}

func (c *OpenAILLMClient) createChatCompletion(
	ctx context.Context,
	systemPrompt, userPrompt string,
	forceJSONObject bool,
) (string, error) {
	req := openai.ChatCompletionRequest{
		Model: c.model,
		Messages: []openai.ChatCompletionMessage{
			{Role: openai.ChatMessageRoleSystem, Content: systemPrompt},
			{Role: openai.ChatMessageRoleUser, Content: userPrompt},
		},
	}
	if forceJSONObject {
		req.ResponseFormat = &openai.ChatCompletionResponseFormat{
			Type: openai.ChatCompletionResponseFormatTypeJSONObject,
		}
	}
	c.logf("POST /chat/completions model=%q response_format=%t", c.model, forceJSONObject)

	resp, err := c.client.CreateChatCompletion(ctx, req)
	if err != nil {
		c.dumpLLMJSON("chat_completions_error", map[string]interface{}{
			"endpoint": "chat_completions",
			"request":  req,
			"error":    err.Error(),
		})
		if forceJSONObject && isUnsupportedResponseFormatError(err) {
			c.logf("Model %q rejected response_format=json_object, retrying without response_format", c.model)
			req.ResponseFormat = nil
			resp, err = c.client.CreateChatCompletion(ctx, req)
			if err != nil {
				c.dumpLLMJSON("chat_completions_error", map[string]interface{}{
					"endpoint": "chat_completions",
					"request":  req,
					"error":    err.Error(),
				})
			}
		}
	}
	if err != nil {
		return "", err
	}
	if len(resp.Choices) == 0 {
		c.dumpLLMJSON("chat_completions_error", map[string]interface{}{
			"endpoint": "chat_completions",
			"request":  req,
			"response": resp,
			"error":    "no response from LLM",
		})
		return "", fmt.Errorf("no response from LLM")
	}
	c.dumpLLMJSON("chat_completions_success", map[string]interface{}{
		"endpoint": "chat_completions",
		"request":  req,
		"response": resp,
	})
	return resp.Choices[0].Message.Content, nil
}

func isUnsupportedResponseFormatError(err error) bool {
	var apiErr *openai.APIError
	if !errors.As(err, &apiErr) {
		return false
	}

	msg := strings.ToLower(apiErr.Message)
	return strings.Contains(msg, "response_format") &&
		(strings.Contains(msg, "not supported") || strings.Contains(msg, "invalid parameter"))
}

func (c *OpenAILLMClient) createCompletion(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	req := openai.CompletionRequest{
		Model:     c.model,
		Prompt:    formatCompletionPrompt(systemPrompt, userPrompt),
		MaxTokens: 4000,
	}
	c.logf("POST /completions model=%q", c.model)
	resp, err := c.client.CreateCompletion(ctx, req)
	if err != nil {
		c.dumpLLMJSON("completions_error", map[string]interface{}{
			"endpoint": "completions",
			"request":  req,
			"error":    err.Error(),
		})
		return "", err
	}
	if len(resp.Choices) == 0 {
		c.dumpLLMJSON("completions_error", map[string]interface{}{
			"endpoint": "completions",
			"request":  req,
			"response": resp,
			"error":    "no response from LLM",
		})
		return "", fmt.Errorf("no response from LLM")
	}
	c.dumpLLMJSON("completions_success", map[string]interface{}{
		"endpoint": "completions",
		"request":  req,
		"response": resp,
	})
	return resp.Choices[0].Text, nil
}

func formatCompletionPrompt(systemPrompt, userPrompt string) string {
	parts := make([]string, 0, 3)
	if strings.TrimSpace(systemPrompt) != "" {
		parts = append(parts, "System instructions:\n"+strings.TrimSpace(systemPrompt))
	}
	parts = append(parts, "User request:\n"+strings.TrimSpace(userPrompt))
	parts = append(parts, "Assistant response:")
	return strings.Join(parts, "\n\n")
}

func prefersCompletionsEndpoint(model string) bool {
	m := strings.ToLower(strings.TrimSpace(model))
	return strings.HasPrefix(m, "text-") ||
		strings.Contains(m, "instruct")
}

func isCodexModel(model string) bool {
	return strings.Contains(strings.ToLower(strings.TrimSpace(model)), "codex")
}

func isStrictCompletionsModel(model string) bool {
	return isCodexModel(model)
}

func shouldFallbackToCompletionsEndpoint(err error) bool {
	if errors.Is(err, openai.ErrChatCompletionInvalidModel) {
		return true
	}

	var apiErr *openai.APIError
	if !errors.As(err, &apiErr) {
		return false
	}

	msg := strings.ToLower(apiErr.Message)
	if strings.Contains(msg, "not a chat model") {
		return true
	}
	if strings.Contains(msg, "v1/chat/completions") && strings.Contains(msg, "v1/completions") {
		return true
	}
	if strings.Contains(msg, "/chat/completions") && strings.Contains(msg, "/completions") {
		return true
	}
	return apiErr.HTTPStatusCode == 404 &&
		(strings.Contains(msg, "chat/completions") || strings.Contains(msg, "not supported"))
}

func shouldFallbackToChatEndpoint(err error) bool {
	if errors.Is(err, openai.ErrCompletionUnsupportedModel) {
		return true
	}

	var apiErr *openai.APIError
	if !errors.As(err, &apiErr) {
		return false
	}

	msg := strings.ToLower(apiErr.Message)
	if strings.Contains(msg, "not a completion model") {
		return true
	}
	if strings.Contains(msg, "v1/completions") &&
		strings.Contains(msg, "v1/chat/completions") &&
		(strings.Contains(msg, "did you mean") || strings.Contains(msg, "please use")) {
		return true
	}
	if strings.Contains(msg, "/completions") &&
		strings.Contains(msg, "/chat/completions") &&
		(strings.Contains(msg, "did you mean") || strings.Contains(msg, "please use")) {
		return true
	}
	return false
}

// ReviewSandboxExecution asks the LLM to analyze execution artifacts (logs, output files, phases).
func (c *OpenAILLMClient) ReviewSandboxExecution(
	ctx context.Context,
	execution *Execution,
	execErr error,
) (*SandboxExecutionReview, error) {
	systemPrompt := `You are a sandbox execution auditor.
You will receive execution artifacts from an isolated sandbox run.
Analyze these artifacts and return ONLY valid JSON:
{
  "overall_assessment": "pass|caution|fail",
  "risk_level": "none|low|medium|high|critical",
  "confidence": 0.0,
  "summary": "brief summary",
  "pipeline_findings": ["list of findings about analyze/build/execute phases"],
  "log_findings": ["insights from stdout/stderr"],
  "file_findings": ["insights from output files/artifacts"],
  "activity_findings": ["sandbox activity or behavior observations"],
  "recommendations": ["practical next steps"]
}
Rules:
- Base conclusions only on provided artifacts.
- If evidence is missing, say so in findings.
- Keep recommendations concrete and security-focused.`

	payload := buildExecutionReviewPayload(execution, execErr)
	artifactsJSON, _ := json.Marshal(payload)
	userPrompt := fmt.Sprintf("Execution artifacts JSON:\n%s", string(artifactsJSON))

	content, err := c.generateText(ctx, systemPrompt, userPrompt, false)
	if err != nil {
		return nil, fmt.Errorf("LLM request failed: %w", err)
	}
	content = extractJSON(content)

	var review SandboxExecutionReview
	if err := json.Unmarshal([]byte(content), &review); err != nil {
		return nil, fmt.Errorf("failed to parse LLM response: %w", err)
	}
	return &review, nil
}

func parseAnalysisResult(content string) (*AnalysisResult, error) {
	var direct AnalysisResult
	if err := json.Unmarshal([]byte(content), &direct); err == nil {
		normalizeAnalysisResult(&direct)
		return &direct, nil
	}

	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(content), &raw); err != nil {
		return nil, err
	}

	result := &AnalysisResult{
		DetectedLanguage:     pickFirstString(raw, "detected_language", "language"),
		DetectedRuntime:      pickFirstString(raw, "detected_runtime", "runtime"),
		DetectedFrameworks:   parseStringSlice(raw["detected_frameworks"]),
		InferredDependencies: parseAnalysisDependencies(raw["inferred_dependencies"]),
		Complexity:           parseComplexity(raw["complexity"]),
		EstimatedRuntime:     pickFirstString(raw, "estimated_runtime"),
		PotentialRisks:       parseStringSlice(raw["potential_risks"]),
		RequiresReview:       parseBool(raw["requires_review"]),
		Summary:              pickFirstString(raw, "summary", "inferred_purpose"),
		DetectedEntryPoints:  parseEntryPoints(raw["detected_entry_points"]),
		RecommendedEntry:     pickFirstString(raw, "recommended_entry"),
	}

	if result.EstimatedRuntime == "" {
		if m, ok := raw["complexity"].(map[string]interface{}); ok {
			result.EstimatedRuntime = pickFirstString(m, "estimated_runtime")
		}
	}

	normalizeAnalysisResult(result)
	return result, nil
}

func normalizeAnalysisResult(result *AnalysisResult) {
	if result == nil {
		return
	}
	if result.DetectedLanguage == "" {
		result.DetectedLanguage = "unknown"
	}
	if result.DetectedRuntime == "" {
		result.DetectedRuntime = "unknown"
	}
	if result.EstimatedRuntime == "" {
		result.EstimatedRuntime = "unknown"
	}
	if result.Complexity == "" {
		result.Complexity = ComplexityModerate
	}
	if result.RecommendedEntry == "" && len(result.DetectedEntryPoints) > 0 {
		result.RecommendedEntry = result.DetectedEntryPoints[0]
	}
}

func pickFirstString(m map[string]interface{}, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			if s := parseString(v); s != "" {
				return s
			}
		}
	}
	return ""
}

func parseString(v interface{}) string {
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case []byte:
		return strings.TrimSpace(string(t))
	default:
		return ""
	}
}

func parseBool(v interface{}) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return strings.EqualFold(strings.TrimSpace(t), "true")
	default:
		return false
	}
}

func parseComplexity(v interface{}) Complexity {
	switch t := v.(type) {
	case string:
		return normalizeComplexity(t)
	case map[string]interface{}:
		if s := parseString(t["level"]); s != "" {
			return normalizeComplexity(s)
		}
	}
	return ComplexityModerate
}

func normalizeComplexity(s string) Complexity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "trivial":
		return ComplexityTrivial
	case "simple":
		return ComplexitySimple
	case "moderate":
		return ComplexityModerate
	case "complex":
		return ComplexityComplex
	case "extreme":
		return ComplexityExtreme
	default:
		return ComplexityModerate
	}
}

func parseEntryPoints(v interface{}) []string {
	items := parseStringSlice(v)
	if len(items) > 0 {
		return items
	}

	raw, ok := v.([]interface{})
	if !ok {
		return nil
	}

	points := make([]string, 0, len(raw))
	for _, item := range raw {
		if m, ok := item.(map[string]interface{}); ok {
			if name := pickFirstString(m, "name", "entry", "location"); name != "" {
				points = append(points, name)
			}
		}
	}
	return points
}

func parseAnalysisDependencies(v interface{}) []Dependency {
	raw, ok := v.([]interface{})
	if !ok {
		return nil
	}

	out := make([]Dependency, 0, len(raw))
	for _, item := range raw {
		switch t := item.(type) {
		case string:
			name := strings.TrimSpace(t)
			if name != "" {
				out = append(out, Dependency{Name: name})
			}
		case map[string]interface{}:
			dep := Dependency{
				Name:    pickFirstString(t, "name", "package", "module"),
				Version: pickFirstString(t, "version"),
				Source:  pickFirstString(t, "source", "manager"),
			}
			if dep.Name != "" {
				out = append(out, dep)
			}
		}
	}
	return out
}

func parseStringSlice(v interface{}) []string {
	switch t := v.(type) {
	case []interface{}:
		out := make([]string, 0, len(t))
		for _, item := range t {
			switch x := item.(type) {
			case string:
				s := strings.TrimSpace(x)
				if s != "" {
					out = append(out, s)
				}
			case map[string]interface{}:
				if s := pickFirstString(x, "description", "title", "name", "risk", "reason"); s != "" {
					out = append(out, s)
					continue
				}
				b, _ := json.Marshal(x)
				if len(b) > 0 {
					out = append(out, string(b))
				}
			default:
				s := strings.TrimSpace(fmt.Sprintf("%v", x))
				if s != "" && s != "<nil>" {
					out = append(out, s)
				}
			}
		}
		return out
	case map[string]interface{}:
		// Some models may emit an object for risks/frameworks.
		out := make([]string, 0, len(t))
		for k, val := range t {
			vs := strings.TrimSpace(fmt.Sprintf("%v", val))
			if vs == "" || vs == "<nil>" {
				out = append(out, k)
			} else {
				out = append(out, fmt.Sprintf("%s: %s", k, vs))
			}
		}
		return out
	case string:
		s := strings.TrimSpace(t)
		if s == "" {
			return nil
		}
		return []string{s}
	default:
		return nil
	}
}

func buildExecutionReviewPayload(execution *Execution, execErr error) map[string]interface{} {
	if execution == nil {
		return map[string]interface{}{
			"error": "execution is nil",
		}
	}

	payload := map[string]interface{}{
		"request_id":      execution.Request.ID,
		"request_policy":  execution.Request.SecurityPolicy,
		"current_phase":   execution.Request.CurrentPhase,
		"status":          execution.Request.Status,
		"phases":          execution.Phases,
		"analysis":        execution.Analysis,
		"synthesis":       execution.Synthesis,
		"validation":      execution.Validation,
		"execution_error": "",
	}
	if execErr != nil {
		payload["execution_error"] = execErr.Error()
	}

	if execution.Result != nil {
		payload["result"] = map[string]interface{}{
			"success":        execution.Result.Success,
			"exit_code":      execution.Result.ExitCode,
			"timed_out":      execution.Result.TimedOut,
			"killed":         execution.Result.Killed,
			"kill_reason":    execution.Result.KillReason,
			"wall_time_ms":   execution.Result.WallTimeMs,
			"stdout":         truncateForLLM(execution.Result.Stdout, 8000),
			"stderr":         truncateForLLM(execution.Result.Stderr, 8000),
			"output_files":   execution.Result.OutputFiles,
			"container_id":   execution.Result.ContainerID,
			"image_id":       execution.Result.ImageID,
			"completed_at":   execution.Result.CompletedAt,
			"memory_used_mb": execution.Result.MemoryUsedMB,
			"cpu_time_ms":    execution.Result.CPUTimeMs,
		}
	}

	return payload
}

func truncateForLLM(text string, max int) string {
	if len(text) <= max {
		return text
	}
	return text[:max] + "\n... (truncated)"
}
