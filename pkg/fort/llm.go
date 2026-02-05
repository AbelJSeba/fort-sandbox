package fort

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/sashabaranov/go-openai"
)

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

	var result AnalysisResult
	content = extractJSON(content)
	if err := json.Unmarshal([]byte(content), &result); err != nil {
		return nil, fmt.Errorf("failed to parse LLM response: %w", err)
	}

	return &result, nil
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
		content, err := c.createResponses(ctx, systemPrompt, userPrompt)
		if err == nil {
			return content, nil
		}

		// Fallback for providers that expose Codex-like models but don't support /responses.
		fallbackContent, fallbackErr := c.createCompletion(ctx, systemPrompt, userPrompt)
		if fallbackErr == nil {
			return fallbackContent, nil
		}
		return "", fmt.Errorf("responses endpoint failed: %w; completions fallback failed: %v", err, fallbackErr)
	}

	if prefersCompletionsEndpoint(c.model) {
		content, err := c.createCompletion(ctx, systemPrompt, userPrompt)
		if err == nil {
			return content, nil
		}
		if shouldFallbackToChatEndpoint(err) && !isStrictCompletionsModel(c.model) {
			fallbackContent, fallbackErr := c.createChatCompletion(ctx, systemPrompt, userPrompt, forceJSONObject)
			if fallbackErr == nil {
				return fallbackContent, nil
			}
			return "", fmt.Errorf("completions endpoint failed: %w; chat fallback failed: %v", err, fallbackErr)
		}
		return "", err
	}

	content, err := c.createChatCompletion(ctx, systemPrompt, userPrompt, forceJSONObject)
	if err == nil {
		return content, nil
	}
	if shouldFallbackToCompletionsEndpoint(err) {
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

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return "", fmt.Errorf("failed to create responses request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if strings.TrimSpace(c.apiKey) != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("responses request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read responses body: %w", err)
	}

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusBadRequest {
		msg := parseResponsesErrorMessage(body)
		return "", fmt.Errorf("error, status code: %d, status: %s, message: %s", resp.StatusCode, resp.Status, msg)
	}

	var response responsesAPIResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return "", fmt.Errorf("failed to decode responses payload: %w", err)
	}

	content := strings.TrimSpace(response.OutputText)
	if content != "" {
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
		return strings.Join(chunks, "\n"), nil
	}

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

	resp, err := c.client.CreateChatCompletion(ctx, req)
	if err != nil {
		return "", err
	}
	if len(resp.Choices) == 0 {
		return "", fmt.Errorf("no response from LLM")
	}
	return resp.Choices[0].Message.Content, nil
}

func (c *OpenAILLMClient) createCompletion(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	resp, err := c.client.CreateCompletion(ctx, openai.CompletionRequest{
		Model:     c.model,
		Prompt:    formatCompletionPrompt(systemPrompt, userPrompt),
		MaxTokens: 4000,
	})
	if err != nil {
		return "", err
	}
	if len(resp.Choices) == 0 {
		return "", fmt.Errorf("no response from LLM")
	}
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
