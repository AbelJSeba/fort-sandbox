package fort

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config represents the Fort configuration file structure
type Config struct {
	// LLM provider configuration
	LLM LLMConfig `yaml:"llm"`

	// Execution defaults
	Execution ExecutionConfig `yaml:"execution"`

	// Security policy defaults
	Security SecurityConfig `yaml:"security"`

	// Docker configuration
	Docker DockerConfig `yaml:"docker"`
}

// LLMConfig holds LLM provider settings
type LLMConfig struct {
	// Provider: openai, openrouter, deepseek, or custom
	Provider string `yaml:"provider"`

	// Model name (e.g., gpt-4, deepseek-chat, anthropic/claude-3-opus)
	Model string `yaml:"model"`

	// API key (can also be set via environment variable)
	APIKey string `yaml:"api_key"`

	// Base URL for custom/self-hosted endpoints
	BaseURL string `yaml:"base_url"`

	// Temperature for LLM responses (0.0-1.0)
	Temperature float32 `yaml:"temperature"`
}

// ExecutionConfig holds default execution settings
type ExecutionConfig struct {
	TimeoutSec int     `yaml:"timeout_sec"`
	MemoryMB   int     `yaml:"memory_mb"`
	CPULimit   float64 `yaml:"cpu_limit"`
	MaxPIDs    int     `yaml:"max_pids"`
}

// SecurityConfig holds security policy defaults
type SecurityConfig struct {
	AllowNetwork    bool     `yaml:"allow_network"`
	AllowFileWrite  bool     `yaml:"allow_file_write"`
	RequireValidate bool     `yaml:"require_validate"`
	BlockedPatterns []string `yaml:"blocked_patterns"`
}

// DockerConfig holds Docker-specific settings
type DockerConfig struct {
	BuildTimeout string `yaml:"build_timeout"`
	NoCache      bool   `yaml:"no_cache"`
	Runtime      string `yaml:"runtime"`
}

// ProviderInfo contains provider-specific defaults
type ProviderInfo struct {
	Name       string
	BaseURL    string
	EnvKey     string
	Models     []string
	DefaultModel string
}

// Known providers with their configurations
var KnownProviders = map[string]ProviderInfo{
	"openai": {
		Name:         "OpenAI",
		BaseURL:      "https://api.openai.com/v1",
		EnvKey:       "OPENAI_API_KEY",
		Models:       []string{"gpt-4", "gpt-4-turbo", "gpt-4o", "gpt-4o-mini", "gpt-3.5-turbo"},
		DefaultModel: "gpt-4",
	},
	"openrouter": {
		Name:         "OpenRouter",
		BaseURL:      "https://openrouter.ai/api/v1",
		EnvKey:       "OPENROUTER_API_KEY",
		Models:       []string{"anthropic/claude-3-opus", "anthropic/claude-3-sonnet", "openai/gpt-4-turbo", "google/gemini-pro", "meta-llama/llama-3-70b-instruct"},
		DefaultModel: "anthropic/claude-3-sonnet",
	},
	"deepseek": {
		Name:         "DeepSeek",
		BaseURL:      "https://api.deepseek.com",
		EnvKey:       "DEEPSEEK_API_KEY",
		Models:       []string{"deepseek-chat", "deepseek-coder"},
		DefaultModel: "deepseek-chat",
	},
	"together": {
		Name:         "Together AI",
		BaseURL:      "https://api.together.xyz/v1",
		EnvKey:       "TOGETHER_API_KEY",
		Models:       []string{"meta-llama/Llama-3-70b-chat-hf", "mistralai/Mixtral-8x7B-Instruct-v0.1"},
		DefaultModel: "meta-llama/Llama-3-70b-chat-hf",
	},
	"groq": {
		Name:         "Groq",
		BaseURL:      "https://api.groq.com/openai/v1",
		EnvKey:       "GROQ_API_KEY",
		Models:       []string{"llama-3.1-70b-versatile", "llama-3.1-8b-instant", "mixtral-8x7b-32768"},
		DefaultModel: "llama-3.1-70b-versatile",
	},
	"ollama": {
		Name:         "Ollama (Local)",
		BaseURL:      "http://localhost:11434/v1",
		EnvKey:       "",
		Models:       []string{"llama3", "codellama", "mistral", "mixtral"},
		DefaultModel: "llama3",
	},
}

// DefaultConfig returns sensible defaults
func DefaultConfig() *Config {
	return &Config{
		LLM: LLMConfig{
			Provider:    "openai",
			Model:       "gpt-4",
			Temperature: 0.1,
		},
		Execution: ExecutionConfig{
			TimeoutSec: 60,
			MemoryMB:   256,
			CPULimit:   1.0,
			MaxPIDs:    100,
		},
		Security: SecurityConfig{
			AllowNetwork:    false,
			AllowFileWrite:  false,
			RequireValidate: true,
		},
		Docker: DockerConfig{
			BuildTimeout: "5m",
			NoCache:      false,
		},
	}
}

// LoadConfig loads configuration from a YAML file
func LoadConfig(path string) (*Config, error) {
	config := DefaultConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return config, nil // Return defaults if no config file
		}
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return config, nil
}

// LoadConfigFromDefaultPaths tries to load config from standard locations
func LoadConfigFromDefaultPaths() (*Config, error) {
	paths := []string{
		"fort.yml",
		"fort.yaml",
		".fort.yml",
		".fort.yaml",
	}

	// Check home directory
	if home, err := os.UserHomeDir(); err == nil {
		paths = append(paths,
			filepath.Join(home, ".config", "fort", "config.yml"),
			filepath.Join(home, ".config", "fort", "config.yaml"),
			filepath.Join(home, ".fort.yml"),
			filepath.Join(home, ".fort.yaml"),
		)
	}

	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return LoadConfig(path)
		}
	}

	return DefaultConfig(), nil
}

// ResolveAPIKey resolves the API key from config or environment
func (c *Config) ResolveAPIKey() string {
	// Config file API key takes precedence
	if c.LLM.APIKey != "" {
		return c.LLM.APIKey
	}

	// Check provider-specific environment variable
	if provider, ok := KnownProviders[c.LLM.Provider]; ok {
		if provider.EnvKey != "" {
			if key := os.Getenv(provider.EnvKey); key != "" {
				return key
			}
		}
	}

	// Fallback to generic environment variables
	envKeys := []string{
		"FORT_API_KEY",
		"LLM_API_KEY",
		"OPENAI_API_KEY", // Common fallback
	}

	for _, key := range envKeys {
		if val := os.Getenv(key); val != "" {
			return val
		}
	}

	return ""
}

// ResolveBaseURL resolves the base URL for the configured provider
func (c *Config) ResolveBaseURL() string {
	// Explicit base URL takes precedence
	if c.LLM.BaseURL != "" {
		return c.LLM.BaseURL
	}

	// Use known provider defaults
	if provider, ok := KnownProviders[c.LLM.Provider]; ok {
		return provider.BaseURL
	}

	// Default to OpenAI
	return KnownProviders["openai"].BaseURL
}

// ResolveModel resolves the model name
func (c *Config) ResolveModel() string {
	if c.LLM.Model != "" {
		return c.LLM.Model
	}

	if provider, ok := KnownProviders[c.LLM.Provider]; ok {
		return provider.DefaultModel
	}

	return "gpt-4"
}

// ToAgentConfig converts Config to AgentConfig
func (c *Config) ToAgentConfig() AgentConfig {
	config := DefaultAgentConfig()

	config.LLMProvider = c.LLM.Provider
	config.LLMModel = c.ResolveModel()
	config.LLMAPIKey = c.ResolveAPIKey()
	config.LLMBaseURL = c.ResolveBaseURL()

	config.RequireValidation = c.Security.RequireValidate

	config.DefaultPolicy.AllowNetwork = c.Security.AllowNetwork
	config.DefaultPolicy.AllowFileWrite = c.Security.AllowFileWrite
	config.DefaultPolicy.MaxMemoryMB = c.Execution.MemoryMB
	config.DefaultPolicy.MaxCPU = c.Execution.CPULimit
	config.DefaultPolicy.MaxTimeoutSec = c.Execution.TimeoutSec

	config.ExecutorConfig.DefaultTimeout = c.Execution.TimeoutSec
	config.ExecutorConfig.DefaultMemoryMB = c.Execution.MemoryMB
	config.ExecutorConfig.MaxPIDs = c.Execution.MaxPIDs

	config.NoBuildCache = c.Docker.NoCache

	return config
}

// WriteConfig writes configuration to a YAML file
func WriteConfig(config *Config, path string) error {
	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	return os.WriteFile(path, data, 0644)
}

// GenerateExampleConfig generates an example configuration file
func GenerateExampleConfig() string {
	return `# Fort Configuration File
# Place this file at: ./fort.yml, ~/.config/fort/config.yml, or ~/.fort.yml

# LLM Provider Configuration
llm:
  # Provider: openai, openrouter, deepseek, together, groq, ollama, or custom
  provider: openai

  # Model name (provider-specific)
  # OpenAI: gpt-4, gpt-4-turbo, gpt-4o, gpt-3.5-turbo
  # OpenRouter: anthropic/claude-3-opus, openai/gpt-4-turbo, etc.
  # DeepSeek: deepseek-chat, deepseek-coder
  # Together: meta-llama/Llama-3-70b-chat-hf
  # Groq: llama-3.1-70b-versatile
  # Ollama: llama3, codellama, mistral
  model: gpt-4

  # API key (optional - can use environment variables instead)
  # Environment variables checked: OPENAI_API_KEY, OPENROUTER_API_KEY,
  # DEEPSEEK_API_KEY, TOGETHER_API_KEY, GROQ_API_KEY, FORT_API_KEY
  # api_key: sk-your-api-key-here

  # Custom base URL (optional - for self-hosted or proxy endpoints)
  # base_url: https://api.example.com/v1

  # Temperature for LLM responses (0.0-1.0, lower = more deterministic)
  temperature: 0.1

# Execution Defaults
execution:
  timeout_sec: 60      # Maximum execution time
  memory_mb: 256       # Memory limit
  cpu_limit: 1.0       # CPU cores limit
  max_pids: 100        # Maximum processes

# Security Policy
security:
  allow_network: false    # Allow network access in containers
  allow_file_write: false # Allow writing to filesystem
  require_validate: true  # Run security validation before execution
  # blocked_patterns:     # Additional patterns to block
  #   - "crypto.*mine"
  #   - "botnet"

# Docker Configuration
docker:
  build_timeout: "5m"   # Docker build timeout
  no_cache: false       # Disable Docker build cache
  # runtime: ""         # Alternative runtime (e.g., runsc for gVisor)
`
}
