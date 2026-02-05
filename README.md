# Fort (Fortress)

**AI-Native Secure Code Execution Sandbox**

Fort is an intelligent code execution sandbox that combines LLM-powered analysis with Docker container isolation. It automatically understands your code, generates optimal Dockerfiles, validates security, and executes safely.

```
╔═══════════════════════════════════════════════════════════════════╗
║   ███████╗ ██████╗ ██████╗ ████████╗                             ║
║   ██╔════╝██╔═══██╗██╔══██╗╚══██╔══╝                             ║
║   █████╗  ██║   ██║██████╔╝   ██║                                ║
║   ██╔══╝  ██║   ██║██╔══██╗   ██║                                ║
║   ██║     ╚██████╔╝██║  ██║   ██║                                ║
║   ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝                                ║
║                                                                   ║
║   Fortress - AI-Native Secure Code Execution                      ║
╚═══════════════════════════════════════════════════════════════════╝
```

## Features

- **LLM-Powered Analysis** - Automatically detects language, frameworks, dependencies, and entry points
- **Smart Dockerfile Generation** - LLM generates optimal multi-stage Dockerfiles for any project
- **40+ Security Patterns** - Static analysis detects command injection, reverse shells, crypto mining, etc.
- **Multi-File Projects** - Supports zip/tar archives with automatic project structure analysis
- **Defense in Depth** - Multiple validation layers before execution
- **15+ Languages** - Python, JavaScript, TypeScript, Go, Rust, Java, C/C++, PHP, Ruby, and more
- **Multiple LLM Providers** - OpenAI, OpenRouter, DeepSeek, Together, Groq, Ollama (local)

## Installation

```bash
# Clone the repository
git clone https://github.com/AbelJSeba/sandbox.git
cd sandbox

# Build
go build -o fort ./cmd/fort

# Or install directly
go install github.com/AbelJSeba/sandbox/cmd/fort@latest
```

### Requirements

- Go 1.22+
- Docker (for container execution)
- LLM API key (OpenAI, OpenRouter, DeepSeek, Together, Groq, or local Ollama)

## Quick Start

```bash
# Initialize config file (optional)
./fort -mode init-config

# Set your API key (choose one)
export OPENAI_API_KEY=sk-...           # OpenAI
export OPENROUTER_API_KEY=sk-or-...    # OpenRouter
export DEEPSEEK_API_KEY=sk-...         # DeepSeek
export TOGETHER_API_KEY=...            # Together AI
export GROQ_API_KEY=gsk_...            # Groq

# Execute Python code
./fort -code 'print("Hello, World!")'

# Execute from file
./fort -file script.py

# Use a specific provider
./fort -provider deepseek -model deepseek-coder -code 'print("Hello!")'

# Analyze without executing
./fort -mode analyze -file main.go

# Full sandbox flow + LLM artifact review
./fort -mode sandbox -file script.py -verbose

# Sandbox flow with raw LLM request/response dumps
./fort -mode sandbox -file script.py -verbose -llm-dump-dir .fort-llm-dumps

# Epic showcase workload (strict sandbox defaults)
./fort -mode sandbox -file examples/epic_sandbox_showcase.py -purpose "Epic sandbox demo" -verbose

# Quick security check (no LLM needed)
./fort -mode quick-validate -code 'import os; os.system("rm -rf /")'

# List available providers
./fort -list-providers
```

## How It Works

Fort uses a 5-phase pipeline:

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   ANALYZE   │───▶│  SYNTHESIZE │───▶│  VALIDATE   │───▶│    BUILD    │───▶│   EXECUTE   │
│             │    │             │    │             │    │             │    │             │
│ LLM detects │    │ LLM generates│   │ Static +    │    │ Docker      │    │ Run in      │
│ language,   │    │ Dockerfile  │    │ LLM security│    │ image build │    │ isolated    │
│ deps, entry │    │ & run cmd   │    │ review      │    │             │    │ container   │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
```

### Phase 1: Analyze
The LLM analyzes your code to detect:
- Programming language and runtime
- Frameworks and libraries used
- Dependencies to install
- Entry points and how to run
- Potential security risks

### Phase 2: Synthesize
The LLM generates an optimal Dockerfile:
- Chooses minimal base image (alpine/slim variants)
- Multi-stage builds for compiled languages
- Installs only necessary dependencies
- Creates non-root user for security
- Sets up proper entry point

### Phase 3: Validate
Multiple security checks:
- 40+ regex patterns for dangerous code
- LLM-based deep security review
- Policy enforcement (network, filesystem)
- Obfuscation detection

### Phase 4: Build
Creates a Docker image:
- Builds from generated Dockerfile
- Tags with execution ID
- Applies security labels

### Phase 5: Execute
Runs in isolated container:
- Resource limits (memory, CPU, PIDs)
- Network isolation (disabled by default)
- Read-only filesystem
- Non-root user
- Timeout enforcement

## CLI Usage

```
Usage: fort [options]

Modes:
  -mode string
        Mode: execute, analyze, validate, quick-validate, report, sandbox, init-config (default "execute")

Input:
  -file string
        Path to code file (or - for stdin)
  -code string
        Inline code to execute
  -lang string
        Language hint (python, go, js, etc.)
  -purpose string
        Description of what the code should do

LLM Provider:
  -provider string
        LLM provider: openai, openrouter, deepseek, together, groq, ollama
  -model string
        LLM model to use (provider-specific)
  -base-url string
        Custom LLM API base URL
  -llm-dump-dir string
        Directory to dump LLM requests/responses as JSON
  -config string
        Path to config file (default: auto-detect)
  -list-providers
        List available LLM providers

Execution:
  -timeout int
        Execution timeout in seconds (0 = use config default)
  -memory int
        Memory limit in MB (0 = use config default)
  -allow-network
        Allow network access (default: disabled)
  -no-validate
        Skip security validation (DANGEROUS)

Output:
  -json
        Output results as JSON
  -verbose
        Verbose output
  -banner
        Show banner (default: true)
  -version
        Show version
```

## Examples

### Execute Python Script
```bash
./fort -file examples/hello.py
```

### Execute with Network Access
```bash
./fort -code 'import requests; print(requests.get("https://api.github.com").status_code)' \
       -allow-network
```

### Analyze a Go Project
```bash
./fort -mode analyze -file main.go -purpose "HTTP server"
```

### Security Validation Only
```bash
./fort -mode validate -file untrusted_script.py
```

### Full Sandbox Pipeline with LLM Result Analysis
```bash
./fort -mode sandbox -file untrusted_script.py -verbose
```

This mode runs:
1. LLM code analysis
2. Container synthesis/build
3. Sandboxed execution
4. LLM parsing of execution artifacts:
   logs (`stdout`/`stderr`), output files captured from `/app/output`, and pipeline activity/phases

### Epic Sandbox Showcase
Run the included showcase script:

```bash
./fort -mode sandbox \
  -file examples/epic_sandbox_showcase.py \
  -purpose "Demonstrate sandbox controls and post-exec LLM review" \
  -verbose
```

For artifact-heavy output file parsing (in addition to logs/activity), use:

```bash
./fort -config examples/fort.sandbox-artifacts.yml \
  -mode sandbox \
  -file examples/epic_sandbox_showcase.py \
  -purpose "Artifact-rich sandbox demo" \
  -verbose
```

What to expect:
1. Normal compute succeeds.
2. Network attempt is blocked when `allow_network=false`.
3. Privileged write attempt (`/etc/...`) is denied.
4. LLM result analysis summarizes pipeline phases, logs, output files, and security implications.

### Quick Static Check (No API Key Needed)
```bash
./fort -mode quick-validate -code 'eval(input())'
# Output: ❌ UNSAFE - Security issues detected
#   1. 🟠 [high] Code injection via eval
```

### JSON Output for Automation
```bash
./fort -json -file script.py | jq '.result.stdout'
```

## Library Usage

```go
package main

import (
    "context"
    "fmt"
    "time"

    "github.com/AbelJSeba/sandbox/pkg/fort"
)

func main() {
    // Create agent
    config := fort.DefaultAgentConfig()
    config.LLMAPIKey = "your-openai-key"

    agent, err := fort.NewAgent(config)
    if err != nil {
        panic(err)
    }
    defer agent.Close()

    // Create execution request
    req := &fort.Request{
        ID:            "exec-001",
        CreatedAt:     time.Now(),
        SourceType:    fort.SourceInline,
        SourceContent: `print("Hello from Fort!")`,
        Language:      "python",
    }

    // Execute
    execution, err := agent.Execute(context.Background(), req)
    if err != nil {
        panic(err)
    }

    fmt.Printf("Success: %v\n", execution.Result.Success)
    fmt.Printf("Output: %s\n", execution.Result.Stdout)
}
```

### Quick Validation (No Docker)

```go
code := `import os; os.system("rm -rf /")`
safe, findings := fort.QuickValidate(code, nil)

if !safe {
    for _, f := range findings {
        fmt.Printf("[%s] %s\n", f.Severity, f.Description)
    }
}
```

### Multi-File Project

```go
// Extract from archive
zipData, _ := os.ReadFile("project.zip")
project, _ := fort.ExtractProject(zipData, "zip")

// Analyze project structure
analyzer := fort.NewProjectAnalyzer(llmClient)
analysis, _ := analyzer.AnalyzeProject(ctx, project, "run the web server")

fmt.Printf("Language: %s\n", analysis.DetectedLanguage)
fmt.Printf("Entry: %s\n", analysis.RecommendedEntry)
fmt.Printf("Dependencies: %d\n", len(project.Dependencies))

// Generate Dockerfile with LLM
synth := fort.NewSynthesizer(llmClient)
result, _ := synth.SynthesizeProject(ctx, project, analysis)

fmt.Println(result.Dockerfile)
```

## Security Features

### Container Isolation
| Feature | Default |
|---------|---------|
| Non-root user | ✅ Enabled |
| Read-only rootfs | ✅ Enabled |
| Network access | ❌ Disabled |
| Capability dropping | ✅ All dropped |
| PID limit | 100 |
| Memory limit | 256 MB |
| CPU limit | 1 core |
| Timeout | 60 seconds |

### Security Patterns Detected
- Command injection (`os.system`, `subprocess`, `exec`)
- Code injection (`eval`, `exec`, dynamic imports)
- Reverse shells (`/dev/tcp`, `nc -e`, `bash -i`)
- Crypto mining (`xmrig`, `stratum`, `hashrate`)
- File system attacks (`rm -rf /`, sensitive file access)
- Network exfiltration (socket connections, HTTP requests)
- Privilege escalation (`chmod 777`, `setuid`, `chown root`)
- Obfuscated code (high entropy, hex encoding)

## Supported Languages

| Language | Template | Build System |
|----------|----------|--------------|
| Python | ✅ | pip, pipenv, poetry |
| JavaScript | ✅ | npm, yarn, pnpm |
| TypeScript | ✅ | npm + tsc |
| Go | ✅ | go mod |
| Rust | ✅ | cargo |
| Java | ✅ | maven, gradle |
| C | ✅ | make, gcc |
| C++ | ✅ | make, cmake, g++ |
| PHP | ✅ | composer |
| Ruby | ✅ | bundler |
| Shell | ✅ | - |

## Configuration

### Config File

Fort looks for configuration in these locations (in order):
1. `./fort.yml` or `./fort.yaml`
2. `./.fort.yml` or `./.fort.yaml`
3. `~/.config/fort/config.yml`
4. `~/.fort.yml`

Generate an example config:
```bash
./fort -mode init-config
```

Example `fort.yml`:
```yaml
# LLM Provider Configuration
llm:
  provider: openai              # openai, openrouter, deepseek, together, groq, ollama
  model: gpt-4                  # Provider-specific model name
  # api_key: sk-...             # Optional: can use environment variables
  # base_url: https://...       # Optional: custom endpoint
  temperature: 0.1
  # dump_dir: .fort-llm-dumps   # Optional: write raw LLM request/response JSON

# Execution Defaults
execution:
  timeout_sec: 60
  memory_mb: 256
  cpu_limit: 1.0
  max_pids: 100

# Security Policy
security:
  allow_network: false
  allow_file_write: false
  require_validate: true

# Docker Configuration
docker:
  build_timeout: "5m"
  no_cache: false
```

### LLM Providers

| Provider | Environment Variable | Models |
|----------|---------------------|--------|
| OpenAI | `OPENAI_API_KEY` | gpt-4, gpt-4-turbo, gpt-4o, gpt-3.5-turbo |
| OpenRouter | `OPENROUTER_API_KEY` | anthropic/claude-3-opus, openai/gpt-4-turbo, etc. |
| DeepSeek | `DEEPSEEK_API_KEY` | deepseek-chat, deepseek-coder |
| Together | `TOGETHER_API_KEY` | meta-llama/Llama-3-70b-chat-hf, etc. |
| Groq | `GROQ_API_KEY` | llama-3.1-70b-versatile, mixtral-8x7b-32768 |
| Ollama | (none - local) | llama3, codellama, mistral |

#### Using DeepSeek (cost-effective)
```bash
export DEEPSEEK_API_KEY=sk-...
./fort -provider deepseek -model deepseek-coder -code 'print("Hello!")'
```

#### Using OpenRouter (access to many models)
```bash
export OPENROUTER_API_KEY=sk-or-...
./fort -provider openrouter -model anthropic/claude-3-sonnet -code 'print("Hello!")'
```

#### Using Ollama (local, free)
```bash
# Start Ollama first: ollama serve
./fort -provider ollama -model llama3 -code 'print("Hello!")'
```

### Environment Variables

```bash
# Provider-specific API keys
OPENAI_API_KEY=sk-...
OPENROUTER_API_KEY=sk-or-...
DEEPSEEK_API_KEY=sk-...
TOGETHER_API_KEY=...
GROQ_API_KEY=gsk_...

# Generic fallbacks
FORT_API_KEY=...               # Used if provider-specific key not found
LLM_API_KEY=...                # Alternative generic key
FORT_LLM_DUMP_DIR=.fort-llm-dumps
```

### Security Policy (Library)

```go
policy := fort.SecurityPolicy{
    AllowNetwork:   false,        // Disable network
    AllowFileWrite: false,        // Read-only filesystem
    AllowFileRead:  true,         // Allow reading files
    MaxMemoryMB:    256,          // Memory limit
    MaxCPU:         1.0,          // CPU cores
    MaxTimeoutSec:  60,           // Execution timeout
    MaxOutputBytes: 100 * 1024,   // Max output size
    SandboxLevel:   "strict",     // Isolation level
}
```

## Project Structure

```
fort-sandbox/
├── cmd/fort/
│   └── main.go           # CLI application
├── pkg/fort/
│   ├── agent.go          # Main orchestration
│   ├── analyzer.go       # Code analysis
│   ├── synthesizer.go    # Dockerfile generation
│   ├── validator.go      # Security validation
│   ├── builder.go        # Docker image building
│   ├── executor.go       # Container execution
│   ├── project.go        # Multi-file project support
│   ├── llm.go            # LLM client abstraction
│   ├── config.go         # Configuration & providers
│   └── types.go          # Domain types
├── fort.example.yml      # Example configuration
├── go.mod
├── go.sum
└── README.md
```

## Roadmap

- [ ] API server mode (`fort serve`)
- [ ] OpenAI Code Interpreter integration
- [ ] WebAssembly sandbox (lighter alternative)
- [ ] Dependency caching
- [ ] Execution history/replay
- [ ] gVisor runtime support
- [ ] Webhook notifications

## Contributing

Contributions welcome! Please open an issue or PR.

## License

MIT License

## Acknowledgments

- OpenAI for LLM capabilities
- Docker for containerization
- The Go community
