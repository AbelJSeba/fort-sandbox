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
- OpenAI API key (for LLM analysis)

## Quick Start

```bash
# Set your OpenAI API key
export OPENAI_API_KEY=your-key-here

# Execute Python code
./fort -code 'print("Hello, World!")'

# Execute from file
./fort -file script.py

# Analyze without executing
./fort -mode analyze -file main.go

# Quick security check (no LLM needed)
./fort -mode quick-validate -code 'import os; os.system("rm -rf /")'
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

Options:
  -mode string
        Mode: execute, analyze, validate, quick-validate (default "execute")
  -file string
        Path to code file (or - for stdin)
  -code string
        Inline code to execute
  -lang string
        Language hint (python, go, js, etc.)
  -purpose string
        Description of what the code should do
  -timeout int
        Execution timeout in seconds (default 60)
  -memory int
        Memory limit in MB (default 256)
  -allow-network
        Allow network access (default: disabled)
  -no-validate
        Skip security validation (DANGEROUS)
  -json
        Output results as JSON
  -verbose
        Verbose output
  -model string
        LLM model to use (default "gpt-4")
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

### Environment Variables

```bash
OPENAI_API_KEY=sk-...        # Required for LLM analysis
OPENAI_MODEL=gpt-4           # Model to use (default: gpt-4)
```

### Security Policy

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
│   └── types.go          # Domain types
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
