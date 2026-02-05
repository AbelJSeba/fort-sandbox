package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/AbelJSeba/sandbox/pkg/fort"
)

var version = "dev"

const banner = `
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║   ███████╗ ██████╗ ██████╗ ████████╗                             ║
║   ██╔════╝██╔═══██╗██╔══██╗╚══██╔══╝                             ║
║   █████╗  ██║   ██║██████╔╝   ██║                                ║
║   ██╔══╝  ██║   ██║██╔══██╗   ██║                                ║
║   ██║     ╚██████╔╝██║  ██║   ██║                                ║
║   ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝                                ║
║                                                                   ║
║   Fortress - AI-Native Secure Code Execution                      ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
`

func main() {
	var (
		mode         = flag.String("mode", "execute", "Mode: execute, analyze, validate, quick-validate, init-config")
		file         = flag.String("file", "", "Path to code file (or - for stdin)")
		code         = flag.String("code", "", "Inline code to execute")
		lang         = flag.String("lang", "", "Language hint (python, go, js, etc.)")
		purpose      = flag.String("purpose", "", "Description of what the code should do")
		timeout      = flag.Int("timeout", 0, "Execution timeout in seconds (0 = use config)")
		memoryMB     = flag.Int("memory", 0, "Memory limit in MB (0 = use config)")
		allowNet     = flag.Bool("allow-network", false, "Allow network access")
		jsonOutput   = flag.Bool("json", false, "Output results as JSON")
		noValidate   = flag.Bool("no-validate", false, "Skip security validation (DANGEROUS)")
		verbose      = flag.Bool("verbose", false, "Verbose output")
		showBanner   = flag.Bool("banner", true, "Show banner")
		showVersion  = flag.Bool("version", false, "Show version")
		configFile   = flag.String("config", "", "Path to config file (default: auto-detect)")
		llmProvider  = flag.String("provider", "", "LLM provider: openai, openrouter, deepseek, together, groq, ollama")
		llmModel     = flag.String("model", "", "LLM model to use")
		llmBaseURL   = flag.String("base-url", "", "Custom LLM API base URL")
		listProviders = flag.Bool("list-providers", false, "List available LLM providers")
	)
	flag.Parse()

	if *showVersion {
		fmt.Printf("Fort %s\n", version)
		return
	}

	if *showBanner && !*jsonOutput && *mode != "init-config" && !*listProviders {
		fmt.Print(banner)
	}

	if *listProviders {
		printProviders()
		return
	}

	// Handle init-config mode
	if *mode == "init-config" {
		initConfig(*configFile)
		return
	}

	// Load configuration
	var cfg *fort.Config
	var err error
	if *configFile != "" {
		cfg, err = fort.LoadConfig(*configFile)
		if err != nil {
			fatal("Failed to load config: %v", err)
		}
	} else {
		cfg, err = fort.LoadConfigFromDefaultPaths()
		if err != nil {
			fatal("Failed to load config: %v", err)
		}
	}

	// Override config with CLI flags
	if *llmProvider != "" {
		cfg.LLM.Provider = *llmProvider
	}
	if *llmModel != "" {
		cfg.LLM.Model = *llmModel
	}
	if *llmBaseURL != "" {
		cfg.LLM.BaseURL = *llmBaseURL
	}
	if *timeout > 0 {
		cfg.Execution.TimeoutSec = *timeout
	}
	if *memoryMB > 0 {
		cfg.Execution.MemoryMB = *memoryMB
	}
	if *allowNet {
		cfg.Security.AllowNetwork = true
	}
	if *noValidate {
		cfg.Security.RequireValidate = false
	}

	// Resolve API key
	apiKey := cfg.ResolveAPIKey()
	if apiKey == "" && *mode != "quick-validate" {
		providerInfo := fort.KnownProviders[cfg.LLM.Provider]
		envHint := "OPENAI_API_KEY"
		if providerInfo.EnvKey != "" {
			envHint = providerInfo.EnvKey
		}
		fatal("No API key found. Set %s environment variable or add api_key to config file", envHint)
	}

	sourceCode, err := getSourceCode(*file, *code)
	if err != nil {
		fatal("Failed to get source code: %v", err)
	}

	if sourceCode == "" && *mode != "init-config" {
		flag.Usage()
		fatal("No code provided. Use -file or -code")
	}

	// Convert config to agent config
	agentConfig := cfg.ToAgentConfig()

	if *verbose {
		fmt.Printf("Provider: %s\n", cfg.LLM.Provider)
		fmt.Printf("Model: %s\n", cfg.ResolveModel())
		fmt.Printf("Base URL: %s\n", cfg.ResolveBaseURL())
		fmt.Println()
	}

	agent, err := fort.NewAgent(agentConfig)
	if err != nil {
		fatal("Failed to create agent: %v", err)
	}
	defer agent.Close()

	req := &fort.Request{
		ID:            generateID(),
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		SubmittedBy:   "cli-user",
		SourceType:    fort.SourceInline,
		SourceContent: sourceCode,
		Language:      *lang,
		Purpose:       *purpose,
		MaxTimeoutSec: *timeout,
		MaxMemoryMB:   *memoryMB,
		AllowNetwork:  *allowNet,
		Status:        fort.StatusPending,
		CurrentPhase:  fort.PhaseAnalysis,
	}

	if *allowNet {
		req.SecurityPolicy.AllowNetwork = true
	}

	ctx := context.Background()

	switch *mode {
	case "quick-validate":
		runQuickValidate(agent, sourceCode, *jsonOutput)

	case "validate":
		runValidate(ctx, agent, req, *verbose, *jsonOutput)

	case "analyze":
		runAnalyze(ctx, agent, req, *verbose, *jsonOutput)

	case "execute":
		runExecute(ctx, agent, req, *verbose, *jsonOutput)

	default:
		fatal("Unknown mode: %s", *mode)
	}
}

func getSourceCode(file, code string) (string, error) {
	if code != "" {
		return code, nil
	}

	if file == "" {
		return "", nil
	}

	var reader io.Reader
	if file == "-" {
		reader = os.Stdin
	} else {
		f, err := os.Open(file)
		if err != nil {
			return "", err
		}
		defer f.Close()
		reader = f
	}

	data, err := io.ReadAll(reader)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func runQuickValidate(agent *fort.Agent, code string, jsonOutput bool) {
	fmt.Println("\n[Quick Validation] Running static analysis...")

	safe, findings := agent.QuickValidate(code, nil)

	if jsonOutput {
		output := map[string]interface{}{
			"safe":     safe,
			"findings": findings,
		}
		printJSON(output)
		return
	}

	if safe {
		fmt.Println("\n✅ SAFE - No critical security issues detected")
	} else {
		fmt.Println("\n❌ UNSAFE - Security issues detected")
	}

	if len(findings) > 0 {
		fmt.Println("\nFindings:")
		for i, f := range findings {
			icon := severityIcon(string(f.Severity))
			fmt.Printf("  %d. %s [%s] %s\n", i+1, icon, f.Severity, f.Description)
			if f.Location != "" {
				fmt.Printf("     Location: %s\n", f.Location)
			}
			if f.Evidence != "" {
				evidence := truncate(f.Evidence, 100)
				fmt.Printf("     Evidence: %s\n", evidence)
			}
		}
	}

	if !safe {
		os.Exit(1)
	}
}

func runValidate(ctx context.Context, agent *fort.Agent, req *fort.Request, verbose, jsonOutput bool) {
	fmt.Println("\n[Validation] Running full security validation...")

	result, err := agent.Validate(ctx, req)
	if err != nil {
		fatal("Validation failed: %v", err)
	}

	if jsonOutput {
		printJSON(result)
		return
	}

	fmt.Println()
	if result.Safe {
		fmt.Println("✅ SAFE - Code passed security validation")
	} else {
		fmt.Println("❌ UNSAFE - Code failed security validation")
		fmt.Printf("   Reason: %s\n", result.RejectionReason)
	}

	fmt.Printf("\nRisk Level: %s (confidence: %.0f%%)\n", result.RiskLevel, result.Confidence*100)

	if len(result.Findings) > 0 {
		fmt.Println("\nFindings:")
		for i, f := range result.Findings {
			icon := severityIcon(string(f.Severity))
			mitigated := ""
			if f.Mitigated {
				mitigated = " (mitigated by sandbox)"
			}
			fmt.Printf("  %d. %s [%s] %s%s\n", i+1, icon, f.Severity, f.Description, mitigated)
		}
	}

	if len(result.PolicyViolations) > 0 {
		fmt.Println("\nPolicy Violations:")
		for _, v := range result.PolicyViolations {
			fmt.Printf("  • %s: %s\n", v.Policy, v.Description)
		}
	}

	if len(result.Recommendations) > 0 {
		fmt.Println("\nRecommendations:")
		for _, r := range result.Recommendations {
			fmt.Printf("  • %s\n", r)
		}
	}

	if !result.Safe {
		os.Exit(1)
	}
}

func runAnalyze(ctx context.Context, agent *fort.Agent, req *fort.Request, verbose, jsonOutput bool) {
	fmt.Println("\n[Analysis] Analyzing code...")

	result, err := agent.Analyze(ctx, req)
	if err != nil {
		fatal("Analysis failed: %v", err)
	}

	if jsonOutput {
		printJSON(result)
		return
	}

	fmt.Println()
	fmt.Printf("Language:   %s\n", result.DetectedLanguage)
	fmt.Printf("Runtime:    %s\n", result.DetectedRuntime)
	fmt.Printf("Complexity: %s\n", result.Complexity)
	fmt.Printf("Est. Time:  %s\n", result.EstimatedRuntime)

	if len(result.DetectedFrameworks) > 0 {
		fmt.Printf("Frameworks: %s\n", strings.Join(result.DetectedFrameworks, ", "))
	}

	fmt.Printf("\nSummary: %s\n", result.Summary)

	if len(result.DetectedEntryPoints) > 0 {
		fmt.Printf("\nEntry Points: %s\n", strings.Join(result.DetectedEntryPoints, ", "))
		fmt.Printf("Recommended:  %s\n", result.RecommendedEntry)
	}

	if len(result.InferredDependencies) > 0 {
		fmt.Println("\nDependencies:")
		for _, dep := range result.InferredDependencies {
			ver := dep.Version
			if ver == "" {
				ver = "latest"
			}
			fmt.Printf("  • %s@%s (%s)\n", dep.Name, ver, dep.Source)
		}
	}

	if len(result.PotentialRisks) > 0 {
		fmt.Println("\n⚠️  Potential Risks:")
		for _, risk := range result.PotentialRisks {
			fmt.Printf("  • %s\n", risk)
		}
	}

	if result.RequiresReview {
		fmt.Println("\n⚠️  This code requires manual review before execution")
	}
}

func runExecute(ctx context.Context, agent *fort.Agent, req *fort.Request, verbose, jsonOutput bool) {
	fmt.Println("\n[Execution] Running full pipeline...")

	if verbose {
		fmt.Println("  → Phase 1: Analysis")
	}

	execution, err := agent.Execute(ctx, req)

	if jsonOutput {
		output := map[string]interface{}{
			"execution": execution,
			"error":     nil,
		}
		if err != nil {
			output["error"] = err.Error()
		}
		printJSON(output)
		return
	}

	fmt.Println()
	for _, phase := range execution.Phases {
		icon := "✅"
		if !phase.Success {
			icon = "❌"
		}
		duration := ""
		if phase.EndedAt != nil {
			duration = fmt.Sprintf(" (%.2fs)", phase.EndedAt.Sub(phase.StartedAt).Seconds())
		}
		fmt.Printf("%s %s%s\n", icon, phase.Phase, duration)
		if phase.Error != "" && verbose {
			fmt.Printf("   Error: %s\n", phase.Error)
		}
	}

	if execution.Analysis != nil && verbose {
		fmt.Printf("\nDetected: %s (%s)\n", execution.Analysis.DetectedLanguage, execution.Analysis.DetectedRuntime)
		fmt.Printf("Summary: %s\n", execution.Analysis.Summary)
	}

	if execution.Validation != nil {
		fmt.Println()
		if execution.Validation.Safe {
			fmt.Printf("Security: ✅ SAFE (risk: %s)\n", execution.Validation.RiskLevel)
		} else {
			fmt.Printf("Security: ❌ REJECTED - %s\n", execution.Validation.RejectionReason)
		}
	}

	if execution.Result != nil {
		fmt.Println()
		fmt.Println("═══════════════════════════════════════════════")
		fmt.Println("EXECUTION RESULT")
		fmt.Println("═══════════════════════════════════════════════")

		if execution.Result.Success {
			fmt.Println("Status: ✅ SUCCESS")
		} else if execution.Result.TimedOut {
			fmt.Println("Status: ⏰ TIMEOUT")
		} else if execution.Result.Killed {
			fmt.Printf("Status: 💀 KILLED - %s\n", execution.Result.KillReason)
		} else {
			fmt.Printf("Status: ❌ FAILED (exit code: %d)\n", execution.Result.ExitCode)
		}

		fmt.Printf("Wall time: %dms\n", execution.Result.WallTimeMs)

		if execution.Result.Stdout != "" {
			fmt.Println("\n--- STDOUT ---")
			fmt.Println(execution.Result.Stdout)
		}

		if execution.Result.Stderr != "" {
			fmt.Println("\n--- STDERR ---")
			fmt.Println(execution.Result.Stderr)
		}
	}

	if err != nil {
		fmt.Printf("\n❌ Error: %v\n", err)
		os.Exit(1)
	}

	if execution.Result != nil && !execution.Result.Success {
		os.Exit(execution.Result.ExitCode)
	}
}

func severityIcon(severity string) string {
	switch severity {
	case "critical":
		return "🔴"
	case "high":
		return "🟠"
	case "medium":
		return "🟡"
	case "low":
		return "🟢"
	default:
		return "⚪"
	}
}

func truncate(s string, maxLen int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}

func printJSON(v interface{}) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

func fatal(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "Error: "+format+"\n", args...)
	os.Exit(1)
}

func generateID() string {
	return fmt.Sprintf("exec_%d", time.Now().UnixNano())
}

func printProviders() {
	fmt.Println("Available LLM Providers:")
	fmt.Println()
	for id, p := range fort.KnownProviders {
		fmt.Printf("  %s (%s)\n", id, p.Name)
		fmt.Printf("    Base URL: %s\n", p.BaseURL)
		if p.EnvKey != "" {
			fmt.Printf("    Env Key:  %s\n", p.EnvKey)
		}
		fmt.Printf("    Models:   %s\n", strings.Join(p.Models, ", "))
		fmt.Printf("    Default:  %s\n", p.DefaultModel)
		fmt.Println()
	}
}

func initConfig(path string) {
	if path == "" {
		path = "fort.yml"
	}

	// Check if file already exists
	if _, err := os.Stat(path); err == nil {
		fmt.Printf("Config file already exists: %s\n", path)
		fmt.Println("Remove it first or specify a different path with -config")
		os.Exit(1)
	}

	content := fort.GenerateExampleConfig()
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		fatal("Failed to write config file: %v", err)
	}

	fmt.Printf("Created config file: %s\n", path)
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Println("  1. Edit the config file to set your preferred provider and API key")
	fmt.Println("  2. Or set the appropriate environment variable:")
	fmt.Println("     - OpenAI:     export OPENAI_API_KEY=sk-...")
	fmt.Println("     - OpenRouter: export OPENROUTER_API_KEY=sk-or-...")
	fmt.Println("     - DeepSeek:   export DEEPSEEK_API_KEY=sk-...")
	fmt.Println("     - Together:   export TOGETHER_API_KEY=...")
	fmt.Println("     - Groq:       export GROQ_API_KEY=gsk_...")
}
