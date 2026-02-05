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
		mode          = flag.String("mode", "execute", "Mode: execute, analyze, validate, quick-validate, report, sandbox, init-config")
		file          = flag.String("file", "", "Path to code file (or - for stdin)")
		code          = flag.String("code", "", "Inline code to execute")
		lang          = flag.String("lang", "", "Language hint (python, go, js, etc.)")
		purpose       = flag.String("purpose", "", "Description of what the code should do")
		timeout       = flag.Int("timeout", 0, "Execution timeout in seconds (0 = use config)")
		memoryMB      = flag.Int("memory", 0, "Memory limit in MB (0 = use config)")
		allowNet      = flag.Bool("allow-network", false, "Allow network access")
		jsonOutput    = flag.Bool("json", false, "Output results as JSON")
		noValidate    = flag.Bool("no-validate", false, "Skip security validation (DANGEROUS)")
		verbose       = flag.Bool("verbose", false, "Verbose output")
		showBanner    = flag.Bool("banner", true, "Show banner")
		showVersion   = flag.Bool("version", false, "Show version")
		configFile    = flag.String("config", "", "Path to config file (default: auto-detect)")
		llmProvider   = flag.String("provider", "", "LLM provider: openai, openrouter, deepseek, together, groq, ollama")
		llmModel      = flag.String("model", "", "LLM model to use")
		llmBaseURL    = flag.String("base-url", "", "Custom LLM API base URL")
		llmDumpDir    = flag.String("llm-dump-dir", "", "Directory to dump LLM requests/responses as JSON")
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
	if *llmDumpDir != "" {
		cfg.LLM.DumpDir = *llmDumpDir
	} else if cfg.LLM.DumpDir == "" {
		cfg.LLM.DumpDir = os.Getenv("FORT_LLM_DUMP_DIR")
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
	if apiKey == "" && modeRequiresLLM(*mode) {
		providerInfo := fort.KnownProviders[cfg.LLM.Provider]
		envHint := "OPENAI_API_KEY"
		if providerInfo.EnvKey != "" {
			envHint = providerInfo.EnvKey
		}
		fatal("No API key found. Set %s environment variable or add api_key to config file", envHint)
	}

	sourceCode := ""
	if modeRequiresSourceCode(*mode) {
		sourceCode, err = getSourceCode(*file, *code)
		if err != nil {
			fatal("Failed to get source code: %v", err)
		}
		if sourceCode == "" {
			flag.Usage()
			fatal("No code provided. Use -file or -code")
		}
	}

	// Convert config to agent config
	agentConfig := cfg.ToAgentConfig()
	agentConfig.Verbose = *verbose

	if *verbose {
		fmt.Printf("Provider: %s\n", cfg.LLM.Provider)
		fmt.Printf("Model: %s\n", cfg.ResolveModel())
		fmt.Printf("Base URL: %s\n", cfg.ResolveBaseURL())
		if cfg.LLM.DumpDir != "" {
			fmt.Printf("LLM dump dir: %s\n", cfg.LLM.DumpDir)
		}
		fmt.Println()
	}

	ctx := context.Background()

	switch *mode {
	case "report":
		runReport(ctx, agentConfig, sourceCode, *lang, *purpose, *verbose)
		return
	case "sandbox":
		runSandbox(ctx, agentConfig, sourceCode, *lang, *purpose, *timeout, *memoryMB, *allowNet, *verbose, *jsonOutput)
		return
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

func modeRequiresLLM(mode string) bool {
	switch mode {
	case "quick-validate", "init-config":
		return false
	default:
		return true
	}
}

func modeRequiresSourceCode(mode string) bool {
	switch mode {
	case "init-config":
		return false
	default:
		return true
	}
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
		fmt.Printf("  → Request ID: %s\n", req.ID)
		fmt.Printf("  → Requested limits: timeout=%ds memory=%dMB network=%t\n", req.MaxTimeoutSec, req.MaxMemoryMB, req.AllowNetwork)
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

func runSandbox(
	ctx context.Context,
	config fort.AgentConfig,
	code, lang, purpose string,
	timeoutSec, memoryMB int,
	allowNetwork, verbose, jsonOutput bool,
) {
	if !jsonOutput {
		fmt.Println("\n[Sandbox] Full pipeline: LLM analysis -> build -> sandbox execution -> LLM result analysis")
	}

	agent, err := fort.NewAgent(config)
	if err != nil {
		fatal("Failed to create sandbox agent: %v", err)
	}
	defer agent.Close()

	policy := config.DefaultPolicy
	policy.AllowNetwork = allowNetwork
	if timeoutSec > 0 {
		policy.MaxTimeoutSec = timeoutSec
	}
	if memoryMB > 0 {
		policy.MaxMemoryMB = memoryMB
	}

	req := &fort.Request{
		ID:             generateID(),
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
		SubmittedBy:    "sandbox-user",
		SourceType:     fort.SourceInline,
		SourceContent:  code,
		Language:       lang,
		Purpose:        purpose,
		MaxTimeoutSec:  timeoutSec,
		MaxMemoryMB:    memoryMB,
		AllowNetwork:   allowNetwork,
		SecurityPolicy: policy,
		Status:         fort.StatusPending,
		CurrentPhase:   fort.PhaseAnalysis,
	}

	if verbose && !jsonOutput {
		fmt.Println("  -> Running secure execution pipeline...")
		fmt.Printf("  -> Request ID: %s\n", req.ID)
		fmt.Printf("  -> Policy: timeout=%ds memory=%dMB cpu=%.2f network=%t file_write=%t\n",
			policy.MaxTimeoutSec, policy.MaxMemoryMB, policy.MaxCPU, policy.AllowNetwork, policy.AllowFileWrite)
	}

	execution, execErr := agent.Execute(ctx, req)

	var llm *fort.OpenAILLMClient
	if config.LLMBaseURL != "" {
		llm = fort.NewOpenAILLMClientWithBaseURL(config.LLMAPIKey, config.LLMModel, config.LLMBaseURL)
	} else {
		llm = fort.NewOpenAILLMClient(config.LLMAPIKey, config.LLMModel)
	}
	llm.SetDebugOptions(config.Verbose, config.LLMDumpDir)

	var review *fort.SandboxExecutionReview
	review, reviewErr := llm.ReviewSandboxExecution(ctx, execution, execErr)

	if jsonOutput {
		output := map[string]interface{}{
			"execution":        execution,
			"execution_error":  "",
			"llm_review":       review,
			"llm_review_error": "",
		}
		if execErr != nil {
			output["execution_error"] = execErr.Error()
		}
		if reviewErr != nil {
			output["llm_review_error"] = reviewErr.Error()
		}
		printJSON(output)
		if execErr != nil {
			os.Exit(1)
		}
		if execution != nil && execution.Result != nil && !execution.Result.Success {
			os.Exit(execution.Result.ExitCode)
		}
		return
	}

	if execution != nil {
		fmt.Println()
		fmt.Println("Pipeline Phases:")
		for _, phase := range execution.Phases {
			icon := "✅"
			if !phase.Success {
				icon = "❌"
			}
			fmt.Printf("  %s %s\n", icon, phase.Phase)
			if phase.Error != "" && verbose {
				fmt.Printf("     Error: %s\n", phase.Error)
			}
		}

		if execution.Result != nil {
			fmt.Println("\nSandbox Execution:")
			fmt.Printf("  Success: %t\n", execution.Result.Success)
			fmt.Printf("  Exit code: %d\n", execution.Result.ExitCode)
			fmt.Printf("  Timed out: %t\n", execution.Result.TimedOut)
			if execution.Result.KillReason != "" {
				fmt.Printf("  Kill reason: %s\n", execution.Result.KillReason)
			}
			fmt.Printf("  Wall time: %dms\n", execution.Result.WallTimeMs)

			if len(execution.Result.OutputFiles) > 0 {
				fmt.Println("  Output files:")
				for _, f := range execution.Result.OutputFiles {
					fmt.Printf("    - %s (%d bytes)\n", f.Path, f.Size)
				}
			}

			if execution.Result.Stdout != "" && verbose {
				fmt.Println("\n--- STDOUT ---")
				fmt.Println(execution.Result.Stdout)
			}
			if execution.Result.Stderr != "" && verbose {
				fmt.Println("\n--- STDERR ---")
				fmt.Println(execution.Result.Stderr)
			}
		}
	}

	if reviewErr != nil {
		fmt.Printf("\nLLM result analysis failed: %v\n", reviewErr)
	} else if review != nil {
		fmt.Println("\nLLM Result Analysis:")
		fmt.Printf("  Assessment: %s\n", review.OverallAssessment)
		fmt.Printf("  Risk level: %s\n", review.RiskLevel)
		fmt.Printf("  Confidence: %.0f%%\n", review.Confidence*100)
		fmt.Printf("  Summary: %s\n", review.Summary)

		if len(review.Recommendations) > 0 {
			fmt.Println("  Recommendations:")
			for _, r := range review.Recommendations {
				fmt.Printf("    - %s\n", r)
			}
		}
	}

	if execErr != nil {
		fmt.Printf("\n❌ Sandbox pipeline failed: %v\n", execErr)
		os.Exit(1)
	}
	if execution != nil && execution.Result != nil && !execution.Result.Success {
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

func runReport(ctx context.Context, config fort.AgentConfig, code, lang, purpose string, verbose bool) {
	fmt.Println("\n[Report] Generating comprehensive analysis report...")

	// Create LLM client
	var llm *fort.OpenAILLMClient
	if config.LLMBaseURL != "" {
		llm = fort.NewOpenAILLMClientWithBaseURL(config.LLMAPIKey, config.LLMModel, config.LLMBaseURL)
	} else {
		llm = fort.NewOpenAILLMClient(config.LLMAPIKey, config.LLMModel)
	}
	llm.SetDebugOptions(config.Verbose, config.LLMDumpDir)

	// Create report generator
	reportConfig := fort.DefaultReportConfig()
	generator := fort.NewReportGenerator(llm, reportConfig)

	// Generate report
	opts := fort.ReportOptions{
		Language: lang,
		Purpose:  purpose,
	}

	var progress fort.ReportProgressFn
	if verbose {
		progress = func(phase int, name string) {
			fmt.Printf("  -> Phase %d: %s...\n", phase, name)
		}
	}

	report, err := generator.GenerateReportWithProgress(ctx, code, opts, progress)
	if err != nil {
		fatal("Report generation failed: %v", err)
	}

	if verbose {
		fmt.Println()
	}

	// Output JSON report
	jsonData, err := report.ToJSON()
	if err != nil {
		fatal("Failed to serialize report: %v", err)
	}

	fmt.Println(string(jsonData))

	// Print summary to stderr if verbose
	if verbose {
		fmt.Fprintln(os.Stderr, "\n--- Summary ---")
		fmt.Fprintf(os.Stderr, "Verdict: %s\n", report.Summary.Verdict)
		fmt.Fprintf(os.Stderr, "Security Score: %d/100\n", report.Summary.SecurityScore)
		fmt.Fprintf(os.Stderr, "Trust Score: %d/100\n", report.Summary.TrustScore)
		fmt.Fprintf(os.Stderr, "Findings: %d\n", len(report.Security.Findings))
	}
}
