package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/AbelJSeba/sandbox/pkg/fort"
)

var version = "dev"
var jsonOutputPath string
var outputCleanup func()
var interactiveStdout bool
var colorStdout bool
var interactiveStderr bool
var colorStderr bool

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
		jsonOutPath   = flag.String("json-out", "", "Write JSON output to file")
		logFilePath   = flag.String("log-file", "", "Write combined stdout/stderr logs to file")
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
	jsonOutputPath = strings.TrimSpace(*jsonOutPath)
	interactiveStdout = detectInteractiveTerminal(os.Stdout)
	interactiveStderr = detectInteractiveTerminal(os.Stderr)
	noColor := strings.TrimSpace(os.Getenv("NO_COLOR")) != ""
	colorStdout = interactiveStdout && !noColor
	colorStderr = interactiveStderr && !noColor

	var err error
	outputCleanup, err = setupOutputTee(strings.TrimSpace(*logFilePath))
	if err != nil {
		fatal("Failed to setup log file: %v", err)
	}
	defer outputCleanup()

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

	if *verbose && !*jsonOutput {
		fmt.Printf("Provider: %s\n", cfg.LLM.Provider)
		fmt.Printf("Model: %s\n", cfg.ResolveModel())
		fmt.Printf("Base URL: %s\n", cfg.ResolveBaseURL())
		if jsonOutputPath != "" {
			fmt.Printf("JSON out: %s\n", jsonOutputPath)
		}
		if strings.TrimSpace(*logFilePath) != "" {
			fmt.Printf("Log file: %s\n", strings.TrimSpace(*logFilePath))
		}
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
		runExecute(ctx, agent, req, *verbose, *jsonOutput, agentConfig.RequireValidation)

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
	if !jsonOutput {
		fmt.Println("\n[Quick Validation] Running static analysis...")
	}

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
		exitWithCode(1)
	}
}

func runValidate(ctx context.Context, agent *fort.Agent, req *fort.Request, verbose, jsonOutput bool) {
	if !jsonOutput {
		fmt.Println("\n[Validation] Running full security validation...")
	}

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
		exitWithCode(1)
	}
}

func runAnalyze(ctx context.Context, agent *fort.Agent, req *fort.Request, verbose, jsonOutput bool) {
	if !jsonOutput {
		fmt.Println("\n[Analysis] Analyzing code...")
	}

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

func runExecute(
	ctx context.Context,
	agent *fort.Agent,
	req *fort.Request,
	verbose, jsonOutput, requireValidation bool,
) {
	if !jsonOutput {
		fmt.Println("\n[Execution] Running full pipeline...")
	}

	if verbose {
		fmt.Println("  → Phase 1: Analysis")
		fmt.Printf("  → Request ID: %s\n", req.ID)
		fmt.Printf("  → Requested limits: timeout=%ds memory=%dMB network=%t\n", req.MaxTimeoutSec, req.MaxMemoryMB, req.AllowNetwork)
	}

	showProgress := !jsonOutput || verbose
	execution, err := executeWithPhaseProgress(ctx, agent, req, requireValidation, showProgress, jsonOutput)

	if jsonOutput {
		executionForJSON := sanitizeExecutionForJSON(execution)
		output := map[string]interface{}{
			"execution": executionForJSON,
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
		exitWithCode(1)
	}

	if execution.Result != nil && !execution.Result.Success {
		exitWithCode(execution.Result.ExitCode)
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

	showProgress := !jsonOutput || verbose
	execution, execErr := executeWithPhaseProgress(ctx, agent, req, config.RequireValidation, showProgress, jsonOutput)

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
		executionForJSON := sanitizeExecutionForJSON(execution)
		output := map[string]interface{}{
			"execution":        executionForJSON,
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
			exitWithCode(1)
		}
		if execution != nil && execution.Result != nil && !execution.Result.Success {
			exitWithCode(execution.Result.ExitCode)
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
		exitWithCode(1)
	}
	if execution != nil && execution.Result != nil && !execution.Result.Success {
		exitWithCode(execution.Result.ExitCode)
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

func executeWithPhaseProgress(
	ctx context.Context,
	agent *fort.Agent,
	req *fort.Request,
	requireValidation bool,
	showProgress bool,
	progressToStderr bool,
) (*fort.Execution, error) {
	if !showProgress {
		return agent.Execute(ctx, req)
	}

	writer := io.Writer(os.Stdout)
	interactive := interactiveStdout
	useColor := colorStdout
	if progressToStderr {
		writer = os.Stderr
		interactive = interactiveStderr
		useColor = colorStderr
	}

	renderer := newPhaseProgressRenderer("Pipeline", expectedPhaseCount(requireValidation), writer, interactive, useColor)
	done := make(chan struct {
		execution *fort.Execution
		err       error
	}, 1)

	go func() {
		execution, err := agent.Execute(ctx, req)
		done <- struct {
			execution *fort.Execution
			err       error
		}{execution: execution, err: err}
	}()

	ticker := time.NewTicker(120 * time.Millisecond)
	defer ticker.Stop()

	renderer.Render(0, fort.PhaseAnalysis, false, nil)
	for {
		select {
		case outcome := <-done:
			finalCompleted := 0
			finalPhase := fort.PhaseComplete
			if outcome.execution != nil {
				finalCompleted = len(outcome.execution.Phases)
				finalPhase = outcome.execution.Request.CurrentPhase
			}
			renderer.Render(finalCompleted, finalPhase, true, outcome.err)
			return outcome.execution, outcome.err
		case <-ticker.C:
			exec, ok := agent.GetExecution(req.ID)
			if !ok || exec == nil {
				renderer.Render(0, fort.PhaseAnalysis, false, nil)
				continue
			}
			renderer.Render(len(exec.Phases), exec.Request.CurrentPhase, false, nil)
		}
	}
}

func expectedPhaseCount(requireValidation bool) int {
	if requireValidation {
		return 5
	}
	return 4
}

type phaseProgressRenderer struct {
	prefix        string
	total         int
	startedAt     time.Time
	writer        io.Writer
	interactive   bool
	useColor      bool
	spinnerIdx    int
	lastCompleted int
	lastPhase     fort.Phase
	initialized   bool
}

func newPhaseProgressRenderer(prefix string, total int, writer io.Writer, interactive, useColor bool) *phaseProgressRenderer {
	if total <= 0 {
		total = 1
	}
	return &phaseProgressRenderer{
		prefix:        prefix,
		total:         total,
		startedAt:     time.Now(),
		writer:        writer,
		interactive:   interactive,
		useColor:      useColor,
		lastCompleted: -1,
	}
}

func (r *phaseProgressRenderer) Render(completed int, phase fort.Phase, done bool, runErr error) {
	completed = clampInt(completed, 0, r.total)
	percent := (completed * 100) / r.total
	elapsed := formatProgressDuration(time.Since(r.startedAt))
	phaseName := phaseLabel(phase)
	bar := phaseProgressBar(completed, r.total, r.useColor)
	icon := r.icon(done, runErr != nil)
	line := fmt.Sprintf("%s %s %3d%% %d/%d  %s  %s", icon, bar, percent, completed, r.total, phaseName, elapsed)

	if done {
		if runErr != nil {
			line += "  " + colorizeWith(r.useColor, "FAILED", ansiRed)
		} else {
			line += "  " + colorizeWith(r.useColor, "DONE", ansiGreen)
		}
	}

	if !r.interactive {
		if !done && r.initialized && completed == r.lastCompleted && phase == r.lastPhase {
			return
		}
		fmt.Fprintf(r.writer, "[%s] %s\n", r.prefix, stripANSI(line))
		r.lastCompleted = completed
		r.lastPhase = phase
		r.initialized = true
		return
	}

	fmt.Fprintf(r.writer, "\r\033[2K%s", colorizeWith(r.useColor, "["+r.prefix+"]", ansiBlue)+" "+line)
	if done {
		fmt.Fprintln(r.writer)
	}

	r.lastCompleted = completed
	r.lastPhase = phase
	r.initialized = true
}

func (r *phaseProgressRenderer) icon(done, failed bool) string {
	if done {
		if failed {
			return colorizeWith(r.useColor, "✖", ansiRed)
		}
		return colorizeWith(r.useColor, "✔", ansiGreen)
	}
	frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	icon := frames[r.spinnerIdx%len(frames)]
	r.spinnerIdx++
	return colorizeWith(r.useColor, icon, ansiCyan)
}

func phaseProgressBar(completed, total int, useColor bool) string {
	if total <= 0 {
		total = 1
	}
	completed = clampInt(completed, 0, total)
	const width = 28
	filled := (completed * width) / total
	if filled < 0 {
		filled = 0
	}
	if filled > width {
		filled = width
	}

	filledPart := strings.Repeat("█", filled)
	emptyPart := strings.Repeat("░", width-filled)
	if useColor {
		filledPart = colorizeWith(true, filledPart, ansiGreen)
		emptyPart = colorizeWith(true, emptyPart, ansiGray)
	}
	return "│" + filledPart + emptyPart + "│"
}

func phaseLabel(phase fort.Phase) string {
	switch phase {
	case fort.PhaseAnalysis:
		return "Analyze"
	case fort.PhaseSynthesis:
		return "Synthesize"
	case fort.PhaseValidation:
		return "Validate"
	case fort.PhaseBuild:
		return "Build"
	case fort.PhaseExecution:
		return "Execute"
	case fort.PhaseComplete:
		return "Complete"
	default:
		if strings.TrimSpace(string(phase)) == "" {
			return "Pending"
		}
		return titleCaseToken(string(phase))
	}
}

func renderReportProgress(phase, total int, name string) {
	if total <= 0 {
		total = 1
	}
	phase = clampInt(phase, 0, total)
	percent := (phase * 100) / total
	label := strings.TrimSpace(name)
	if label == "" {
		label = fmt.Sprintf("Phase %d", phase)
	}
	icon := colorizeWith(colorStderr, "◉", ansiCyan)
	if phase >= total {
		icon = colorizeWith(colorStderr, "✔", ansiGreen)
	}

	line := fmt.Sprintf("%s %s %3d%% %d/%d  %s", icon, phaseProgressBar(phase, total, colorStderr), percent, phase, total, label)
	if !interactiveStderr {
		fmt.Fprintf(os.Stderr, "[Report] %s\n", stripANSI(line))
		return
	}

	fmt.Fprintf(os.Stderr, "\r\033[2K%s %s", colorizeWith(colorStderr, "[Report]", ansiBlue), line)
	if phase >= total {
		fmt.Fprintln(os.Stderr)
	}
}

const (
	ansiReset = "\033[0m"
	ansiGray  = "\033[90m"
	ansiRed   = "\033[31m"
	ansiGreen = "\033[32m"
	ansiBlue  = "\033[34m"
	ansiCyan  = "\033[36m"
)

func colorizeWith(enabled bool, text, code string) string {
	if !enabled || strings.TrimSpace(code) == "" {
		return text
	}
	return code + text + ansiReset
}

func stripANSI(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	inEscape := false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if inEscape {
			if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') {
				inEscape = false
			}
			continue
		}
		if ch == 0x1b {
			inEscape = true
			continue
		}
		b.WriteByte(ch)
	}
	return b.String()
}

func clampInt(v, min, max int) int {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

func formatProgressDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	totalSec := int(d.Seconds())
	minutes := totalSec / 60
	seconds := totalSec % 60
	return fmt.Sprintf("%02d:%02d", minutes, seconds)
}

func detectInteractiveTerminal(file *os.File) bool {
	if file == nil {
		return false
	}
	info, err := file.Stat()
	if err != nil {
		return false
	}
	if (info.Mode() & os.ModeCharDevice) == 0 {
		return false
	}
	term := strings.ToLower(strings.TrimSpace(os.Getenv("TERM")))
	return term != "" && term != "dumb"
}

func titleCaseToken(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}
	runes := []rune(s)
	out := make([]rune, 0, len(runes))
	capNext := true
	for _, r := range runes {
		if r == '_' || r == '-' || r == ' ' {
			out = append(out, ' ')
			capNext = true
			continue
		}
		if capNext {
			if r >= 'a' && r <= 'z' {
				r = r - ('a' - 'A')
			}
			capNext = false
		}
		out = append(out, r)
	}
	return strings.TrimSpace(string(out))
}

func printJSON(v interface{}) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fatal("Failed to serialize JSON output: %v", err)
	}
	data = append(data, '\n')
	writeJSONOutput(data)
}

func writeJSONOutput(data []byte) {
	if jsonOutputPath == "" {
		fmt.Print(string(data))
		return
	}

	dir := filepath.Dir(jsonOutputPath)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			fatal("Failed to create output directory %s: %v", dir, err)
		}
	}

	if err := os.WriteFile(jsonOutputPath, data, 0644); err != nil {
		fatal("Failed to write JSON output to %s: %v", jsonOutputPath, err)
	}
}

func sanitizeExecutionForJSON(execution *fort.Execution) *fort.Execution {
	if execution == nil {
		return nil
	}

	executionCopy := *execution
	requestCopy := executionCopy.Request

	if requestCopy.SourceContent != "" {
		requestCopy.SourceContent = fmt.Sprintf("[omitted %d bytes of source content]", len(requestCopy.SourceContent))
	}
	executionCopy.Request = requestCopy
	return &executionCopy
}

func fatal(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "Error: "+format+"\n", args...)
	exitWithCode(1)
}

func exitWithCode(code int) {
	if outputCleanup != nil {
		outputCleanup()
	}
	os.Exit(code)
}

func setupOutputTee(path string) (func(), error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return func() {}, nil
	}

	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, err
		}
	}

	logFile, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}

	origStdout := os.Stdout
	origStderr := os.Stderr

	stdoutReader, stdoutWriter, err := os.Pipe()
	if err != nil {
		_ = logFile.Close()
		return nil, err
	}
	stderrReader, stderrWriter, err := os.Pipe()
	if err != nil {
		_ = stdoutReader.Close()
		_ = stdoutWriter.Close()
		_ = logFile.Close()
		return nil, err
	}

	os.Stdout = stdoutWriter
	os.Stderr = stderrWriter

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(io.MultiWriter(origStdout, logFile), stdoutReader)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(io.MultiWriter(origStderr, logFile), stderrReader)
	}()

	var once sync.Once
	cleanup := func() {
		once.Do(func() {
			_ = stdoutWriter.Close()
			_ = stderrWriter.Close()
			wg.Wait()
			os.Stdout = origStdout
			os.Stderr = origStderr
			_ = stdoutReader.Close()
			_ = stderrReader.Close()
			_ = logFile.Close()
		})
	}

	return cleanup, nil
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
		exitWithCode(1)
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
			renderReportProgress(phase, 5, name)
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
	if len(jsonData) == 0 || jsonData[len(jsonData)-1] != '\n' {
		jsonData = append(jsonData, '\n')
	}

	writeJSONOutput(jsonData)

	// Print summary to stderr if verbose
	if verbose {
		fmt.Fprintln(os.Stderr, "\n--- Summary ---")
		fmt.Fprintf(os.Stderr, "Verdict: %s\n", report.Summary.Verdict)
		fmt.Fprintf(os.Stderr, "Security Score: %d/100\n", report.Summary.SecurityScore)
		fmt.Fprintf(os.Stderr, "Trust Score: %d/100\n", report.Summary.TrustScore)
		fmt.Fprintf(os.Stderr, "Findings: %d\n", len(report.Security.Findings))
	}
}
