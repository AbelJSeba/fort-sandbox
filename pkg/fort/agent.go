package fort

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/docker/docker/client"
)

// Agent is the main Fort secure execution agent
type Agent struct {
	analyzer    *Analyzer
	synthesizer *Synthesizer
	validator   *Validator
	builder     *Builder
	executor    *Executor

	config AgentConfig

	// Active executions tracking
	mu         sync.RWMutex
	executions map[string]*Execution
}

// AgentConfig holds agent configuration
type AgentConfig struct {
	// LLM configuration
	LLMProvider string
	LLMModel    string
	LLMAPIKey   string
	LLMBaseURL  string
	LLMDumpDir  string
	Verbose     bool

	// Builder configuration
	BuildTimeout time.Duration
	NoBuildCache bool

	// Executor configuration
	ExecutorConfig ExecutorConfig

	// Validation configuration
	DefaultPolicy     SecurityPolicy
	RequireValidation bool
}

// DefaultAgentConfig returns sensible defaults
func DefaultAgentConfig() AgentConfig {
	return AgentConfig{
		LLMProvider:       "openai",
		LLMModel:          "gpt-4",
		BuildTimeout:      5 * time.Minute,
		NoBuildCache:      false,
		ExecutorConfig:    DefaultExecutorConfig(),
		DefaultPolicy:     DefaultSecurityPolicy(),
		RequireValidation: true,
	}
}

// NewAgent creates a new Fort Agent
func NewAgent(config AgentConfig) (*Agent, error) {
	// Create LLM client
	var llmClient *OpenAILLMClient
	if config.LLMBaseURL != "" {
		llmClient = NewOpenAILLMClientWithBaseURL(config.LLMAPIKey, config.LLMModel, config.LLMBaseURL)
	} else {
		llmClient = NewOpenAILLMClient(config.LLMAPIKey, config.LLMModel)
	}
	llmClient.SetDebugOptions(config.Verbose, config.LLMDumpDir)
	var llm LLMClient = llmClient

	// Create Docker client
	dockerClient, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("failed to create Docker client: %w", err)
	}

	// Create components
	analyzer := NewAnalyzer(llm)
	synthesizer := NewSynthesizer(llm)
	validator := NewValidator(llm)
	builder := NewBuilder(dockerClient, BuilderConfig{
		BuildTimeout: config.BuildTimeout,
		NoCache:      config.NoBuildCache,
	})
	executor := NewExecutor(dockerClient, config.ExecutorConfig)

	return &Agent{
		analyzer:    analyzer,
		synthesizer: synthesizer,
		validator:   validator,
		builder:     builder,
		executor:    executor,
		config:      config,
		executions:  make(map[string]*Execution),
	}, nil
}

// NewAgentWithLLM creates an agent with a custom LLM client
func NewAgentWithLLM(llm LLMClient, config AgentConfig) (*Agent, error) {
	dockerClient, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("failed to create Docker client: %w", err)
	}

	analyzer := NewAnalyzer(llm)
	synthesizer := NewSynthesizer(llm)
	validator := NewValidator(llm)
	builder := NewBuilder(dockerClient, BuilderConfig{
		BuildTimeout: config.BuildTimeout,
		NoCache:      config.NoBuildCache,
	})
	executor := NewExecutor(dockerClient, config.ExecutorConfig)

	return &Agent{
		analyzer:    analyzer,
		synthesizer: synthesizer,
		validator:   validator,
		builder:     builder,
		executor:    executor,
		config:      config,
		executions:  make(map[string]*Execution),
	}, nil
}

// Execute runs the full execution pipeline
func (a *Agent) Execute(ctx context.Context, req *Request) (*Execution, error) {
	execution := &Execution{
		Request: *req,
		Phases:  make([]PhaseRecord, 0),
	}

	a.mu.Lock()
	a.executions[req.ID] = execution
	a.mu.Unlock()

	// Update status helper
	updateStatus := func(status ExecStatus, phase Phase) {
		a.mu.Lock()
		execution.Request.Status = status
		execution.Request.CurrentPhase = phase
		a.mu.Unlock()
	}

	// Record phase helper
	recordPhase := func(phase Phase, err error) {
		now := time.Now()
		record := PhaseRecord{
			Phase:     phase,
			StartedAt: now,
			EndedAt:   &now,
			Success:   err == nil,
		}
		if err != nil {
			record.Error = err.Error()
		}
		a.mu.Lock()
		execution.Phases = append(execution.Phases, record)
		a.mu.Unlock()
	}

	// Phase 1: Analysis
	updateStatus(StatusAnalyzing, PhaseAnalysis)
	analysis, err := a.analyzer.Analyze(ctx, req)
	recordPhase(PhaseAnalysis, err)
	if err != nil {
		updateStatus(StatusFailed, PhaseAnalysis)
		return execution, fmt.Errorf("analysis failed: %w", err)
	}
	execution.Analysis = analysis

	// Phase 2: Synthesis
	updateStatus(StatusBuilding, PhaseSynthesis)
	synthesis, err := a.synthesizer.Synthesize(ctx, req, analysis)
	recordPhase(PhaseSynthesis, err)
	if err != nil {
		updateStatus(StatusFailed, PhaseSynthesis)
		return execution, fmt.Errorf("synthesis failed: %w", err)
	}
	execution.Synthesis = synthesis

	// Phase 3: Validation
	if a.config.RequireValidation {
		updateStatus(StatusValidating, PhaseValidation)
		validation, err := a.validator.Validate(ctx, req, analysis, synthesis)
		recordPhase(PhaseValidation, err)
		if err != nil {
			updateStatus(StatusFailed, PhaseValidation)
			return execution, fmt.Errorf("validation failed: %w", err)
		}
		execution.Validation = validation

		if !validation.Safe {
			updateStatus(StatusRejected, PhaseValidation)
			return execution, fmt.Errorf("execution rejected: %s", validation.RejectionReason)
		}
	}

	// Phase 4: Build
	updateStatus(StatusBuilding, PhaseBuild)
	buildResult, err := a.builder.Build(ctx, req, synthesis)
	recordPhase(PhaseBuild, err)
	if err != nil {
		updateStatus(StatusFailed, PhaseBuild)
		return execution, fmt.Errorf("build failed: %w", err)
	}

	// Ensure cleanup of built image
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = a.builder.Cleanup(cleanupCtx, buildResult.ImageID)
	}()

	// Phase 5: Execution
	updateStatus(StatusExecuting, PhaseExecution)
	policy := req.SecurityPolicy
	if policy.MaxMemoryMB == 0 {
		policy = a.config.DefaultPolicy
	}
	result, err := a.executor.Execute(ctx, req, synthesis, buildResult.ImageTag, &policy)
	recordPhase(PhaseExecution, err)
	if err != nil {
		updateStatus(StatusFailed, PhaseExecution)
		return execution, fmt.Errorf("execution failed: %w", err)
	}
	execution.Result = result

	// Determine final status
	if result.Success {
		updateStatus(StatusCompleted, PhaseComplete)
	} else if result.TimedOut {
		updateStatus(StatusKilled, PhaseComplete)
	} else if result.Killed {
		updateStatus(StatusKilled, PhaseComplete)
	} else {
		updateStatus(StatusFailed, PhaseComplete)
	}

	return execution, nil
}

// Analyze performs only the analysis phase
func (a *Agent) Analyze(ctx context.Context, req *Request) (*AnalysisResult, error) {
	return a.analyzer.Analyze(ctx, req)
}

// Synthesize performs analysis and synthesis
func (a *Agent) Synthesize(ctx context.Context, req *Request) (*SynthesisResult, error) {
	analysis, err := a.analyzer.Analyze(ctx, req)
	if err != nil {
		return nil, err
	}
	return a.synthesizer.Synthesize(ctx, req, analysis)
}

// Validate performs analysis, synthesis, and validation
func (a *Agent) Validate(ctx context.Context, req *Request) (*ValidationResult, error) {
	analysis, err := a.analyzer.Analyze(ctx, req)
	if err != nil {
		return nil, err
	}
	synthesis, err := a.synthesizer.Synthesize(ctx, req, analysis)
	if err != nil {
		return nil, err
	}
	return a.validator.Validate(ctx, req, analysis, synthesis)
}

// GetExecution returns an execution by ID
func (a *Agent) GetExecution(id string) (*Execution, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	exec, ok := a.executions[id]
	return exec, ok
}

// Cancel attempts to cancel a running execution
func (a *Agent) Cancel(ctx context.Context, id string) error {
	a.mu.Lock()
	exec, ok := a.executions[id]
	a.mu.Unlock()

	if !ok {
		return fmt.Errorf("execution not found: %s", id)
	}

	if exec.Result != nil && exec.Result.ContainerID != "" {
		return a.executor.KillContainer(ctx, exec.Result.ContainerID)
	}

	return nil
}

// Cleanup removes execution record and any associated resources
func (a *Agent) Cleanup(ctx context.Context, id string) error {
	a.mu.Lock()
	exec, ok := a.executions[id]
	if ok {
		delete(a.executions, id)
	}
	a.mu.Unlock()

	if !ok {
		return nil
	}

	if exec.Result != nil && exec.Result.ImageID != "" {
		_ = a.builder.Cleanup(ctx, exec.Result.ImageID)
	}

	return nil
}

// Close shuts down the agent and releases resources
func (a *Agent) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_ = a.executor.CleanupManagedContainers(ctx)
	_ = a.executor.Close()
	_ = a.builder.Close()

	return nil
}

// QuickValidate performs fast static-only validation without LLM
func (a *Agent) QuickValidate(code string, policy *SecurityPolicy) (bool, []SecurityFinding) {
	if policy == nil {
		defaultPolicy := a.config.DefaultPolicy
		policy = &defaultPolicy
	}
	return QuickValidate(code, policy)
}
