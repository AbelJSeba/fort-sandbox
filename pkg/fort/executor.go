package fort

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/client"
)

// Executor runs code in isolated containers
type Executor struct {
	docker *client.Client
	config ExecutorConfig
}

// ExecutorConfig holds executor configuration
type ExecutorConfig struct {
	Runtime          string        // runc, runsc (gVisor), kata
	DefaultMemoryMB  int
	DefaultCPU       float64
	DefaultTimeout   int           // seconds
	MaxMemoryMB      int
	MaxCPU           float64
	MaxTimeout       time.Duration
	MaxPIDs          int           // Maximum number of processes
	ReadOnlyRootfs   bool
	NoNewPrivileges  bool
	DropCapabilities []string
	NetworkDisabled  bool
	TmpfsSize        string
}

// DefaultExecutorConfig returns secure defaults
func DefaultExecutorConfig() ExecutorConfig {
	return ExecutorConfig{
		Runtime:          "runc",
		DefaultMemoryMB:  256,
		DefaultCPU:       1.0,
		DefaultTimeout:   60,
		MaxMemoryMB:      512,
		MaxCPU:           2.0,
		MaxTimeout:       5 * time.Minute,
		MaxPIDs:          100,
		ReadOnlyRootfs:   true,
		NoNewPrivileges:  true,
		NetworkDisabled:  true,
		TmpfsSize:        "64m",
		DropCapabilities: []string{"ALL"},
	}
}

// NewExecutor creates a new Executor
func NewExecutor(dockerClient *client.Client, config ExecutorConfig) *Executor {
	return &Executor{
		docker: dockerClient,
		config: config,
	}
}

// NewExecutorFromEnv creates an Executor using environment Docker config
func NewExecutorFromEnv(config ExecutorConfig) (*Executor, error) {
	dockerClient, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("failed to create Docker client: %w", err)
	}
	return NewExecutor(dockerClient, config), nil
}

// Execute runs a container and captures output
func (e *Executor) Execute(ctx context.Context, req *Request, synthesis *SynthesisResult, imageID string, policy *SecurityPolicy) (*ExecResult, error) {
	startTime := time.Now()

	// Determine resource limits
	memoryMB := e.clampMemory(synthesis.RecommendedMemoryMB, req.MaxMemoryMB)
	cpu := e.clampCPU(synthesis.RecommendedCPU, req.MaxCPU)
	timeout := e.clampTimeout(synthesis.RecommendedTimeout, req.MaxTimeoutSec)

	// Create execution context with timeout
	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Create container config
	containerConfig := &container.Config{
		Image:        imageID,
		Cmd:          synthesis.RunCommand,
		WorkingDir:   synthesis.WorkDir,
		Env:          mapToEnvSlice(synthesis.EnvironmentVars),
		AttachStdout: true,
		AttachStderr: true,
		Tty:          false,
		Labels: map[string]string{
			"fort.request_id": req.ID,
			"fort.managed":    "true",
		},
	}

	// Create host config with security settings
	hostConfig := &container.HostConfig{
		Resources: container.Resources{
			Memory:    int64(memoryMB) * 1024 * 1024,
			NanoCPUs:  int64(cpu * 1e9),
			PidsLimit: ptrInt64(int64(e.config.MaxPIDs)), // Prevent fork bombs
		},
		ReadonlyRootfs: e.config.ReadOnlyRootfs && !policy.AllowFileWrite,
		SecurityOpt: []string{
			"no-new-privileges:true",
		},
		CapDrop:     e.config.DropCapabilities,
		NetworkMode: container.NetworkMode("none"),
	}

	// Allow network if policy permits
	if policy.AllowNetwork {
		hostConfig.NetworkMode = container.NetworkMode("bridge")
	}

	// Add tmpfs mount for /tmp
	if e.config.TmpfsSize != "" {
		hostConfig.Tmpfs = map[string]string{
			"/tmp": fmt.Sprintf("size=%s,mode=1777", e.config.TmpfsSize),
		}
	}

	// Add read-only mounts if needed
	if e.config.ReadOnlyRootfs && policy.AllowFileWrite {
		// Allow write to /app only
		hostConfig.Mounts = append(hostConfig.Mounts, mount.Mount{
			Type:   mount.TypeTmpfs,
			Target: "/app/output",
			TmpfsOptions: &mount.TmpfsOptions{
				SizeBytes: 64 * 1024 * 1024, // 64MB for outputs
			},
		})
	}

	// Use gVisor if configured
	if e.config.Runtime != "" && e.config.Runtime != "runc" {
		hostConfig.Runtime = e.config.Runtime
	}

	// Create container
	createResp, err := e.docker.ContainerCreate(execCtx, containerConfig, hostConfig, nil, nil, "")
	if err != nil {
		return nil, fmt.Errorf("failed to create container: %w", err)
	}
	containerID := createResp.ID

	// Ensure cleanup
	defer func() {
		removeCtx, removeCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer removeCancel()
		_ = e.docker.ContainerRemove(removeCtx, containerID, container.RemoveOptions{Force: true})
	}()

	// Attach to capture output before starting
	attachResp, err := e.docker.ContainerAttach(execCtx, containerID, container.AttachOptions{
		Stream: true,
		Stdout: true,
		Stderr: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to attach to container: %w", err)
	}
	defer attachResp.Close()

	// Start container
	if err := e.docker.ContainerStart(execCtx, containerID, container.StartOptions{}); err != nil {
		return nil, fmt.Errorf("failed to start container: %w", err)
	}

	// Read output
	var stdout, stderr bytes.Buffer
	outputDone := make(chan error, 1)
	go func() {
		_, err := stdCopy(&stdout, &stderr, attachResp.Reader)
		outputDone <- err
	}()

	// Wait for container to finish
	statusCh, errCh := e.docker.ContainerWait(execCtx, containerID, container.WaitConditionNotRunning)

	var exitCode int
	var timedOut, killed bool
	var killReason string

	select {
	case err := <-errCh:
		if err != nil {
			if execCtx.Err() == context.DeadlineExceeded {
				timedOut = true
				killReason = "execution timeout exceeded"
			} else {
				return nil, fmt.Errorf("error waiting for container: %w", err)
			}
		}
	case status := <-statusCh:
		exitCode = int(status.StatusCode)
		if status.Error != nil {
			killReason = status.Error.Message
			killed = true
		}
	case <-execCtx.Done():
		timedOut = true
		killReason = "execution timeout exceeded"
		_ = e.docker.ContainerKill(context.Background(), containerID, "SIGKILL")
	}

	// Wait for output collection to complete
	select {
	case <-outputDone:
	case <-time.After(5 * time.Second):
	}

	wallTime := time.Since(startTime)

	result := &ExecResult{
		RequestID:   req.ID,
		CompletedAt: time.Now(),
		Success:     exitCode == 0 && !timedOut && !killed,
		ExitCode:    exitCode,
		Stdout:      stdout.String(),
		Stderr:      stderr.String(),
		WallTimeMs:  wallTime.Milliseconds(),
		TimedOut:    timedOut,
		Killed:      killed,
		KillReason:  killReason,
		ContainerID: containerID,
		ImageID:     imageID,
	}

	// Truncate output if too long
	const maxOutput = 100 * 1024 // 100KB
	if len(result.Stdout) > maxOutput {
		result.Stdout = result.Stdout[:maxOutput] + "\n... (output truncated)"
	}
	if len(result.Stderr) > maxOutput {
		result.Stderr = result.Stderr[:maxOutput] + "\n... (output truncated)"
	}

	return result, nil
}

// stdCopy handles Docker's multiplexed stdout/stderr stream
func stdCopy(stdout, stderr io.Writer, src io.Reader) (written int64, err error) {
	header := make([]byte, 8)

	for {
		_, err := io.ReadFull(src, header)
		if err != nil {
			if err == io.EOF {
				return written, nil
			}
			return written, err
		}

		size := int64(header[4])<<24 | int64(header[5])<<16 | int64(header[6])<<8 | int64(header[7])

		var dst io.Writer
		switch header[0] {
		case 1:
			dst = stdout
		case 2:
			dst = stderr
		default:
			dst = stdout
		}

		n, err := io.CopyN(dst, src, size)
		written += n
		if err != nil {
			return written, err
		}
	}
}

func (e *Executor) clampMemory(recommended, requestMax int) int {
	if recommended <= 0 {
		recommended = e.config.DefaultMemoryMB
	}
	if requestMax > 0 && recommended > requestMax {
		recommended = requestMax
	}
	if recommended > e.config.MaxMemoryMB {
		recommended = e.config.MaxMemoryMB
	}
	return recommended
}

func (e *Executor) clampCPU(recommended, requestMax float64) float64 {
	if recommended <= 0 {
		recommended = e.config.DefaultCPU
	}
	if requestMax > 0 && recommended > requestMax {
		recommended = requestMax
	}
	if recommended > e.config.MaxCPU {
		recommended = e.config.MaxCPU
	}
	return recommended
}

func (e *Executor) clampTimeout(recommendedSec, requestMaxSec int) time.Duration {
	recommended := time.Duration(recommendedSec) * time.Second
	if recommended <= 0 {
		recommended = time.Duration(e.config.DefaultTimeout) * time.Second
	}
	requestMax := time.Duration(requestMaxSec) * time.Second
	if requestMax > 0 && recommended > requestMax {
		recommended = requestMax
	}
	if recommended > e.config.MaxTimeout {
		recommended = e.config.MaxTimeout
	}
	return recommended
}

func mapToEnvSlice(m map[string]string) []string {
	if m == nil {
		return nil
	}
	result := make([]string, 0, len(m))
	for k, v := range m {
		result = append(result, fmt.Sprintf("%s=%s", k, v))
	}
	return result
}

func ptrInt64(v int64) *int64 {
	return &v
}

// Close closes the Docker client connection
func (e *Executor) Close() error {
	return e.docker.Close()
}

// KillContainer forcefully stops a running container
func (e *Executor) KillContainer(ctx context.Context, containerID string) error {
	return e.docker.ContainerKill(ctx, containerID, "SIGKILL")
}

// ListManagedContainers returns all containers managed by Fort
func (e *Executor) ListManagedContainers(ctx context.Context) ([]string, error) {
	containers, err := e.docker.ContainerList(ctx, container.ListOptions{All: true})
	if err != nil {
		return nil, err
	}

	var managed []string
	for _, c := range containers {
		if c.Labels["fort.managed"] == "true" {
			managed = append(managed, c.ID)
		}
	}
	return managed, nil
}

// CleanupManagedContainers removes all Fort-managed containers
func (e *Executor) CleanupManagedContainers(ctx context.Context) error {
	containers, err := e.ListManagedContainers(ctx)
	if err != nil {
		return err
	}

	var errs []string
	for _, id := range containers {
		if err := e.docker.ContainerRemove(ctx, id, container.RemoveOptions{Force: true}); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", id[:12], err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("failed to remove some containers: %s", strings.Join(errs, "; "))
	}
	return nil
}
