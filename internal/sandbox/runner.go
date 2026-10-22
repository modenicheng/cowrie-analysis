package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"time"
)

// Limits bounds resource usage for a Runner.
type Limits struct {
	TimeoutMS      int   // per-task wall-clock cap; per-call timeout requests are clamped to this
	MaxInputBytes  int64 // max serialized task JSON fed to the child process
	MaxOutputBytes int64 // max result JSON accepted from the child process stdout
}

// Result is the structured outcome of one script execution. It mirrors the
// child process envelope:
//
//	{"ok":bool,"result":any|null,"error":{"type","message"}|null,"duration_ms":int}
type Result struct {
	OK           bool
	Result       json.RawMessage // embedded result JSON (nil when the script failed)
	ErrorType    string          // "" on success; classification otherwise
	ErrorMessage string
	DurationMS   int64
}

// UnmarshalJSON decodes the script-runner wire envelope into Result.
func (r *Result) UnmarshalJSON(data []byte) error {
	var wire struct {
		OK     bool            `json:"ok"`
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Type    string `json:"type"`
			Message string `json:"message"`
		} `json:"error"`
		DurationMS int64 `json:"duration_ms"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	r.OK = wire.OK
	r.Result = wire.Result
	r.ErrorType, r.ErrorMessage = "", ""
	if wire.Error != nil {
		r.ErrorType = wire.Error.Type
		r.ErrorMessage = wire.Error.Message
	}
	r.DurationMS = wire.DurationMS
	return nil
}

// Task is the stdin wire format for cmd/script-runner.
type Task struct {
	Code      string `json:"code"`
	Input     any    `json:"input"`
	TimeoutMS int    `json:"timeout_ms"`
}

// Sentinel errors returned by Runner.Execute; classify with errors.Is.
var (
	// ErrInputTooLarge is returned when the serialized task exceeds
	// Limits.MaxInputBytes, before any process is started.
	ErrInputTooLarge = errors.New("sandbox: task input exceeds MaxInputBytes")
	// ErrBadInput is returned when the child process rejected the task
	// (exit code 2), e.g. oversized or malformed task JSON.
	ErrBadInput = errors.New("sandbox: script-runner rejected the task input")
)

// gracePeriodMS is added on top of the script timeout before the child
// process is killed, giving it room to report a structured TimeoutError.
const gracePeriodMS = 2000

// Runner executes untrusted scripts in an isolated child process
// (cmd/script-runner), never in the host process.
type Runner struct {
	path   string
	limits Limits
	sem    chan struct{}
}

// NewRunner creates a Runner around the script-runner binary at path.
// maxConcurrency bounds in-flight executions; excess callers block until a
// slot frees up (they are not rejected).
func NewRunner(path string, limits Limits, maxConcurrency int) *Runner {
	if maxConcurrency <= 0 {
		maxConcurrency = 1
	}
	return &Runner{
		path:   path,
		limits: limits,
		sem:    make(chan struct{}, maxConcurrency),
	}
}

// newCommand builds the child process command with an explicitly EMPTY
// environment. Host credentials (API keys, ntfy tokens, ...) must never
// enter the script process (SPEC §9.3, §14).
func (r *Runner) newCommand(ctx context.Context) *exec.Cmd {
	cmd := exec.CommandContext(ctx, r.path)
	cmd.Env = []string{} // deliberately empty: do NOT inherit os.Environ()
	return cmd
}

// Execute runs code with the given input in the isolated child process and
// returns its structured result. Infrastructure failures (start failure,
// unparseable output, rejected input) are returned as Go errors; script-level
// failures (syntax errors, timeouts, oversized output) come back as a Result
// with OK=false.
func (r *Runner) Execute(ctx context.Context, code string, input any, timeoutMS int) (*Result, error) {
	if timeoutMS <= 0 || timeoutMS > r.limits.TimeoutMS {
		timeoutMS = r.limits.TimeoutMS
	}
	payload, err := json.Marshal(Task{Code: code, Input: input, TimeoutMS: timeoutMS})
	if err != nil {
		return nil, fmt.Errorf("sandbox: encode task: %w", err)
	}
	if int64(len(payload)) > r.limits.MaxInputBytes {
		return nil, fmt.Errorf("%w: %d bytes > limit %d", ErrInputTooLarge, len(payload), r.limits.MaxInputBytes)
	}

	// Concurrency gate: block until a slot is free; abort only if the
	// caller's context is cancelled while waiting.
	select {
	case r.sem <- struct{}{}:
		defer func() { <-r.sem }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	runCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutMS+gracePeriodMS)*time.Millisecond)
	defer cancel()

	cmd := r.newCommand(runCtx)
	cmd.Stdin = bytes.NewReader(payload)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("sandbox: stdout pipe: %w", err)
	}
	stderr := &cappedBuffer{max: 8 << 10}
	cmd.Stderr = stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("sandbox: start script-runner: %w", err)
	}

	// Read at most MaxOutputBytes+1 bytes so over-limit output is detected
	// without buffering unbounded data.
	out, readErr := io.ReadAll(io.LimitReader(stdout, r.limits.MaxOutputBytes+1))
	if readErr != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, fmt.Errorf("sandbox: read runner output: %w", readErr)
	}

	if int64(len(out)) > r.limits.MaxOutputBytes {
		// The child is likely still blocked writing; kill before waiting.
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return &Result{
			OK:           false,
			ErrorType:    "OutputTooLarge",
			ErrorMessage: fmt.Sprintf("runner output exceeded the %d byte limit", r.limits.MaxOutputBytes),
		}, nil
	}

	waitErr := cmd.Wait()

	if ctx.Err() != nil {
		return nil, ctx.Err() // caller cancelled the task
	}
	if runCtx.Err() != nil {
		// Killed after the grace period: the child failed to self-terminate.
		return &Result{
			OK:           false,
			ErrorType:    "TimeoutError",
			ErrorMessage: fmt.Sprintf("runner process killed after %dms grace period", gracePeriodMS),
		}, nil
	}

	exitCode := 0
	if waitErr != nil {
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			return nil, fmt.Errorf("sandbox: wait script-runner: %w (stderr: %s)", waitErr, stderr)
		}
	}

	switch exitCode {
	case 0:
		var res Result
		if err := json.Unmarshal(out, &res); err != nil {
			return nil, fmt.Errorf("sandbox: decode runner output: %w (stdout: %.200q, stderr: %s)", err, string(out), stderr)
		}
		return &res, nil
	case 2:
		var rejected Result
		_ = json.Unmarshal(out, &rejected)
		msg := rejected.ErrorMessage
		if msg == "" {
			msg = stderr.String()
		}
		return nil, fmt.Errorf("%w: %s", ErrBadInput, msg)
	default:
		return nil, fmt.Errorf("sandbox: script-runner exited with code %d (stderr: %s)", exitCode, stderr)
	}
}

// cappedBuffer retains at most max bytes of a stream (stderr diagnostics),
// silently discarding the rest so a chatty child cannot exhaust memory.
type cappedBuffer struct {
	buf       bytes.Buffer
	max       int64
	truncated bool
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if c.max > 0 {
		room := int(c.max - int64(c.buf.Len()))
		if room > 0 {
			if len(p) <= room {
				c.buf.Write(p)
				return len(p), nil
			}
			c.buf.Write(p[:room])
		}
	}
	c.truncated = true
	return len(p), nil
}

func (c *cappedBuffer) String() string {
	s := c.buf.String()
	if c.truncated {
		s += "...(truncated)"
	}
	return s
}
