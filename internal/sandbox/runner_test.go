package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// runnerBin is the script-runner binary built once for the whole test run.
var runnerBin string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "e3-script-runner-test")
	if err != nil {
		fmt.Fprintf(os.Stderr, "MkdirTemp: %v\n", err)
		os.Exit(1)
	}
	bin := filepath.Join(dir, "script-runner")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	// Module root is two levels above this package (internal/sandbox).
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Abs: %v\n", err)
		os.Exit(1)
	}
	build := exec.Command("go", "build", "-o", bin, "./cmd/script-runner")
	build.Dir = root
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "building script-runner failed: %v\n%s\n", err, out)
		os.Exit(1)
	}
	runnerBin = bin

	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func testRunner() *Runner {
	return NewRunner(runnerBin, Limits{
		TimeoutMS:      5000,
		MaxInputBytes:  1 << 20,
		MaxOutputBytes: 1 << 20,
	}, 2)
}

// Test 9: end-to-end execution through the isolated child process.
func TestRunnerEndToEnd(t *testing.T) {
	r := testRunner()
	res, err := r.Execute(context.Background(), "input.n*2", map[string]any{"n": 21}, 1000)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !res.OK {
		t.Fatalf("expected OK result, got error %q: %q", res.ErrorType, res.ErrorMessage)
	}
	if got := strings.TrimSpace(string(res.Result)); got != "42" {
		t.Fatalf("expected result 42, got %s", got)
	}
	if res.DurationMS < 0 {
		t.Fatalf("negative duration: %d", res.DurationMS)
	}
}

// Script errors surface as structured results (exit 0), not Go errors.
func TestRunnerScriptErrorStructured(t *testing.T) {
	r := testRunner()
	res, err := r.Execute(context.Background(), "var x = ;", nil, 1000)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if res.OK {
		t.Fatalf("expected failure result, got OK with %s", res.Result)
	}
	if res.ErrorType != "SyntaxError" {
		t.Fatalf("expected SyntaxError, got %q (%q)", res.ErrorType, res.ErrorMessage)
	}
}

// Test 10: runaway script in the child is stopped with a timeout error.
func TestRunnerChildTimeout(t *testing.T) {
	r := testRunner()
	start := time.Now()
	res, err := r.Execute(context.Background(), "while (true) {}", nil, 200)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if res.OK {
		t.Fatalf("expected failure result, got OK with %s", res.Result)
	}
	if res.ErrorType != "TimeoutError" {
		t.Fatalf("expected TimeoutError, got %q (%q)", res.ErrorType, res.ErrorMessage)
	}
	if elapsed >= 5*time.Second {
		t.Fatalf("timeout enforcement too slow: %v", elapsed)
	}
}

// Test 11: the child process inherits no host environment or secrets.
func TestRunnerEnvironmentIsolation(t *testing.T) {
	const secret = "ntfy-secret-token-do-not-leak-9f8e7d6c"
	t.Setenv("SECRET_TOKEN_FOR_TEST", secret)

	r := testRunner()

	// 11a: no `process` object is visible to scripts.
	res, err := r.Execute(context.Background(), "typeof process", nil, 1000)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !res.OK || mustJSONString(t, res.Result) != "undefined" {
		t.Fatalf("expected typeof process == \"undefined\", got ok=%v result=%s err=%q",
			res.OK, res.Result, res.ErrorMessage)
	}

	// 11b: the secret never appears anywhere on the child's global object.
	res, err = r.Execute(context.Background(),
		"Object.getOwnPropertyNames(globalThis).join(',') + '|' + String(globalThis.SECRET_TOKEN_FOR_TEST)", nil, 1000)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !res.OK {
		t.Fatalf("expected OK result, got error %q: %q", res.ErrorType, res.ErrorMessage)
	}
	names := strings.Split(mustJSONString(t, res.Result), "|")[0]
	for _, forbidden := range []string{"process", "os", "require", "fetch"} {
		for _, n := range strings.Split(names, ",") {
			if n == forbidden {
				t.Fatalf("globalThis in child exposes %q (properties: %s)", forbidden, names)
			}
		}
	}
	if strings.Contains(string(res.Result), secret) {
		t.Fatalf("host secret leaked into child process output: %s", res.Result)
	}

	// 11c: white-box check — the command environment is explicitly empty, so
	// no host credentials (API keys, ntfy tokens) can reach the child.
	cmd := r.newCommand(context.Background())
	if len(cmd.Env) != 0 {
		t.Fatalf("child command must have an empty Env, got %v", cmd.Env)
	}
}

// Test 12: oversized task input is rejected before starting a process.
func TestRunnerInputTooLarge(t *testing.T) {
	r := NewRunner(runnerBin, Limits{
		TimeoutMS:      1000,
		MaxInputBytes:  128,
		MaxOutputBytes: 4096,
	}, 1)
	_, err := r.Execute(context.Background(), "// "+strings.Repeat("x", 300), nil, 100)
	if !errors.Is(err, ErrInputTooLarge) {
		t.Fatalf("expected ErrInputTooLarge, got %v", err)
	}
}

// Blocking concurrency gate: concurrent executions all succeed and never
// error out due to contention.
func TestRunnerConcurrencyGate(t *testing.T) {
	r := NewRunner(runnerBin, Limits{
		TimeoutMS:      5000,
		MaxInputBytes:  1 << 20,
		MaxOutputBytes: 1 << 20,
	}, 2)

	const n = 6
	errCh := make(chan error, n)
	for i := 0; i < n; i++ {
		go func(i int) {
			res, err := r.Execute(context.Background(),
				fmt.Sprintf("input.i + %d", i), map[string]any{"i": 100}, 2000)
			if err != nil {
				errCh <- err
				return
			}
			if !res.OK || strings.TrimSpace(string(res.Result)) != fmt.Sprintf("%d", 100+i) {
				errCh <- fmt.Errorf("task %d: unexpected result ok=%v result=%s err=%q",
					i, res.OK, res.Result, res.ErrorMessage)
				return
			}
			errCh <- nil
		}(i)
	}
	for i := 0; i < n; i++ {
		if err := <-errCh; err != nil {
			t.Fatal(err)
		}
	}
}

// Direct subprocess checks of the BadInput contract (exit code 2).
func TestScriptRunnerBadInput(t *testing.T) {
	// Malformed JSON on stdin.
	cmd := exec.Command(runnerBin)
	cmd.Env = []string{}
	cmd.Stdin = strings.NewReader("this is not json")
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	err := cmd.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 2 {
		t.Fatalf("expected exit code 2, got err=%v", err)
	}
	var res Result
	if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
		t.Fatalf("BadInput envelope is not valid JSON: %v (raw: %s)", err, stdout.String())
	}
	if res.OK || res.ErrorType != "BadInput" {
		t.Fatalf("expected BadInput error envelope, got ok=%v type=%q", res.OK, res.ErrorType)
	}

	// Stdin over the 9 MiB task limit: feed exactly maxTaskBytes+1 bytes so
	// the child consumes everything and cleanly reports the violation.
	oversized := bytes.Repeat([]byte("a"), 9<<20+1)
	cmd = exec.Command(runnerBin)
	cmd.Env = []string{}
	cmd.Stdin = bytes.NewReader(oversized)
	stdout.Reset()
	cmd.Stdout = &stdout
	err = cmd.Run()
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 2 {
		t.Fatalf("expected exit code 2 for oversized stdin, got err=%v", err)
	}
	if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
		t.Fatalf("oversize envelope is not valid JSON: %v (raw: %s)", err, stdout.String())
	}
	if res.OK || res.ErrorType != "BadInput" {
		t.Fatalf("expected BadInput error envelope, got ok=%v type=%q", res.OK, res.ErrorType)
	}
}
