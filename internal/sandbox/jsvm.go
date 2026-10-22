// Package sandbox provides the restricted JavaScript execution environment
// used by the execute_js tool (SPEC §5.2, §7.3, §15 "Goja Runner").
//
// Security model:
//   - RunCode evaluates untrusted code in a fresh goja runtime whose global
//     environment contains exactly one binding, "input". No host functions
//     (require/fetch/readFile/os/process/Go/...) are registered; a fresh
//     goja runtime exposes only the ECMAScript standard built-ins.
//   - Process-level isolation is provided by Runner, which executes
//     cmd/script-runner as a child process with an explicitly empty
//     environment, so host credentials never reach script code (SPEC §9).
package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/dop251/goja"
	"github.com/dop251/goja/parser"
)

// Defaults applied by RunCode when non-positive limits are passed.
const (
	DefaultTimeoutMS      = 5000
	DefaultMaxOutputBytes = 1 << 20 // 1 MiB
	// maxCallStackDepth bounds JS call depth. goja's default is
	// math.MaxInt32, i.e. effectively unlimited: runaway recursion would
	// eat memory until the wall-clock timeout. A fixed cap turns it into an
	// immediate *StackOverflowError (reported as RuntimePanic).
	maxCallStackDepth = 2048
)

// RunCode executes untrusted JavaScript in the current process and returns
// the JSON-serialized value of the last expression.
//
// On success errType is "" and out holds the result JSON ("null" when the
// final expression evaluates to undefined or null). On failure out is nil,
// errType classifies the error and errMsg carries a diagnostic message:
//
//	SyntaxError        compile-time syntax error (pre-parsed before execution)
//	TimeoutError       execution exceeded timeoutMS and was interrupted
//	RuntimePanic       goja panic or uncatchable stack overflow
//	UnsupportedResult  result is a Promise; there is no event loop
//	NotSerializable    result cannot be encoded as JSON (symbol, function, NaN, ...)
//	OutputTooLarge     serialized result exceeds maxOutputBytes
//	InternalError      binding the input failed (should never happen)
//
// Any other errType is the name of the JavaScript error thrown by the script
// (e.g. "TypeError", "RangeError", "Error").
func RunCode(code string, input any, timeoutMS int, maxOutputBytes int64) (out []byte, errType, errMsg string, durationMS int64) {
	start := time.Now()
	defer func() { durationMS = time.Since(start).Milliseconds() }()

	if timeoutMS <= 0 {
		timeoutMS = DefaultTimeoutMS
	}
	if maxOutputBytes <= 0 {
		maxOutputBytes = DefaultMaxOutputBytes
	}

	// Pre-parse so that syntax errors are reported without running anything.
	prog, err := parser.ParseFile(nil, "script", code, 0)
	if err != nil {
		return nil, "SyntaxError", err.Error(), 0
	}

	vm := goja.New() // fresh runtime: globals contain only ECMAScript built-ins
	vm.SetMaxCallStackSize(maxCallStackDepth)

	// Capture the pristine Promise constructor before user code can shadow it.
	promiseCtor := vm.Get("Promise")

	// The single entry point for data; attack-log content passed here is
	// always treated as data, never as instructions (SPEC §9).
	if err := vm.Set("input", input); err != nil {
		return nil, "InternalError", "cannot bind input: " + err.Error(), 0
	}

	timer := time.AfterFunc(time.Duration(timeoutMS)*time.Millisecond, func() {
		vm.Interrupt(context.DeadlineExceeded)
	})
	// defer LIFO: stop the timer first, then clear any lingering interrupt flag.
	defer vm.ClearInterrupt()
	defer timer.Stop()

	var (
		result       goja.Value
		runErr       error
		panicked     bool
		compileError bool
	)

	runErr = func() (err error) {
		defer func() {
			if p := recover(); p != nil {
				panicked = true
				err = fmt.Errorf("%v", p)
			}
		}()
		compiled, cerr := goja.CompileAST(prog, false)
		if cerr != nil {
			compileError = true
			return cerr
		}
		result, err = vm.RunProgram(compiled)
		return err
	}()

	if runErr != nil {
		var interrupted *goja.InterruptedError
		var overflow *goja.StackOverflowError
		var exc *goja.Exception
		switch {
		case panicked:
			return nil, "RuntimePanic", "goja runtime panic: " + runErr.Error(), 0
		case compileError:
			return nil, "SyntaxError", runErr.Error(), 0
		case errors.As(runErr, &interrupted):
			return nil, "TimeoutError",
				fmt.Sprintf("script execution exceeded the %dms time limit and was interrupted", timeoutMS), 0
		case errors.As(runErr, &overflow):
			return nil, "RuntimePanic", "stack overflow: " + runErr.Error(), 0
		case errors.As(runErr, &exc):
			name, msg := exceptionInfo(vm, exc)
			return nil, name, msg, 0
		default:
			return nil, "RuntimeError", runErr.Error(), 0
		}
	}

	// undefined/null results are normalized to JSON null.
	if result == nil || goja.IsUndefined(result) || goja.IsNull(result) {
		return []byte("null"), "", "", 0
	}

	if isPromise(vm, result, promiseCtor) {
		return nil, "UnsupportedResult",
			"script returned a Promise; there is no event loop, scripts must compute their result synchronously", 0
	}

	data, err := json.Marshal(result.Export())
	if err != nil {
		return nil, "NotSerializable", "result is not JSON-serializable: " + err.Error(), 0
	}
	if int64(len(data)) > maxOutputBytes {
		return nil, "OutputTooLarge",
			fmt.Sprintf("serialized result is %d bytes, exceeding the %d byte limit", len(data), maxOutputBytes), 0
	}
	return data, "", "", 0
}

// exceptionInfo extracts the JS error name and message from a goja exception.
func exceptionInfo(vm *goja.Runtime, exc *goja.Exception) (name, msg string) {
	name, msg = "Error", exc.Error()
	v := exc.Value()
	if v == nil || goja.IsUndefined(v) || goja.IsNull(v) {
		return name, msg
	}
	obj := v.ToObject(vm)
	if obj == nil {
		return name, msg
	}
	if n := obj.Get("name"); n != nil && !goja.IsUndefined(n) && !goja.IsNull(n) {
		if s, ok := n.Export().(string); ok && s != "" {
			name = s
		}
	}
	if m := obj.Get("message"); m != nil && !goja.IsUndefined(m) && !goja.IsNull(m) {
		if s, ok := m.Export().(string); ok && s != "" {
			msg = s
		}
	}
	return name, msg
}

// isPromise reports whether v is a Promise (or Promise-like), which cannot be
// awaited because the runtime has no event loop.
func isPromise(vm *goja.Runtime, v goja.Value, promiseCtor goja.Value) bool {
	if v == nil || goja.IsUndefined(v) || goja.IsNull(v) {
		return false
	}
	obj := v.ToObject(vm)
	if obj == nil {
		return false
	}
	if promiseCtor != nil {
		if ctor, ok := obj.Get("constructor").(*goja.Object); ok && ctor.SameAs(promiseCtor) {
			return true
		}
	}
	if tag := obj.GetSymbol(goja.SymToStringTag); tag != nil {
		if s, ok := tag.Export().(string); ok && s == "Promise" {
			return true
		}
	}
	return false
}
