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
	"reflect"
	"strconv"
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

	// estimateSafetyFactor is the multiple of maxOutputBytes at which the
	// pre-marshal size gate (security review High#1) rejects a result.
	//
	// The gate works because every weight in estimateJSONSize is the exact
	// MINIMUM JSON encoding of a value (string byte length, shortest number
	// form, punctuation), so for anything the gate actually enumerates the
	// estimate can only under-count, never over-count, the real
	// encoding/json output — a result that passes the exact post-marshal
	// check therefore never reaches the 2x threshold, and the gate cannot
	// reject output the exact check would have accepted. The factor's job is
	// only to absorb the deliberately coarse paths that size by length
	// without enumerating (typed arrays, Map/Set entries, strings that
	// marshal with \u escapes, 'g'-vs-'f' float formatting): those can
	// under-count by a bounded factor, and 2x keeps such borderline results
	// flowing to the exact post-marshal check instead of being falsely
	// rejected here. The gate's target is the GB-regime bomb, where any of
	// these estimates is over the limit by orders of magnitude.
	estimateSafetyFactor = 2
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

	// Pre-marshal size gate (security review High#1). The old flow paid for
	// an oversized result twice AFTER the script had already finished:
	// Export() materialized a full Go copy of the value graph, then
	// json.Marshal allocated the encoded bytes on top — turning an in-VM
	// bomb string into ~3x its size of process memory. The gate walks the
	// goja value directly (no Export) and rejects before both steps when the
	// estimate already exceeds estimateSafetyFactor x maxOutputBytes.
	//
	// Boundary of this defense, deliberately: results that PASS the gate can
	// still make Export()+Marshal allocate up to ~2x the byte limit each —
	// bounded by construction, and exactly what the existing post-marshal
	// check then enforces. What the gate must and does stop is the
	// marshal-side amplification of results that are over the limit by
	// orders of magnitude. Inspecting a hostile result can re-enter the
	// interpreter through getters/proxy traps; that stays bounded by the
	// still-armed timeout interrupt, and any panic it causes is converted
	// into a structured error below instead of escaping RunCode.
	if est, panicVal := estimateJSONSize(result, maxOutputBytes*estimateSafetyFactor); panicVal != nil {
		if _, interrupted := panicVal.(*goja.InterruptedError); interrupted {
			return nil, "TimeoutError",
				fmt.Sprintf("inspecting the script result exceeded the %dms time limit and was interrupted", timeoutMS), 0
		}
		return nil, "NotSerializable",
			"result is not safely serializable: inspecting it threw an exception: " + fmt.Sprint(panicVal), 0
	} else if est >= maxOutputBytes*estimateSafetyFactor {
		return nil, "OutputTooLarge",
			fmt.Sprintf("estimated serialized result is %d bytes, exceeding the %d byte limit", est, maxOutputBytes), 0
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

// Minimum-JSON weights used by estimateJSONSize. Each is the exact smallest
// encoding encoding/json can produce for that piece of a value, which is what
// makes the estimate a lower bound (see estimateSafetyFactor).
const (
	// jsonNull is the encoding of null (and of undefined, which the caller
	// normalizes earlier but nested occurrences still export as nil).
	jsonNull = int64(4)
	// jsonMinArrayElement covers "," plus one minimal element ("0"); the
	// enclosing "[" and "]" are counted once per array.
	jsonMinArrayElement = int64(2)
	// jsonMinObjectEntry covers the quotes and colon around a key plus ","
	// and one minimal value; the key's own byte length is added separately.
	jsonMinObjectEntry = int64(5)
)

// estimateJSONSize cheaply estimates how many bytes json.Marshal of v's
// exported value would produce, WITHOUT materializing the value the way
// Value.Export() does on objects. The walk short-circuits as soon as the
// running total reaches budget and returns (estimate, nil); if inspecting v
// panics (a getter or proxy trap re-entering the interpreter), the panic
// value is returned instead with a zero estimate.
//
// Walk strategy — never more expensive than the Export() it prevents:
//   - primitives: exported one by one (cheap for non-objects) and measured
//     exactly; strings by byte length, numbers by their shortest form.
//   - JS arrays: rejected early by the length property alone when that
//     already overflows the budget; otherwise iterated element-wise with the
//     same early exit (iteration is capped at budget/2 elements).
//   - slice-exporting exotics (Set, Map, typed arrays): sized by their
//     length/size/byteLength property without enumerating. Their index
//     properties are enumerable, so the generic Keys() path would itself
//     allocate a huge key slice and defeat the gate.
//   - String wrapper objects: sized by length; they export as a plain
//     string.
//   - anything else (plain objects, class instances, wrapped Go input
//     values): Keys() plus one Get per key. Keys() materializes the key
//     slice, but that is never larger than the object's own property
//     storage — i.e. never larger than the Export() map this gate exists to
//     avoid.
//
// Known under-counts (never over-counts, by construction of the weights):
// strings marshaling with \u escapes (up to ~6x), 'g'-vs-'f' float
// formatting (a few bytes per number), and the by-length paths above. All
// fall through to the exact post-marshal size check, which remains the
// authoritative enforcement.
func estimateJSONSize(v goja.Value, budget int64) (estimate int64, panicValue any) {
	defer func() {
		if p := recover(); p != nil {
			panicValue = p
		}
	}()
	return estimateValueSize(v, budget), nil
}

// estimateValueSize is the recursive body of estimateJSONSize. budget is the
// remaining allowance from the enclosing structure; each level stops adding
// as soon as it is reached.
func estimateValueSize(v goja.Value, budget int64) int64 {
	if v == nil || goja.IsUndefined(v) || goja.IsNull(v) {
		return jsonNull
	}
	if obj, ok := v.(*goja.Object); ok {
		return estimateObjectSize(obj, budget)
	}
	// Primitives only: Export() on a non-object copies at most the value
	// itself (strings share their backing), never a nested graph.
	switch x := v.Export().(type) {
	case string:
		return int64(len(x)) + 2 // quotes; escaping only grows the encoding
	case bool:
		if x {
			return 4 // true
		}
		return 5 // false
	case int64:
		var buf [24]byte
		return int64(len(strconv.AppendInt(buf[:0], x, 10)))
	case float64:
		// encoding/json uses a shortest form close to 'g'; a few bytes of
		// divergence per number is absorbed by the safety factor.
		var buf [32]byte
		return int64(len(strconv.AppendFloat(buf[:0], x, 'g', -1, 64)))
	default:
		return 8 // symbols, functions, ... marshal lossily to something tiny
	}
}

// estimateObjectSize sizes object values per the strategy documented on
// estimateJSONSize.
func estimateObjectSize(obj *goja.Object, budget int64) int64 {
	// JS arrays: length first, elements only if the length alone cannot
	// overflow the budget (this bounds iteration at budget/2 Get calls).
	// Checked before the ExportType branch because a JS array also exports
	// as a slice.
	if obj.ClassName() == "Array" {
		length := propLength(obj, "length")
		if length >= budget/jsonMinArrayElement {
			return 2 + length*jsonMinArrayElement // >= budget, exact lower bound
		}
		n := int64(2) // "[" "]"
		for i := int64(0); i < length; i++ {
			n += jsonMinArrayElement + estimateValueSize(obj.Get(strconv.FormatInt(i, 10)), budget-n)
			if n >= budget {
				return n
			}
		}
		return n
	}

	// Slice-exporting exotics (Set -> []any, Map -> [][2]any, typed arrays
	// -> element slices, Uint8Array -> []byte/base64): size by property, not
	// by enumeration. ExportType never runs user code or materializes data.
	// jsonMinArrayElement stays a strict lower bound even for Map's [key,
	// value] pairs and base64 bytes (~1.4x), at the cost of rejecting those
	// shapes a bit later than an exact walk would.
	if t := obj.ExportType(); t.Kind() == reflect.Slice || t.Kind() == reflect.Array {
		n := maxInt64(propLength(obj, "length"), maxInt64(propLength(obj, "size"), propLength(obj, "byteLength")))
		return 2 + n*jsonMinArrayElement
	}

	// String wrappers export as a plain string; measure like one.
	if obj.ClassName() == "String" {
		return propLength(obj, "length") + 2
	}

	// Generic path: enumerate own enumerable string keys. Symbol keys never
	// marshal. Get() may run a getter; that is bounded by the still-armed
	// timeout interrupt and recovered by estimateJSONSize.
	n := int64(2) // "{" "}"
	for _, k := range obj.Keys() {
		n += int64(len(k)) + jsonMinObjectEntry + estimateValueSize(obj.Get(k), budget-n)
		if n >= budget {
			return n
		}
	}
	return n
}

// propLength reads an integer-ish own/inherited property used for sizing
// (length, size, byteLength), returning 0 when absent or negative. Built-in
// accessors never run script code; hostile traps are covered by the recover
// in estimateJSONSize.
func propLength(obj *goja.Object, name string) int64 {
	v := obj.Get(name)
	if v == nil || goja.IsUndefined(v) || goja.IsNull(v) {
		return 0
	}
	if n := v.ToInteger(); n > 0 {
		return n
	}
	return 0
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
