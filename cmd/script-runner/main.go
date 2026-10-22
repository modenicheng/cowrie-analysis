// Command script-runner executes one JavaScript analysis task.
//
// It reads a JSON task from stdin, runs it in the restricted goja
// environment (internal/sandbox.RunCode) and writes the result envelope to
// stdout (see internal/sandbox for the wire formats).
//
// The process is hermetic by construction: it reads nothing but stdin,
// writes nothing but stdout, never reads environment variables, and never
// touches the network or the file system (SPEC §5.2, §9, §15). Its parent
// (sandbox.Runner) starts it with an explicitly empty environment.
//
// Exit codes: 0 = task was executed (script errors are part of the JSON
// envelope); 2 = bad input (oversized or malformed task JSON); 3 = internal
// panic inside the runner process.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime/debug"

	"github.com/modenc/e3-security-analyst/internal/sandbox"
)

const (
	// maxTaskBytes caps the stdin payload to prevent memory abuse.
	maxTaskBytes = 9 << 20 // 9 MiB
	// maxResultBytes is the child-side backstop on the serialized script
	// result; the parent Runner enforces its own Limits.MaxOutputBytes.
	maxResultBytes = 4 << 20
	// softMemoryLimit is a Go runtime soft limit for this process (security
	// review High#1): goja's vm.Interrupt only takes effect between
	// interpreter instructions, so a single uninterruptible builtin call
	// (e.g. "A".repeat(1<<30) or new Array(1e9).fill(0)) can allocate without
	// bound before the wall-clock timeout fires. A soft limit makes the GC
	// collect ever harder as the heap approaches it instead of letting the
	// process balloon unopposed. Two harder layers back it up: the parent
	// kills the child after timeout+grace, and systemd MemoryMax=256M (see
	// deploy/*.service) is the final OOM ceiling — 192MiB sits below it with
	// headroom for the GC to work, and far above any legitimate task (9 MiB
	// input, 4 MiB result, a few multiples of both in goja values). Not
	// configurable: this child runs with an empty environment and reads no
	// config (YAGNI).
	softMemoryLimit = 192 << 20 // 192 MiB
)

type runError struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

type envelope struct {
	OK         bool            `json:"ok"`
	Result     json.RawMessage `json:"result"`
	Error      *runError       `json:"error"`
	DurationMS int64           `json:"duration_ms"`
}

func emit(envelope envelope) {
	enc, err := json.Marshal(envelope)
	if err != nil {
		// All envelope fields are trivially marshalable; this is a last
		// resort so the parent always receives valid JSON on stdout.
		enc = []byte(`{"ok":false,"result":null,"error":{"type":"InternalError","message":"encode result failed"},"duration_ms":0}`)
	}
	os.Stdout.Write(enc)
}

func emitBadInput(format string, args ...any) {
	emit(envelope{
		OK:         false,
		Error:      &runError{Type: "BadInput", Message: fmt.Sprintf(format, args...)},
		DurationMS: 0,
	})
}

func main() {
	// Install the soft memory limit before any task data is read so no
	// script-driven allocation can precede it (security review High#1).
	debug.SetMemoryLimit(softMemoryLimit)
	os.Exit(run())
}

func run() int {
	// A panic in the runner process is an infrastructure fault, not a script
	// error: report it on stdout and exit with a dedicated code.
	defer func() {
		if p := recover(); p != nil {
			emit(envelope{
				OK:    false,
				Error: &runError{Type: "InternalError", Message: fmt.Sprintf("script-runner panic: %v", p)},
			})
			os.Exit(3)
		}
	}()

	data, err := io.ReadAll(io.LimitReader(os.Stdin, maxTaskBytes+1))
	if err != nil {
		emitBadInput("read stdin: %v", err)
		return 2
	}
	if int64(len(data)) > maxTaskBytes {
		emitBadInput("task input exceeds %d bytes", int64(maxTaskBytes))
		return 2
	}

	var task sandbox.Task
	if err := json.Unmarshal(data, &task); err != nil {
		emitBadInput("invalid task JSON: %v", err)
		return 2
	}

	out, errType, errMsg, durationMS := sandbox.RunCode(task.Code, task.Input, task.TimeoutMS, maxResultBytes)
	env := envelope{DurationMS: durationMS}
	if errType == "" {
		env.OK = true
		env.Result = json.RawMessage(out) // out is valid JSON ("null" allowed)
	} else {
		env.Error = &runError{Type: errType, Message: errMsg}
	}
	emit(env)
	return 0
}
