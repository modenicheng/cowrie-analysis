package tools

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/modenc/e3-security-analyst/internal/llm"
	"github.com/modenc/e3-security-analyst/internal/store"
)

// execute_js 工具约束。
const outputPreviewBytes = 512 // script_runs.output_preview 截断长度（字节）

// executeJSArgs 是 execute_js 的参数；Input 用 RawMessage 承载任意 JSON，
// 既可精确测量序列化大小，又能原样透传给 runner。
type executeJSArgs struct {
	Code      string          `json:"code"`
	Input     json.RawMessage `json:"input"`
	TimeoutMS *int64          `json:"timeout_ms"`
}

// jsOKResult / jsErrResult 是回传给模型的执行信封（与 sandbox 子进程协议一致）。
type jsOKResult struct {
	OK         bool            `json:"ok"`
	Result     json.RawMessage `json:"result"`
	DurationMS int64           `json:"duration_ms"`
}

type jsErrResult struct {
	OK         bool        `json:"ok"`
	Error      jsErrorInfo `json:"error"`
	DurationMS int64       `json:"duration_ms"`
}

type jsErrorInfo struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

// handleExecuteJS 执行 execute_js：
//   - runner 未配置或 cfg.ScriptRunner.Enabled=false → “execute_js 已禁用”；
//   - input 序列化后超过 cfg.ScriptRunner.MaxInputBytes → error（提示缩小）；
//   - timeout_ms 缺省 cfg.ScriptRunner.TimeoutMS，且钳制不超过该值；
//   - runner 基础错误（启动失败、超时杀进程、输出不可解析）→ error；
//   - 脚本级错误（OK=false，如语法错误/超时/超大输出）→ 正常返回
//     {"ok":false,"error":{...}} 让模型自行修正；
//   - 无论成败都写 script_runs 审计（RunID=win.RunID、CodeSHA256、耗时、
//     输出字节数与 512 字节预览）；审计写入失败仅告警，不丢弃执行结果。
func (d *Dispatcher) handleExecuteJS(ctx context.Context, call llm.ToolCall, win TaskWindow) (string, error) {
	var a executeJSArgs
	if err := decodeStrict(call.ArgsJSON, &a); err != nil {
		return "", fmt.Errorf("execute_js 参数不合法: %v", err)
	}
	if a.Code == "" {
		return "", fmt.Errorf("execute_js.code 不能为空：请提交要执行的 JavaScript 源码")
	}
	if d.runner == nil || !d.cfg.ScriptRunner.Enabled {
		return "", fmt.Errorf("execute_js 已禁用（runner=%t enabled=%t）",
			d.runner != nil, d.cfg.ScriptRunner.Enabled)
	}
	if max := d.cfg.ScriptRunner.MaxInputBytes; max > 0 && int64(len(a.Input)) > max {
		return "", fmt.Errorf(
			"execute_js 输入超限：input 序列化后 %d 字节，超过上限 %d 字节，请缩小 input（只传入必要字段，或用 query_events 的 cursor 分批获取）",
			len(a.Input), max)
	}

	timeoutMS := d.cfg.ScriptRunner.TimeoutMS
	if timeoutMS <= 0 {
		timeoutMS = 2000
	}
	if a.TimeoutMS != nil && *a.TimeoutMS > 0 && *a.TimeoutMS < int64(timeoutMS) {
		timeoutMS = int(*a.TimeoutMS)
	}

	res, err := d.runner.Execute(ctx, a.Code, any(a.Input), timeoutMS)
	if err != nil {
		return "", fmt.Errorf("execute_js 执行失败: %w", err)
	}

	var (
		resultJSON string
		out        []byte // 审计用输出（成功=result JSON；失败=错误对象 JSON）
	)
	if res.OK {
		r := res.Result
		if len(r) == 0 {
			r = json.RawMessage("null")
		}
		out = r
		payload, merr := json.Marshal(jsOKResult{OK: true, Result: r, DurationMS: res.DurationMS})
		if merr != nil {
			return "", fmt.Errorf("execute_js 序列化结果失败: %w", merr)
		}
		resultJSON = string(payload)
	} else {
		info := jsErrorInfo{Type: res.ErrorType, Message: res.ErrorMessage}
		out, _ = json.Marshal(info)
		payload, merr := json.Marshal(jsErrResult{OK: false, Error: info, DurationMS: res.DurationMS})
		if merr != nil {
			return "", fmt.Errorf("execute_js 序列化错误结果失败: %w", merr)
		}
		resultJSON = string(payload)
	}

	// 审计：无论脚本成败都记录（best-effort，失败仅告警不丢结果）。
	sum := sha256.Sum256([]byte(a.Code))
	if d.db != nil {
		if err := d.db.InsertScriptRun(ctx, &store.ScriptRun{
			RunID:         win.RunID,
			CodeSHA256:    hex.EncodeToString(sum[:]),
			DurationMS:    res.DurationMS,
			OK:            res.OK,
			OutputBytes:   int64(len(out)),
			OutputPreview: truncateBytes(string(out), outputPreviewBytes),
		}); err != nil {
			d.log.Warn("记录 script_runs 失败", "run_id", win.RunID, "err", err.Error())
		}
	}
	d.log.Debug("execute_js 完成", "ok", res.OK, "duration_ms", res.DurationMS)
	return resultJSON, nil
}
