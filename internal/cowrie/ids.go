// Package cowrie 负责 Cowrie JSONL 事件解析与事件类型契约。
// 本文件定义事件 ID 常量与归类函数，是 collector 与 rules 的共同契约，禁止随意改动语义。
// 事件名称以实际 Cowrie 版本为准；未知 eventid 必须归类为 KindOther，不得丢弃。
package cowrie

// Cowrie 事件 ID 常量（以 Cowrie 主线为准，未知变体按前缀归类）。
const (
	EventConnect       = "cowrie.session.connect"
	EventLoginFailed   = "cowrie.login.failed"
	EventLoginSuccess  = "cowrie.login.success"
	EventCommandInput  = "cowrie.command.input"
	EventFileUpload    = "cowrie.session.file_upload"
	EventFileDownload  = "cowrie.session.file_download"
	EventSessionClosed = "cowrie.session.closed"
)

// Kind 是事件的行为归类，供规则引擎与统计使用。
type Kind int

const (
	KindOther Kind = iota
	KindConnect
	KindLoginFailed
	KindLoginSuccess
	KindCommand
	KindFileUpload
	KindFileDownload
	KindFileFailed
	KindSessionClosed
)

// Classify 按 eventid 归类事件。file_download.failed 等失败变体归为 KindFileFailed。
func Classify(eventID string) Kind {
	switch eventID {
	case EventConnect:
		return KindConnect
	case EventLoginFailed:
		return KindLoginFailed
	case EventLoginSuccess:
		return KindLoginSuccess
	case EventCommandInput:
		return KindCommand
	case EventFileUpload:
		return KindFileUpload
	case EventSessionClosed:
		return KindSessionClosed
	}
	switch {
	case eventID == EventFileDownload:
		return KindFileDownload
	case eventID == "cowrie.session.file_download.failed" || eventID == "cowrie.session.file_upload.failed":
		return KindFileFailed
	}
	return KindOther
}
