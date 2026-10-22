package llm

import "encoding/json"

// Wire types for the OpenAI-compatible chat completions protocol (DeepSeek).

// responseFormat selects the response encoding, e.g. {"type":"json_object"}.
type responseFormat struct {
	Type string `json:"type"`
}

// functionDef is the function description inside a tool definition.
type functionDef struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Parameters  json.RawMessage `json:"parameters,omitempty"` // JSON Schema
}

// toolDefinition is one entry of the request "tools" array.
type toolDefinition struct {
	Type     string      `json:"type"` // always "function"
	Function functionDef `json:"function"`
}

// functionCall names a function plus its JSON-encoded arguments string.
type functionCall struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"` // JSON object encoded as string
}

// toolCallMsg is one entry of an assistant message's "tool_calls" array.
type toolCallMsg struct {
	ID       string       `json:"id"`
	Type     string       `json:"type"` // "function"
	Function functionCall `json:"function"`
}

// message is one entry of the request/response "messages" array, supporting
// the system, user, assistant and tool roles.
type message struct {
	Role       string        `json:"role"`                   // system|user|assistant|tool
	Content    string        `json:"content"`                // tool results and text content
	ToolCalls  []toolCallMsg `json:"tool_calls,omitempty"`   // assistant only
	ToolCallID string        `json:"tool_call_id,omitempty"` // tool role only
}

// chatRequest is the POST /chat/completions body.
type chatRequest struct {
	Model          string           `json:"model"`
	Messages       []message        `json:"messages"`
	MaxTokens      int              `json:"max_tokens,omitempty"`
	Stream         bool             `json:"stream"` // always false
	Tools          []toolDefinition `json:"tools,omitempty"`
	ToolChoice     any              `json:"tool_choice,omitempty"` // "auto" when tools present
	ResponseFormat *responseFormat  `json:"response_format,omitempty"`
}

// usageInfo is the token accounting block of a response.
type usageInfo struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
}

// choice is one entry of the response "choices" array; only the first is used.
type choice struct {
	Message      message `json:"message"`
	FinishReason string  `json:"finish_reason"`
}

// chatResponse is the parsed completion response.
type chatResponse struct {
	Choices []choice  `json:"choices"`
	Usage   usageInfo `json:"usage"`
}
