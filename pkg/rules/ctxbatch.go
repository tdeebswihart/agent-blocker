package rules

const ctxBatchExecuteTool = "mcp__plugin_context-mode_context-mode__ctx_batch_execute"

// CtxBatchCommand is a single command entry in a ctx_batch_execute call.
type CtxBatchCommand struct {
	Label   string `json:"label"`
	Command string `json:"command"`
}

// CtxBatchExecuteInput is the tool_input for ctx_batch_execute calls.
type CtxBatchExecuteInput struct {
	Commands []CtxBatchCommand `json:"commands"`
	Queries  []string          `json:"queries,omitempty"`
	Timeout  int               `json:"timeout,omitempty"`
}
