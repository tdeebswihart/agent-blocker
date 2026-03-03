Craft per-tool-name style matchers as Golang structs that match the unique tools (jq .tool_name) in @example.jsonl . Each tool should have a specific input struct (like BashInput,
  GrepInput, LogMCPInput) that parse their specific JSON and return a Result like the following:
  ```go
  type Decision string
  const (
    Allow = Decision("allow")
    Ask = Decision("ask")
    Deny = Decision("deny")
  )
 
 type Result struct {
 	Decision	Decision `json:"decision"`
 	Reason string `json:"reason"`
 	HookSpecificOutput json.RawMessage `json:"hookSpecificOutput`
 }
 
 // IMPORTANT: PreToolUse previously used top-level decision and reason fields, but these are deprecated for this event. Use hookSpecificOutput.permissionDecision and hookSpecificOutput.permissionDecisionReason instead. The deprecated values "approve" and "block" map to "allow" and "deny" respectively. Other events like PostToolUse and Stop continue to use top-level decision and reason as their current format.
 type PreToolUseOutput struct {
 	HookEventName string `json:"hookEventName"` // always "PreToolUse"	
 	PermissionDecision Decision `json:"permissionDecision"`
 	// Additional context the LLM will intake
 	AdditionalContext string `json:"additionalContext"` 
 }
  ```
  
  Each tool should be executed like:
  ```go
  rule, handled := <ToolConstructor>(<parameters>)
  result := rule.Apply(<tool-specific input type>)
  if handled {
  	return result
  }
  ```
  
  Put these under pkg/rules/<tool_name>.go. Use red/green tdd