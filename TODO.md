Add `PermissionDecisionReason string `json:"permissionDecisionReason,omitempty"` to PreToolUseOutput.
  Use it instead of AdditionalContext: leave AdditionalContext unused for now
  
  config file
  access log for learning new tools
  - No subshell parsing: (a && b) splits through parens (operators inside are still found)
  - No $() or backtick command substitution parsing
  - No heredoc or process substitution parsing
  - No backslash-escaped operator handling
