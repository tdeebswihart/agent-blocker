package rules

// DefaultRules returns built-in permission rules for tools/patterns not
// covered by ~/.claude/settings.json. Most rules now live in settings.json
// and are loaded by SettingsRules; these cover edge cases and composite
// matchers that settings.json's simple pattern syntax can't express.
func DefaultRules(cwd string) []Matcher {
	return []Matcher{
		// ================================================================
		// ALLOW — composite matchers and patterns not expressible in
		// settings.json's simple permission syntax.
		// ================================================================

		// Composite matchers that validate arguments beyond simple globs.
		BashEcho(cwd),
		Mkdir(cwd),
		BashCD(cwd),
		BashLocalCmd(cwd),
	}
}
