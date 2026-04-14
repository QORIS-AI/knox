# Knox Changelog

## [1.0.1] — 2026-04-14

### Fixed
- Remove `"hooks"` pointer from `plugin.json` — `hooks/hooks.json` is auto-discovered by Claude Code and specifying it explicitly caused a duplicate hooks load error on install

## [1.0.0] — 2026-04-14

### Initial release

**Enforcement (PreToolUse)**
- 51 blocklist patterns: destruction, exfiltration, bash-inline, eval, pipe-to-shell, miners, escalation, network manipulation, self-protection
- Script content inspection: reads script files before execution, scans recursively (depth 3, max 10 files), covers Python/Node/Shell/Ruby/Perl
- Write path protection: blocks writes to shell configs (`.bashrc`, `.profile`, `.zshrc`), Knox files, git hooks, SSH/AWS/GPG credential paths
- Read path protection: blocks reads to `.env`, `~/.ssh/`, `~/.aws/credentials`, `~/.gnupg/`, `~/.kube/config`
- MCP tool injection scanning: scans string values in `mcp__*` tool inputs for injection patterns
- Sudo sanitization: strips `sudo` + flags at standard preset, denies outright at strict/paranoid
- Paranoid preset: uses `permissionDecision: "ask"` — user approval required instead of hard block

**Injection detection**
- UserPromptSubmit: scans every user message; exit 2 erases poisoned prompts from context
- InstructionsLoaded: scans CLAUDE.md and `.claude/rules/*.md` files; audit-only (Claude Code limitation — cannot block)
- CronCreate / TaskCreated: scans scheduled task prompts for injection strings

**Session management**
- SessionStart: initializes per-session denial state
- SessionEnd: writes audit summary when denials occurred
- SubagentStart: injects Knox security posture into spawned subagents via additionalContext
- FileChanged: live config reload when `.knox.json` or `.knox.local.json` changes on disk

**Audit and escalation**
- PostToolUse: JSONL audit log for every tool call; injects denial count into conversation via additionalContext
- PermissionDenied: audits when Claude Code's own permission classifier auto-denies
- Escalation tracking: per-session threshold (default 3) + cross-session sliding window (default 10/hour)
- ConfigChange: self-protection — blocks settings changes that would disable Knox hooks

**Configuration**
- 4 presets: minimal / standard (default) / strict / paranoid
- 5-level config precedence: managed > user > project > local > env
- 8 toggleable check categories via `knox policy disable/enable`
- Union merge for custom_allowlist/custom_blocklist across config levels

**CLI** (`knox` binary)
- `status`, `verify` (12 test vectors), `test`, `audit`, `report`
- `policy list/add-block/add-allow/add-package/remove/lint/export`
- `policy list-checks/disable/enable`
- `install` (wires all 11 hooks into `~/.claude/settings.json`) / `uninstall`
- `upgrade`

**7 skills**
- `/knox:status`, `/knox:audit`, `/knox:policy` — invocable by Claude autonomously
- `/knox:allow`, `/knox:block`, `/knox:report`, `/knox:help` — user-only (Claude on explicit instruction)

**Testing**
- 112 unit tests (patterns, bypass vectors ×50, check logic, state, audit, config, policy CLI, script inspection)
- 33 integration tests (all 11 hook stdin→stdout flows)
- 51 scenario tests (8 attack scenarios, 3 dev workflow scenarios)
