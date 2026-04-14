# Knox Changelog

## [1.1.0] — 2026-04-14

### Architecture shift — pattern engine → recursive unwrap + tokenized parsers

Knox v1.0 was pure flat regex on the raw command string. A red-team against it found a ~70% bypass rate: rm flag variants, wrapper unwrapping (`bash -c`, `eval`, `$()`), inline interpreter code, self-protection gaps. v1.1 replaces the core matching pipeline with:

1. **Self-protection checks** (unconditional, run first)
2. **Env-var prefix strip + block** (`KNOX_PRESET=off <cmd>` → blocked)
3. **Recursive unwrapping** — `bash -c`, `sh -c`, `eval`, `$(...)`, backticks, `<(...)`, delimiter split (`;`, `&&`, `||`) — each fragment checked against full blocklist
4. **Tokenized `rm`/`find` parsers** — argv-aware, expand `$HOME`/`~`/`${HOME}`, resolve absolute paths, catch long-flag variants
5. **Inline code extraction** — scans `python -c "..."`, `node -e "..."`, `perl -e`, `ruby -e`, `php -r` contents for dangerous APIs (`os.system`, `subprocess`, `child_process`, `socket`, `fsockopen`)
6. **Exfil conjunction** — sensitive-path read (`~/.ssh/id_rsa`, `~/.aws/credentials`, `/etc/shadow`) paired with egress verb (`curl -F @`, `nc`, `scp`, `rsync`, `/dev/tcp`) → block. Either alone still allowed.
7. **Redirect target parsing** — `>`, `>>`, `tee` targets fed through path protection; catches `>> ~/.ssh/authorized_keys`, `> /etc/cron.d/x`, `> /etc/systemd/system/x.service`
8. **Interactive root shell detection** — `sudo bash`, `sudo -i`, `pkexec bash`, `doas sh`
9. **GTFOBin patterns** — `vim -c :!bash`, `find -exec bash`

### New blocklist patterns (BL-052 through BL-068)

- `BL-052 cmd_sub_fetch_exec` — `$(curl ...)` / `` `curl ...` `` (critical)
- `BL-053 dev_tcp_redirect` — bash `/dev/tcp/` reverse shell (critical)
- `BL-054 nc_exec_variants` — `nc -c/-e/--exec bash` (critical)
- `BL-055 mkfifo_shell` — FIFO-based reverse shell (critical)
- `BL-056 sudo_interactive_shell` — `sudo bash`, `sudo -u root bash` (high)
- `BL-057 pkexec_doas_shell` — alternative escalation paths (high)
- `BL-058 iptables_policy_flip` — `iptables -P INPUT ACCEPT` (critical)
- `BL-059 gtfobin_vim` — `vim -c ':!bash'` (high)
- `BL-060 gtfobin_find_exec` — `find -exec bash` (high)
- `BL-061 ssh_reverse_forward` — `ssh -R` (high, strict preset)
- `BL-062 authorized_keys_append` — `>> ~/.ssh/authorized_keys` (critical)
- `BL-063 cron_dir_write` — `> /etc/cron.d/*` (high)
- `BL-064 systemd_unit_write` — `> /etc/systemd/system/*.service` (high)
- `BL-065 sudoers_append` — `>> /etc/sudoers` (critical)
- `BL-066 miner_donate_flag` — `--donate-level` flag detects generic miners (critical)
- `BL-067 stratum_client` — stratum-client binary names (high)
- `BL-068 shell_reverse_dev_tcp` — `bash -i >& /dev/tcp/...` (critical)

### New self-protection rules

- `SP-001 env_var_prefix_override` — leading `KNOX_*=val` command prefix (critical, unconditional)
- `SP-002 knox_file_mutate` — any write/mv/chmod/ln/sed/jq targeting Knox's own files (critical, unconditional)
- `SP-003 alias_shadow` — aliasing/shadowing `rm`/`curl`/`sudo` etc. (high)
- `SP-004 knox_kill` — `pkill -f knox`, `killall knox-check` (critical)
- `SP-RM` — tokenized rm parser flags destructive calls on `$HOME`, `/`, `/etc`, `/var`, `~/.ssh`, etc.
- `SP-FIND` — find -delete / find -exec rm on sensitive targets only
- `SP-EX` — exfiltration pair detection (sensitive read + egress)
- `SP-RD` — redirect targeting persistence paths (cron, systemd, authorized_keys, sudoers)
- `IL-PY-*` / `IL-JS-*` / `IL-PL-*` / `IL-RB-*` / `IL-PH-*` — inline interpreter code inspection

### New lib modules

- `lib/self-protect.js` — env prefix, knox-path mutation guard, alias shadow, knox-kill
- `lib/unwrap.js` — recursive wrapper extraction + delimiter splitting
- `lib/tokenize.js` — zero-dependency argv-style shell tokenizer, path expansion
- `lib/parsers/rm.js` — tokenized rm/find analysis with sensitive target list
- `lib/inline-inspect.js` — per-language dangerous API patterns
- `lib/exfil.js` — sensitive-read + egress conjunction rule
- `lib/redirect.js` — redirect target parsing to protected persistence paths

### Legacy pattern retirement

These v1.0 blocklist entries are now superseded by smarter parsers and skipped in the regex pass (marked provisional in `lib/check.js`):

- `BL-001 rm_rf_root`, `BL-002 rm_rf_home`, `BL-003 rm_rf_relative` → tokenized rm parser
- `BL-011 bash_inline` → recursive unwrap (blanket `bash -c` block had high FP rate)
- `BL-040 find_delete_exec` → tokenized find parser (now only fires on sensitive targets)

### Tests

- **322 unit tests passing** (up from 112)
- **25/25 real pipeline benchmark passing** (actual knox-check binary invocation via stdin)
- **Average hook latency: 78ms** measured end-to-end
- 6 new test files: `v11-self-protection`, `v11-unwrap`, `v11-rm-parser`, `v11-inline-code`, `v11-exfil-redirect`, `v11-escalation-network`

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
