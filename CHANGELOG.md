# Knox Changelog

## [1.2.0] — 2026-04-15

### Added
- **ClawHub distribution** — Knox is now publishable to ClawHub as a `bundle-plugin` for OpenClaw users. Adds `openclaw.bundle.json` (hostTargets=["claude-code"], format="claude-code-plugin") and an `openclaw` metadata block in `package.json`. Claude Code users are unaffected — the existing `qoris-ai/qoris-marketplace` install path continues to work exactly as before.
- **`.clawhubignore`** — excludes tests, logs, lockfiles, and local state from ClawHub uploads (ClawHub CLI does not respect `.gitignore`/`.npmignore`, only `.clawhubignore`).

## [1.1.5] — 2026-04-14

### Added
- **README "Known limitations and red-team results" section** — transparent documentation of the 1.1% bypass rate, what specifically is not caught at `standard` preset, and why (design vs. real gap vs. LLM's job)
- **`bin/knox-test` wrapper** — unambiguous `BLOCK`/`ALLOW` harness for red-teaming, handles both hard-block (exit 2) and soft-block (exit 0 + JSON decision) paths
- **`/redteam` skill** at `skills/redteam/SKILL.md` — systematic 8-category attack walkthrough usable by any Claude session
- **Custom-config recipes** in README for closing the known gaps: `.env` blocks, external curl blocks, interactive shell blocks, suspicious-binary blocks

### Fixed
- `rm -rf ~/test` (cleanup inside own home dir) now ALLOWED — was false-positive blocked because `/home` was in `SENSITIVE_TARGETS`. Added differentiated check: `/home/<otheruser>` still blocks, `/home/<current_user>/...` is allowed.

## [1.1.4] — 2026-04-14

### Fixed
- `find / -name id_rsa -exec cat {} \;` — `analyzeFind` now detects `-name` / `-iname` matching known secret filenames (id_*, *_rsa, *_ed25519, *.pem, *.key, credentials, shadow, authorized_keys, .env*) paired with `-exec` running a reader (cat/less/head/tail/xxd/od/base64/strings/nc/curl/wget). Blocks at SP-FIND.
- `xargs -I{} bash -c "{}"` and variants — new BL-088 pattern catches xargs piping stdin payloads into shell/interpreter `-c` calls.

After v1.1.4, Opus clean red-team reports **1.1% bypass rate** (2 of 184 commands tested) — both remaining gaps are design decisions (single reads of local secrets allowed at standard preset) rather than unfixable bugs.

## [1.1.3] — 2026-04-14

### Fixed
- Extended knox-file mutation guard to cover `lib/*.js` files (editing `lib/check.js` would neutralize Knox)
- Added `cp`, `mv`, `install` target parsing to redirect module — `cp /tmp/evil .git/hooks/pre-commit` now blocks (persistence via copy)

## [1.1.2] — 2026-04-14

### Added (9 new gap closures from clean red-team)
- `SP-005` variable indirection: catches `r=rm; $r -rf ~` and similar shell variable alias tricks
- Extended `BL-050` hex_encoded_payload to match `echo -e '\xXX'` variants (not just printf)
- `ln -sf` symlink replacement of shell config files (`ln -sf /tmp/evil ~/.bashrc`) via redirect module
- Extended `BL-051` mining_pool_protocol with common pool domains: minexmr.com, ethermine.org, 2miners.com, f2pool.com, flexpool.io, supportxmr.com, moneroocean.stream, viabtc.com
- `UNCONDITIONAL_SECRET_READS` set: `/etc/shadow` and `~/.gnupg/private-keys-v1.d/*` blocked outright (not just paired with egress)
- `FIND_XARGS_SECRET`: `find / -name id_rsa | xargs cat` pattern
- `checkKnoxKill` extended to cover `unlink`/`rm`/`truncate`/`shred` targeting Knox audit log files
- Self-protect `KNOX_PROTECTED_PATHS` expanded with `~/.knox`, `policies/patterns.json`, `lib/*.js`, `bin/knox-check`, `bin/run-check.sh`
- System file redirect protection (`> /etc/passwd`, `: > /etc/passwd`) via `SYSTEM_PROTECTED_PATHS` set

## [1.1.1] — 2026-04-14

### Added (22 new patterns closing red-team gaps)
- `BL-069 rm_rf_glob` — `rm -rf /*` glob form (glob resolution bypasses literal-path match)
- `BL-070 systemctl_persist` — `systemctl enable/start` moved from strict to standard
- `BL-071 update_rc_d` — SysV service registration
- `BL-072 chmod_git_hooks` — `chmod +x .git/hooks/*`
- `BL-073 autostart_write` — `~/.config/autostart/` writes (cp, mv, redirect)
- `BL-074 crontab_stdin_pipe` — generic `| crontab -` stdin (catches benign-looking cron installs)
- `BL-075 ngrok_tunnel` — ngrok tcp/http/tls
- `BL-076 chisel_tunnel` — chisel client/server
- `BL-077 ssh_remote_forward` — `ssh -R <port>:` moved from strict to standard
- `BL-078 network_scanner` — nmap / masscan / zmap / rustscan
- `BL-079 tcpdump_capture` — `tcpdump -w` to file
- `BL-080 newgrp_sudo` — `newgrp sudo` / `sg sudo`
- `BL-081 curl_F_file` — `curl -F file=@/path` upload form
- `BL-082 curl_T_upload` — `curl -T -` stdin upload
- `BL-083 dns_exfil_dig` — `cat file | xargs dig` DNS exfiltration chain
- `BL-084 bash_history_exfil` — bash_history piped to egress
- `BL-085 redirect_system_file` — `> /etc/passwd` and siblings
- `BL-086 colon_redirect_system` — `: > /etc/passwd` null-command truncation
- `BL-087 two_step_fetch_exec` — `curl > /tmp/x && bash /tmp/x` download-then-exec chain
- `IL-PY-009` urllib/requests library detection in inline Python
- `IL-PY-010` `open('/etc/shadow')` direct file reads
- `IL-PY-011` `open('~/.ssh/id_rsa')` SSH private key opens
- New `checkEnvExport` catches bare `export KNOX_PRESET=off` (session poison, not just command prefix)

### Fixed
- BL-024 `\bsu\s+-\b` didn't match `su -` (trailing `\b` problem with non-word char) → now uses `\bsu\s+-(?:\s|$)|^\s*su\s*$`
- `LD_PRELOAD=/tmp/e.so id` env-var strip no longer strips dangerous env vars before BL-039 can match (new `DANGEROUS_ENV_VARS` set: `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`, `BASH_ENV`, `ENV`, `PROMPT_COMMAND`, `DYLD_INSERT_LIBRARIES`, `IFS`)
- `rm -rf ../../` parent-traversal detection in rm parser
- Self-protect `extractTargets` refined to only scan sub-commands split on shell delimiters, preventing false positives on commit messages containing `knox-check` substrings

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
