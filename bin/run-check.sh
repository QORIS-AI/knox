#!/usr/bin/env bash
# Hook subprocesses are non-interactive non-login shells.
# Bash does NOT source .bashrc or .profile in this context.
# ${BASH_SOURCE[0]} resolves correctly even when the script is called via symlink.
PLUGIN_ROOT="${KNOX_ROOT:-${CLAUDE_PLUGIN_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}}"

# Dev-CWD warning: if the hook is firing from a tree outside the marketplace
# cache, a developer is running Knox from source. That's fine, but the user
# may have forgotten — and updates won't flow through `claude plugin update`.
# Warn once per machine; suppressible via KNOX_DEV_QUIET=1.
if [ -z "$KNOX_DEV_QUIET" ]; then
  case "$PLUGIN_ROOT" in
    "$HOME/.claude/plugins/cache/"*) ;;
    *)
      _warn_sentinel="$HOME/.cache/knox/dev-warning-shown"
      if [ ! -f "$_warn_sentinel" ]; then
        mkdir -p "$HOME/.cache/knox" 2>/dev/null
        printf 'Knox: hook firing from %s (not marketplace cache). Suppress with KNOX_DEV_QUIET=1.\n' "$PLUGIN_ROOT" >&2
        : > "$_warn_sentinel" 2>/dev/null
      fi ;;
  esac
fi

exec node "$PLUGIN_ROOT/bin/knox-check"
