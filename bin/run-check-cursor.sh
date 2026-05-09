#!/usr/bin/env bash
# Cursor hook entry — analogous to run-check.sh but routes to the Cursor adapter.
# Cursor passes events with flat fields (e.g. {command, cwd} for beforeShellExecution)
# and expects {permission, user_message, agent_message} responses on stdout.
PLUGIN_ROOT="${KNOX_ROOT:-${CURSOR_PLUGIN_ROOT:-${CLAUDE_PLUGIN_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}}}"

if [ -z "$KNOX_DEV_QUIET" ]; then
  case "$PLUGIN_ROOT" in
    "$HOME/.claude/plugins/cache/"*) ;;
    "$HOME/.cursor/plugins/"*) ;;
    *)
      _warn_sentinel="$HOME/.cache/knox/dev-warning-shown"
      if [ ! -f "$_warn_sentinel" ]; then
        mkdir -p "$HOME/.cache/knox" 2>/dev/null
        printf 'Knox: hook firing from %s (not marketplace cache). Suppress with KNOX_DEV_QUIET=1.\n' "$PLUGIN_ROOT" >&2
        : > "$_warn_sentinel" 2>/dev/null
      fi ;;
  esac
fi

exec node "$PLUGIN_ROOT/bin/knox-check-cursor"
