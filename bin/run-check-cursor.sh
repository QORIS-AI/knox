#!/usr/bin/env bash
# Cursor hook entry — analogous to run-check.sh but routes to the Cursor adapter.
# Cursor passes events with flat fields (e.g. {command, cwd} for beforeShellExecution)
# and expects {permission, user_message, agent_message} responses on stdout.
PLUGIN_ROOT="${KNOX_ROOT:-${CURSOR_PLUGIN_ROOT:-${CLAUDE_PLUGIN_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}}}"
exec node "$PLUGIN_ROOT/bin/knox-check-cursor"
