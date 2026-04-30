#!/usr/bin/env bash
# Hook subprocesses are non-interactive non-login shells.
# Bash does NOT source .bashrc or .profile in this context.
# ${BASH_SOURCE[0]} resolves correctly even when the script is called via symlink.
PLUGIN_ROOT="${KNOX_ROOT:-${CLAUDE_PLUGIN_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}}"
exec node "$PLUGIN_ROOT/bin/knox-check"
