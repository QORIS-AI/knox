---
name: knox:preset
description: Switch the active Knox security preset (minimal | standard | strict | paranoid | disabled).
argument-hint: "[paranoid | strict | standard | minimal | disabled]"
disable-model-invocation: true
allowed-tools: Bash(${CLAUDE_PLUGIN_ROOT}/bin/knox preset *)
---

Run `${CLAUDE_PLUGIN_ROOT}/bin/knox preset $ARGUMENTS` to switch the active Knox preset for this user.

Validation lives in the script — typos exit 1 with the allowed list. The CLI writes `~/.config/knox/config.json`, which overrides any `/plugin` UI checkboxes. Tell the user to **restart their Claude Code session** afterwards (hooks read env at session start; preset changes don't hot-reload).

This skill is `disable-model-invocation: true` — Claude must not change presets autonomously. The user has to type `/knox:preset <name>` or `knox preset <name>` themselves.
