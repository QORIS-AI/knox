#!/usr/bin/env node
'use strict';
const fs = require('fs');
const path = require('path');
const os = require('os');

// Absolute path at install time (KNOX_ROOT/CLAUDE_PLUGIN_ROOT may not be set in npm context)
const PLUGIN_ROOT = process.env.KNOX_ROOT || process.env.CLAUDE_PLUGIN_ROOT || path.dirname(__dirname);
const SETTINGS_FILE = path.join(os.homedir(), '.claude', 'settings.json');
const CACHE_PREFIX = path.join(os.homedir(), '.claude', 'plugins', 'cache');
const KNOX_CACHE_DIR = path.join(CACHE_PREFIX, 'qoris', 'knox');

// Complete hook registration for all 11 event types.
// Sync (timeout) for blocking hooks, async:true for audit-only / info hooks.
function buildHookEntries(root) {
  return {
    // ── PreToolUse (7 matcher groups, all SYNC — must block before execution) ──
    PreToolUse: [
      {
        matcher: 'Bash|Monitor|PowerShell|Read',
        hooks: [{ type: 'command', command: `${root}/bin/run-check.sh`, timeout: 10 }]
      },
      {
        matcher: 'Write|Edit|MultiEdit|NotebookEdit',
        hooks: [{ type: 'command', command: `${root}/bin/run-check.sh`, timeout: 5 }]
      },
      {
        matcher: 'CronCreate',
        hooks: [{ type: 'command', command: `${root}/bin/knox-cron-guard`, timeout: 5 }]
      },
      {
        matcher: '^mcp__',
        hooks: [{ type: 'command', command: `${root}/bin/run-check.sh`, timeout: 5 }]
      }
    ],

    // ── UserPromptSubmit (SYNC — exit 2 erases poisoned prompt) ──
    UserPromptSubmit: [
      {
        matcher: '',
        hooks: [{ type: 'command', command: `${root}/bin/knox-guard`, timeout: 3 }]
      }
    ],

    // ── ConfigChange (SYNC — blocks self-removal attempts) ──
    ConfigChange: [
      {
        matcher: 'user_settings|project_settings|local_settings',
        hooks: [{ type: 'command', command: `${root}/bin/knox-guard`, timeout: 3 }]
      }
    ],

    // ── InstructionsLoaded (SYNC — audit-only, cannot block, but timeout prevents hang) ──
    InstructionsLoaded: [
      {
        matcher: 'session_start|include|path_glob_match|nested_traversal|compact',
        hooks: [{ type: 'command', command: `${root}/bin/knox-guard`, timeout: 3 }]
      }
    ],

    // ── PostToolUse (ASYNC — audit + additionalContext injection after every tool call) ──
    PostToolUse: [
      {
        matcher: '*',
        hooks: [{ type: 'command', command: `${root}/bin/knox-post-audit`, async: true }]
      }
    ],

    // ── PermissionDenied (SYNC — ensures audit write completes before session moves on) ──
    PermissionDenied: [
      {
        matcher: '*',
        hooks: [{ type: 'command', command: `${root}/bin/knox-post-audit`, timeout: 5 }]
      }
    ],

    // ── SubagentStart (ASYNC — injects Knox context into spawned subagents) ──
    SubagentStart: [
      {
        matcher: '*',
        hooks: [{ type: 'command', command: `${root}/bin/knox-session`, async: true }]
      }
    ],

    // ── FileChanged (ASYNC — live config reload when .knox.json changes) ──
    FileChanged: [
      {
        matcher: '.knox.json|.knox.local.json',
        hooks: [{ type: 'command', command: `${root}/bin/knox-session`, async: true }]
      }
    ],

    // ── TaskCreated (SYNC — blocks injection in scheduled task prompts) ──
    TaskCreated: [
      {
        matcher: '',
        hooks: [{ type: 'command', command: `${root}/bin/knox-cron-guard`, timeout: 5 }]
      }
    ],

    // ── SessionEnd (ASYNC — flush audit, write session summary) ──
    SessionEnd: [
      {
        matcher: 'clear|prompt_input_exit|logout|resume|bypass_permissions_disabled|other',
        hooks: [{ type: 'command', command: `${root}/bin/knox-session`, async: true }]
      }
    ],

    // ── SessionStart (ASYNC — init state, prune stale escalation records) ──
    SessionStart: [
      {
        matcher: 'startup|resume|clear|compact',
        hooks: [{ type: 'command', command: `${root}/bin/knox-session`, async: true }]
      }
    ]
  };
}

// Returns true if this entry group is already registered for Knox
function isKnoxEntry(entry) {
  return (entry.hooks || []).some(h => h.command && h.command.includes('knox'));
}

function isInsideMarketplaceCache() {
  return __dirname.startsWith(CACHE_PREFIX + path.sep);
}

function knoxAlreadyInstalledViaMarketplace() {
  try { return fs.existsSync(KNOX_CACHE_DIR); } catch { return false; }
}

function writeSettingsJson() {
  let settings = {};
  try {
    if (fs.existsSync(SETTINGS_FILE)) {
      settings = JSON.parse(fs.readFileSync(SETTINGS_FILE, 'utf8'));
    }
  } catch {
    console.warn('Knox: could not read existing settings.json, starting fresh');
  }
  if (!settings.hooks) settings.hooks = {};

  const entries = buildHookEntries(PLUGIN_ROOT);
  let wired = 0;
  let skipped = 0;

  for (const [event, newEntries] of Object.entries(entries)) {
    if (!settings.hooks[event]) settings.hooks[event] = [];
    for (const entry of newEntries) {
      const alreadyPresent = settings.hooks[event].some(
        e => isKnoxEntry(e) && e.matcher === entry.matcher
      );
      if (!alreadyPresent) {
        settings.hooks[event].push(entry);
        wired++;
      } else {
        skipped++;
      }
    }
  }

  fs.mkdirSync(path.dirname(SETTINGS_FILE), { recursive: true });
  const tmp = SETTINGS_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(settings, null, 2));
  fs.renameSync(tmp, SETTINGS_FILE);

  const eventCount = Object.keys(entries).length;
  console.log(`Knox: ${wired} hook entries wired across ${eventCount} events${skipped ? ` (${skipped} already present, skipped)` : ''}.`);
}

function main() {
  // 1. Defensive: if Claude Code somehow invokes this from inside the marketplace
  //    cache, do nothing. Plugin scope is its own ~/.claude/plugins/cache/.../hooks/hooks.json
  //    and writing user-scope settings would duplicate hooks.
  if (isInsideMarketplaceCache()) return;

  // 2. Allow callers to opt out entirely (e.g. CI tooling that wants the package
  //    installed without any side effects)
  if (process.env.KNOX_POSTINSTALL_NOOP === '1') return;

  const legacy = process.argv.includes('--legacy-direct-hooks');

  // 3. If knox is already installed via the Claude Code marketplace, refuse to
  //    write user-scope hooks unless the user explicitly asks for it. Stacking
  //    user-scope on top of plugin-scope was the v<2.3 leak bug.
  if (knoxAlreadyInstalledViaMarketplace() && !legacy) {
    console.log('Knox is already installed via the Claude Code marketplace.');
    console.log(`Use 'claude plugin install knox@qoris' or '/plugin' to manage it.`);
    console.log('(To force direct-write into ~/.claude/settings.json anyway, pass --legacy-direct-hooks.)');
    return;
  }

  // 4. Default for plain `npm install -g @qoris/knox`: print a one-liner and
  //    exit. Do NOT touch settings.json.
  if (!legacy) {
    console.log('Knox CLI installed.');
    console.log('To enable hooks in Claude Code:  claude plugin install knox@qoris');
    console.log('For Cursor:                       knox install --target cursor');
    console.log('For OpenAI Codex:                 knox install --target codex');
    return;
  }

  // 5. Legacy direct-write path (--legacy-direct-hooks). Reserved for unsupported
  //    environments — CI, custom forks, agents that still expect Knox in user
  //    settings instead of plugin scope.
  console.warn('');
  console.warn('Knox: LEGACY DIRECT-WRITE MODE');
  console.warn('  Wiring 11 hooks directly into ~/.claude/settings.json with hardcoded');
  console.warn('  paths. These entries will NOT be managed by Claude Code\'s /plugin UI.');
  console.warn('  To remove them later, run:  knox clean-settings');
  console.warn('');
  writeSettingsJson();
  console.log('Knox: run `knox verify` to confirm enforcement is active.');
}

try { main(); } catch (e) { console.error('Knox postinstall warning:', e.message); }
