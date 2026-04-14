'use strict';

// Paths Knox itself owns — mutations here mean Knox neutralization
const KNOX_PROTECTED_PATHS = [
  '~/.claude/plugins/knox',
  '~/.claude/plugins/data/knox',
  '~/.claude/settings.json',
  '~/.config/knox',
  '~/.knox.json',
  '~/.knox.local.json',
];
const KNOX_PROTECTED_FILES = ['knox-check', 'run-check.sh', 'knox-post-audit', 'knox-session'];

// Env vars that must never be set from a command line (would downgrade/disable Knox)
const KNOX_ENV_OVERRIDES = /^KNOX_(?:PRESET|DISABLE|CHECKS|POLICY|CONFIG|AUDIT)|^CLAUDE_PLUGIN_OPTION_/;

// Env vars that are themselves dangerous (LD_PRELOAD, BASH_ENV, etc.) — must NOT
// be stripped from the command before pattern matching, or BL-039/BL-023 will miss them.
const DANGEROUS_ENV_VARS = /^(?:LD_PRELOAD|LD_LIBRARY_PATH|LD_AUDIT|BASH_ENV|ENV|PROMPT_COMMAND|DYLD_INSERT_LIBRARIES|IFS)$/;

// Commands that dangerous if aliased/shadowed
const SHADOWABLE_COMMANDS = /^(?:rm|mv|cp|chmod|chown|curl|wget|sudo|dd|nc|ssh|kill|pkill|killall)$/;

/**
 * Check for leading KEY=val environment variable assignments that would
 * downgrade/disable Knox. Returns { blocked, reason, stripped } where
 * `stripped` is the command with the assignments removed for further checks.
 */
function checkEnvPrefix(command) {
  let rest = command.trimStart();
  const prefix = [];
  // Match leading KEY=val ... KEY=val assignments (simplified shell grammar)
  const assignRe = /^([A-Za-z_][A-Za-z0-9_]*)=((?:"[^"]*"|'[^']*'|\S)*)\s+/;
  while (true) {
    const m = rest.match(assignRe);
    if (!m) break;
    const key = m[1];
    if (KNOX_ENV_OVERRIDES.test(key)) {
      return {
        blocked: true,
        reason: `Knox: Blocked — env-var override attempt: ${key} [SP-001]`,
        ruleId: 'SP-001',
        risk: 'critical',
      };
    }
    // Don't strip dangerous env vars — leave them in the command so BL-039 etc. can match
    if (DANGEROUS_ENV_VARS.test(key)) {
      return { blocked: false, stripped: command };
    }
    prefix.push(m[0]);
    rest = rest.slice(m[0].length);
  }
  return { blocked: false, stripped: rest };
}

/**
 * Normalize a command fragment that may reference a file target. Returns the
 * target path strings found in the command, handling quotes, tilde expansion,
 * and common redirect/mutation forms.
 */
function extractTargets(command) {
  const targets = [];
  // Split on shell delimiters (;, &&, ||, |) and scan each sub-command separately.
  // Only MUTATION verbs at the START of a sub-command are considered.
  const subs = command.split(/(?:\s*(?:;|\|\||\||&&)\s*)/);
  for (const sub of subs) {
    const trimmed = sub.trim();
    if (!trimmed) continue;
    // Strip leading env var assignments (KEY=val)
    const withoutEnv = trimmed.replace(/^(?:[A-Za-z_][A-Za-z0-9_]*=(?:"[^"]*"|'[^']*'|\S+)\s+)+/, '');
    // Verb must be the first token (or follow leading env vars). Then examine args.
    const m = withoutEnv.match(/^(rm|chmod|chown|mv|cp|ln|tee|truncate)\b\s+(.+)$/);
    if (m) {
      // Find any argument containing ~ or .claude or knox
      const args = m[2];
      const argMatch = args.match(/(\S*(?:~|\.claude|knox)\S*)/g);
      if (argMatch) for (const a of argMatch) targets.push(a);
    }
    // sed -i / sed --in-place <file>
    const sedM = withoutEnv.match(/^sed\s+(?:-[a-zA-Z]*i|--in-place)\b\s+(.+)$/);
    if (sedM) {
      const argMatch = sedM[1].match(/(\S*(?:\.claude|knox|settings\.json)\S*)/g);
      if (argMatch) for (const a of argMatch) targets.push(a);
    }
    // jq -i or jq with redirect to protected file
    const jqM = withoutEnv.match(/^jq\b\s+(.+)$/);
    if (jqM && /-i|--in-place|>\s*\S*(?:\.claude|settings\.json)/.test(jqM[1])) {
      const argMatch = jqM[1].match(/(\S*(?:\.claude|knox|settings\.json)\S*)/g);
      if (argMatch) for (const a of argMatch) targets.push(a);
    }
  }
  // Redirect targets (>, >>) anywhere — writes to protected path are always suspicious
  const redirRe = /(?:^|[^2&>])>{1,2}\s*(?:"([^"]+)"|'([^']+)'|(\S+))/g;
  let rm;
  while ((rm = redirRe.exec(command)) !== null) {
    const t = rm[1] || rm[2] || rm[3];
    if (t && /(?:~|\.claude|knox)/.test(t)) targets.push(t);
  }
  return targets.map(t => t.replace(/^["']|["']$/g, ''));
}

function isKnoxProtectedTarget(target) {
  if (!target) return false;
  const os = require('os');
  const path = require('path');
  const home = os.homedir();
  const expanded = target.startsWith('~')
    ? path.join(home, target.slice(target.startsWith('~/') ? 2 : 1))
    : target;
  for (const p of KNOX_PROTECTED_PATHS) {
    const pExp = p.startsWith('~/') ? path.join(home, p.slice(2)) : p;
    if (expanded === pExp || expanded.startsWith(pExp + path.sep) || expanded.startsWith(pExp)) {
      return true;
    }
    if (target === p || target.startsWith(p + '/') || target.startsWith(p)) return true;
  }
  for (const f of KNOX_PROTECTED_FILES) {
    if (target.endsWith('/' + f) || target === f || path.basename(expanded) === f) return true;
  }
  return false;
}

/**
 * Check command for operations that would modify Knox's own files.
 */
function checkKnoxFileMutate(command) {
  const targets = extractTargets(command);
  for (const t of targets) {
    if (isKnoxProtectedTarget(t)) {
      return {
        blocked: true,
        reason: `Knox: Blocked — self-protection: mutation of ${t} [SP-002]`,
        ruleId: 'SP-002',
        risk: 'critical',
      };
    }
  }
  // Catch `sed -i '/knox/d'` even when target path was obfuscated
  if (/\bsed\b\s+(?:-[a-zA-Z]*i|--in-place)\b[^;&|]*\/knox\//.test(command)) {
    return {
      blocked: true,
      reason: 'Knox: Blocked — self-protection: sed editing knox settings [SP-002]',
      ruleId: 'SP-002',
      risk: 'critical',
    };
  }
  // Catch `jq 'del(.hooks)'` targeting settings.json
  if (/\bjq\b[^|;&]*?del\([^)]*hooks/.test(command) && /settings|\.claude/.test(command)) {
    return {
      blocked: true,
      reason: 'Knox: Blocked — self-protection: jq removing hooks [SP-002]',
      ruleId: 'SP-002',
      risk: 'critical',
    };
  }
  return null;
}

/**
 * Check command for alias/function/unalias shadowing of dangerous commands.
 */
function checkAliasShadow(command) {
  // alias rm='...'
  const aliasRe = /\balias\s+(\w+)\s*=/;
  const am = command.match(aliasRe);
  if (am && SHADOWABLE_COMMANDS.test(am[1])) {
    return {
      blocked: true,
      reason: `Knox: Blocked — alias shadowing dangerous command: ${am[1]} [SP-003]`,
      ruleId: 'SP-003',
      risk: 'high',
    };
  }
  // function rm() { ... }
  const fnRe = /\bfunction\s+(\w+)\s*(?:\(\s*\))?\s*\{/;
  const fm = command.match(fnRe);
  if (fm && SHADOWABLE_COMMANDS.test(fm[1])) {
    return {
      blocked: true,
      reason: `Knox: Blocked — function shadowing dangerous command: ${fm[1]} [SP-003]`,
      ruleId: 'SP-003',
      risk: 'high',
    };
  }
  // unalias rm
  const um = command.match(/\bunalias\s+(\w+)/);
  if (um && SHADOWABLE_COMMANDS.test(um[1])) {
    return {
      blocked: true,
      reason: `Knox: Blocked — unalias of dangerous command: ${um[1]} [SP-003]`,
      ruleId: 'SP-003',
      risk: 'high',
    };
  }
  return null;
}

/**
 * Check for attempts to kill Knox processes.
 */
function checkKnoxKill(command) {
  // pkill -f knox, killall knox-check, kill $(pgrep knox), kill `pidof knox`
  if (/\b(?:pkill|killall)\b[^|;&]*\bknox\b/i.test(command)) {
    return {
      blocked: true,
      reason: 'Knox: Blocked — attempt to kill knox process [SP-004]',
      ruleId: 'SP-004',
      risk: 'critical',
    };
  }
  if (/\bkill\b[^|;&]*(?:\$\(|`)\s*(?:pgrep|pidof|ps\b.*\bknox|pgrep.*\bknox)/i.test(command)) {
    return {
      blocked: true,
      reason: 'Knox: Blocked — kill targeting knox pid [SP-004]',
      ruleId: 'SP-004',
      risk: 'critical',
    };
  }
  return null;
}

module.exports = {
  checkEnvPrefix,
  checkKnoxFileMutate,
  checkAliasShadow,
  checkKnoxKill,
  extractTargets,
  isKnoxProtectedTarget,
  KNOX_PROTECTED_PATHS,
  KNOX_PROTECTED_FILES,
};
