'use strict';
const { getBlocklistForPreset } = require('./patterns');
const { extractScriptPath, inspectScript } = require('./script-inspect');

function normalizeCommand(cmd) {
  // Strip sudo + all flags (e.g. sudo -n -u root, sudo --non-interactive)
  return cmd.replace(/^\s*sudo\s+(?:-[A-Za-z]+\s+)*(?:--\S+\s+)*(?:-[A-Za-z]+=\S+\s+)*/, '').trim();
}

/**
 * Returns true if a check category has been disabled via config.disabled_checks.
 * 'blocklist' and 'self_protection' are never toggleable — callers must not pass them.
 */
function isCheckDisabled(config, checkName) {
  return Array.isArray(config.disabled_checks) && config.disabled_checks.includes(checkName);
}

/**
 * Check a Bash/Monitor/PowerShell command against policy.
 * Returns: { blocked, sanitized, decision, reason, ruleId, risk } or null (allow)
 */
function checkCommand(command, config) {
  const preset = (config && config.preset) || 'standard';
  const blocklist = getBlocklistForPreset(preset);

  // Check if command contains sudo — for sanitization
  const hasSudo = /^\s*sudo\s/.test(command);
  const normalized = normalizeCommand(command);

  // Default blocklist check on normalized command
  for (const pattern of blocklist) {
    if (pattern.re.test(normalized)) {
      // sudo su is always blocked even with sudo stripping
      if (hasSudo && pattern.id === 'BL-024') {
        return { blocked: true, reason: 'Knox: Blocked — sudo su', ruleId: pattern.id, risk: pattern.risk, sanitized: false };
      }
      const decision = (config && config.use_ask_not_deny) ? 'ask' : 'deny';
      return {
        blocked: true,
        decision,
        reason: `Knox: Blocked — ${pattern.label.replace(/_/g, ' ')} [${pattern.id}]`,
        ruleId: pattern.id,
        risk: pattern.risk,
        sanitized: false
      };
    }
  }

  // Also check original command (in case sudo masking hid something)
  for (const pattern of blocklist) {
    if (pattern.re.test(command) && !pattern.re.test(normalized)) {
      const decision = (config && config.use_ask_not_deny) ? 'ask' : 'deny';
      return {
        blocked: true,
        decision,
        reason: `Knox: Blocked — ${pattern.label.replace(/_/g, ' ')} [${pattern.id}]`,
        ruleId: pattern.id,
        risk: pattern.risk,
        sanitized: false
      };
    }
  }

  // Custom blocklist (checked BEFORE allowlist)
  for (const cb of ((config && config.custom_blocklist) || [])) {
    try {
      const re = new RegExp(cb.pattern, cb.flags || 'i');
      if (re.test(normalized) || re.test(command)) {
        return {
          blocked: true,
          reason: `Knox: Blocked — custom rule: ${cb.label || cb.pattern}`,
          ruleId: 'custom',
          risk: cb.risk || 'high',
          sanitized: false
        };
      }
    } catch { /* invalid custom pattern — skip */ }
  }

  // Custom allowlist — checked LAST (cannot override default blocklist)
  for (const al of ((config && config.custom_allowlist) || [])) {
    try {
      const re = new RegExp(al.pattern, al.flags || 'i');
      if (re.test(normalized) || re.test(command)) {
        return null; // explicitly allowed
      }
    } catch { /* invalid pattern — skip */ }
  }

  // Script content inspection (standard+ presets, unless disabled)
  const scriptInspectionEnabled = config
    ? (config.script_inspection !== false && !isCheckDisabled(config, 'script_inspection'))
    : true;
  if (preset !== 'minimal' && scriptInspectionEnabled) {
    const scriptPath = extractScriptPath(command);
    if (scriptPath) {
      const result = inspectScript(scriptPath, process.env.CLAUDE_PROJECT_DIR || process.cwd());
      if (result && result.blocked) {
        return {
          blocked: true,
          reason: `Knox: Blocked — ${result.reason}`,
          ruleId: result.id,
          risk: result.risk || 'high',
          sanitized: false
        };
      }
    }
  }

  // sudo sanitization at standard (not strict/paranoid — those deny outright)
  if (hasSudo && (config && config.sanitize_sudo !== false) && (preset === 'minimal' || preset === 'standard')) {
    return {
      blocked: false,
      sanitized: true,
      sanitizedCommand: normalized,
      reason: 'Knox: sudo stripped — running without elevation',
      ruleId: 'sanitize-sudo',
      risk: 'low'
    };
  }

  return null; // allow
}

// Sensitive paths blocked for Read tool
const SENSITIVE_READ_PREFIXES = [
  { p: '~/.ssh/', label: 'SSH private keys' },
  { p: '~/.aws/credentials', label: 'AWS credentials' },
  { p: '~/.gnupg/', label: 'GPG keys' },
  { p: '~/.kube/config', label: 'Kubernetes credentials' },
  { p: '~/.config/gcloud/', label: 'GCloud credentials' },
  { p: '~/.netrc', label: 'netrc credentials' }
];
const SENSITIVE_READ_EXACT = ['.env', '.env.local', '.env.production', '.env.development'];

/**
 * Check a file path for read protection (sensitive files).
 * Returns { blocked, reason } or null (allow).
 */
function checkReadPath(filePath, config) {
  if (config && isCheckDisabled(config, 'read_path_protection')) return null;
  const os = require('os');
  const p = require('path');
  const basename = p.basename(p.resolve(filePath));

  // Exact sensitive filenames
  for (const e of SENSITIVE_READ_EXACT) {
    if (basename === e || filePath === e) {
      return { blocked: true, reason: `Knox: Reading ${e} blocked — may contain secrets` };
    }
  }
  // Sensitive path prefixes
  for (const { p: prefix, label } of SENSITIVE_READ_PREFIXES) {
    const expanded = prefix.startsWith('~/') ? p.join(os.homedir(), prefix.slice(2)) : prefix;
    if (filePath.startsWith(prefix) || p.resolve(filePath).startsWith(p.resolve(expanded))) {
      return { blocked: true, reason: `Knox: Reading ${label} blocked (${prefix}*)` };
    }
  }
  return null;
}

/**
 * Check a file path for write protection.
 * Returns { blocked, critical, reason } or null (allow).
 */
function checkWritePath(filePath, config) {
  if (config && isCheckDisabled(config, 'write_path_protection')) return null;
  const { loadPatterns } = require('./patterns');
  const patterns = loadPatterns();
  const { exact, prefix } = patterns.protected_write_paths;

  const p = require('path');
  const os = require('os');
  const resolved = p.resolve(filePath);
  const basename = p.basename(resolved);

  for (const e of exact) {
    if (basename === e || filePath === e) {
      return { blocked: true, critical: true, reason: `Knox: Write to ${e} blocked` };
    }
  }
  for (const pfx of prefix) {
    if (pfx.startsWith('~/')) {
      // Expand ~/  and resolve for homedir-anchored paths
      const expanded = p.join(os.homedir(), pfx.slice(2));
      if (filePath.startsWith(pfx) || resolved.startsWith(expanded)) {
        return { blocked: true, critical: true, reason: `Knox: Write to ${pfx}* blocked` };
      }
    } else {
      // Literal prefix match only — never resolve relative paths like ../
      // (resolving ../ to CWD parent would match ALL project files)
      if (filePath.startsWith(pfx) || filePath === pfx.replace(/\/$/, '')) {
        return { blocked: true, critical: true, reason: `Knox: Write to ${pfx}* blocked` };
      }
    }
  }
  return null;
}

/**
 * Check text content for injection patterns.
 * Returns { detected, reason, id } or null.
 */
function checkInjection(text, config) {
  if (config && isCheckDisabled(config, 'injection_detection')) return null;
  const { loadPatterns } = require('./patterns');
  const patterns = loadPatterns();
  for (const p of patterns.injection_patterns) {
    if (p.re.test(text)) {
      return { detected: true, reason: `Knox: Injection pattern detected — ${p.label}`, id: p.id };
    }
  }
  return null;
}

module.exports = {
  checkCommand,
  checkWritePath,
  checkReadPath,
  checkInjection,
  normalizeCommand,
  isCheckDisabled
};
