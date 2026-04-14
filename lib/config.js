'use strict';
const fs = require('fs');
const path = require('path');
const os = require('os');

const PLUGIN_ROOT = process.env.CLAUDE_PLUGIN_ROOT ||
  path.resolve(path.dirname(process.argv[1] || __filename), '..');
const PLUGIN_DATA = process.env.CLAUDE_PLUGIN_DATA ||
  path.join(os.homedir(), '.claude', 'plugins', 'data', 'knox');

function loadJSON(filePath) {
  try {
    const resolved = filePath.startsWith('~/')
      ? path.join(os.homedir(), filePath.slice(2))
      : filePath;
    if (!fs.existsSync(resolved)) return {};
    return JSON.parse(fs.readFileSync(resolved, 'utf8'));
  } catch { return {}; }
}

function mergeConfigs(...configs) {
  const result = {
    preset: 'standard',
    audit: {
      enabled: true,
      path: path.join(PLUGIN_DATA, 'audit'),
      max_size_mb: 50,
      include_allowed: false,
      command_preview_chars: 120
    },
    alerts: { enabled: false, webhook: '', min_severity: 'high', cooldown_seconds: 60 },
    escalation: { session_threshold: 3, agent_window_hours: 1, agent_threshold: 10 },
    custom_allowlist: [],
    custom_blocklist: [],
    apt_package_extra: [],
    disabled_checks: [],
    sanitize_sudo: true,
    script_inspection: true,
    use_ask_not_deny: false
  };
  for (const cfg of configs) {
    if (!cfg || typeof cfg !== 'object') continue;
    if (cfg.preset) result.preset = cfg.preset;
    if (cfg.audit) Object.assign(result.audit, cfg.audit);
    if (cfg.alerts) Object.assign(result.alerts, cfg.alerts);
    if (cfg.escalation) Object.assign(result.escalation, cfg.escalation);
    if (Array.isArray(cfg.custom_allowlist)) result.custom_allowlist.push(...cfg.custom_allowlist);
    if (Array.isArray(cfg.custom_blocklist)) result.custom_blocklist.push(...cfg.custom_blocklist);
    if (Array.isArray(cfg.apt_package_extra)) result.apt_package_extra.push(...cfg.apt_package_extra);
    if (Array.isArray(cfg.disabled_checks)) {
      // Union merge: add new entries only
      for (const c of cfg.disabled_checks) {
        if (!result.disabled_checks.includes(c)) result.disabled_checks.push(c);
      }
    }
    if (cfg.sanitize_sudo !== undefined) result.sanitize_sudo = cfg.sanitize_sudo;
    if (cfg.script_inspection !== undefined) result.script_inspection = cfg.script_inspection;
    if (cfg.use_ask_not_deny !== undefined) result.use_ask_not_deny = cfg.use_ask_not_deny;
  }
  return result;
}

function loadPreset(presetName) {
  try {
    const presetFile = path.join(PLUGIN_ROOT, 'policies', 'presets', `${presetName}.json`);
    return JSON.parse(fs.readFileSync(presetFile, 'utf8'));
  } catch { return {}; }
}

function loadConfig() {
  const userCfg = loadJSON(path.join(os.homedir(), '.config', 'knox', 'config.json'));
  const projectCfg = loadJSON('.knox.json');
  const localCfg = loadJSON('.knox.local.json');

  // Env vars override (highest precedence)
  const envCfg = {};
  if (process.env.KNOX_PRESET) envCfg.preset = process.env.KNOX_PRESET;
  if (process.env.CLAUDE_PLUGIN_OPTION_PRESET) envCfg.preset = process.env.CLAUDE_PLUGIN_OPTION_PRESET;
  if (process.env.CLAUDE_PLUGIN_OPTION_WEBHOOK) {
    envCfg.alerts = { enabled: true, webhook: process.env.CLAUDE_PLUGIN_OPTION_WEBHOOK };
  }
  if (process.env.CLAUDE_PLUGIN_OPTION_AUDIT_PATH) {
    envCfg.audit = { path: process.env.CLAUDE_PLUGIN_OPTION_AUDIT_PATH };
  }

  const result = mergeConfigs(userCfg, projectCfg, localCfg, envCfg);

  // Apply preset-level overrides after merge
  const preset = loadPreset(result.preset);
  if (preset.sanitize_sudo !== undefined) result.sanitize_sudo = preset.sanitize_sudo;
  if (preset.script_inspection !== undefined) result.script_inspection = preset.script_inspection;
  if (preset.use_ask_not_deny !== undefined) result.use_ask_not_deny = preset.use_ask_not_deny;
  if (preset.audit) Object.assign(result.audit, preset.audit);
  if (preset.escalation) Object.assign(result.escalation, preset.escalation);

  // env/local overrides take final priority on scalars
  if (envCfg.preset) result.preset = envCfg.preset;

  return result;
}

module.exports = { loadConfig, PLUGIN_ROOT, PLUGIN_DATA };
