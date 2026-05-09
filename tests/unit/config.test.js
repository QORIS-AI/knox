'use strict';
const path = require('path');
const os = require('os');
const fs = require('fs');

process.env.CLAUDE_PLUGIN_ROOT = path.resolve(__dirname, '../..');
process.env.CLAUDE_PLUGIN_DATA = path.join(os.tmpdir(), 'knox-config-test-' + Date.now());

// Isolate from any pre-existing ~/.config/knox/config.json on the dev machine.
// The user-config file sits above plugin-defaults in precedence, so a real config
// would shadow the boolean env vars these tests set.
const _userCfgFile = path.join(os.homedir(), '.config', 'knox', 'config.json');
let _userCfgBackup = null;
beforeEach(() => {
  if (fs.existsSync(_userCfgFile)) {
    _userCfgBackup = fs.readFileSync(_userCfgFile, 'utf8');
    fs.unlinkSync(_userCfgFile);
  } else {
    _userCfgBackup = null;
  }
});
afterEach(() => {
  delete process.env.KNOX_PRESET;
  delete process.env.CLAUDE_PLUGIN_OPTION_PRESET;
  delete process.env.CLAUDE_PLUGIN_OPTION_WEBHOOK;
  delete process.env.CLAUDE_PLUGIN_OPTION_PRESET_PARANOID;
  delete process.env.CLAUDE_PLUGIN_OPTION_PRESET_STRICT;
  delete process.env.CLAUDE_PLUGIN_OPTION_PRESET_STANDARD;
  delete process.env.CLAUDE_PLUGIN_OPTION_PRESET_MINIMAL;
  delete process.env.CLAUDE_PLUGIN_OPTION_PRESET_DISABLED;
  if (_userCfgBackup !== null) {
    fs.mkdirSync(path.dirname(_userCfgFile), { recursive: true });
    fs.writeFileSync(_userCfgFile, _userCfgBackup);
  }
});

describe('config loading', () => {
  test('returns defaults when no config files exist', () => {
    jest.resetModules();
    const { loadConfig } = require('../../lib/config');
    const cfg = loadConfig();
    expect(cfg.preset).toBe('standard');
    expect(cfg.audit.enabled).toBe(true);
  });

  test('KNOX_PRESET env overrides preset', () => {
    process.env.KNOX_PRESET = 'strict';
    jest.resetModules();
    const { loadConfig } = require('../../lib/config');
    const cfg = loadConfig();
    expect(cfg.preset).toBe('strict');
  });

  test('CLAUDE_PLUGIN_OPTION_PRESET (legacy single-string field) sets preset', () => {
    process.env.CLAUDE_PLUGIN_OPTION_PRESET = 'paranoid';
    jest.resetModules();
    const { loadConfig } = require('../../lib/config');
    const cfg = loadConfig();
    expect(cfg.preset).toBe('paranoid');
  });

  test('CLAUDE_PLUGIN_OPTION_PRESET_<NAME> boolean sets preset', () => {
    process.env.CLAUDE_PLUGIN_OPTION_PRESET_STRICT = 'true';
    jest.resetModules();
    const { loadConfig } = require('../../lib/config');
    const cfg = loadConfig();
    expect(cfg.preset).toBe('strict');
  });

  test('boolean precedence — most-restrictive wins (paranoid + disabled both true → paranoid)', () => {
    process.env.CLAUDE_PLUGIN_OPTION_PRESET_PARANOID = 'true';
    process.env.CLAUDE_PLUGIN_OPTION_PRESET_DISABLED = 'true';
    jest.resetModules();
    const { loadConfig } = require('../../lib/config');
    const cfg = loadConfig();
    expect(cfg.preset).toBe('paranoid');
  });

  test('boolean precedence — strict + minimal → strict wins', () => {
    process.env.CLAUDE_PLUGIN_OPTION_PRESET_STRICT = 'true';
    process.env.CLAUDE_PLUGIN_OPTION_PRESET_MINIMAL = 'true';
    jest.resetModules();
    const { loadConfig } = require('../../lib/config');
    const cfg = loadConfig();
    expect(cfg.preset).toBe('strict');
  });

  test('disabled boolean alone resolves to disabled', () => {
    process.env.CLAUDE_PLUGIN_OPTION_PRESET_DISABLED = 'true';
    jest.resetModules();
    const { loadConfig } = require('../../lib/config');
    const cfg = loadConfig();
    expect(cfg.preset).toBe('disabled');
  });

  test('booleans set to "false" strings are not treated as enabled', () => {
    process.env.CLAUDE_PLUGIN_OPTION_PRESET_PARANOID = 'false';
    process.env.CLAUDE_PLUGIN_OPTION_PRESET_STANDARD = 'true';
    jest.resetModules();
    const { loadConfig } = require('../../lib/config');
    const cfg = loadConfig();
    expect(cfg.preset).toBe('standard');
  });

  test('KNOX_PRESET env beats userConfig booleans', () => {
    process.env.CLAUDE_PLUGIN_OPTION_PRESET_PARANOID = 'true';
    process.env.KNOX_PRESET = 'minimal';
    jest.resetModules();
    const { loadConfig } = require('../../lib/config');
    const cfg = loadConfig();
    expect(cfg.preset).toBe('minimal');
  });

  test('boolean and legacy string both set → boolean wins', () => {
    process.env.CLAUDE_PLUGIN_OPTION_PRESET_STRICT = 'true';
    process.env.CLAUDE_PLUGIN_OPTION_PRESET = 'minimal';
    jest.resetModules();
    const { loadConfig } = require('../../lib/config');
    const cfg = loadConfig();
    expect(cfg.preset).toBe('strict');
  });

  test('custom_allowlist and custom_blocklist default to empty arrays', () => {
    jest.resetModules();
    const { loadConfig } = require('../../lib/config');
    const cfg = loadConfig();
    expect(Array.isArray(cfg.custom_allowlist)).toBe(true);
    expect(Array.isArray(cfg.custom_blocklist)).toBe(true);
  });

  test('disabled_checks defaults to empty array', () => {
    jest.resetModules();
    const { loadConfig } = require('../../lib/config');
    const cfg = loadConfig();
    expect(Array.isArray(cfg.disabled_checks)).toBe(true);
    expect(cfg.disabled_checks).toHaveLength(0);
  });

  test('5-level precedence: env beats local beats project', () => {
    const tmpCwd = fs.mkdtempSync(path.join(os.tmpdir(), 'knox-prec-'));
    fs.writeFileSync(path.join(tmpCwd, '.knox.json'), JSON.stringify({ preset: 'strict' }));
    fs.writeFileSync(path.join(tmpCwd, '.knox.local.json'), JSON.stringify({ preset: 'paranoid' }));
    process.env.KNOX_PRESET = 'minimal';
    const origCwd = process.cwd();
    process.chdir(tmpCwd);
    try {
      jest.resetModules();
      const { loadConfig } = require('../../lib/config');
      const cfg = loadConfig();
      expect(cfg.preset).toBe('minimal'); // env wins
    } finally {
      process.chdir(origCwd);
      delete process.env.KNOX_PRESET;
      fs.rmSync(tmpCwd, { recursive: true });
    }
  });

  test('5-level precedence: local beats project when no env override', () => {
    const tmpCwd = fs.mkdtempSync(path.join(os.tmpdir(), 'knox-prec2-'));
    fs.writeFileSync(path.join(tmpCwd, '.knox.json'), JSON.stringify({ preset: 'strict' }));
    fs.writeFileSync(path.join(tmpCwd, '.knox.local.json'), JSON.stringify({ preset: 'paranoid' }));
    const origCwd = process.cwd();
    process.chdir(tmpCwd);
    try {
      jest.resetModules();
      const { loadConfig } = require('../../lib/config');
      const cfg = loadConfig();
      expect(cfg.preset).toBe('paranoid'); // local beats project
    } finally {
      process.chdir(origCwd);
      fs.rmSync(tmpCwd, { recursive: true });
    }
  });

  test('5-level precedence: project used when no local or env override', () => {
    const tmpCwd = fs.mkdtempSync(path.join(os.tmpdir(), 'knox-prec3-'));
    fs.writeFileSync(path.join(tmpCwd, '.knox.json'), JSON.stringify({ preset: 'strict' }));
    const origCwd = process.cwd();
    process.chdir(tmpCwd);
    try {
      jest.resetModules();
      const { loadConfig } = require('../../lib/config');
      const cfg = loadConfig();
      expect(cfg.preset).toBe('strict');
    } finally {
      process.chdir(origCwd);
      fs.rmSync(tmpCwd, { recursive: true });
    }
  });

  test('custom_allowlist merges (union) across config levels', () => {
    const tmpCwd = fs.mkdtempSync(path.join(os.tmpdir(), 'knox-merge-'));
    fs.writeFileSync(path.join(tmpCwd, '.knox.json'), JSON.stringify({
      custom_allowlist: [{ pattern: 'npm run test', label: 'test' }]
    }));
    fs.writeFileSync(path.join(tmpCwd, '.knox.local.json'), JSON.stringify({
      custom_allowlist: [{ pattern: 'yarn build', label: 'build' }]
    }));
    const origCwd = process.cwd();
    process.chdir(tmpCwd);
    try {
      jest.resetModules();
      const { loadConfig } = require('../../lib/config');
      const cfg = loadConfig();
      const patterns = cfg.custom_allowlist.map(r => r.pattern);
      expect(patterns).toContain('npm run test');
      expect(patterns).toContain('yarn build');
    } finally {
      process.chdir(origCwd);
      fs.rmSync(tmpCwd, { recursive: true });
    }
  });

  test('.knox.local.json disabled_checks is merged into config', () => {
    const tmpCwd = fs.mkdtempSync(path.join(os.tmpdir(), 'knox-dc-'));
    fs.writeFileSync(path.join(tmpCwd, '.knox.local.json'), JSON.stringify({ disabled_checks: ['mcp_inspection'] }));
    const origCwd = process.cwd();
    process.chdir(tmpCwd);
    try {
      jest.resetModules();
      const { loadConfig } = require('../../lib/config');
      const cfg = loadConfig();
      expect(cfg.disabled_checks).toContain('mcp_inspection');
    } finally {
      process.chdir(origCwd);
      fs.rmSync(tmpCwd, { recursive: true });
    }
  });
});
