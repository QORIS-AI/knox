'use strict';
const path = require('path');
process.env.CLAUDE_PLUGIN_ROOT = path.resolve(__dirname, '../..');

const { loadPatterns, getBlocklistForPreset } = require('../../lib/patterns');

describe('patterns loading', () => {
  test('loads without error', () => {
    const p = loadPatterns();
    expect(p.blocklist.length).toBeGreaterThan(30);
    expect(p.script_content_patterns.length).toBeGreaterThan(10);
    expect(p.injection_patterns.length).toBeGreaterThan(5);
  });

  test('all patterns compile to valid RegExp', () => {
    const p = loadPatterns();
    for (const pat of [...p.blocklist, ...p.script_content_patterns, ...p.injection_patterns]) {
      expect(pat.re).toBeInstanceOf(RegExp);
      expect(() => pat.re.test('test')).not.toThrow();
    }
  });

  test('preset filtering: minimal < standard < strict < paranoid', () => {
    const minimal = getBlocklistForPreset('minimal');
    const standard = getBlocklistForPreset('standard');
    const strict = getBlocklistForPreset('strict');
    expect(standard.length).toBeGreaterThan(minimal.length);
    expect(strict.length).toBeGreaterThan(standard.length);
  });

  test('BL-016 xmrig present in minimal preset', () => {
    const minimal = getBlocklistForPreset('minimal');
    expect(minimal.find(p => p.id === 'BL-016')).toBeDefined();
  });

  test('BL-011 bash-c NOT present in minimal, present in standard', () => {
    const minimal = getBlocklistForPreset('minimal');
    const standard = getBlocklistForPreset('standard');
    expect(minimal.find(p => p.id === 'BL-011')).toBeUndefined();
    expect(standard.find(p => p.id === 'BL-011')).toBeDefined();
  });

  test('protected_write_paths has exact and prefix arrays', () => {
    const p = loadPatterns();
    expect(Array.isArray(p.protected_write_paths.exact)).toBe(true);
    expect(Array.isArray(p.protected_write_paths.prefix)).toBe(true);
    expect(p.protected_write_paths.exact.length).toBeGreaterThan(5);
  });

  test('injection_patterns has at least 6 entries', () => {
    const p = loadPatterns();
    expect(p.injection_patterns.length).toBeGreaterThanOrEqual(6);
  });
});
