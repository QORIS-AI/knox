'use strict';
const path = require('path');
process.env.CLAUDE_PLUGIN_ROOT = path.resolve(__dirname, '../..');

jest.resetModules();
const { checkCommand } = require('../../lib/check');

const stdConfig = {
  preset: 'standard',
  custom_allowlist: [],
  custom_blocklist: [],
  disabled_checks: [],
  sanitize_sudo: true,
  script_inspection: true,
  use_ask_not_deny: false
};

function isBlocked(cmd, cfg = stdConfig) {
  const r = checkCommand(cmd, cfg);
  return r !== null && r.blocked === true;
}

describe('v1.1 — P2: rm variant coverage (must block)', () => {
  const cases = [
    'rm -rf ~',
    'rm -rf ~/',
    'rm -fr ~',
    'rm -rf  ~', // double space
    'rm  -rf  ~',
    'rm --recursive --force ~',
    'rm --force --recursive ~',
    '/bin/rm -rf ~',
    '/usr/bin/rm -rf ~',
    'rm -rf "$HOME"',
    "rm -rf '$HOME'",
    'rm -rf ${HOME}',
    'rm -rf "${HOME}"',
    'rm -rf --no-preserve-root /',
    'rm --no-preserve-root -rf /',
    'rm -rf /etc',
    'rm -rf /var/log',
    'rm -rf /usr',
  ];
  for (const cmd of cases) {
    test(`blocks: ${cmd}`, () => {
      expect(isBlocked(cmd)).toBe(true);
    });
  }
});

describe('v1.1 — P2: legitimate rm still works', () => {
  const cases = [
    'rm -rf node_modules',
    'rm -rf node_modules/',
    'rm -rf build',
    'rm -rf build/ dist/',
    'rm -rf /tmp/foo',
    'rm -rf /tmp/my-test-dir',
    'rm some.txt',
    'rm -f file.log',
    'rm -rf .next',
    'rm -rf target',
    'rm -rf coverage/',
    'rm -rf __pycache__',
    'rm -f /tmp/lock',
  ];
  for (const cmd of cases) {
    test(`allows: ${cmd}`, () => {
      expect(isBlocked(cmd)).toBe(false);
    });
  }
});

describe('v1.1 — P2: find destructive patterns', () => {
  const blockCases = [
    'find / -delete',
    'find / -type f -delete',
    'find ~ -delete',
    'find ~/.ssh -exec rm {} \\;',
    'find /etc -exec rm -rf {} +',
  ];
  for (const cmd of blockCases) {
    test(`blocks: ${cmd}`, () => {
      expect(isBlocked(cmd)).toBe(true);
    });
  }
  const allowCases = [
    'find . -name "*.pyc" -delete',
    'find . -name "*.log" -delete',
    'find ./build -name "*.tmp" -delete',
    'find /tmp -older +7 -delete',
    'find node_modules -type d -name .cache -exec rm -rf {} +',
  ];
  for (const cmd of allowCases) {
    test(`allows: ${cmd}`, () => {
      expect(isBlocked(cmd)).toBe(false);
    });
  }
});
