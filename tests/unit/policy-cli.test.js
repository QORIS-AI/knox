'use strict';
const { spawnSync } = require('child_process');
const path = require('path');
const fs = require('fs');
const os = require('os');

const KNOX_BIN = path.resolve(__dirname, '../../bin/knox');
const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'knox-policy-test-'));

function runKnox(args, cwd) {
  return spawnSync(process.execPath, [KNOX_BIN, ...args], {
    cwd: cwd || tmpDir,
    encoding: 'utf8',
    timeout: 5000,
    env: {
      ...process.env,
      CLAUDE_PLUGIN_ROOT: path.resolve(__dirname, '../..'),
      CLAUDE_PLUGIN_DATA: path.join(os.tmpdir(), 'knox-policy-data-' + Date.now())
    }
  });
}

afterAll(() => { try { fs.rmSync(tmpDir, { recursive: true }); } catch {} });

describe('knox policy list-checks', () => {
  test('exits 0 and lists all 8 check categories', () => {
    const r = runKnox(['policy', 'list-checks']);
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/read_path_protection/);
    expect(r.stdout).toMatch(/write_path_protection/);
    expect(r.stdout).toMatch(/script_inspection/);
    expect(r.stdout).toMatch(/mcp_inspection/);
    expect(r.stdout).toMatch(/injection_detection/);
    expect(r.stdout).toMatch(/cron_inspection/);
    expect(r.stdout).toMatch(/escalation_tracking/);
    expect(r.stdout).toMatch(/sudo_sanitization/);
  });

  test('shows enabled status when nothing disabled', () => {
    const r = runKnox(['policy', 'list-checks']);
    expect(r.stdout).toMatch(/✓ enabled/);
    expect(r.stdout).not.toMatch(/✗ disabled/);
  });
});

describe('knox policy disable / enable', () => {
  test('disable writes check to .knox.local.json', () => {
    const r = runKnox(['policy', 'disable', 'mcp_inspection']);
    expect(r.status).toBe(0);
    const localFile = path.join(tmpDir, '.knox.local.json');
    expect(fs.existsSync(localFile)).toBe(true);
    const local = JSON.parse(fs.readFileSync(localFile, 'utf8'));
    expect(local.disabled_checks).toContain('mcp_inspection');
  });

  test('disable --project writes to .knox.json not .knox.local.json', () => {
    const r = runKnox(['policy', 'disable', 'cron_inspection', '--project']);
    expect(r.status).toBe(0);
    const projFile = path.join(tmpDir, '.knox.json');
    expect(fs.existsSync(projFile)).toBe(true);
    const proj = JSON.parse(fs.readFileSync(projFile, 'utf8'));
    expect(proj.disabled_checks).toContain('cron_inspection');
  });

  test('list-checks shows disabled after disable', () => {
    const r = runKnox(['policy', 'list-checks']);
    expect(r.stdout).toMatch(/✗ disabled/);
    expect(r.stdout).toMatch(/mcp_inspection|cron_inspection/);
  });

  test('enable removes check from local file', () => {
    runKnox(['policy', 'enable', 'mcp_inspection']);
    const localFile = path.join(tmpDir, '.knox.local.json');
    if (fs.existsSync(localFile)) {
      const local = JSON.parse(fs.readFileSync(localFile, 'utf8'));
      expect((local.disabled_checks || [])).not.toContain('mcp_inspection');
    }
  });

  test('disable is idempotent — adding same check twice does not duplicate', () => {
    runKnox(['policy', 'disable', 'read_path_protection']);
    runKnox(['policy', 'disable', 'read_path_protection']); // second call
    const localFile = path.join(tmpDir, '.knox.local.json');
    const local = JSON.parse(fs.readFileSync(localFile, 'utf8'));
    const count = (local.disabled_checks || []).filter(c => c === 'read_path_protection').length;
    expect(count).toBe(1);
  });

  test('disable with unknown check name: output mentions the name', () => {
    const r = runKnox(['policy', 'disable', 'not_a_real_check']);
    // Should either exit 1 or exit 0 with name mentioned — never silent
    const combined = r.stdout + r.stderr;
    expect(combined).toMatch(/not_a_real_check/);
  });

  test('enable with no arg exits non-zero', () => {
    const r = runKnox(['policy', 'enable']);
    expect(r.status).not.toBe(0);
  });

  test('disable with no arg exits non-zero', () => {
    const r = runKnox(['policy', 'disable']);
    expect(r.status).not.toBe(0);
  });
});
