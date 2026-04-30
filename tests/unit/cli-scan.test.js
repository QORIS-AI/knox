'use strict';
const path = require('path');
const fs = require('fs');
const os = require('os');
const { execFileSync } = require('child_process');

const KNOX = path.resolve(__dirname, '../../bin/knox');
const SCANNER_ENV = {
  ...process.env,
  KNOX_ROOT: path.resolve(__dirname, '../..')
};

function runScan(args, opts = {}) {
  try {
    const out = execFileSync('node', [KNOX, 'scan', ...args], {
      env: SCANNER_ENV,
      encoding: 'utf8',
      ...opts
    });
    return { stdout: out, exitCode: 0 };
  } catch (e) {
    return { stdout: e.stdout || '', stderr: e.stderr || '', exitCode: e.status };
  }
}

describe('knox scan — directory walker + script content inspection', () => {
  let tmpDir;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'knox-scan-test-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('benign script passes (exit 0)', () => {
    fs.writeFileSync(path.join(tmpDir, 'safe.sh'), '#!/bin/bash\necho hello\n');
    const r = runScan([tmpDir]);
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain('1 scanned');
    expect(r.stdout).toContain('0 finding');
  });

  test('JSON mode emits NDJSON one line per file', () => {
    fs.writeFileSync(path.join(tmpDir, 'a.sh'), 'echo a\n');
    fs.writeFileSync(path.join(tmpDir, 'b.sh'), 'echo b\n');
    const r = runScan([tmpDir, '--json']);
    expect(r.exitCode).toBe(0);
    const lines = r.stdout.trim().split('\n').filter(Boolean);
    expect(lines).toHaveLength(2);
    for (const l of lines) {
      const o = JSON.parse(l);
      expect(o).toHaveProperty('file');
      expect(o).toHaveProperty('status', 'allow');
    }
  });

  test('non-existent target exits 1 with stderr message', () => {
    const r = runScan(['/this/path/does/not/exist']);
    expect(r.exitCode).toBe(1);
    expect(r.stderr).toContain('does not exist');
  });

  test('skips node_modules and .git by default', () => {
    fs.mkdirSync(path.join(tmpDir, 'node_modules'));
    fs.writeFileSync(path.join(tmpDir, 'node_modules/x.sh'), 'echo node_modules\n');
    fs.mkdirSync(path.join(tmpDir, '.git'));
    fs.writeFileSync(path.join(tmpDir, '.git/x.sh'), 'echo git\n');
    fs.writeFileSync(path.join(tmpDir, 'real.sh'), 'echo real\n');
    const r = runScan([tmpDir]);
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain('1 scanned');
  });

  test('--ext flag restricts scanned extensions', () => {
    fs.writeFileSync(path.join(tmpDir, 'shell.sh'), 'echo a\n');
    fs.writeFileSync(path.join(tmpDir, 'python.py'), 'print(1)\n');
    fs.writeFileSync(path.join(tmpDir, 'js.js'), 'console.log(1)\n');
    const r = runScan([tmpDir, '--ext', '.sh', '--json']);
    expect(r.exitCode).toBe(0);
    const lines = r.stdout.trim().split('\n').filter(Boolean);
    expect(lines).toHaveLength(1);
    expect(JSON.parse(lines[0]).file).toBe('shell.sh');
  });

  test('reports zero matching files cleanly', () => {
    fs.writeFileSync(path.join(tmpDir, 'foo.txt'), 'not a script\n');
    const r = runScan([tmpDir]);
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain('No matching files');
  });

  test('--max-size with units (5KB) parses correctly + flags oversized files', () => {
    // 6KB file
    fs.writeFileSync(path.join(tmpDir, 'big.sh'), 'a'.repeat(6 * 1024));
    const r = runScan([tmpDir, '--max-size', '5KB']);
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain('skipped');
  });

  test('single-file target works', () => {
    const fp = path.join(tmpDir, 'one.sh');
    fs.writeFileSync(fp, 'echo solo\n');
    const r = runScan([fp]);
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain('1 scanned');
  });
});
