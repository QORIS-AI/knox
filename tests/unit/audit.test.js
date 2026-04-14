'use strict';
const path = require('path');
const os = require('os');
const fs = require('fs');

process.env.CLAUDE_PLUGIN_ROOT = path.resolve(__dirname, '../..');
const tmpData = path.join(os.tmpdir(), 'knox-audit-test-' + Date.now());
const auditPath = path.join(tmpData, 'audit');

beforeAll(() => fs.mkdirSync(auditPath, { recursive: true }));
afterAll(() => { try { fs.rmSync(tmpData, { recursive: true }); } catch {} });

const { writeAudit, writeAuditEntry } = require('../../lib/audit');

describe('audit log', () => {
  test('writeAudit creates JSONL file with O_APPEND', () => {
    writeAudit(auditPath, { session_id: 'a', tool_name: 'Bash', action: 'deny', operation_preview: 'xmrig', hook_event: 'PreToolUse' });
    writeAudit(auditPath, { session_id: 'a', tool_name: 'Bash', action: 'allow', operation_preview: 'git status', hook_event: 'PreToolUse' });
    const today = new Date().toISOString().slice(0, 10);
    const content = fs.readFileSync(path.join(auditPath, `${today}.jsonl`), 'utf8');
    const lines = content.trim().split('\n').filter(Boolean);
    expect(lines.length).toBeGreaterThanOrEqual(2);
    expect(JSON.parse(lines[0]).action).toBe('deny');
    expect(JSON.parse(lines[1]).action).toBe('allow');
  });

  test('operation_preview is truncated to command_preview_chars (default 120)', () => {
    const longCmd = 'x'.repeat(300);
    writeAudit(auditPath, {
      session_id: 'b',
      tool_name: 'Bash',
      action: 'deny',
      operation_preview: longCmd,
      _preview_chars: 120,
      hook_event: 'PreToolUse'
    });
    const today = new Date().toISOString().slice(0, 10);
    const lines = fs.readFileSync(path.join(auditPath, `${today}.jsonl`), 'utf8').trim().split('\n').filter(Boolean);
    const last = JSON.parse(lines[lines.length - 1]);
    expect(last.operation_preview.length).toBeLessThanOrEqual(120);
  });

  test('audit entries are valid JSON on each line (JSONL format)', () => {
    const today = new Date().toISOString().slice(0, 10);
    const lines = fs.readFileSync(path.join(auditPath, `${today}.jsonl`), 'utf8').trim().split('\n').filter(Boolean);
    lines.forEach(l => {
      expect(() => JSON.parse(l)).not.toThrow();
    });
  });

  test('audit entry contains required fields: timestamp, version, session_id, action', () => {
    const today = new Date().toISOString().slice(0, 10);
    const lines = fs.readFileSync(path.join(auditPath, `${today}.jsonl`), 'utf8').trim().split('\n').filter(Boolean);
    const entry = JSON.parse(lines[0]);
    expect(entry).toHaveProperty('timestamp');
    expect(entry).toHaveProperty('version');
    expect(entry).toHaveProperty('session_id');
    expect(entry).toHaveProperty('action');
  });

  test('writeAuditEntry is an alias for writeAudit', () => {
    expect(typeof writeAuditEntry).toBe('function');
    // Should not throw
    expect(() => writeAuditEntry(auditPath, { session_id: 'c', action: 'allow', tool_name: 'Bash', hook_event: 'PreToolUse' })).not.toThrow();
  });

  test('audit write failure does not throw (audit cannot crash hook)', () => {
    // Write to an invalid path — must not throw
    expect(() => {
      writeAudit('/dev/null/not-a-dir/audit', { action: 'deny', session_id: 'x', hook_event: 'test' });
    }).not.toThrow();
  });
});
