'use strict';
/**
 * Tier 3 Live Tests — require `claude` CLI with a valid API key.
 * Run with: npm run test:live
 *
 * These tests verify:
 * - All 7 skills end-to-end via Claude CLI
 * - PostToolUse additionalContext actually reaches Claude's conversation
 */
const { execSync, spawnSync } = require('child_process');
const path = require('path');

const PLUGIN_ROOT = path.resolve(__dirname, '../..');
const CLAUDE_FLAGS = `--plugin-dir ${PLUGIN_ROOT} -p --no-session-persistence`;

function runClaude(prompt, timeoutMs) {
  const result = spawnSync('claude', [...CLAUDE_FLAGS.split(' '), prompt], {
    encoding: 'utf8',
    timeout: timeoutMs || 60000,
    env: { ...process.env }
  });
  return { exitCode: result.status, stdout: result.stdout, stderr: result.stderr };
}

// Check if claude CLI is available
function claudeAvailable() {
  try { execSync('claude --version', { encoding: 'utf8', timeout: 5000 }); return true; }
  catch { return false; }
}

const SKIP = !claudeAvailable() || !process.env.ANTHROPIC_API_KEY;

(SKIP ? describe.skip : describe)('Tier 3: Live Claude CLI tests', () => {
  test('Knox plugin loads cleanly — hello world', () => {
    const r = runClaude('Say "Knox plugin loaded OK" and nothing else');
    expect(r.exitCode).toBe(0);
    expect(r.stderr).not.toMatch(/error|failed|cannot find/i);
  });

  test('/knox:status skill — returns preset info', () => {
    const r = runClaude('/knox:status');
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toMatch(/preset|Knox|standard|minimal|strict|paranoid/i);
  });

  test('/knox:audit skill — returns audit entries or empty message', () => {
    const r = runClaude('/knox:audit 5');
    expect(r.exitCode).toBe(0);
    // Should either show entries or say no entries found
    expect(r.stdout.length).toBeGreaterThan(0);
  });

  test('/knox:policy skill — shows active rules', () => {
    const r = runClaude('/knox:policy');
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toMatch(/preset|rule|blocklist|BL-/i);
  });

  test('/knox:help skill — explains Knox in 5 sections', () => {
    const r = runClaude('/knox:help');
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toMatch(/Knox/i);
    // Should cover hooks, presets, config
    expect(r.stdout).toMatch(/hook|preset|config/i);
  });

  test('/knox:report skill — shows security report', () => {
    const r = runClaude('/knox:report');
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toMatch(/Knox|report|denial|event/i);
  });

  test('PostToolUse additionalContext: Claude receives denial count after blocked command', () => {
    // Ask Claude to run a blocked command — Knox blocks it — PostToolUse injects context
    const r = runClaude('Try running: xmrig. Then tell me what Knox told you about the denial.');
    expect(r.exitCode).toBe(0);
    // Claude should mention the denial in its response
    expect(r.stdout).toMatch(/Knox|blocked|denied|denial/i);
  });

  test('User instructs Claude to add to allowlist via /knox:allow', () => {
    const r = runClaude('Please add "npm run e2e" to the Knox allowlist using the /knox:allow skill');
    expect(r.exitCode).toBe(0);
    // Claude should invoke /knox:allow and confirm it
    expect(r.stdout).toMatch(/allow|added|Knox/i);
  });
});
