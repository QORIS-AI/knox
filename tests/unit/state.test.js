'use strict';
const path = require('path');
const os = require('os');
const fs = require('fs');

// Override PLUGIN_DATA for tests
const TEST_DATA = path.join(os.tmpdir(), 'knox-state-test-' + Date.now());
process.env.CLAUDE_PLUGIN_DATA = TEST_DATA;
process.env.CLAUDE_PLUGIN_ROOT = path.resolve(__dirname, '../..');

beforeAll(() => fs.mkdirSync(TEST_DATA, { recursive: true }));
afterAll(() => { try { fs.rmSync(TEST_DATA, { recursive: true }); } catch {} });
afterEach(() => {
  // Clean up state files between tests
  try { fs.rmSync(path.join(TEST_DATA, 'state.json')); } catch {}
  try { fs.rmSync(path.join(TEST_DATA, 'escalation.json')); } catch {}
});

// Reload modules fresh with new PLUGIN_DATA
let readState, writeState, incrementDenial, readCrossSession, recordCrossDenial;
beforeEach(() => {
  jest.resetModules();
  process.env.CLAUDE_PLUGIN_DATA = TEST_DATA;
  process.env.CLAUDE_PLUGIN_ROOT = path.resolve(__dirname, '../..');
  const stateLib = require('../../lib/state');
  readState = stateLib.readState;
  writeState = stateLib.writeState;
  incrementDenial = stateLib.incrementDenial;
  readCrossSession = stateLib.readCrossSession;
  recordCrossDenial = stateLib.recordCrossDenial;
});

describe('state management', () => {
  test('readState returns default for unknown session', () => {
    const s = readState('sess-abc');
    expect(s.denial_count).toBe(0);
    expect(s.flagged).toBe(false);
  });

  test('writeState + readState round-trips', () => {
    writeState({ session_id: 'sess-abc', denial_count: 2, flagged: false });
    const s = readState('sess-abc');
    expect(s.denial_count).toBe(2);
  });

  test('incrementDenial increments count', () => {
    const s = incrementDenial('sess-xyz', 3);
    expect(s.denial_count).toBe(1);
    expect(s.flagged).toBe(false);
  });

  test('incrementDenial flags at threshold', () => {
    incrementDenial('sess-xyz', 3);
    incrementDenial('sess-xyz', 3);
    const s = incrementDenial('sess-xyz', 3);
    expect(s.denial_count).toBe(3);
    expect(s.flagged).toBe(true);
  });

  test('different session IDs are independent (readState returns 0 for new session)', () => {
    incrementDenial('sess-a', 3);
    const sB = readState('sess-b');
    expect(sB.denial_count).toBe(0);
  });

  test('state file is written atomically (no .tmp left behind)', () => {
    writeState({ session_id: 'sess-atomic', denial_count: 1, flagged: false });
    expect(fs.existsSync(path.join(TEST_DATA, 'state.json.tmp'))).toBe(false);
    expect(fs.existsSync(path.join(TEST_DATA, 'state.json'))).toBe(true);
  });

  test('cross-session recordCrossDenial increments and returns count', () => {
    const c1 = recordCrossDenial('sess-a', 1);
    const c2 = recordCrossDenial('sess-b', 1);
    expect(c2).toBeGreaterThanOrEqual(c1);
    expect(c2).toBeGreaterThan(0);
  });

  test('cross-session sliding window: entries outside window are pruned', () => {
    // Add a very old entry manually
    const escalationFile = path.join(TEST_DATA, 'escalation.json');
    const oldEntry = { ts: Date.now() - 2 * 3600 * 1000, session_id: 'old-sess' };
    fs.writeFileSync(escalationFile, JSON.stringify({ denials: [oldEntry] }));

    // Record a new one with 1-hour window — old entry should be pruned
    const count = recordCrossDenial('new-sess', 1);
    expect(count).toBe(1); // only the new one survives
  });
});
