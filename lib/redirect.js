'use strict';

// Protected persistence paths — writes here via bash redirect are always suspicious.
const PROTECTED_REDIRECT_PATHS = [
  /~?\/?\.ssh\/authorized_keys\b/,           // SSH keys
  /\/etc\/cron(?:\.[a-z]+)?\//,              // cron.d, cron.daily, etc.
  /\/var\/spool\/cron\//,                    // user crontabs
  /\/etc\/systemd\/system\/.*\.service/,     // systemd units
  /\/etc\/init\.d\//,                        // init scripts
  /\/etc\/sudoers(?:\.d\/)?/,                // sudoers
  /~?\/?\.config\/autostart\//,              // desktop autostart
  /\/lib\/systemd\//,                        // system-level systemd
  /\.git\/hooks\//,                          // git hooks
];

// Shell config dotfiles — write via redirect is persistence
const PROTECTED_DOTFILES = /~?\/?\.(?:bashrc|zshrc|profile|bash_profile|bash_login|bash_aliases|zprofile|kshrc|cshrc)\b/;

/**
 * Check if a command uses redirect (>, >>, tee) to write to a protected path.
 * Returns { blocked, reason, ruleId, risk } or null.
 */
function checkRedirectWrite(command) {
  // Find redirect targets: `> path`, `>> path`, `tee path`, `tee -a path`
  const redirRe = /(?:^|[^2&>])(?:>{1,2})\s*(?:"([^"]+)"|'([^']+)'|(\S+))/g;
  let m;
  const targets = [];
  while ((m = redirRe.exec(command)) !== null) {
    targets.push(m[1] || m[2] || m[3]);
  }

  // tee and tee -a targets
  const teeRe = /\btee\b(?:\s+-[aA])?\s+(?:"([^"]+)"|'([^']+)'|(\S+))/g;
  while ((m = teeRe.exec(command)) !== null) {
    targets.push(m[1] || m[2] || m[3]);
  }

  for (const target of targets) {
    if (!target) continue;
    // Skip process substitutions and file descriptors
    if (target.startsWith('/dev/fd/') || target.startsWith('&')) continue;

    for (const p of PROTECTED_REDIRECT_PATHS) {
      if (p.test(target) || p.test(command)) {
        return {
          blocked: true,
          reason: `Knox: Blocked — persistence write to ${target} [SP-RD]`,
          ruleId: 'SP-RD',
          risk: 'critical',
        };
      }
    }
    // Dotfile appends (>>) to shell configs
    if (PROTECTED_DOTFILES.test(target)) {
      // Only block append (>>), not truncate (>) — but truncate is also bad
      return {
        blocked: true,
        reason: `Knox: Blocked — write to shell config: ${target} [SP-RD]`,
        ruleId: 'SP-RD',
        risk: 'high',
      };
    }
  }
  return null;
}

module.exports = { checkRedirectWrite, PROTECTED_REDIRECT_PATHS, PROTECTED_DOTFILES };
