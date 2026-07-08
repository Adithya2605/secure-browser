/**
 * process-monitor.js — Suspicious Process Monitor
 *
 * Scans the OS process list on a configurable interval and flags any
 * process whose name matches the blocklist.
 *
 * Design decisions:
 *  - Uses Node.js built-in `child_process.execFile` to call the OS-native
 *    `tasklist` (Windows) or `ps` (macOS/Linux) command.
 *    → Zero additional npm dependencies.
 *  - Extends EventEmitter — callers react to events instead of polling.
 *  - Tracks "active" (currently running) vs "new" alerts separately,
 *    so repeat detections do not spam the log.
 *  - NEVER kills any process — flagging only.
 *
 * Events emitted:
 *  'alert'         { alerts: Alert[] }          New suspicious processes found this scan
 *  'resolved'      { resolved: Alert[] }        Previously active processes no longer running
 *  'scan'          { active: Alert[], scan: N } Fired after every scan (full active set)
 *  'error'         { error: Error }             Process-list command failed
 *
 * Alert object shape:
 *  {
 *    name:        string,   // e.g. "zoom.exe"
 *    pid:         number,   // OS process ID (Windows only; -1 on others)
 *    category:    string,   // e.g. "SCREEN_SHARE"
 *    severity:    string,   // "HIGH" | "MEDIUM" | "LOW"
 *    description: string,   // human-readable reason
 *    detectedAt:  string,   // ISO timestamp of first detection this session
 *    lastSeenAt:  string,   // ISO timestamp of most recent scan it was seen
 *    scanCount:   number,   // how many consecutive scans it has been present
 *  }
 */

'use strict';

const { EventEmitter } = require('events');
const { execFile }     = require('child_process');
const path             = require('path');
const fs               = require('fs');
const { app }          = require('electron');

class ProcessMonitor extends EventEmitter {
  /**
   * @param {Array}   blockedApps          Entries from blocked-apps.js
   * @param {object}  config
   * @param {number}  config.intervalMs    Scan frequency in ms (default 5000)
   * @param {boolean} config.logAlerts     Write alerts to disk (default true)
   */
  constructor(blockedApps, config = {}) {
    super();

    // Build a Map keyed by lowercase exe name for O(1) lookup
    this._blocklist = new Map(
      blockedApps.map(app => [app.name.toLowerCase(), app])
    );

    this._intervalMs  = config.intervalMs ?? 5000;
    this._logEnabled  = config.logAlerts  !== false;

    // Map<lowercaseName → Alert> of processes currently running
    this._active      = new Map();

    // Full chronological alert log for the session
    this._allAlerts   = [];

    this._timer       = null;
    this._scanCount   = 0;
    this._running     = false;

    this._logPath = path.join(
      app.getPath('userData'),
      'process-alerts.log'
    );
  }

  // ─── Public API ─────────────────────────────────────────────────────────────

  /** Start periodic scanning. Safe to call multiple times. */
  start() {
    if (this._running) return;
    this._running = true;
    console.log(`[ProcessMonitor] Started — interval=${this._intervalMs}ms, watching ${this._blocklist.size} apps`);
    this._writeLog(`[${new Date().toISOString()}] MONITOR_STARTED interval=${this._intervalMs}ms\n`);
    this._scheduleNext();
  }

  /** Stop scanning and clear the timer. */
  stop() {
    if (!this._running) return;
    this._running = false;
    if (this._timer) {
      clearTimeout(this._timer);
      this._timer = null;
    }
    console.log('[ProcessMonitor] Stopped');
    this._writeLog(`[${new Date().toISOString()}] MONITOR_STOPPED\n`);
  }

  /** Returns all alerts logged so far this session (immutable copy). */
  getAllAlerts() {
    return [...this._allAlerts];
  }

  /** Returns only currently-active (still running) suspicious processes. */
  getActiveAlerts() {
    return [...this._active.values()];
  }

  /** Returns the path to the on-disk alert log. */
  getLogPath() {
    return this._logPath;
  }

  /** Total number of unique suspicious processes ever detected. */
  getTotalCount() {
    return this._allAlerts.length;
  }

  // ─── Internal scan loop ──────────────────────────────────────────────────────

  _scheduleNext() {
    if (!this._running) return;
    this._timer = setTimeout(async () => {
      await this._scan();
      this._scheduleNext();
    }, this._intervalMs);
  }

  async _scan() {
    this._scanCount++;
    let processMap; // Map<lowerName → pid[]>

    try {
      processMap = await this._getProcessMap();
    } catch (err) {
      console.error('[ProcessMonitor] Failed to read process list:', err.message);
      this.emit('error', { error: err });
      return;
    }

    const now        = new Date().toISOString();
    const newAlerts  = [];
    const resolved   = [];

    // ── Detect new / continuing suspicious processes ─────────────────────────
    for (const [lowerName, pids] of processMap) {
      const entry = this._blocklist.get(lowerName);
      if (!entry) continue;

      const pid = pids[0] ?? -1; // report first PID if multiple instances

      if (this._active.has(lowerName)) {
        // Already flagged — update lastSeenAt and scanCount
        const existing = this._active.get(lowerName);
        existing.lastSeenAt = now;
        existing.scanCount++;
      } else {
        // Newly detected this scan
        const alert = {
          name:        entry.name,
          pid,
          category:    entry.category,
          severity:    entry.severity,
          description: entry.description,
          detectedAt:  now,
          lastSeenAt:  now,
          scanCount:   1,
        };
        this._active.set(lowerName, alert);
        this._allAlerts.push(alert);
        newAlerts.push(alert);

        const line = `[${now}] DETECTED  [${entry.severity}] [${entry.category}] ${entry.name} (PID ${pid}) — ${entry.description}\n`;
        console.warn(`[ProcessMonitor] ${line.trim()}`);
        this._writeLog(line);
      }
    }

    // ── Detect processes that have since exited ──────────────────────────────
    for (const [lowerName, alert] of this._active) {
      if (!processMap.has(lowerName)) {
        const line = `[${now}] RESOLVED  ${alert.name} (was PID ${alert.pid}) — no longer running\n`;
        console.info(`[ProcessMonitor] ${line.trim()}`);
        this._writeLog(line);
        resolved.push(alert);
        this._active.delete(lowerName);
      }
    }

    // ── Emit events ──────────────────────────────────────────────────────────
    if (newAlerts.length > 0) {
      this.emit('alert', { alerts: newAlerts });
    }
    if (resolved.length > 0) {
      this.emit('resolved', { resolved });
    }

    this.emit('scan', {
      active:    [...this._active.values()],
      scan:      this._scanCount,
      timestamp: now,
    });
  }

  // ─── OS process enumeration ──────────────────────────────────────────────────

  /**
   * Returns a Map<lowercaseExeName → number[]> of running PIDs.
   * Uses:
   *   Windows → `tasklist /FO CSV /NH`
   *   macOS   → `ps -eo comm,pid`
   *   Linux   → `ps -eo comm,pid`
   */
  _getProcessMap() {
    return process.platform === 'win32'
      ? this._getProcessMapWindows()
      : this._getProcessMapUnix();
  }

  /**
   * Windows: parse tasklist CSV output.
   *
   * Output format (one line per process):
   *   "chrome.exe","12345","Console","1","51,844 K"
   */
  _getProcessMapWindows() {
    return new Promise((resolve, reject) => {
      execFile(
        'tasklist',
        ['/FO', 'CSV', '/NH'],
        { timeout: 8000, windowsHide: true },
        (err, stdout, stderr) => {
          if (err) return reject(new Error(`tasklist error: ${stderr || err.message}`));

          const map = new Map();
          for (const line of stdout.split(/\r?\n/)) {
            const trimmed = line.trim();
            if (!trimmed) continue;

            // Parse CSV — first field is name (quoted), second is PID (quoted)
            const match = trimmed.match(/^"([^"]+)","(\d+)"/);
            if (!match) continue;

            const name = match[1].toLowerCase();
            const pid  = parseInt(match[2], 10);

            if (!map.has(name)) map.set(name, []);
            map.get(name).push(pid);
          }
          resolve(map);
        }
      );
    });
  }

  /**
   * macOS / Linux: parse `ps` output.
   *
   * Output format (one line per process):
   *   zoom 12345
   *
   * Note: macOS process names are often without .exe suffix. The blocklist
   * should include both variants if cross-platform support is needed.
   */
  _getProcessMapUnix() {
    return new Promise((resolve, reject) => {
      execFile(
        'ps',
        ['-eo', 'comm,pid', '--no-headers'],
        { timeout: 8000 },
        (err, stdout, stderr) => {
          if (err) return reject(new Error(`ps error: ${stderr || err.message}`));

          const map = new Map();
          for (const line of stdout.split(/\n/)) {
            const parts = line.trim().split(/\s+/);
            if (parts.length < 2) continue;

            const name = parts[0].toLowerCase();
            const pid  = parseInt(parts[1], 10);

            if (!map.has(name)) map.set(name, []);
            map.get(name).push(pid);
          }
          resolve(map);
        }
      );
    });
  }

  // ─── Logging ────────────────────────────────────────────────────────────────

  _writeLog(line) {
    if (!this._logEnabled) return;
    try { fs.appendFileSync(this._logPath, line); } catch (_) { /* non-fatal */ }
  }
}

module.exports = ProcessMonitor;
