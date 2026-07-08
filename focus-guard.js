/**
 * focus-guard.js — Focus & Fullscreen Enforcement Module
 *
 * Handles:
 *   - Detecting window blur (focus loss)
 *   - Re-claiming focus after a configurable delay
 *   - Re-entering fullscreen when the candidate exits it
 *   - Logging every violation to a persistent file in userData
 *   - Exposing violation count / log path to the main process
 *
 * PURE ELECTRON — no native modules required.
 */

'use strict';

const { app } = require('electron');
const path     = require('path');
const fs       = require('fs');

class FocusGuard {
  /**
   * @param {Electron.BrowserWindow} win     - The window to guard
   * @param {object}                 config  - Subset of config.json
   * @param {boolean}  config.fullscreen     - Whether to re-enter fullscreen on exit
   * @param {number}   config.refocusDelayMs - ms before re-focusing after blur (default 200)
   * @param {boolean}  config.logViolations  - Whether to write violations to disk
   */
  constructor(win, config = {}) {
    this._win             = win;
    this._fullscreen      = config.fullscreen !== false;
    this._refocusDelay    = config.refocusDelayMs ?? 200;
    this._loggingEnabled  = config.logViolations !== false;
    this._violations      = [];
    this._refocusTimer    = null;
    this._started         = false;

    // Bound handler references — stored so we can remove them in stop()
    this._boundOnBlur              = () => this._onBlur();
    this._boundOnFocus             = () => this._onFocus();
    this._boundOnLeaveFullscreen   = () => this._onLeaveFullscreen();
    this._boundOnMinimize          = () => this._onMinimize();

    // Violations are written to the user-data directory so they survive app restarts
    this._logPath = path.join(app.getPath('userData'), 'violations.log');
  }

  // ─── Public API ─────────────────────────────────────────────────────────────

  /** Begin monitoring. Call once after the window is created. */
  start() {
    if (this._started) return;
    this._started = true;

    this._win.on('blur',              this._boundOnBlur);
    this._win.on('focus',             this._boundOnFocus);
    this._win.on('leave-full-screen', this._boundOnLeaveFullscreen);
    this._win.on('minimize',          this._boundOnMinimize);

    this._log('GUARD_STARTED', `log=${this._logPath}`);
  }

  /** Stop monitoring (e.g. when the assessment is complete). */
  stop() {
    this._cancelRefocus();
    this._started = false;

    // Remove all listeners so handlers can no longer fire after stop().
    // Previously stop() only set _started=false but left listeners attached,
    // meaning _onLeaveFullscreen() would still re-enter fullscreen even
    // after assessment-complete called setFullScreen(false).
    if (this._win && !this._win.isDestroyed()) {
      this._win.off('blur',              this._boundOnBlur);
      this._win.off('focus',             this._boundOnFocus);
      this._win.off('leave-full-screen', this._boundOnLeaveFullscreen);
      this._win.off('minimize',          this._boundOnMinimize);
    }

    this._log('GUARD_STOPPED');
  }

  /**
   * Disable fullscreen enforcement without fully stopping the guard.
   * Call this before setFullScreen(false) during a clean exit so the
   * leave-full-screen handler does not immediately re-enter fullscreen.
   */
  disableFullscreen() {
    this._fullscreen = false;
  }

  /** Returns a copy of all recorded violations. */
  getViolations() {
    return [...this._violations];
  }

  /** Returns the absolute path to the violation log file. */
  getLogPath() {
    return this._logPath;
  }

  /** Returns total violation count (excludes GUARD_STARTED / GUARD_STOPPED). */
  getCount() {
    return this._violations.filter(v =>
      !['GUARD_STARTED', 'GUARD_STOPPED'].includes(v.type)
    ).length;
  }

  // ─── Internal handlers ───────────────────────────────────────────────────────

  _onBlur() {
    this._log('FOCUS_LOST');
    this._scheduleRefocus();
  }

  _onFocus() {
    this._cancelRefocus();
    // Keep window above everything else once it regains focus
    if (!this._win.isDestroyed()) {
      this._win.setAlwaysOnTop(true, 'screen-saver');
    }
  }

  _onLeaveFullscreen() {
    this._log('FULLSCREEN_EXIT');
    if (this._fullscreen) {
      // Small delay so the OS animation finishes before we push back
      const timer = setTimeout(() => {
        if (!this._win.isDestroyed()) {
          this._win.setFullScreen(true);
        }
      }, 80);
      timer.unref?.(); // Don't block process exit
    }
  }

  _onMinimize() {
    this._log('WINDOW_MINIMIZED');
    if (!this._win.isDestroyed()) {
      this._win.restore();
      this._win.focus();
      if (this._fullscreen) this._win.setFullScreen(true);
    }
  }

  _scheduleRefocus() {
    this._cancelRefocus();
    this._refocusTimer = setTimeout(() => {
      if (this._win && !this._win.isDestroyed()) {
        this._win.setAlwaysOnTop(true, 'screen-saver');
        this._win.focus();
        if (this._fullscreen && !this._win.isFullScreen()) {
          this._win.setFullScreen(true);
        }
      }
    }, this._refocusDelay);
  }

  _cancelRefocus() {
    if (this._refocusTimer !== null) {
      clearTimeout(this._refocusTimer);
      this._refocusTimer = null;
    }
  }

  // ─── Logging ────────────────────────────────────────────────────────────────

  _log(type, detail = '') {
    const entry = {
      timestamp: new Date().toISOString(),
      type,
      detail,
      total: this._violations.length + 1,
    };
    this._violations.push(entry);

    const line = detail
      ? `[${entry.timestamp}] ${type} — ${detail}\n`
      : `[${entry.timestamp}] ${type}\n`;

    console.warn(`[FocusGuard] ${line.trim()}`);

    if (this._loggingEnabled) {
      try { fs.appendFileSync(this._logPath, line); } catch (_) { /* non-fatal */ }
    }
  }
}

module.exports = FocusGuard;
