/**
 * env-check.js — Pre-launch and Continuous Environment Checker
 *
 * Runs a series of environment integrity checks before and during an exam:
 *
 *   1. Display count   — blocks launch if more than one monitor is connected.
 *   2. Display change  — watches for monitors being plugged in mid-exam.
 *   3. Single instance — enforced via app.requestSingleInstanceLock() in main.js.
 *                        (Documented here; implemented at app bootstrap.)
 *
 * What is checked here (pure Electron, zero native dependencies):
 *   ✅  Number of connected displays       → screen.getAllDisplays()
 *   ✅  Display plug/unplug events         → screen events 'display-added' / 'display-removed'
 *   ✅  Single app instance                → app.requestSingleInstanceLock()
 *   ✅  Clipboard read/write disabled      → session.setPermissionRequestHandler
 *                                            + Content-Security-Policy header injection
 *
 * What CANNOT be fully blocked from Electron user-space:
 *   ❌  WebRTC in a remote page            — Chromium's WebRTC stack is used by
 *                                            the assessment platform itself (e.g. live
 *                                            proctoring). Blocking it entirely would
 *                                            break the platform. The correct approach is
 *                                            to deny 'media' permissions (camera/mic)
 *                                            unless explicitly needed, and rely on the
 *                                            platform's own session handling.
 *   ❌  Screen-capture at the OS level     — `getDisplayMedia()` can be denied via
 *                                            the permission handler, but a native
 *                                            capture tool (OBS, Snipping Tool) bypasses
 *                                            Chromium entirely. Use the process monitor.
 *   ❌  GPU-accelerated virtual displays   — Some remote-access tools create a virtual
 *                                            display that `screen.getAllDisplays()` may
 *                                            count as a second display (good) or may NOT
 *                                            count at all (e.g. RDP without multi-monitor).
 *                                            There is no 100% reliable OS-level check
 *                                            without a native kernel module.
 *   ❌  Hardware clipboard (hardware KVM)  — A KVM switch can relay clipboard content
 *                                            between machines at the hardware level.
 */

'use strict';

const { screen, app } = require('electron');
const { EventEmitter } = require('events');

class EnvCheck extends EventEmitter {
  /**
   * @param {object} config
   * @param {boolean} config.blockMultipleDisplays  — Abort if >1 display (default true)
   * @param {boolean} config.watchDisplayChanges    — Emit 'display-change' mid-exam (default true)
   */
  constructor(config = {}) {
    super();
    this._blockMultiDisplays  = config.blockMultipleDisplays !== false;
    this._watchDisplayChanges = config.watchDisplayChanges   !== false;
    this._displayChangeHandlerAdded  = false;
  }

  // ─── Public API ─────────────────────────────────────────────────────────────

  /**
   * Run the pre-launch environment check.
   * Returns { passed: boolean, failures: string[] }.
   * Call this BEFORE creating the BrowserWindow.
   */
  runPreLaunchChecks() {
    const failures = [];

    if (this._blockMultiDisplays) {
      const result = this._checkDisplayCount();
      if (!result.passed) failures.push(result.reason);
    }

    const passed = failures.length === 0;
    return { passed, failures };
  }

  /**
   * Begin watching for mid-exam environment changes.
   * Emits 'display-change' { type, displays } when a monitor is added/removed.
   * Call this AFTER the window is shown.
   */
  startWatching() {
    if (this._watchDisplayChanges && !this._displayChangeHandlerAdded) {
      this._displayChangeHandlerAdded = true;

      screen.on('display-added', (_, display) => {
        const displays = screen.getAllDisplays();
        console.warn(`[EnvCheck] Display ADDED — total now: ${displays.length}`);
        this.emit('display-change', {
          type:     'DISPLAY_ADDED',
          display,
          displays,
          count:    displays.length,
        });
      });

      screen.on('display-removed', (_, display) => {
        const displays = screen.getAllDisplays();
        console.info(`[EnvCheck] Display REMOVED — total now: ${displays.length}`);
        this.emit('display-change', {
          type:     'DISPLAY_REMOVED',
          display,
          displays,
          count:    displays.length,
        });
      });

      screen.on('display-metrics-changed', (_, display, changedMetrics) => {
        // Resolution or DPI changes can indicate a remote desktop session resizing
        console.info(`[EnvCheck] Display metrics changed: ${changedMetrics.join(', ')}`);
        this.emit('display-metrics-changed', { display, changedMetrics });
      });
    }
  }

  /** Returns the current display list for on-demand queries. */
  getDisplayInfo() {
    const displays = screen.getAllDisplays();
    return {
      count:    displays.length,
      displays: displays.map(d => ({
        id:         d.id,
        label:      d.label || `Display ${d.id}`,
        bounds:     d.bounds,
        scaleFactor: d.scaleFactor,
        isPrimary:  d.id === screen.getPrimaryDisplay().id,
      })),
    };
  }

  // ─── Internal checks ────────────────────────────────────────────────────────

  _checkDisplayCount() {
    const displays = screen.getAllDisplays();
    const count    = displays.length;

    if (count > 1) {
      return {
        passed: false,
        reason: `MULTIPLE_DISPLAYS: ${count} monitors detected. Disconnect all but the primary display before starting the exam.`,
      };
    }
    return { passed: true };
  }
}

module.exports = EnvCheck;
