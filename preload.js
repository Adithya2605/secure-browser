/**
 * preload.js — Renderer-side protections
 *
 * Runs in an isolated context BEFORE any page JS executes.
 * contextIsolation: true means page scripts cannot reach this scope.
 *
 * Responsibilities:
 *  1. Disable right-click context menu
 *  2. Block dangerous keyboard shortcuts (DevTools, reload, tab-switch, etc.)
 *  3. Block drag-and-drop URL navigation
 *  4. Block middle-click (opens links in new tab in Chromium)
 *  5. Detect page visibility change (user switched away) and notify main
 *  6. Block clipboard cut/copy/paste keyboard shortcuts
 *  7. Forward process-monitor and env-check push events from main to the page
 *  8. Expose a minimal, safe IPC bridge to the assessment page
 *
 * ════════════════════════════════════════════════════════════════════════════
 *  Keyboard shortcut notes
 * ════════════════════════════════════════════════════════════════════════════
 *  Alt+Tab and Windows key generate events that reach this handler ONLY when
 *  the browser window is focused. Once focus is lost (which is what Alt+Tab
 *  causes), these events stop arriving. The main process handles focus
 *  recovery via FocusGuard. Preload blocks what it can, main.js catches the
 *  rest at the globalShortcut level.
 */

'use strict';

const { contextBridge, ipcRenderer } = require('electron');

// ─── 1. Disable right-click context menu ─────────────────────────────────────
window.addEventListener('contextmenu', (e) => {
  e.preventDefault();
  e.stopImmediatePropagation();
}, true);

// ─── 2. Keyboard shortcut firewall ───────────────────────────────────────────

/** Standalone keys that are always blocked. */
const BLOCKED_SINGLE_KEYS = new Set([
  'F1', 'F3', 'F4', 'F5', 'F6', 'F7',
  'F10', 'F11', 'F12',
  'PrintScreen',
  'ContextMenu',   // Application / Menu key on Windows keyboards
]);

/**
 * Keys blocked when Ctrl (or Cmd on Mac) is held.
 * Lowercase + uppercase listed because e.key is case-sensitive.
 */
const BLOCKED_WITH_CTRL = new Set([
  'r', 'R',   // Reload page
  'l', 'L',   // Address bar focus (Chromium)
  'n', 'N',   // New window
  't', 'T',   // New tab
  'w', 'W',   // Close tab / window
  'j', 'J',   // Downloads panel
  'u', 'U',   // View source
  'p', 'P',   // Print
  'h', 'H',   // History
  'g', 'G',   // Find next
  'q', 'Q',   // Quit (macOS)
]);

/** Keys blocked when Ctrl+Shift is held. */
const BLOCKED_WITH_CTRL_SHIFT = new Set([
  'i', 'I',       // DevTools (Chrome)
  'j', 'J',       // Console (Chrome)
  'c', 'C',       // Inspector (Chrome)
  'k', 'K',       // Console (Firefox)
  'e', 'E',       // Elements (Firefox)
  'q', 'Q',       // (various)
  'Delete',       // Task Manager (Chrome)
]);

/** Keys blocked when Alt is held. */
const BLOCKED_WITH_ALT = new Set([
  'F4',          // Close window (Windows)
  'ArrowLeft',   // Browser back
  'ArrowRight',  // Browser forward
  'Home',        // Browser home
  'Tab',         // Window switcher — fires briefly before focus is lost;
                 // won't fully prevent switching but slows it down
  'd',  'D',     // Address bar (IE/Edge legacy)
  'F',  'f',     // File menu
  ' ',           // System menu (Windows — Space opens title-bar menu)
]);

window.addEventListener('keydown', (e) => {
  const key   = e.key;
  const ctrl  = e.ctrlKey || e.metaKey;
  const alt   = e.altKey;
  const shift = e.shiftKey;

  // 1. Standalone blocked keys
  if (!ctrl && !alt && !shift && BLOCKED_SINGLE_KEYS.has(key)) {
    e.preventDefault();
    e.stopImmediatePropagation();
    return;
  }

  // 2. Ctrl / Cmd combos
  if (ctrl && !alt) {
    if (shift && BLOCKED_WITH_CTRL_SHIFT.has(key)) {
      e.preventDefault();
      e.stopImmediatePropagation();
      return;
    }
    if (!shift && BLOCKED_WITH_CTRL.has(key)) {
      e.preventDefault();
      e.stopImmediatePropagation();
      return;
    }
  }

  // 3. Alt combos
  if (alt && !ctrl && BLOCKED_WITH_ALT.has(key)) {
    e.preventDefault();
    e.stopImmediatePropagation();
    return;
  }

  // 4. Windows / Meta key (partially suppressed here; full block needs OS policy)
  if (key === 'Meta' || key === 'OS') {
    e.preventDefault();
    e.stopImmediatePropagation();
    return;
  }

  // 5. Escape — prevent candidates from exiting fullscreen via Esc
  //    (main process re-enters fullscreen anyway, but we also block at page level)
  if (key === 'Escape') {
    e.preventDefault();
    e.stopImmediatePropagation();
  }
}, true);

// ─── 3. Block drag-and-drop navigation ───────────────────────────────────────
window.addEventListener('dragover', (e) => e.preventDefault(), true);
window.addEventListener('drop',     (e) => e.preventDefault(), true);

// ─── 4. Block middle-click (opens link in new background tab) ────────────────
window.addEventListener('mousedown', (e) => {
  if (e.button === 1) e.preventDefault();
}, true);

// ─── 5b. Clipboard cut / copy / paste blocking ───────────────────────────────
//
// Layer 1: keyboard shortcut block (in the existing keydown listener above,
//          Ctrl+C, Ctrl+X, Ctrl+V are NOT in the blocklist by default so that
//          candidates can type. To fully block them, add them to BLOCKED_WITH_CTRL.
//
// Layer 2: DOM clipboard events — cancelled here so paste/copy from the browser
//          UI (right-click was already blocked) cannot exfiltrate data.
//
// ⚠️  LIMITATION: This blocks clipboard events dispatched to the page. The OS
//     clipboard is a shared memory region; a separate process (another app)
//     can still read from it. The main-process permission handler blocks the
//     Clipboard API JS permission request, which is the stronger control.
//
// To fully disable Ctrl+C / Ctrl+V in the exam, add 'c','C','x','X','v','V'
// to the BLOCKED_WITH_CTRL set above.
//
window.addEventListener('copy',  (e) => { e.preventDefault(); e.stopImmediatePropagation(); }, true);
window.addEventListener('cut',   (e) => { e.preventDefault(); e.stopImmediatePropagation(); }, true);
// Note: paste is intentionally allowed so candidates can type into fields.
// If your assessment needs full clipboard lockdown, uncomment the line below:
// window.addEventListener('paste', (e) => { e.preventDefault(); e.stopImmediatePropagation(); }, true);

// ─── 5. Page Visibility API — detect tab/window switching ────────────────────
//
// document.visibilityState changes to 'hidden' when the user Alt+Tabs or
// minimises the window. This fires even before the 'blur' event reaches
// the main process, giving an early-warning signal.
//

// ─── 6. Page Visibility API — detect tab/window switching ────────────────────
document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'hidden') {
    ipcRenderer.send('visibility-hidden');
  }
});

// ─── 7. Forward process-monitor, display-change, and env-check push events ───
//
// main.js emits these via webContents.send() when the ProcessMonitor fires or
// when a display change is detected. Relayed as CustomEvents to the page.
//
ipcRenderer.on('process-alert', (_event, alerts) => {
  window.dispatchEvent(
    new CustomEvent('secure-browser:process-alert', { detail: alerts })
  );
});

ipcRenderer.on('process-resolved', (_event, resolved) => {
  window.dispatchEvent(
    new CustomEvent('secure-browser:process-resolved', { detail: resolved })
  );
});

ipcRenderer.on('display-change', (_event, data) => {
  window.dispatchEvent(
    new CustomEvent('secure-browser:display-change', { detail: data })
  );
});

ipcRenderer.on('env-violation', (_event, data) => {
  window.dispatchEvent(
    new CustomEvent('secure-browser:env-violation', { detail: data })
  );
});

ipcRenderer.on('display-metrics-changed', (_event, data) => {
  window.dispatchEvent(
    new CustomEvent('secure-browser:display-metrics-changed', { detail: data })
  );
});

// ─── 8. Safe IPC bridge ───────────────────────────────────────────────────────
//
// Only these specific, named APIs are exposed to the page.
// The page cannot reach ipcRenderer or any other Electron API directly.
//
contextBridge.exposeInMainWorld('secureBrowser', {
  /**
   * Called by the assessment platform when the candidate submits.
   * Triggers a clean application exit in the main process.
   */
  assessmentComplete: () => ipcRenderer.send('assessment-complete'),

  /**
   * Retry loading the assessment URL (called from the did-fail-load error page).
   */
  retryLoad: () => ipcRenderer.send('retry-load'),

  /**
   * Called by the success overlay Close button to quit the app.
   * Only works after assessment-complete has been processed.
   */
  closeBrowser: () => ipcRenderer.send('close-browser'),

  /**
   * Returns a promise resolving to { count, violations, logPath }.
   * Useful for displaying a violation summary to the proctor.
   */
  getViolations: () => ipcRenderer.invoke('get-violations'),

  // ─ Process monitor API ───────────────────────────────────────────────────

  /**
   * Full session history of ALL suspicious process detections.
   * Resolves to Alert[] (see process-monitor.js for shape).
   */
  getProcessAlerts: () => ipcRenderer.invoke('get-process-alerts'),

  /**
   * Only the processes that are CURRENTLY still running.
   * Resolves to Alert[].
   */
  getActiveProcessAlerts: () => ipcRenderer.invoke('get-active-process-alerts'),

  /**
   * Absolute path to the on-disk process alert log file.
   * Resolves to string | null.
   */
  getProcessLogPath: () => ipcRenderer.invoke('get-process-log-path'),

  /**
   * Subscribe to real-time push alerts.
   * callback receives Alert[] whenever new suspicious processes are detected.
   *
   * Usage:
   *   const unsub = window.secureBrowser.onProcessAlert(alerts => { ... });
   *   unsub(); // stop listening
   */
  onProcessAlert: (callback) => {
    const handler = (e) => callback(e.detail);
    window.addEventListener('secure-browser:process-alert', handler);
    return () => window.removeEventListener('secure-browser:process-alert', handler);
  },

  /**
   * Subscribe to push notifications when a previously-flagged process exits.
   * callback receives Alert[] of resolved entries.
   */
  onProcessResolved: (callback) => {
    const handler = (e) => callback(e.detail);
    window.addEventListener('secure-browser:process-resolved', handler);
    return () => window.removeEventListener('secure-browser:process-resolved', handler);
  },

  // ─ Environment check API ─────────────────────────────────────────────────

  /**
   * Returns current display info: { count: number, displays: Display[] }.
   */
  getDisplayInfo: () => ipcRenderer.invoke('get-display-info'),

  /**
   * Runs a fresh display count check.
   * Resolves to { passed: boolean, failures: string[] }.
   */
  runDisplayCheck: () => ipcRenderer.invoke('run-display-check'),

  /**
   * Subscribe to mid-exam display plug/unplug events.
   * callback receives { type, count, displays }.
   */
  onDisplayChange: (callback) => {
    const handler = (e) => callback(e.detail);
    window.addEventListener('secure-browser:display-change', handler);
    return () => window.removeEventListener('secure-browser:display-change', handler);
  },

  /**
   * Subscribe to environment violation alerts (e.g. second monitor plugged in).
   * callback receives { type, message, count }.
   */
  onEnvViolation: (callback) => {
    const handler = (e) => callback(e.detail);
    window.addEventListener('secure-browser:env-violation', handler);
    return () => window.removeEventListener('secure-browser:env-violation', handler);
  },

  // ─ Proctoring API ──────────────────────────────────────────────────────────

  /** Most-recent proctor status. Resolves to ProctoStatus | null. */
  getProctoringStatus: () => ipcRenderer.invoke('get-proctor-status'),

  /** Full session detection history. Resolves to ProctoStatus[]. */
  getProctoringHistory: () => ipcRenderer.invoke('get-proctor-history'),

  /** Path to the on-disk proctor log. Resolves to string | null. */
  getProctoringLogPath: () => ipcRenderer.invoke('get-proctor-log-path'),

  /**
   * Subscribe to real-time proctoring updates.
   * callback receives { status, faceCount, faces, timestamp }.
   * Returns an unsubscribe function.
   *
   * status values:
   *   'FACE_PRESENT'   — exactly one face detected (normal)
   *   'NO_FACE'        — no face visible (candidate looked away)
   *   'MULTIPLE_FACES' — more than one person visible
   *   'CAMERA_ERROR'   — webcam access failed
   *   'MODEL_ERROR'    — TF.js model failed to load
   */
  onProctoringUpdate: (callback) => {
    const handler = (e) => callback(e.detail);
    window.addEventListener('secure-browser:proctor-status', handler);
    return () => window.removeEventListener('secure-browser:proctor-status', handler);
  },

  // ─ Audit log API ──────────────────────────────────────────────────────────

  /** Returns the absolute path to the current session's NDJSON audit log. */
  getAuditLogPath:   () => ipcRenderer.invoke('get-audit-log-path'),

  /** Returns the UUID for the current exam session (use for server correlation). */
  getAuditSessionId: () => ipcRenderer.invoke('get-audit-session-id'),

  /**
   * Verify the integrity of the local audit log.
   * Resolves to { valid: boolean, totalEvents: number, firstBrokenSeq: number|null }.
   * Call before submission to confirm the log chain is intact.
   */
  verifyAuditChain:  () => ipcRenderer.invoke('verify-audit-chain'),

  /**
   * Trigger an immediate sync to the backend (normally sync is periodic).
   * Call this on exam submission to flush all remaining events before the
   * app closes. Resolves when sync completes or all retries are exhausted.
   */
  triggerSync:       () => ipcRenderer.invoke('trigger-sync'),

  // ─ Risk scoring API ───────────────────────────────────────────────────────

  /** Current risk score and level. Resolves to { score: number, level: string }. */
  getRiskScore:   () => ipcRenderer.invoke('get-risk-score'),

  /** Full scoring history. Resolves to ScoreEntry[]. */
  getRiskHistory: () => ipcRenderer.invoke('get-risk-history'),

  /**
   * Session risk summary (for proctor dashboard / submit payload).
   * Resolves to { score, level, totalEvents, criticalEvents, breakdown, elapsedMs, config }.
   */
  getRiskSummary: () => ipcRenderer.invoke('get-risk-summary'),

  /**
   * Subscribe to real-time risk score updates.
   * callback receives { points, score, level, reason, action }.
   * Returns an unsubscribe function.
   */
  onRiskScoreUpdate: (callback) => {
    const handler = (e) => callback(e.detail);
    window.addEventListener('secure-browser:risk-score-update', handler);
    return () => window.removeEventListener('secure-browser:risk-score-update', handler);
  },

  /**
   * Subscribe to risk level changes (LOW → MEDIUM → HIGH → CRITICAL).
   * callback receives { from, to, score, action, reason }.
   * action values: 'WARNING' | 'FLAG' | 'FLAG_CRITICAL' | 'TERMINATE' | null
   * Returns an unsubscribe function.
   */
  onRiskLevelChange: (callback) => {
    const handler = (e) => callback(e.detail);
    window.addEventListener('secure-browser:risk-level-change', handler);
    return () => window.removeEventListener('secure-browser:risk-level-change', handler);
  },
});


// Forward proctor push events from main process → page CustomEvents
ipcRenderer.on('proctor-status', (_event, data) => {
  window.dispatchEvent(
    new CustomEvent('secure-browser:proctor-status', { detail: data })
  );
});

ipcRenderer.on('proctor-error', (_event, data) => {
  window.dispatchEvent(
    new CustomEvent('secure-browser:proctor-status', { detail: data })
  );
});

// Forward risk engine push events from main process → page CustomEvents
ipcRenderer.on('risk-score-update', (_event, data) => {
  window.dispatchEvent(
    new CustomEvent('secure-browser:risk-score-update', { detail: data })
  );
});

ipcRenderer.on('risk-level-change', (_event, data) => {
  window.dispatchEvent(
    new CustomEvent('secure-browser:risk-level-change', { detail: data })
  );
});

// Forward submission-confirmed from main → page so overlay can show Close button
ipcRenderer.on('submission-confirmed', () => {
  window.dispatchEvent(new CustomEvent('secure-browser:submission-confirmed'));
});
