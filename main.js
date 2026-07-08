/**
 * main.js — Secure Assessment Browser
 *
 * Security features:
 *  - Fullscreen / kiosk lockdown  (re-entered automatically on exit)
 *  - Window always-on-top enforcement
 *  - Focus guard   → re-focuses window on blur, logs every violation
 *  - Close guard   → window cannot be closed without admin confirmation
 *  - Whitelist-only navigation (blocks any URL outside allowedDomains)
 *  - Blocks new-window / new-tab creation
 *  - DevTools disabled (menu-bar + keyboard shortcut + API level)
 *  - Context menu disabled (handled in preload)
 *  - Blocks file:// / blob:// / data:// schemes
 *  - globalShortcut intercepts Alt+F4, Ctrl+Esc, and the admin exit combo
 *  - Minimise / close buttons disabled (frame: false + closable: false)
 *  - Page Visibility API signal from preload triggers focus-recovery
 *  - Process monitor scans OS process list every N seconds and flags
 *    suspicious apps (screen share, remote access, other browsers, AI tools)
 *  - Environment checks: multi-monitor detection, display change watcher,
 *    single-instance enforcement, clipboard + WebRTC/screen-capture denial
 *
 * ════════════════════════════════════════════════════════════════════════════
 *  What is possible in pure Electron (no native modules)
 * ════════════════════════════════════════════════════════════════════════════
 *  ✅  Detect focus loss         → BrowserWindow 'blur' event
 *  ✅  Re-claim focus            → win.focus() + setAlwaysOnTop()
 *  ✅  Re-enter fullscreen       → 'leave-full-screen' + setFullScreen(true)
 *  ✅  Prevent window close      → 'close' event.preventDefault()
 *  ✅  Intercept Alt+F4          → globalShortcut.register('Alt+F4', ...)
 *  ✅  Intercept Ctrl+Esc        → globalShortcut.register('Control+Escape', ...)
 *  ✅  Log violations to disk    → fs.appendFileSync in FocusGuard
 *  ✅  Block in-page shortcuts   → preload.js keydown listener
 *
 * ════════════════════════════════════════════════════════════════════════════
 *  What REQUIRES native modules / OS policy
 * ════════════════════════════════════════════════════════════════════════════
 *  ❌  Alt+Tab         — OS-managed window switcher; cannot be globally
 *                        intercepted from user-space without a kernel-level
 *                        hook (e.g. uiohook-napi, requiring node-gyp build)
 *  ❌  Windows key     — Handled by explorer.exe; Electron cannot suppress it
 *  ❌  Ctrl+Shift+Esc  — Task Manager shortcut; OS-reserved
 *  ❌  PrintScreen     — Hardware scancode; needs low-level keyboard driver hook
 *
 *  For those, use Windows Group Policy, an MDM profile, or a kiosk OS image.
 *  Setting kiosk: true in config.json hides the taskbar, which reduces
 *  Alt+Tab and Windows-key surface significantly.
 */

'use strict';

// ─── Admin Mode Guard ─────────────────────────────────────────────────────────
// If the secure browser is launched with --admin flag or SECURE_BROWSER_ADMIN=1
// env variable, it must NOT start the locked-down student window.
// Admins use the separate admin-dashboard (Vite/React app) instead.
const IS_ADMIN_MODE =
  process.argv.includes('--admin') ||
  process.env.SECURE_BROWSER_ADMIN === '1';

if (IS_ADMIN_MODE) {
  console.log('[SecureBrowser] Admin mode detected — secure browser window suppressed.');
  console.log('[SecureBrowser] Please use the admin-dashboard application instead.');
  // Quit as soon as the app is ready (cannot call app.quit() before ready)
  const { app: _app } = require('electron');
  _app.whenReady().then(() => _app.quit());
}

const { app, BrowserWindow, screen, session, Menu, ipcMain, globalShortcut, dialog } = require('electron');
const path       = require('path');
const fs         = require('fs');
const http       = require('http');
const mime = {
  '.html': 'text/html; charset=utf-8',
  '.css':  'text/css',
  '.js':   'application/javascript',
  '.json': 'application/json',
  '.png':  'image/png',
  '.jpg':  'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif':  'image/gif',
  '.svg':  'image/svg+xml',
  '.ico':  'image/x-icon',
  '.woff': 'font/woff',
  '.woff2':'font/woff2',
  '.ttf':  'font/ttf',
  '.mp4':  'video/mp4',
};

// ─── Built-in static server for mock-exam ─────────────────────────────────────
const MOCK_EXAM_PORT = 3000;
const MOCK_EXAM_DIR  = path.join(__dirname, '..', 'mock-exam');

function startMockExamServer() {
  return new Promise((resolve, reject) => {
    const server = http.createServer((req, res) => {
      // Strip query string and decode
      let urlPath = req.url.split('?')[0];
      try { urlPath = decodeURIComponent(urlPath); } catch (_) {}

      // Default to index.html
      if (urlPath === '/' || urlPath === '') urlPath = '/index.html';

      const filePath = path.join(MOCK_EXAM_DIR, urlPath);

      // Security: stay inside MOCK_EXAM_DIR
      if (!filePath.startsWith(MOCK_EXAM_DIR)) {
        res.writeHead(403); res.end('Forbidden'); return;
      }

      fs.readFile(filePath, (err, data) => {
        if (err) {
          res.writeHead(404, { 'Content-Type': 'text/plain' });
          res.end('Not found');
          return;
        }
        const ext = path.extname(filePath).toLowerCase();
        res.writeHead(200, { 'Content-Type': mime[ext] || 'application/octet-stream' });
        res.end(data);
      });
    });

    server.listen(MOCK_EXAM_PORT, '127.0.0.1', () => {
      console.log(`[MockExamServer] Serving ${MOCK_EXAM_DIR} on http://127.0.0.1:${MOCK_EXAM_PORT}`);
      resolve(server);
    });
    server.on('error', reject);
  });
}
const FocusGuard       = require('./focus-guard');
const ProcessMonitor   = require('./process-monitor');
const BLOCKED_APPS     = require('./blocked-apps');
const EnvCheck         = require('./env-check');
const ProctorManager   = require('./proctor');
const ScreenMonitor    = require('./screen-monitor');
const { getLogger }    = require('./event-logger');
const SyncClient       = require('./sync-client');
const { RiskEngine }   = require('./risk-engine');
const NetworkGuard     = require('./network-guard');
const configManager    = require('./config-manager');
const firebaseClient   = require('./firebase/firebase-client');

process.on('uncaughtException', (error) => {
  console.error('[FATAL] Uncaught Exception:', error);
  fs.appendFileSync('crash.log', `[FATAL] Uncaught Exception: ${error.stack}\n`);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('[FATAL] Unhandled Rejection at:', promise, 'reason:', reason);
  fs.appendFileSync('crash.log', `[FATAL] Unhandled Rejection: ${reason}\n`);
});

// ─── Configuration Globals (Initialised in whenReady) ─────────────────────────
let ALLOWED_URL, ALLOWED_DOMAINS, ALLOWED_CDNS, NETWORK_GUARD_CFG;
let WINDOW_TITLE, USE_FULLSCREEN, USE_KIOSK, ADMIN_EXIT_SHORTCUT;
let REFOCUS_DELAY_MS, LOG_VIOLATIONS, PROCESS_MONITORING, PROCESS_CHECK_INTERVAL;
let BLOCK_MULTI_DISPLAY, ALLOW_CLIPBOARD, DISPLAY_CHECK_INTERVAL;
let PROCTORING_ENABLED, PROCTOR_INTERVAL_MS;
let HMAC_SECRET, SYNC_ENDPOINT, SYNC_API_KEY, SYNC_INTERVAL_MS;
let RISK_CONFIG;
let FIREBASE_CONFIG;
let SCREEN_MONITOR_ENABLED, SCREEN_MONITOR_CFG;

// ─── Close-guard flag ─────────────────────────────────────────────────────────
// Set to true only when an authorised exit is confirmed
let allowClose = false;

// ─── Wizard phase flag ────────────────────────────────────────────────────────
// true  → wizard is running; monitoring is NOT active; media permissions allowed
// false → lockdown applied; all security controls are live
let wizardPhase = true;
let wizardMediaAllowed = false;
let candidateIdentity  = null; // set during identity verification step

// ─── Helpers ──────────────────────────────────────────────────────────────────

/** Returns true when the URL belongs to a whitelisted domain or is a local file. */
function isAllowed(urlString) {
  try {
    const { hostname, protocol } = new URL(urlString);
    // Always allow local file:// loads (wizard HTML, error page, etc.)
    if (protocol === 'file:') return true;
    if (!['https:', 'http:'].includes(protocol)) return false;
    const allowed = configManager.getValue('exam.allowedDomains', []);
    return allowed.some(domain =>
      hostname === domain || hostname.endsWith('.' + domain)
    );
  } catch {
    return false;
  }
}

// ─── Application bootstrap ────────────────────────────────────────────────────

// Remove default application menu (eliminates View → Developer Tools)
Menu.setApplicationMenu(null);

let mainWindow;
let focusGuard;
let processMonitor;
let envCheck;
let proctorManager;
let screenMonitor;
let syncClient;
let riskEngine;
let networkGuard;

// Event logger is instantiated later once config is loaded
let eventLogger;

// ─── Single-instance lock ─────────────────────────────────────────────────────
// Prevents a second instance of the app from launching.
// If someone tries to open a second window (e.g. to cheat via a second session),
// the second instance quits immediately and the first instance regains focus.
const gotSingleInstanceLock = app.requestSingleInstanceLock();
if (!gotSingleInstanceLock) {
  console.error('[SecureBrowser] Another instance is already running — quitting.');
  app.quit();
}

app.on('second-instance', () => {
  // A second instance was launched — bring the first one to front
  if (mainWindow) {
    if (mainWindow.isMinimized()) mainWindow.restore();
    mainWindow.focus();
    if (USE_FULLSCREEN) mainWindow.setFullScreen(true);
  }
});

function createWindow() {
  console.log('[Debug] Entering createWindow');

  // During wizard phase: no fullscreen/kiosk/alwaysOnTop so that OS permission
  // dialogs (camera, mic) can appear above the browser window.
  mainWindow = new BrowserWindow({
    title:        WINDOW_TITLE,
    fullscreen:   false,          // wizard step 4 enters fullscreen explicitly
    kiosk:        false,          // activated in enterLockdown()
    resizable:    false,
    movable:      false,
    minimizable:  false,
    maximizable:  false,
    closable:     false,
    frame:        false,
    show:         false,
    alwaysOnTop:  false,          // must be false so permission dialogs appear
    backgroundColor: '#07071a',

    webPreferences: {
      preload:                    path.join(__dirname, 'launch-preload.js'),
      contextIsolation:           true,
      nodeIntegration:            false,
      sandbox:                    true,
      devTools:                   false,
      webviewTag:                 false,
      allowRunningInsecureContent: false,
      navigateOnDragDrop:         false,
    },
  });

  // FocusGuard, RiskEngine, ProcessMonitor are NOT started here.
  // They are deferred to enterLockdown() (wizard step 7) so they don't
  // interfere with the permission-requesting wizard steps.

  // ── Prevent window from being closed without admin confirmation ───────────
  mainWindow.on('close', async (event) => {
    if (allowClose) return; // authorised exit — let it through

    event.preventDefault(); // block the close
    focusGuard?.getViolations?.();  // null-safe: focusGuard is null until lockdown
    eventLogger.logCloseAttempt();

    // The window may have lost focus while the dialog is shown;
    // setAlwaysOnTop keeps us visible above the OS close dialog.
    const { response } = await dialog.showMessageBox(mainWindow, {
      type:    'warning',
      title:   'Exit Secure Browser',
      message: 'Are you sure you want to close the secure browser?\nThis will end the assessment session.',
      buttons: ['Cancel', 'Exit (Admin)'],
      defaultId: 0,
      cancelId:  0,
    });

    if (response === 1) {
      cleanExit();
    } else {
      // Candidate tried to close — re-claim focus immediately
      mainWindow.focus();
      if (USE_FULLSCREEN) mainWindow.setFullScreen(true);
    }
  });

  // ── Disable DevTools via event (belt-and-suspenders with devTools:false) ──
  mainWindow.webContents.on('devtools-opened', () => {
    mainWindow.webContents.closeDevTools();
  });

  // ── Show window gracefully ────────────────────────────────────────────────
  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
    // During wizard phase: show centred at a reasonable size (not fullscreen)
    // so OS permission dialogs can appear above the window.
    if (wizardPhase) {
      mainWindow.setSize(960, 720);
      mainWindow.center();
    } else {
      mainWindow.setAlwaysOnTop(true, 'screen-saver');
      if (USE_FULLSCREEN) mainWindow.setFullScreen(true);
    }
    envCheck.startWatching();
    // Proctoring is deferred to enterLockdown() (wizard step 7).
  });


  envCheck.on('display-change', ({ type, count, displays }) => {
    console.warn(`[SecureBrowser] Display change event: ${type}, total=${count}`);
    eventLogger.logDisplayChange({ type, count, displayCount: displays?.length });
    if (mainWindow && !mainWindow.isDestroyed()) {
      envCheck.on('display-change', (change) => {
        if (change.type === 'DISPLAY_ADDED' && BLOCK_MULTI_DISPLAY) {
          eventLogger.logIntegrityEvent('MULTIPLE_DISPLAYS_DETECTED');
          riskEngine.addEvent('MULTIPLE_DISPLAYS', 'CRITICAL');
        }
      });
      mainWindow.webContents.send('env-violation', {
        type:    'MULTIPLE_DISPLAYS_MID_EXAM',
        message: `${count} monitors detected mid-exam. Please disconnect the extra display.`,
        count,
      });
    }
  });

  envCheck.on('display-metrics-changed', ({ changedMetrics }) => {
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('display-metrics-changed', { changedMetrics });
    }
  });

  // ── Block ALL new-window / new-tab creation ───────────────────────────────
  mainWindow.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));

  // ── Navigation whitelist ─────────────────────────────────────────────────
  mainWindow.webContents.on('will-navigate', (event, url) => {
    if (!isAllowed(url)) {
      console.warn(`[SecureBrowser] Blocked navigation → ${url}`);
      eventLogger.logNavBlocked(url, { trigger: 'will-navigate' });
      event.preventDefault();
    }
  });

  mainWindow.webContents.on('will-redirect', (event, url) => {
    if (!isAllowed(url)) {
      console.warn(`[SecureBrowser] Blocked redirect → ${url}`);
      eventLogger.logNavBlocked(url, { trigger: 'will-redirect' });
      event.preventDefault();
    }
  });

  mainWindow.webContents.on('did-navigate', (_event, url) => {
    if (!isAllowed(url)) mainWindow.webContents.loadURL(ALLOWED_URL);
  });

  mainWindow.webContents.on('will-frame-navigate', (event, details) => {
    if (details.isMainFrame && !isAllowed(details.url)) event.preventDefault();
  });

  // ── Handle load failures (e.g. assessment server not running) ────────────
  mainWindow.webContents.on('did-fail-load', (_event, errorCode, errorDescription, validatedURL) => {
    // ERR_ABORTED (-3) fires on every navigation cancel (e.g. redirect), ignore it
    if (errorCode === -3) return;
    // Avoid infinite loop if the error page itself fails
    if (validatedURL && validatedURL.startsWith('data:')) return;
    // During wizard phase, file:// loads can fail transiently — skip error page
    if (validatedURL && validatedURL.startsWith('file:')) return;
    console.error(`[SecureBrowser] Failed to load ${validatedURL}: ${errorDescription} (${errorCode})`);
    const friendly = `
      <!DOCTYPE html><html><head><meta charset="utf-8">
      <title>Connection Error</title>
      <style>
        body { margin:0; display:flex; flex-direction:column; align-items:center;
               justify-content:center; height:100vh; background:#1a1a2e;
               color:#e0e0e0; font-family:sans-serif; text-align:center; }
        h1   { color:#ff6b6b; font-size:2rem; margin-bottom:.5rem; }
        p    { color:#aaa; max-width:500px; line-height:1.6; }
        code { background:#2a2a4a; padding:4px 10px; border-radius:4px;
               color:#6ec6ff; font-size:.95rem; }
        button { margin-top:2rem; padding:10px 28px; background:#6ec6ff;
                 color:#1a1a2e; border:none; border-radius:8px;
                 font-size:1rem; cursor:pointer; font-weight:600; }
        button:hover { background:#90d8ff; }
      </style></head><body>
      <h1>⚠ Cannot reach the assessment server</h1>
      <p>The URL <code>${validatedURL || ALLOWED_URL}</code> could not be loaded.<br>
         Make sure the assessment server is running and reachable, then retry.</p>
      <p style="color:#666;font-size:.85rem;">Error: ${errorDescription} (${errorCode})</p>
      <button onclick="window.__retryLoad()">Retry</button>
      <script>
        window.__retryLoad = function() {
          // Use the safe IPC bridge exposed by preload.js via contextBridge
          if (window.secureBrowser && typeof window.secureBrowser.retryLoad === 'function') {
            window.secureBrowser.retryLoad();
          }
        };
      </script>
      </body></html>`;
    mainWindow.webContents.loadURL(`data:text/html;charset=utf-8,${encodeURIComponent(friendly)}`);

  });

  // ── Load the wizard (exam URL is loaded after lockdown in step 8) ─────────
  mainWindow.loadFile(path.join(__dirname, 'launch-wizard.html'));
}

// ─── activateLockdown — called by wizard:enter-lockdown IPC ────────────────────
// Sets up all security controls that were deferred from createWindow().
function activateLockdown() {
  wizardPhase        = false;
  wizardMediaAllowed = false;

  // Restore locked-down permission handler (deny media again)
  const ALLOWED_PERMISSIONS = ['fullscreen'];
  if (ALLOW_CLIPBOARD) ALLOWED_PERMISSIONS.push('clipboard-read', 'clipboard-write');
  session.defaultSession.setPermissionRequestHandler((_wc, permission, callback) => {
    callback(ALLOWED_PERMISSIONS.includes(permission));
  });
  session.defaultSession.setPermissionCheckHandler((_wc, permission) =>
    ALLOWED_PERMISSIONS.includes(permission)
  );

  // ── FocusGuard ───────────────────────────────────────────────────────────
  focusGuard = new FocusGuard(mainWindow, {
    fullscreen:     USE_FULLSCREEN,
    refocusDelayMs: REFOCUS_DELAY_MS,
    logViolations:  LOG_VIOLATIONS,
  });
  focusGuard.start();
  mainWindow.on('blur',  () => eventLogger.logFocusLoss());
  mainWindow.on('focus', () => eventLogger.logFocusRestored());

  // ── RiskEngine ───────────────────────────────────────────────────────────
  riskEngine = new RiskEngine(RISK_CONFIG);
  eventLogger.on('event', (event) => {
    const entry = riskEngine.ingest(event);
    if (entry.points !== 0 && mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('risk-score-update', entry);
    }
  });
  riskEngine.on('level-change', (change) => {
    console.warn(`[RiskEngine] Level change: ${change.from} → ${change.to} (score=${change.score})`);
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('risk-level-change', change);
    }
    if (change.action === 'TERMINATE' && RISK_CONFIG.autoTerminate) {
      eventLogger.log('SESSION_END', 'CRITICAL', 'risk-engine', {
        trigger: 'auto-terminate', score: change.score, reason: change.reason,
      });
      cleanExit();
    }
  });
  riskEngine.start();
  firebaseClient.setRiskEngine(riskEngine);

  // ── ProcessMonitor ───────────────────────────────────────────────────────
  if (PROCESS_MONITORING) {
    processMonitor = new ProcessMonitor(BLOCKED_APPS, {
      intervalMs: PROCESS_CHECK_INTERVAL,
      logAlerts:  LOG_VIOLATIONS,
    });
    processMonitor.on('alert', ({ alerts }) => {
      alerts.forEach(a => eventLogger.logProcessDetected(a));
      if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('process-alert', alerts);
    });
    processMonitor.on('resolved', ({ resolved }) => {
      resolved.forEach(r => eventLogger.logProcessResolved(r));
      if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('process-resolved', resolved);
    });
    processMonitor.on('error', ({ error }) => console.error('[ProcessMonitor] error:', error.message));
    processMonitor.start();
  }

  // ── ProctorManager ───────────────────────────────────────────────────────
  if (PROCTORING_ENABLED) {
    proctorManager = new ProctorManager({ proctoring: true, proctorIntervalMs: PROCTOR_INTERVAL_MS });
    proctorManager.on('status', (data) => {
      eventLogger.logFaceStatus(data.status, data.faceCount, { timestamp: data.timestamp });
      if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('proctor-status', data);
    });
    proctorManager.on('error', (data) => {
      const isCameraError = data.status === 'CAMERA_ERROR' || data.phase === 'camera';
      eventLogger.log('FACE_ERROR', 'CRITICAL', 'proctor', {
        ...data, phase: isCameraError ? 'camera' : (data.phase || 'detection'),
      });
      if (riskEngine) {
        const entry = riskEngine.ingest({
          type:'FACE_ERROR', severity:'CRITICAL', source:'proctor',
          timestamp: data.timestamp || new Date().toISOString(),
          metadata: { phase: isCameraError ? 'camera' : 'detection', status: data.status },
        });
        if (entry.points !== 0 && mainWindow && !mainWindow.isDestroyed())
          mainWindow.webContents.send('risk-score-update', entry);
      }
      if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('proctor-error', { ...data, isCameraError });
    });
    proctorManager.start();
  }

  // ── Window lockdown ──────────────────────────────────────────────────────
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.setResizable(false);
    mainWindow.setAlwaysOnTop(true, 'screen-saver');
    if (USE_FULLSCREEN) mainWindow.setFullScreen(true);
    if (USE_KIOSK)      mainWindow.setKiosk(true);
  }

  // ── Screen Monitor (AI proctoring) ───────────────────────────────────────
  // Uses Electron's desktopCapturer — runs in main process, invisible to the
  // candidate, completely independent of the blocked web getDisplayMedia API.
  if (SCREEN_MONITOR_ENABLED) {
    const uploadToFirebase = SCREEN_MONITOR_CFG.uploadToFirebase !== false;

    screenMonitor = new ScreenMonitor({
      intervalMs:    SCREEN_MONITOR_CFG.intervalMs    ?? 30_000,
      thumbWidth:    SCREEN_MONITOR_CFG.thumbWidth    ?? 1280,
      thumbHeight:   SCREEN_MONITOR_CFG.thumbHeight   ?? 720,
      maxLocalFiles: SCREEN_MONITOR_CFG.maxLocalFiles ?? 120,

      onCapture: async (capture) => {
        // Log to audit trail
        eventLogger.log('SCREEN_CAPTURED', 'INFO', 'screen-monitor', {
          index:       capture.index,
          timestamp:   capture.timestamp,
          displayName: capture.displayName,
          filePath:    capture.filePath,
        });

        // Notify renderer (for HUD / admin panel if needed)
        if (mainWindow && !mainWindow.isDestroyed()) {
          mainWindow.webContents.send('screen-capture', {
            index:     capture.index,
            timestamp: capture.timestamp,
          });
        }

        // Push to Firebase Firestore
        if (uploadToFirebase) {
          firebaseClient.uploadScreenCapture(capture).catch(() => {});
        }
      },
    });

    screenMonitor.on('error', ({ error, timestamp }) => {
      console.warn('[ScreenMonitor] Capture error:', error);
      eventLogger.log('SCREEN_CAPTURE_ERROR', 'WARN', 'screen-monitor', { error, timestamp });
    });

    screenMonitor.start();
    console.info('[ScreenMonitor] AI screen monitoring active.');
  }

  console.info('[SecureBrowser] Lockdown activated — all security controls live.');
}


// ─── Global shortcut registration ────────────────────────────────────────────

function registerGlobalShortcuts() {
  //
  // ── Alt+F4 ────────────────────────────────────────────────────────────────
  // Electron's globalShortcut CAN intercept Alt+F4 on Windows before the
  // WM_SYSCOMMAND/SC_CLOSE message is processed by the window.
  //
  tryRegister('Alt+F4', () => {
    console.warn('[SecureBrowser] Alt+F4 intercepted — blocked');
    if (focusGuard) focusGuard.getViolations(); // violations already logged by guard
    // Re-focus so the candidate cannot alt-tab away after pressing Alt+F4
    if (mainWindow && !mainWindow.isDestroyed()) mainWindow.focus();
  });

  //
  // ── Ctrl+Esc (opens Windows Start menu) ──────────────────────────────────
  // globalShortcut can register this, but whether it suppresses the Start
  // menu depends on whether Windows lets user-space apps intercept it.
  // On most standard Windows installs this WILL suppress the Start menu.
  //
  tryRegister('Control+Escape', () => {
    console.warn('[SecureBrowser] Ctrl+Esc intercepted — blocked');
    if (mainWindow && !mainWindow.isDestroyed()) mainWindow.focus();
  });

  //
  // ── Admin exit combo (configurable in config.json) ───────────────────────
  // Default: Ctrl+Alt+Q
  // A proctor who is physically present can press this to confirm exit.
  //
  tryRegister(ADMIN_EXIT_SHORTCUT, async () => {
    if (!mainWindow || mainWindow.isDestroyed()) return;

    const { response } = await dialog.showMessageBox(mainWindow, {
      type:      'question',
      title:     'Admin Exit',
      message:   `Exit the Secure Browser?\n\nViolations recorded: ${focusGuard?.getCount() ?? 0}`,
      detail:    `Log file: ${focusGuard?.getLogPath() ?? 'N/A'}`,
      buttons:   ['Cancel', 'Confirm Exit'],
      defaultId: 0,
      cancelId:  0,
    });

    if (response === 1) {
      cleanExit();
    }
  });
}

/**
 * Restore the OS desktop state and quit cleanly.
 *
 * Must be called instead of bare app.quit() everywhere so that Windows
 * always gets back focus, fullscreen is exited, and the taskbar /
 * Alt+Tab switcher are usable again after the secure browser closes.
 */
async function cleanExit() {
  // Guard: prevent double-exit (server-side timeout + renderer IPC can both fire)
  if (cleanExit._called) return;
  cleanExit._called = true;

  // 1. Unregister all global shortcuts first so they stop intercepting
  //    key presses immediately (e.g. Ctrl+Alt+Q, Alt+F4 polyfill).
  globalShortcut.unregisterAll();

  // 2. Restore window state before destroying it.
  //    On Windows, destroying a window that still has alwaysOnTop=TOPMOST
  //    or is in fullscreen/kiosk can leave the desktop in a broken state
  //    where Alt+Tab, the taskbar, and other windows are inaccessible.
  if (mainWindow && !mainWindow.isDestroyed()) {
    try {
      mainWindow.setAlwaysOnTop(false);
      if (USE_KIOSK)      mainWindow.setKiosk(false);
      if (USE_FULLSCREEN) mainWindow.setFullScreen(false);
    } catch (_) { /* window may already be closing */ }
  }

  allowClose = true;

  // Explicitly destroy the window before app.quit().
  // On Windows, closable:false can prevent app.quit() from closing the window
  // via the normal close-event path, so we force-destroy it here.
  if (mainWindow && !mainWindow.isDestroyed()) {
    try { mainWindow.destroy(); } catch (_) {}
  }

  app.quit();
}

/**
 * Safely attempt to register a global shortcut.
 * Logs a warning instead of throwing if the shortcut is already taken
 * by another app or is OS-reserved.
 */
function tryRegister(shortcut, handler) {
  try {
    const ok = globalShortcut.register(shortcut, handler);
    if (!ok) console.warn(`[SecureBrowser] Could not register shortcut: ${shortcut} (already claimed by OS or another app)`);
  } catch (err) {
    console.warn(`[SecureBrowser] Error registering shortcut ${shortcut}:`, err.message);
  }
}

// ─── App lifecycle ────────────────────────────────────────────────────────────

app.whenReady().then(async () => {
  // Admin mode: already handled above — skip everything
  if (IS_ADMIN_MODE) return;
  // ── Load configuration asynchronously ──────────────────────────────────────
  const configPath = path.join(__dirname, 'config.json');
  await configManager.load(configPath);

  ALLOWED_URL            = configManager.getValue('exam.allowedUrl');
  ALLOWED_DOMAINS        = configManager.getValue('exam.allowedDomains', []);
  ALLOWED_CDNS           = configManager.getValue('exam.allowedCDNs', []);
  NETWORK_GUARD_CFG      = configManager.get('networkGuard') || {};
  WINDOW_TITLE           = configManager.getValue('general.windowTitle');
  USE_FULLSCREEN         = configManager.getValue('general.fullscreen');
  USE_KIOSK              = configManager.getValue('general.kiosk');
  ADMIN_EXIT_SHORTCUT    = configManager.getValue('general.adminExitShortcut');
  REFOCUS_DELAY_MS       = configManager.getValue('general.refocusDelayMs');
  LOG_VIOLATIONS         = configManager.getValue('general.logViolations');
  PROCESS_MONITORING     = configManager.getValue('security.processMonitoring');
  PROCESS_CHECK_INTERVAL = configManager.getValue('security.processCheckIntervalMs');
  BLOCK_MULTI_DISPLAY    = configManager.getValue('security.blockMultipleDisplays');
  ALLOW_CLIPBOARD        = configManager.getValue('security.allowClipboard');
  DISPLAY_CHECK_INTERVAL = configManager.getValue('security.displayCheckIntervalMs');
  PROCTORING_ENABLED     = configManager.getValue('proctoring.enabled');
  PROCTOR_INTERVAL_MS    = configManager.getValue('proctoring.intervalMs');
  HMAC_SECRET            = configManager.getValue('sync.hmacSecret');
  SYNC_ENDPOINT          = configManager.getValue('sync.endpoint');
  SYNC_API_KEY           = configManager.getValue('sync.apiKey');
  SYNC_INTERVAL_MS       = configManager.getValue('sync.intervalMs');
  RISK_CONFIG            = configManager.get('riskScoring') || {};
  FIREBASE_CONFIG        = configManager.get('firebase') || null;
  SCREEN_MONITOR_CFG     = configManager.get('screenMonitoring') || {};
  SCREEN_MONITOR_ENABLED = SCREEN_MONITOR_CFG.enabled !== false;

  // ── Initialize audit logger ───────────────────────────────────────────────
  eventLogger = getLogger({ hmacSecret: HMAC_SECRET });
  eventLogger.init();

  // ── Initialize Firebase (if credentials are configured) ───────────────────
  if (FIREBASE_CONFIG && FIREBASE_CONFIG.projectId && !FIREBASE_CONFIG.projectId.startsWith('your-')) {
    try {
      firebaseClient.init(FIREBASE_CONFIG);

      // Start pushing audit logs to Firestore every 15 s
      firebaseClient.startLogSync(eventLogger, 15_000);

      firebaseClient.on('synced',      ({ count }) => console.info(`[Firebase] Synced ${count} log events`));
      firebaseClient.on('sync-failed', ({ error }) => console.warn('[Firebase] Sync failed:', error));

      // Subscribe to live exam config changes from the admin dashboard.
      // When the proctor saves changes (allowedDomains, proctoring toggle, pause)
      // those changes propagate here in real time and update the running config.
      firebaseClient.listenToExamConfig((remoteConfig) => {
        console.info('[Firebase] Live exam config received:', Object.keys(remoteConfig).join(', '));

        // Sync allowed domains/CDNs into configManager so NetworkGuard updates
        if (Array.isArray(remoteConfig.allowedDomains)) {
          configManager.update({ exam: { allowedDomains: remoteConfig.allowedDomains } });
        }
        if (Array.isArray(remoteConfig.allowedCdns)) {
          configManager.update({ exam: { allowedCDNs: remoteConfig.allowedCdns } });
        }

        // Proctor paused the exam — show hold overlay in renderer
        if (typeof remoteConfig.paused === 'boolean' && mainWindow && !mainWindow.isDestroyed()) {
          mainWindow.webContents.send('exam-paused', { paused: remoteConfig.paused });
        }

        // Proctor terminated the exam remotely
        if (remoteConfig.terminated === true) {
          console.warn('[Firebase] Remote termination received — ending session');
          eventLogger.logAdminAction('REMOTE_TERMINATE', { trigger: 'admin-dashboard' });
          cleanExit();
        }
      });

      console.info('[Firebase] Connected and log sync started');
    } catch (err) {
      // Firebase failure must never crash the browser — exam continues offline
      console.error('[Firebase] Initialization failed (exam continues offline):', err.message);
    }
  } else {
    console.info('[Firebase] No credentials configured — running in offline mode');
  }

  // ── Initialize sync client (no-op if no endpoint configured) ─────────────
  syncClient = new SyncClient(eventLogger, {
    endpoint:      SYNC_ENDPOINT,
    hmacSecret:    HMAC_SECRET,
    apiKey:        SYNC_API_KEY,
    syncIntervalMs: SYNC_INTERVAL_MS,
  });
  syncClient.on('synced',      ({ count }) => console.info(`[SyncClient] Synced ${count} events`));
  syncClient.on('sync-failed', ({ count }) => console.warn(`[SyncClient] Failed to sync ${count} events`));
  syncClient.on('offline',     ()          => console.info('[SyncClient] Offline — will retry later'));
  syncClient.start();

  // ── Network request filtering & headers (NetworkGuard) ───────────────────
  networkGuard = new NetworkGuard({
    allowedDomains: ALLOWED_DOMAINS,
    allowedCDNs:    ALLOWED_CDNS,
    ...NETWORK_GUARD_CFG,
    onBlocked: (details) => eventLogger.logRequestBlocked(details),
  });
  networkGuard.attach(session.defaultSession);

  // ── Permission policy ─────────────────────────────────────────────────────
  //
  // Deny all permissions by default; allow only what the assessment requires.
  //
  // ┌─────────────────────────┬──────────────────────────────────────────────┐
  // │ Permission              │ Why denied / allowed                         │
  // ├─────────────────────────┼──────────────────────────────────────────────┤
  // │ media (camera/mic)      │ DENIED — prevents WebRTC screen/audio share  │
  // │ display-capture         │ DENIED — blocks getDisplayMedia() calls      │
  // │ clipboard-read/write    │ DENIED by default (allow via config)         │
  // │ notifications           │ DENIED — distraction risk                    │
  // │ geolocation             │ DENIED — not needed for assessments          │
  // │ fullscreen              │ ALLOWED — needed by assessment platform UI   │
  // └─────────────────────────┴──────────────────────────────────────────────┘
  //
  // ⚠️  LIMITATION: This denies the JS-level API permission prompt. A native
  //     screen-capture application (OBS, Snipping Tool, RDP) bypasses
  //     Chromium's permission system entirely and cannot be blocked here.
  //     Use the process monitor for that threat.
  //
  const ALLOWED_PERMISSIONS = [
    'fullscreen',
    // Add 'media' here ONLY if your assessment platform uses live proctoring
  ];
  if (ALLOW_CLIPBOARD) {
    ALLOWED_PERMISSIONS.push('clipboard-read', 'clipboard-write');
  }

  session.defaultSession.setPermissionRequestHandler((_wc, permission, callback) => {
    // During wizard phase steps 1–2, temporarily allow media so getUserMedia works
    if (wizardMediaAllowed && permission === 'media') {
      callback(true);
      return;
    }
    const granted = ALLOWED_PERMISSIONS.includes(permission);
    if (!granted) console.warn(`[SecureBrowser] Permission denied: ${permission}`);
    callback(granted);
  });

  // Also deny permission checks (synchronous, no prompt shown)
  session.defaultSession.setPermissionCheckHandler((_wc, permission) => {
    if (wizardMediaAllowed && permission === 'media') return true;
    return ALLOWED_PERMISSIONS.includes(permission);
  });

  // ── Initialise EnvCheck ───────────────────────────────────────────────────
  envCheck = new EnvCheck({
    blockMultipleDisplays: BLOCK_MULTI_DISPLAY,
    watchDisplayChanges:   true,
  });

  // ── Pre-launch environment gate ───────────────────────────────────────────
  if (BLOCK_MULTI_DISPLAY) {
    const { passed, failures } = envCheck.runPreLaunchChecks();
    if (!passed) {
      dialog.showErrorBox('Environment Check Failed', failures.join('\n\n') + '\n\nDisconnect the extra monitor and restart the Secure Browser.');
      app.quit();
      return;
    }
  }

  // ── Runtime Config Updaters ───────────────────────────────────────────────
  configManager.on('update:exam.allowedDomains', () => {
    if (networkGuard) networkGuard.updateDomains(
      configManager.getValue('exam.allowedDomains', []),
      configManager.getValue('exam.allowedCDNs', [])
    );
  });
  
  configManager.on('update:exam.allowedCDNs', () => {
    if (networkGuard) networkGuard.updateDomains(
      configManager.getValue('exam.allowedDomains', []),
      configManager.getValue('exam.allowedCDNs', [])
    );
  });

  configManager.on('update:proctoring.enabled', (enabled) => {
    if (!proctorManager) return;
    if (enabled) proctorManager.start();
    else proctorManager.stop();
  });

  configManager.on('update:security.processMonitoring', (enabled) => {
    if (!processMonitor) return;
    if (enabled) processMonitor.start();
    else processMonitor.stop();
  });

  // ── Start the mock exam static server ────────────────────────────────────
  try {
    await startMockExamServer();
  } catch (err) {
    console.warn(`[MockExamServer] Could not start on port ${MOCK_EXAM_PORT}: ${err.message}`);
  }

  // ── Wizard IPC handlers ──────────────────────────────────────────────────

  // Step 1 & 2 — Allow OS media permission dialog
  ipcMain.handle('wizard:enable-media', () => {
    wizardMediaAllowed = true;
    console.info('[Wizard] Media permissions enabled for wizard phase');
    return { ok: true };
  });

  // Step 3 — Screen recording policy acknowledged
  ipcMain.handle('wizard:confirm-screen', () => ({ ok: true }));

  // Steps 1 & 2 — Open Windows Privacy Settings for camera or microphone
  // Uses ms-settings: URI scheme (Windows 10/11 only). Safe to call from renderer
  // because shell.openExternal is restricted to known-safe URI schemes here.
  ipcMain.handle('wizard:open-privacy-settings', (_e, type) => {
    const { shell } = require('electron');
    const uriMap = {
      camera:      'ms-settings:privacy-webcamera',
      microphone:  'ms-settings:privacy-microphone',
    };
    const uri = uriMap[type];
    if (uri) shell.openExternal(uri).catch(() => {});
    return { ok: !!uri };
  });

  // Step 6 — Kill a specific suspicious process by name so the candidate can
  // close it without leaving the wizard to find it themselves in Task Manager.
  // Only allowed during the wizard phase (before lockdown).
  ipcMain.handle('wizard:kill-process', (_e, processName) => {
    if (!wizardPhase) return { ok: false, error: 'Not in wizard phase' };

    // Sanitise: only allow simple filenames (no path separators, no shell chars)
    if (!processName || !/^[\w.\- ]+$/i.test(processName)) {
      return { ok: false, error: 'Invalid process name' };
    }

    return new Promise((resolve) => {
      const { execFile } = require('child_process');
      if (process.platform === 'win32') {
        // /F = force, /IM = image name, /T = also kill child processes
        execFile(
          'taskkill', ['/F', '/IM', processName, '/T'],
          { timeout: 5000, windowsHide: true },
          (err, stdout, stderr) => {
            if (err) {
              const msg = (stderr || err.message || '').trim();
              console.warn(`[Wizard] taskkill "${processName}" failed: ${msg}`);
              resolve({ ok: false, error: msg });
            } else {
              console.info(`[Wizard] Killed process: ${processName}`);
              resolve({ ok: true });
            }
          }
        );
      } else {
        // macOS / Linux fallback — killall by name
        execFile('killall', ['-9', processName.replace(/\.exe$/i, '')],
          { timeout: 5000 },
          (err) => resolve(err ? { ok: false, error: err.message } : { ok: true })
        );
      }
    });
  });

  // Step 4 — Enter fullscreen for the wizard window
  // We must wait for the actual 'enter-full-screen' event before resolving so
  // the renderer knows fullscreen genuinely took effect. On Windows, setFullScreen(true)
  // is asynchronous — the window goes through a transition before it reports isFullScreen().
  // We also clear the manual size / position set during the wizard so Windows lets the
  // window expand to the full display bounds.
  ipcMain.handle('wizard:enter-fullscreen', () => {
    if (!mainWindow || mainWindow.isDestroyed()) return { ok: false };

    // Already fullscreen — nothing to do
    if (mainWindow.isFullScreen()) return { ok: true };

    return new Promise((resolve) => {
      const TIMEOUT_MS = 3000;
      let settled = false;

      function onEnter() {
        if (settled) return;
        settled = true;
        mainWindow.removeListener('enter-full-screen', onEnter);
        clearTimeout(timer);
        resolve({ ok: true });
      }

      // Safety-net: if the OS never fires the event, resolve anyway after timeout
      const timer = setTimeout(() => {
        if (settled) return;
        settled = true;
        mainWindow.removeListener('enter-full-screen', onEnter);
        resolve({ ok: mainWindow.isFullScreen() });
      }, TIMEOUT_MS);

      mainWindow.once('enter-full-screen', onEnter);

      // On Windows, a window with explicit size/position set via setSize()/center()
      // must have those constraints cleared before setFullScreen(true) will work.
      try {
        mainWindow.setResizable(true);   // temporarily allow resize so fullscreen can expand
        mainWindow.setFullScreen(true);
      } catch (err) {
        settled = true;
        clearTimeout(timer);
        mainWindow.removeListener('enter-full-screen', onEnter);
        resolve({ ok: false, error: err.message });
      }
    });
  });

  // Step 5 — Save candidate identity to userData and audit log
  ipcMain.handle('wizard:submit-identity', (_e, data) => {
    candidateIdentity = { name: data.name, examId: data.examId, capturedAt: new Date().toISOString() };
    const identityPath = path.join(app.getPath('userData'), 'identity.json');
    try {
      fs.writeFileSync(identityPath, JSON.stringify(candidateIdentity, null, 2));
    } catch (err) {
      console.warn('[Wizard] Could not save identity.json:', err.message);
    }
    eventLogger.log('SESSION_START', 'INFO', 'wizard', {
      candidateName: data.name,
      examId:        data.examId,
      hasPhoto:      !!data.photoDataUrl,
    });
    console.info(`[Wizard] Identity recorded: ${data.name} (${data.examId})`);
    return { ok: true };
  });

  // Step 6 — Run one-shot security checks
  ipcMain.handle('wizard:run-security-check', async () => {
    const checks = [];

    // 1. Display check
    const displayResult = envCheck ? envCheck.runPreLaunchChecks() : { passed: true, failures: [] };
    checks.push({
      id: 'disp', label: 'Display Configuration',
      passed: displayResult.passed,
      message: displayResult.passed ? 'Single display detected' : displayResult.failures[0],
    });

    // 2. Process scan (Windows: tasklist, others: ps)
    try {
      const { execFile } = require('child_process');
      const runningNames = await new Promise((resolve, reject) => {
        const cmd  = process.platform === 'win32' ? 'tasklist' : 'ps';
        const args = process.platform === 'win32' ? ['/FO', 'CSV', '/NH'] : ['-eo', 'comm'];
        execFile(cmd, args, { timeout: 8000, windowsHide: true }, (err, stdout) => {
          if (err) return reject(err);
          const names = new Set();
          for (const line of stdout.split(/\r?\n/)) {
            const m = line.match(/^"?([^,"\r\n]+)/);
            if (m) names.add(m[1].toLowerCase().trim());
          }
          resolve(names);
        });
      });
      const found = BLOCKED_APPS.filter(a => runningNames.has(a.name.toLowerCase()));
      checks.push({
        id: 'proc', label: 'Suspicious Applications',
        passed: found.length === 0,
        message: found.length === 0
          ? 'No suspicious processes detected'
          : `Please close: ${found.map(a => a.name).join(', ')}`,
      });
    } catch {
      checks.push({ id:'proc', label:'Suspicious Applications', passed:true, message:'Process scan unavailable' });
    }

    // 3. Network / Firebase reachability
    let netOk = true;
    try {
      await require('dns').promises.lookup('firestore.googleapis.com');
    } catch { netOk = false; }
    checks.push({
      id:'net', label:'Network Connectivity',
      passed: netOk,
      message: netOk ? 'Exam server reachable' : 'Cannot reach exam server — check your internet connection',
    });

    // 4 & 5 — Camera & mic are verified by the renderer in steps 1–2
    checks.push({ id:'cam', label:'Camera Access',     passed:true, message:'Camera verified in step 1' });
    checks.push({ id:'mic', label:'Microphone Access', passed:true, message:'Microphone verified in step 2' });

    const allPassed = checks.every(c => c.passed !== false);
    return { checks, allPassed };
  });

  // Step 7 — Activate all security controls
  ipcMain.handle('wizard:enter-lockdown', async () => {
    activateLockdown();
    return { ok: true };
  });

  // Step 8 — Swap preload and load the exam URL
  ipcMain.handle('wizard:launch-exam', () => {
    if (mainWindow && !mainWindow.isDestroyed()) {
      // Switch to the exam preload before loading the exam URL
      mainWindow.webContents.session.setPreloads([path.join(__dirname, 'preload.js')]);
      mainWindow.loadURL(ALLOWED_URL);
    }
    return { ok: true };
  });

  // ── End wizard IPC handlers ──────────────────────────────────────────────

  registerGlobalShortcuts();
  createWindow();
  // riskEngine is null here (deferred to lockdown) — setRiskEngine is called
  // inside activateLockdown() instead.
});

// ─── Prevent additional windows ───────────────────────────────────────────────
// Allow the hidden proctor window; destroy anything else.
app.on('browser-window-created', (_event, win) => {
  // Allow the proctor window — use optional chaining because getWindow() may return
  // null if the event fires synchronously during BrowserWindow construction (before
  // this._win has been assigned inside ProctorManager._spawnProctorWindow).
  if (proctorManager?.getWindow?.() && win === proctorManager.getWindow()) return;

  // To prevent destroying the main window during its constructor:
  // Since we only ever explicitly call `new BrowserWindow` twice (main and proctor),
  // use a generous setTimeout so both assignments complete before we check.
  setTimeout(() => {
    const proctorWin = proctorManager?.getWindow?.() ?? null;
    if (win !== mainWindow && win !== proctorWin) {
      console.warn('[SecureBrowser] Blocked unauthorized window creation');
      if (!win.isDestroyed()) win.destroy();
    }
  }, 500);
});

// ─── macOS dock click ────────────────────────────────────────────────────────
app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) createWindow();
});

// ─── IPC: renderer signals assessment complete (e.g. "Submit" button) ────────
// ─── IPC: retry loading the assessment URL (from error page) ─────────────────
ipcMain.on('retry-load', () => {
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.loadURL(ALLOWED_URL);
  }
});

ipcMain.on('assessment-complete', async () => {
  eventLogger.logSessionEnd({ trigger: 'assessment-complete' });

  // ── Kill fullscreen enforcement FIRST ────────────────────────────────────
  if (focusGuard) focusGuard.disableFullscreen();

  // ── Stop all monitoring services ──────────────────────────────────────────
  if (focusGuard)      focusGuard.stop();
  if (processMonitor)  processMonitor.stop();
  if (proctorManager)  proctorManager.stop();
  if (screenMonitor)   screenMonitor.stop();
  if (riskEngine)      riskEngine.stop();

  // ── Unregister shortcuts ──────────────────────────────────────────────────
  globalShortcut.unregisterAll();

  // ── Exit fullscreen / kiosk / alwaysOnTop ─────────────────────────────────
  if (mainWindow && !mainWindow.isDestroyed()) {
    try {
      mainWindow.setAlwaysOnTop(false);
      if (USE_KIOSK)      mainWindow.setKiosk(false);
      if (USE_FULLSCREEN) mainWindow.setFullScreen(false);
    } catch (_) { /* ignore */ }
  }

  // ── Flush sync ────────────────────────────────────────────────────────────
  if (syncClient) await syncClient.flush().catch(() => {});
  if (syncClient)      syncClient.stop();

  // ── Flush Firebase logs and stop listeners ────────────────────────────────
  try {
    await firebaseClient.flushLogs().catch(() => {});
    firebaseClient.stopLogSync();
    firebaseClient.stopListening();
    await firebaseClient.endSession({ trigger: 'assessment-complete' }).catch(() => {});
  } catch (_) { /* Firebase errors must not block exam completion */ }

  // ── Signal renderer: services stopped, countdown can begin ───────────────
  // The exam page shows its own 5-second animated countdown.
  // After the countdown the renderer calls closeBrowser() → close-browser IPC.
  // We also set a 6.5s server-side safety-net timer in case the IPC is missed.
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send('submission-confirmed');
  }

  // Safety-net: force quit 6.5 s after confirming, regardless of renderer IPC.
  setTimeout(() => cleanExit(), 6500).unref();
});

// ─── IPC: renderer's auto-close countdown finished → quit ────────────────────
// Fired by window.secureBrowser.closeBrowser() after the 5-second countdown.
ipcMain.on('close-browser', () => {
  cleanExit();
});

// ─── IPC: event logger queries ──────────────────────────────────────────
ipcMain.handle('get-audit-log-path',   () => eventLogger.getLogPath());
ipcMain.handle('get-audit-session-id', () => eventLogger.getSessionId());
ipcMain.handle('verify-audit-chain',   () => eventLogger.verifyChain());
ipcMain.handle('trigger-sync',         async () => { if (syncClient) await syncClient.flush(); });

// ─── IPC: risk engine queries ────────────────────────────────────────────
ipcMain.handle('get-risk-score',   () => ({ score: riskEngine?.getScore() ?? 0, level: riskEngine?.getLevel() ?? 'LOW' }));
ipcMain.handle('get-risk-history', () => riskEngine?.getHistory() ?? []);
ipcMain.handle('get-risk-summary', () => riskEngine?.getSummary() ?? null);

// ─── IPC: renderer requests violation report ──────────────────────────────────
ipcMain.handle('get-violations', () => {
  return {
    count:      focusGuard?.getCount()      ?? 0,
    violations: focusGuard?.getViolations() ?? [],
    logPath:    focusGuard?.getLogPath()    ?? null,
  };
});

// ─── IPC: environment check queries ──────────────────────────────────────────

/** Returns current display info: { count, displays[] } */
ipcMain.handle('get-display-info', () => {
  return envCheck?.getDisplayInfo() ?? { count: screen.getAllDisplays().length, displays: [] };
});

/** Returns the result of a fresh pre-launch-style display count check. */
ipcMain.handle('run-display-check', () => {
  if (!envCheck) return { passed: true, failures: [] };
  return BLOCK_MULTI_DISPLAY
    ? envCheck.runPreLaunchChecks()
    : { passed: true, failures: [] };
});

// ─── IPC: proctor queries ─────────────────────────────────────────────────────

ipcMain.handle('get-proctor-status', () => proctorManager?.getCurrentStatus() ?? null);
ipcMain.handle('get-proctor-history', () => proctorManager?.getHistory() ?? []);
ipcMain.handle('get-proctor-log-path', () => proctorManager?.getLogPath() ?? null);

// ─── IPC: screen monitor queries ─────────────────────────────────────────────
ipcMain.handle('get-screen-capture-count',   () => screenMonitor?.getCaptureCount() ?? 0);
ipcMain.handle('get-screen-capture-dir',     () => screenMonitor?.getCaptureDir()   ?? null);
ipcMain.handle('get-screen-monitor-log',     () => screenMonitor?.getLogPath()      ?? null);

// ─── IPC: preload signals that Page Visibility API went 'hidden' ──────────────
// This fires even before the BrowserWindow 'blur' event, giving an early
// warning that the candidate has switched away from the browser.
// ─── IPC: process monitor queries ───────────────────────────────────────────

/** Full session alert history (all detections, including already-resolved). */
ipcMain.handle('get-process-alerts', () => {
  return processMonitor?.getAllAlerts() ?? [];
});

/** Currently-running suspicious processes only. */
ipcMain.handle('get-active-process-alerts', () => {
  return processMonitor?.getActiveAlerts() ?? [];
});

/** Path to the on-disk process alert log file. */
ipcMain.handle('get-process-log-path', () => {
  return processMonitor?.getLogPath() ?? null;
});

ipcMain.on('visibility-hidden', () => {
  console.warn('[SecureBrowser] Page visibility hidden — candidate may have switched away');
  // FocusGuard's 'blur' event will fire moments later and handle recovery;
  // this signal is used for logging / analytics only.
  if (focusGuard) focusGuard._log('VISIBILITY_HIDDEN');
});

// ─── Clean up before quit (safety-net — cleanExit() should have run first) ───
// This fires even if app.quit() was called directly, so it guarantees
// shortcuts are released and the window state is restored no matter what.
app.on('will-quit', () => {
  globalShortcut.unregisterAll();
  // Belt-and-suspenders: restore window state if cleanExit() was bypassed
  if (mainWindow && !mainWindow.isDestroyed()) {
    try {
      mainWindow.setAlwaysOnTop(false);
      if (USE_KIOSK)      mainWindow.setKiosk(false);
      if (USE_FULLSCREEN) mainWindow.setFullScreen(false);
    } catch (_) { /* ignore */ }
  }
});

// ─── Graceful quit ────────────────────────────────────────────────────────────
app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});
