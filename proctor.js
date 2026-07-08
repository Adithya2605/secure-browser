/**
 * proctor.js — Proctoring Manager (main process)
 *
 * Manages a hidden BrowserWindow that runs TF.js BlazeFace detection
 * against the webcam feed. Results are forwarded to the assessment window.
 *
 * Architecture:
 *   Hidden proctor window (own session, nodeIntegration: true)
 *     └─ webcam → TF.js BlazeFace → IPC 'proctor-status'
 *   Main process (this file)
 *     └─ receives status → emits 'status' event → forwarded to renderer
 *
 * Why a separate BrowserWindow?
 *   - TF.js needs WebGL which requires a renderer process
 *   - Isolating it in its own window + session keeps it completely
 *     separate from the locked-down assessment session
 *   - If face detection crashes, the assessment window is unaffected
 *
 * Status values:
 *   INITIALISING    — model loading
 *   FACE_PRESENT    — exactly one face detected
 *   NO_FACE         — zero faces detected
 *   MULTIPLE_FACES  — two or more faces detected
 *   CAMERA_ERROR    — camera access failed
 *   MODEL_ERROR     — model failed to load
 */

'use strict';

const { BrowserWindow, session, ipcMain, app } = require('electron');
const path = require('path');
const fs   = require('fs');
const { EventEmitter } = require('events');

class ProctorManager extends EventEmitter {
  constructor(config = {}) {
    super();
    this._enabled      = config.proctoring       !== false;
    this._intervalMs   = config.proctorIntervalMs ?? 5000;
    this._win          = null;
    this._ipcAttached  = false;
    this._history      = [];   // capped ring buffer
    this._current      = null;
    this._logPath      = path.join(app.getPath('userData'), 'proctor.log');
  }

  start() {
    if (!this._enabled) return;
    this._attachIPC();
    this._spawnProctorWindow();
  }

  stop() {
    if (this._win && !this._win.isDestroyed()) {
      this._win.destroy();
      this._win = null;
    }
  }

  getCurrentStatus() { return this._current; }
  getHistory()       { return [...this._history]; }
  getLogPath()       { return this._logPath; }
  getWindow()        { return this._win; }

  // ─── Private ─────────────────────────────────────────────────────────────

  _spawnProctorWindow() {
    // Own partition → not subject to defaultSession request filter or permissions
    const proctorSession = session.fromPartition('proctor', { cache: false });

    // Grant camera (media) permission only for this hidden window
    proctorSession.setPermissionRequestHandler((_wc, permission, cb) => {
      cb(permission === 'media');
    });
    proctorSession.setPermissionCheckHandler((_wc, permission) => {
      return permission === 'media';
    });

    this._win = new BrowserWindow({
      width:        320,
      height:       240,
      show:         false,
      skipTaskbar:  true,
      webPreferences: {
        session:          proctorSession,
        nodeIntegration:  true,   // needed: require('electron').ipcRenderer in HTML
        contextIsolation: false,
        webSecurity:      false,  // needed: load file:// scripts from node_modules
        devTools:         false,
      },
    });

    this._win.loadFile(path.join(__dirname, 'proctor-window.html'));

    // Pass the configured interval to the window once it's ready
    this._win.webContents.once('did-finish-load', () => {
      this._win.webContents.send('set-interval', this._intervalMs);
    });

    this._win.on('closed', () => { this._win = null; });
  }

  _attachIPC() {
    if (this._ipcAttached) return;
    this._ipcAttached = true;

    ipcMain.on('proctor-status', (_event, data) => {
      this._current = data;
      this._history.push(data);
      if (this._history.length > 500) this._history.shift(); // cap size
      this._writeLog(data);
      this.emit('status', data);
    });

    ipcMain.on('proctor-error', (_event, { phase, message }) => {
      const data = {
        status:    phase === 'camera' ? 'CAMERA_ERROR' : 'MODEL_ERROR',
        faceCount: 0,
        error:     message,
        timestamp: new Date().toISOString(),
      };
      this._current = data;
      this._writeLog(data);
      this.emit('error', data);
    });

    ipcMain.on('proctor-log', (_event, msg) => {
      console.log('[Proctor]', msg);
    });
  }

  _writeLog(entry) {
    const line = `[${entry.timestamp}] ${entry.status} faces=${entry.faceCount ?? 0}${entry.error ? ' err=' + entry.error : ''}\n`;
    try { fs.appendFileSync(this._logPath, line); } catch (_) {}
  }
}

module.exports = ProctorManager;
