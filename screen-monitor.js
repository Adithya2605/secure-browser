/**
 * screen-monitor.js — AI Screen Proctoring via Electron desktopCapturer
 *
 * Uses Electron's native desktopCapturer API (main-process only) to
 * periodically capture the candidate's screen and make them available for
 * AI-based proctoring analysis.
 *
 * ─── Key design points ───────────────────────────────────────────────────────
 *  ✅  Runs entirely in the main process — NOT via browser APIs
 *  ✅  Cannot be blocked or detected by the candidate
 *  ✅  Independent of the blocked web getDisplayMedia / display-capture APIs
 *  ✅  Emits 'capture' events with { dataUrl, timestamp, index } for consumers
 *  ✅  Emits 'error' events with { error, timestamp } on failure
 *  ✅  Stores captures in userData/screen-captures/ as JPEG files (ring buffer)
 *  ✅  Calls onCapture callback so callers can push to Firebase / AI endpoint
 *
 * ─── Configuration ───────────────────────────────────────────────────────────
 *  intervalMs     — how often to capture (default: 30 000 ms = 30 s)
 *  thumbWidth     — capture width in px (default: 1280)
 *  thumbHeight    — capture height in px (default: 720)
 *  maxLocalFiles  — max JPEG files to keep on disk before overwriting oldest
 *  onCapture      — async callback(capture) called for each successful capture
 *                   capture: { dataUrl, timestamp, index, filePath }
 */

'use strict';

const { desktopCapturer, app } = require('electron');
const { EventEmitter }         = require('events');
const path  = require('path');
const fs    = require('fs');

class ScreenMonitor extends EventEmitter {
  /**
   * @param {object} options
   * @param {number}   [options.intervalMs=30000]   Capture interval in ms
   * @param {number}   [options.thumbWidth=1280]     Thumbnail width
   * @param {number}   [options.thumbHeight=720]     Thumbnail height
   * @param {number}   [options.maxLocalFiles=120]   Max screenshots on disk
   * @param {function} [options.onCapture]           Async callback per capture
   * @param {boolean}  [options.logEnabled=true]     Write capture log to disk
   */
  constructor(options = {}) {
    super();
    this._intervalMs    = options.intervalMs    ?? 30_000;
    this._thumbWidth    = options.thumbWidth    ?? 1280;
    this._thumbHeight   = options.thumbHeight   ?? 720;
    this._maxLocalFiles = options.maxLocalFiles ?? 120;
    this._onCapture     = options.onCapture     ?? null;
    this._logEnabled    = options.logEnabled    !== false;

    this._running       = false;
    this._timer         = null;
    this._index         = 0;      // monotonic counter for this session

    // Storage directory — <userData>/screen-captures/
    this._captureDir = path.join(app.getPath('userData'), 'screen-captures');
    this._logPath    = path.join(app.getPath('userData'), 'screen-monitor.log');

    // Ensure capture directory exists
    try { fs.mkdirSync(this._captureDir, { recursive: true }); } catch (_) {}
  }

  // ─── Public API ─────────────────────────────────────────────────────────────

  /** Start periodic screen capture. Call after lockdown is activated. */
  start() {
    if (this._running) return;
    this._running = true;
    this._log('SCREEN_MONITOR_STARTED', `interval=${this._intervalMs}ms`);

    // Take an immediate first capture, then schedule repeats
    this._capture();
    this._timer = setInterval(() => this._capture(), this._intervalMs);
    this._timer.unref?.();
  }

  /** Stop monitoring (e.g. on assessment-complete). */
  stop() {
    if (!this._running) return;
    this._running = false;
    if (this._timer) {
      clearInterval(this._timer);
      this._timer = null;
    }
    this._log('SCREEN_MONITOR_STOPPED', `total_captures=${this._index}`);
  }

  /** Returns the path to the local captures directory. */
  getCaptureDir() { return this._captureDir; }

  /** Returns the absolute path to the log file. */
  getLogPath() { return this._logPath; }

  /** Returns total number of captures taken in this session. */
  getCaptureCount() { return this._index; }

  // ─── Internals ──────────────────────────────────────────────────────────────

  async _capture() {
    if (!this._running) return;

    const timestamp = new Date().toISOString();

    try {
      // getSources runs in the main process — no browser permission needed.
      // 'screen' type captures the primary display (or all displays).
      const sources = await desktopCapturer.getSources({
        types:         ['screen'],
        thumbnailSize: { width: this._thumbWidth, height: this._thumbHeight },
        fetchWindowIcons: false,
      });

      if (!sources || sources.length === 0) {
        this._log('SCREEN_CAPTURE_NO_SOURCE', timestamp);
        this.emit('error', { error: 'No screen source found', timestamp });
        return;
      }

      // Use the first source (primary monitor)
      const thumbnail = sources[0].thumbnail;
      const dataUrl   = thumbnail.toDataURL();   // 'data:image/png;base64,...'

      // Convert PNG data URL to JPEG buffer for smaller file size
      const jpegBuffer = thumbnail.toJPEG(80);   // quality 0-100

      // Write to disk with ring-buffer rotation
      const fileName = `cap_${String(this._index).padStart(6, '0')}.jpg`;
      const filePath = path.join(this._captureDir, fileName);

      try {
        fs.writeFileSync(filePath, jpegBuffer);
        this._rotateOldFiles();
      } catch (writeErr) {
        console.warn('[ScreenMonitor] Could not write capture file:', writeErr.message);
      }

      this._index++;
      this._log('SCREEN_CAPTURED', `index=${this._index} file=${fileName}`);

      const captureRecord = {
        dataUrl,           // full PNG data URL (for Firebase upload)
        jpegBuffer,        // Buffer — for local storage or HTTP upload
        filePath,          // absolute path to local JPEG
        timestamp,
        index: this._index,
        width: this._thumbWidth,
        height: this._thumbHeight,
        displayName: sources[0].name,
      };

      // Notify listeners
      this.emit('capture', captureRecord);

      // Call user-supplied async callback (e.g. push to Firebase)
      if (this._onCapture) {
        try {
          await this._onCapture(captureRecord);
        } catch (cbErr) {
          console.warn('[ScreenMonitor] onCapture callback error:', cbErr.message);
        }
      }
    } catch (err) {
      console.error('[ScreenMonitor] Capture failed:', err.message);
      this._log('SCREEN_CAPTURE_ERROR', err.message);
      this.emit('error', { error: err.message, timestamp });
    }
  }

  /** Remove oldest capture files when the ring buffer is full. */
  _rotateOldFiles() {
    try {
      const files = fs.readdirSync(this._captureDir)
        .filter(f => f.startsWith('cap_') && f.endsWith('.jpg'))
        .sort();

      while (files.length > this._maxLocalFiles) {
        const oldest = files.shift();
        try { fs.unlinkSync(path.join(this._captureDir, oldest)); } catch (_) {}
      }
    } catch (_) {}
  }

  _log(type, detail = '') {
    const line = `[${new Date().toISOString()}] ${type}${detail ? ' — ' + detail : ''}\n`;
    console.info(`[ScreenMonitor] ${line.trim()}`);
    if (this._logEnabled) {
      try { fs.appendFileSync(this._logPath, line); } catch (_) {}
    }
  }
}

module.exports = ScreenMonitor;
