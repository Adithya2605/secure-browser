/**
 * event-logger.js — Centralized Audit Event Logger
 *
 * Design principles:
 *   1. Offline-first  — every event written to disk synchronously before anything else
 *   2. Append-only    — NDJSON format; never overwrites existing records
 *   3. Hash-chained   — each event embeds SHA-256(prev event) for tamper detection
 *   4. HMAC-signed    — each event is individually signed with a shared secret
 *   5. Sequenced      — monotonic counter detects deletions or reordering
 *   6. Singleton      — one logger instance per process; call getLogger() everywhere
 *
 * ────────────────────────────────────────────────────────────────────────────
 *  Event JSON Schema
 * ────────────────────────────────────────────────────────────────────────────
 *  {
 *    "id":        string (UUID v4)       — globally unique per event
 *    "sessionId": string (UUID v4)       — ties all events to one exam session
 *    "seq":       integer ≥ 0            — monotonic, gaps indicate deletions
 *    "timestamp": string (ISO-8601 UTC)  — event creation time
 *    "type":      string (EVENT_TYPES)   — what happened
 *    "severity":  "INFO"|"WARNING"|"CRITICAL"
 *    "source":    string                 — which module produced the event
 *    "metadata":  object                 — event-specific payload
 *    "prevHash":  string (hex-64)        — SHA-256 of the previous serialized event
 *    "hmac":      string (hex-64)        — HMAC-SHA256(secret, JSON of above fields)
 *    "hash":      string (hex-64)        — SHA-256(JSON of above + hmac) — chain anchor
 *  }
 *
 * ────────────────────────────────────────────────────────────────────────────
 *  Tamper-prevention layers
 * ────────────────────────────────────────────────────────────────────────────
 *  Layer 1 — HMAC signature
 *    Every event is signed. The server holds the same secret and can verify
 *    that no field was altered after the app wrote it.
 *
 *  Layer 2 — Hash chain (blockchain-style)
 *    Each event's `prevHash` = hash of the previous event (including its HMAC).
 *    Deleting, inserting, or reordering any event breaks the chain.
 *    verifyChain() walks the file and reports the first broken link.
 *
 *  Layer 3 — Sequence numbers
 *    A gap in `seq` (e.g. 0,1,3) proves an event was deleted even if the
 *    file is otherwise intact.
 *
 *  Layer 4 — Session binding
 *    Every event carries the `sessionId`. Cross-session splicing is trivially
 *    detectable because HMAC will fail (different sessionId → different signature).
 *
 *  What this does NOT prevent:
 *    — A candidate who patches the Electron binary or replaces the HMAC secret
 *    — OS-level filesystem snapshot restore (mitigated by sync: once events
 *      are ACK'd by the server, local tampering is moot)
 */

'use strict';

const { createHmac, createHash, randomUUID } = require('crypto');
const path  = require('path');
const fs    = require('fs');
const { app } = require('electron');
const { EventEmitter } = require('events');

// ─── Event type constants ─────────────────────────────────────────────────────
const EVENT_TYPES = Object.freeze({
  // Session lifecycle
  SESSION_START:       'SESSION_START',
  SESSION_END:         'SESSION_END',

  // Focus / window
  FOCUS_LOSS:          'FOCUS_LOSS',
  FOCUS_RESTORED:      'FOCUS_RESTORED',
  CLOSE_ATTEMPT:       'CLOSE_ATTEMPT',
  FULLSCREEN_EXIT:     'FULLSCREEN_EXIT',

  // Process monitoring
  PROCESS_DETECTED:    'PROCESS_DETECTED',
  PROCESS_RESOLVED:    'PROCESS_RESOLVED',

  // Proctoring / face
  FACE_STATUS:         'FACE_STATUS',        // metadata.status = FACE_PRESENT | NO_FACE | MULTIPLE_FACES
  FACE_ERROR:          'FACE_ERROR',

  // Environment
  DISPLAY_CHANGE:      'DISPLAY_CHANGE',
  DISPLAY_VIOLATION:   'DISPLAY_VIOLATION',

  // Navigation & network
  NAV_BLOCKED:         'NAV_BLOCKED',
  REQUEST_BLOCKED:     'REQUEST_BLOCKED',

  // Input
  SHORTCUT_BLOCKED:    'SHORTCUT_BLOCKED',

  // Generic
  WARNING:             'WARNING',
  ADMIN_ACTION:        'ADMIN_ACTION',
});

const SEVERITY = Object.freeze({ INFO: 'INFO', WARNING: 'WARNING', CRITICAL: 'CRITICAL' });

// ─── Helpers ──────────────────────────────────────────────────────────────────

function sha256(str) {
  return createHash('sha256').update(str, 'utf8').digest('hex');
}

function hmacSign(secret, str) {
  return createHmac('sha256', secret).update(str, 'utf8').digest('hex');
}

// ─── Logger class ─────────────────────────────────────────────────────────────

class EventLogger extends EventEmitter {
  /**
   * @param {object} config
   * @param {string} [config.sessionId]   — provide a pre-generated UUID for the exam session
   * @param {string} [config.hmacSecret]  — shared secret; MUST match server-side verifier
   */
  constructor(config = {}) {
    super();
    this._sessionId  = config.sessionId  || randomUUID();
    this._secret     = config.hmacSecret || 'seb-audit-key-v1-CHANGE-IN-PRODUCTION';
    this._seq        = 0;
    this._prevHash   = '0'.repeat(64);   // genesis (no previous event)
    this._logDir     = path.join(app.getPath('userData'), 'audit-logs');
    this._logPath    = null;
    this._syncPath   = null;             // sync-state JSON
    this._syncedIds  = new Set();
    this._initialized = false;
  }

  // ─── Lifecycle ──────────────────────────────────────────────────────────────

  /** Must be called once before first log(). Returns `this` for chaining. */
  init() {
    if (this._initialized) return this;
    this._initialized = true;

    fs.mkdirSync(this._logDir, { recursive: true });

    const date = new Date().toISOString().slice(0, 10);
    const tag  = this._sessionId.slice(0, 8);
    this._logPath  = path.join(this._logDir, `session-${tag}-${date}.ndjson`);
    this._syncPath = path.join(this._logDir, 'sync-state.json');

    this._loadSyncState();
    this.log(EVENT_TYPES.SESSION_START, SEVERITY.INFO, 'session', {
      logPath:   this._logPath,
      sessionId: this._sessionId,
    });

    return this;
  }

  // ─── Core log() ─────────────────────────────────────────────────────────────

  /**
   * Write one audit event to disk and emit 'event' for in-process listeners.
   * Returns the complete, signed event object.
   */
  log(type, severity, source, metadata = {}) {
    if (!this._initialized) this.init();

    // Build the signable payload (no hmac/hash yet)
    const base = {
      id:        randomUUID(),
      sessionId: this._sessionId,
      seq:       this._seq++,
      timestamp: new Date().toISOString(),
      type,
      severity,
      source,
      metadata,
      prevHash:  this._prevHash,
    };

    // Sign: HMAC over the JSON of the base object
    const baseJson = JSON.stringify(base);
    const hmac     = hmacSign(this._secret, baseJson);

    // Chain anchor: SHA-256(baseJson + hmac) — this is what prevHash points to next
    const hash     = sha256(baseJson + hmac);

    const event = { ...base, hmac, hash };
    this._prevHash = hash;

    this._persist(event);
    this.emit('event', event);
    return event;
  }

  // ─── Convenience methods (typed wrappers) ───────────────────────────────────

  logSessionStart(meta = {})                { return this.log(EVENT_TYPES.SESSION_START,    SEVERITY.INFO,     'session',         meta); }
  logSessionEnd(meta = {})                  { return this.log(EVENT_TYPES.SESSION_END,      SEVERITY.INFO,     'session',         meta); }
  logFocusLoss(meta = {})                   { return this.log(EVENT_TYPES.FOCUS_LOSS,       SEVERITY.WARNING,  'focus-guard',     meta); }
  logFocusRestored(meta = {})               { return this.log(EVENT_TYPES.FOCUS_RESTORED,   SEVERITY.INFO,     'focus-guard',     meta); }
  logCloseAttempt(meta = {})                { return this.log(EVENT_TYPES.CLOSE_ATTEMPT,    SEVERITY.CRITICAL, 'window',          meta); }
  logFullscreenExit(meta = {})              { return this.log(EVENT_TYPES.FULLSCREEN_EXIT,  SEVERITY.WARNING,  'window',          meta); }
  logProcessDetected(proc)                  { return this.log(EVENT_TYPES.PROCESS_DETECTED, SEVERITY.CRITICAL, 'process-monitor', proc); }
  logProcessResolved(proc)                  { return this.log(EVENT_TYPES.PROCESS_RESOLVED, SEVERITY.INFO,     'process-monitor', proc); }
  logDisplayChange(meta = {})               { return this.log(EVENT_TYPES.DISPLAY_CHANGE,   SEVERITY.WARNING,  'env-check',       meta); }
  logDisplayViolation(meta = {})            { return this.log(EVENT_TYPES.DISPLAY_VIOLATION,SEVERITY.CRITICAL, 'env-check',       meta); }
  logNavBlocked(url, meta = {})             { return this.log(EVENT_TYPES.NAV_BLOCKED,      SEVERITY.WARNING,  'navigation',      { url, ...meta }); }
  logRequestBlocked(details)                { return this.log(EVENT_TYPES.REQUEST_BLOCKED,  SEVERITY.WARNING,  'network',         details); }
  logShortcutBlocked(key, meta = {})        { return this.log(EVENT_TYPES.SHORTCUT_BLOCKED, SEVERITY.WARNING,  'keyboard',        { key, ...meta }); }
  logWarning(message, source, meta = {})    { return this.log(EVENT_TYPES.WARNING,          SEVERITY.WARNING,  source,            { message, ...meta }); }
  logAdminAction(action, meta = {})         { return this.log(EVENT_TYPES.ADMIN_ACTION,     SEVERITY.INFO,     'admin',           { action, ...meta }); }

  logFaceStatus(status, faceCount, meta = {}) {
    const severity = status === 'MULTIPLE_FACES' ? SEVERITY.CRITICAL
                   : status === 'NO_FACE'        ? SEVERITY.WARNING
                   :                               SEVERITY.INFO;
    return this.log(EVENT_TYPES.FACE_STATUS, severity, 'proctor', { status, faceCount, ...meta });
  }

  // ─── Sync support ───────────────────────────────────────────────────────────

  /**
   * Returns up to `limit` events that have not yet been confirmed synced.
   * The SyncClient calls this, sends the batch, then calls markSynced().
   */
  getPendingBatch(limit = 100) {
    if (!this._logPath || !fs.existsSync(this._logPath)) return [];
    const lines = fs.readFileSync(this._logPath, 'utf8').split('\n').filter(Boolean);
    const events = [];
    for (const line of lines) {
      if (events.length >= limit) break;
      try {
        const e = JSON.parse(line);
        if (!this._syncedIds.has(e.id)) events.push(e);
      } catch (_) { /* skip corrupted line */ }
    }
    return events;
  }

  /** Mark event IDs as successfully synced to the server. */
  markSynced(ids = []) {
    ids.forEach(id => this._syncedIds.add(id));
    this._saveSyncState();
  }

  // ─── Integrity verification ─────────────────────────────────────────────────

  /**
   * Walk the log file and verify every event's HMAC and chain link.
   * Returns { valid: boolean, totalEvents: number, firstBrokenSeq: number|null }
   */
  verifyChain() {
    if (!this._logPath || !fs.existsSync(this._logPath)) {
      return { valid: true, totalEvents: 0, firstBrokenSeq: null };
    }

    const lines = fs.readFileSync(this._logPath, 'utf8').split('\n').filter(Boolean);
    let prevHash = '0'.repeat(64);

    for (const line of lines) {
      let event;
      try { event = JSON.parse(line); }
      catch { return { valid: false, totalEvents: lines.length, firstBrokenSeq: -1 }; }

      const { hmac, hash, ...base } = event;
      const expectedHmac = hmacSign(this._secret, JSON.stringify(base));
      const expectedHash = sha256(JSON.stringify(base) + hmac);

      if (
        hmac          !== expectedHmac  ||
        hash          !== expectedHash  ||
        event.prevHash !== prevHash
      ) {
        return { valid: false, totalEvents: lines.length, firstBrokenSeq: event.seq };
      }
      prevHash = hash;
    }

    return { valid: true, totalEvents: lines.length, firstBrokenSeq: null };
  }

  // ─── Accessors ──────────────────────────────────────────────────────────────

  getSessionId()  { return this._sessionId; }
  getLogPath()    { return this._logPath; }
  getLogDir()     { return this._logDir; }
  getEventCount() { return this._seq; }

  // ─── Private ────────────────────────────────────────────────────────────────

  _persist(event) {
    try {
      fs.appendFileSync(this._logPath, JSON.stringify(event) + '\n', { encoding: 'utf8', flag: 'a' });
    } catch (err) {
      console.error('[EventLogger] Disk write failed:', err.message);
    }
  }

  _loadSyncState() {
    try {
      if (fs.existsSync(this._syncPath)) {
        const { syncedIds = [] } = JSON.parse(fs.readFileSync(this._syncPath, 'utf8'));
        this._syncedIds = new Set(syncedIds);
      }
    } catch { this._syncedIds = new Set(); }
  }

  _saveSyncState() {
    try {
      fs.writeFileSync(this._syncPath, JSON.stringify({ syncedIds: [...this._syncedIds] }), 'utf8');
    } catch (err) {
      console.error('[EventLogger] Sync-state save failed:', err.message);
    }
  }
}

// ─── Singleton ────────────────────────────────────────────────────────────────

let _instance = null;

/** Returns the singleton EventLogger. Pass config only on first call. */
function getLogger(config) {
  if (!_instance) _instance = new EventLogger(config);
  return _instance;
}

module.exports = { EventLogger, getLogger, EVENT_TYPES, SEVERITY };
