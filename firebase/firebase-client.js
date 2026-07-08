/**
 * firebase-client.js — Firebase SDK integration for the Secure Exam Browser
 *
 * Replaces the generic sync-client.js HTTP POST with native Firebase SDK calls.
 * This module handles:
 *   1. Firebase app initialization
 *   2. Custom-token authentication (server issues token for exam session)
 *   3. Firestore writes for audit logs, session lifecycle, and config fetch
 *   4. Real-time listener for exam config changes (e.g. proctor disables exam)
 *
 * Usage in main.js:
 *   const firebaseClient = require('./firebase/firebase-client');
 *   await firebaseClient.init(config.firebase);
 *   await firebaseClient.authenticate(customToken);
 *   firebaseClient.startLogSync(eventLogger);
 *
 * ── Why Custom Tokens instead of email/password? ──────────────────────────────
 *   The exam platform backend generates a Firebase Custom Token that encodes:
 *     - uid:       candidate's platform user ID
 *     - examId:    which exam they're taking
 *     - sessionId: matches the EventLogger sessionId
 *   This token is passed to the Electron app at launch (via deep-link or config).
 *   The candidate never sees Firebase credentials.
 */

'use strict';

const { initializeApp }                  = require('firebase/app');
const { getAuth, signInWithCustomToken } = require('firebase/auth');
const {
  getFirestore,
  collection,
  doc,
  setDoc,
  addDoc,
  writeBatch,
  onSnapshot,
  serverTimestamp,
  Timestamp,
} = require('firebase/firestore');
const { EventEmitter } = require('events');

class FirebaseClient extends EventEmitter {
  constructor() {
    super();
    this._app       = null;
    this._auth      = null;
    this._db        = null;
    this._uid       = null;
    this._examId    = null;
    this._sessionId = null;
    this._unsubConfigListener = null;
    this._syncTimer = null;
    this._syncing   = false;
  }

  // ─── 1. Initialize Firebase ─────────────────────────────────────────────────

  /**
   * @param {object} firebaseConfig — standard Firebase web config object
   *   { apiKey, authDomain, projectId, storageBucket, messagingSenderId, appId }
   */
  init(firebaseConfig) {
    if (this._app) return;
    this._app  = initializeApp(firebaseConfig);
    this._auth = getAuth(this._app);
    this._db   = getFirestore(this._app);
    console.info('[FirebaseClient] Initialized');
  }

  // ─── 2. Authenticate ────────────────────────────────────────────────────────

  /**
   * Sign in with a Firebase Custom Token issued by your exam platform backend.
   *
   * @param {string} customToken — JWT from admin.auth().createCustomToken(uid, claims)
   *   Expected custom claims: { examId, sessionId }
   */
  async authenticate(customToken) {
    if (!this._auth) throw new Error('FirebaseClient not initialized');

    const cred = await signInWithCustomToken(this._auth, customToken);
    this._uid  = cred.user.uid;

    // Parse custom claims from the ID token
    const idToken = await cred.user.getIdTokenResult();
    this._examId    = idToken.claims.examId    || null;
    this._sessionId = idToken.claims.sessionId || null;

    console.info(`[FirebaseClient] Authenticated as uid=${this._uid}, exam=${this._examId}`);

    // Write/update the session document
    await this._createSession();
    return { uid: this._uid, examId: this._examId, sessionId: this._sessionId };
  }

  // ─── 3. Session lifecycle ───────────────────────────────────────────────────

  async _createSession() {
    if (!this._sessionId) return;
    const sessionRef = doc(this._db, 'sessions', this._sessionId);
    await setDoc(sessionRef, {
      userId:       this._uid,
      examId:       this._examId,
      status:       'ACTIVE',
      startedAt:    serverTimestamp(),
      lastHeartbeat: serverTimestamp(),
      clientVersion: require('../package.json').version,
      platform:     process.platform,
    }, { merge: true });
  }

  async heartbeat(riskSnapshot = {}) {
    if (!this._sessionId) return;
    const sessionRef = doc(this._db, 'sessions', this._sessionId);
    await setDoc(sessionRef, {
      lastHeartbeat: serverTimestamp(),
      ...riskSnapshot,
    }, { merge: true });
  }

  async endSession(summary = {}) {
    if (!this._sessionId) return;
    const sessionRef = doc(this._db, 'sessions', this._sessionId);
    await setDoc(sessionRef, {
      status:   'COMPLETED',
      endedAt:  serverTimestamp(),
      summary,
    }, { merge: true });
  }

  // ─── 4. Log sync (EventLogger → Firestore) ─────────────────────────────────

  /**
   * Start periodic sync from the local EventLogger to Firestore.
   * @param {import('../event-logger').EventLogger} logger
   * @param {number} intervalMs — how often to push (default 15s)
   */
  startLogSync(logger, intervalMs = 15_000) {
    this._logger = logger;
    this._syncIntervalMs = intervalMs;

    // Push logs immediately, then periodically
    this._pushLogs();
    this._syncTimer = setInterval(() => this._pushLogs(), intervalMs);
    console.info(`[FirebaseClient] Log sync started — every ${intervalMs / 1000}s`);
  }

  stopLogSync() {
    if (this._syncTimer) {
      clearInterval(this._syncTimer);
      this._syncTimer = null;
    }
  }

  /** Immediate flush — call on exam submission. */
  async flushLogs() {
    await this._pushLogs();
  }

  async _pushLogs() {
    if (this._syncing || !this._logger || !this._sessionId) return;
    this._syncing = true;

    try {
      const batch = this._logger.getPendingBatch(50);
      if (batch.length === 0) {
        // Even with no new logs, refresh the heartbeat + risk score
        await this.heartbeat(this._getRiskSnapshot());
        return;
      }

      // Firestore batched writes — max 500 per batch; we send 50 at a time
      const fb = writeBatch(this._db);
      const logsRef = collection(this._db, 'sessions', this._sessionId, 'logs');

      for (const event of batch) {
        const logDoc = doc(logsRef, event.id);
        fb.set(logDoc, {
          ...event,
          // Convert ISO string to Firestore Timestamp for indexing/querying
          firestoreTimestamp: Timestamp.fromDate(new Date(event.timestamp)),
          syncedAt:          serverTimestamp(),
        });
      }

      await fb.commit();
      this._logger.markSynced(batch.map(e => e.id));
      this.emit('synced', { count: batch.length });

      // Update heartbeat and persist current risk score so the dashboard
      // can read it from the session doc without waiting for all logs to load.
      await this.heartbeat(this._getRiskSnapshot());
    } catch (err) {
      console.error('[FirebaseClient] Log push failed:', err.message);
      this.emit('sync-failed', { error: err.message });
    } finally {
      this._syncing = false;
    }
  }

  /**
   * Returns a { riskScore, riskLevel } snapshot from the attached risk engine,
   * or an empty object if none is set. Call setRiskEngine() from main.js.
   */
  _getRiskSnapshot() {
    if (!this._riskEngine) return {};
    return {
      riskScore: this._riskEngine.getScore?.() ?? 0,
      riskLevel: this._riskEngine.getLevel?.() ?? 'LOW',
    };
  }

  /** Attach the risk engine so _pushLogs can read the live score. */
  setRiskEngine(riskEngine) {
    this._riskEngine = riskEngine;
  }

  // ─── 5. Fetch exam config ───────────────────────────────────────────────────

  /**
   * Fetch exam-specific configuration from Firestore.
   * Returns the exam document data.
   */
  async fetchExamConfig() {
    if (!this._examId) return null;
    const { getDoc } = require('firebase/firestore');
    const examRef = doc(this._db, 'exams', this._examId);
    const snap = await getDoc(examRef);
    return snap.exists() ? snap.data() : null;
  }

  // ─── 6. Real-time config listener ───────────────────────────────────────────

  /**
   * Subscribe to real-time changes on the exam config document.
   * The proctor can toggle fields like `paused`, `terminated`, or update
   * `allowedDomains` — the client reacts immediately.
   *
   * @param {function} callback — receives the updated exam config object
   */
  listenToExamConfig(callback) {
    if (!this._examId) return;
    const examRef = doc(this._db, 'exams', this._examId);

    this._unsubConfigListener = onSnapshot(examRef, (snap) => {
      if (snap.exists()) {
        const data = snap.data();
        callback(data);
        this.emit('config-update', data);
      }
    }, (err) => {
      console.error('[FirebaseClient] Config listener error:', err.message);
    });
  }

  /** Stop listening to config changes. */
  stopListening() {
    if (this._unsubConfigListener) {
      this._unsubConfigListener();
      this._unsubConfigListener = null;
    }
  }

  // ─── 8. Screen capture upload ────────────────────────────────────────────────

  /**
   * Upload a screen capture record to Firestore.
   * Called by ScreenMonitor's onCapture callback.
   *
   * Stored under: sessions/{sessionId}/screenCaptures/{autoId}
   *
   * @param {{ dataUrl: string, timestamp: string, index: number, displayName: string, width: number, height: number }} capture
   */
  async uploadScreenCapture(capture) {
    if (!this._db || !this._sessionId) return;

    try {
      const capturesRef = collection(
        this._db,
        'sessions', this._sessionId, 'screenCaptures'
      );

      // Store the JPEG as a base64 string (data URL minus the prefix)
      // For large-scale deployments replace this with Firebase Storage upload.
      const base64 = capture.dataUrl.replace(/^data:image\/\w+;base64,/, '');

      await addDoc(capturesRef, {
        index:       capture.index,
        timestamp:   capture.timestamp,
        displayName: capture.displayName || 'screen',
        width:       capture.width,
        height:      capture.height,
        imageBase64: base64,          // JPEG at 80% quality
        syncedAt:    serverTimestamp(),
      });
    } catch (err) {
      // Non-fatal — local file is always kept as backup
      console.warn('[FirebaseClient] Screen capture upload failed:', err.message);
    }
  }

  // ─── 7. Accessors ───────────────────────────────────────────────────────────

  getUid()       { return this._uid; }
  getExamId()    { return this._examId; }
  getSessionId() { return this._sessionId; }
  isAuthenticated() { return !!this._uid; }
}

module.exports = new FirebaseClient(); // singleton
