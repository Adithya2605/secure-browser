/**
 * Cloud Functions for Firebase — Server-side Exam Event Processing
 *
 * These functions run in Google's infrastructure, NOT on the client.
 * They provide the server-side validation, aggregation, and alerting
 * that the client cannot be trusted to perform.
 *
 * Deploy:  firebase deploy --only functions
 *
 * Functions:
 *   1. generateExamToken  — HTTP: issues a Firebase Custom Token for a candidate
 *   2. onLogCreated       — Firestore trigger: validates HMAC, detects anomalies
 *   3. onSessionEnd       — Firestore trigger: computes integrity report
 *   4. getExamConfig      — HTTP: returns sanitized exam config to client
 */

'use strict';

const { onRequest }           = require('firebase-functions/v2/https');
const { onDocumentCreated, onDocumentUpdated } = require('firebase-functions/v2/firestore');
const { initializeApp }       = require('firebase-admin/app');
const { getAuth }             = require('firebase-admin/auth');
const { getFirestore, FieldValue } = require('firebase-admin/firestore');
const { createHmac, createHash }   = require('crypto');
const { defineSecret }        = require('firebase-functions/params');

// The HMAC secret MUST be stored as a Firebase Secret — never in code.
const HMAC_SECRET = defineSecret('HMAC_SECRET');

initializeApp();
const db = getFirestore();

// ═══════════════════════════════════════════════════════════════════════════════
//  1. generateExamToken — Called by your exam platform backend (NOT the client)
// ═══════════════════════════════════════════════════════════════════════════════
//
// Request body:
//   { userId: string, examId: string, sessionId: string, apiKey: string }
//
// Response:
//   { token: string }   — Firebase Custom Token
//
// This endpoint MUST be protected by your own API key or service-to-service auth.
// The Electron client does NOT call this directly.

exports.generateExamToken = onRequest(
  { secrets: [HMAC_SECRET] },
  async (req, res) => {
    if (req.method !== 'POST') {
      res.status(405).json({ error: 'Method not allowed' });
      return;
    }

    const { userId, examId, sessionId, apiKey } = req.body;

    // Validate server-to-server API key (replace with your own auth mechanism)
    if (apiKey !== process.env.PLATFORM_API_KEY) {
      res.status(403).json({ error: 'Invalid API key' });
      return;
    }

    if (!userId || !examId || !sessionId) {
      res.status(400).json({ error: 'Missing required fields: userId, examId, sessionId' });
      return;
    }

    // Verify the exam exists and is active
    const examSnap = await db.doc(`exams/${examId}`).get();
    if (!examSnap.exists) {
      res.status(404).json({ error: 'Exam not found' });
      return;
    }
    const exam = examSnap.data();
    if (exam.terminated) {
      res.status(403).json({ error: 'Exam has been terminated' });
      return;
    }

    // Create the Firebase Custom Token with embedded claims
    const token = await getAuth().createCustomToken(userId, {
      role:      'candidate',
      examId,
      sessionId,
    });

    res.status(200).json({ token });
  }
);

// ═══════════════════════════════════════════════════════════════════════════════
//  2. onLogCreated — Server-side validation of every audit log event
// ═══════════════════════════════════════════════════════════════════════════════
//
// This trigger fires whenever the client writes a new document to:
//   /sessions/{sessionId}/logs/{logId}
//
// What it does:
//   a. Re-verifies the HMAC signature (the client CANNOT fake this)
//   b. Checks for anomalies (impossible timestamps, suspicious patterns)
//   c. Updates aggregation counters on the session document
//   d. Sends real-time alerts for CRITICAL events

exports.onLogCreated = onDocumentCreated(
  {
    document: 'sessions/{sessionId}/logs/{logId}',
    secrets:  [HMAC_SECRET],
  },
  async (event) => {
    const data      = event.data.data();
    const sessionId = event.params.sessionId;
    const logId     = event.params.logId;
    const secret    = HMAC_SECRET.value();

    // ── a. HMAC Verification ──────────────────────────────────────────────
    const { hmac, hash, firestoreTimestamp, syncedAt, ...base } = data;
    const baseJson     = JSON.stringify(base);
    const expectedHmac = createHmac('sha256', secret).update(baseJson, 'utf8').digest('hex');

    if (hmac !== expectedHmac) {
      console.error(`[TAMPER] HMAC mismatch on log ${logId} in session ${sessionId}`);
      // Mark the log as tampered — do NOT delete it (evidence preservation)
      await event.data.ref.update({
        _serverVerified: false,
        _tamperDetected: true,
        _verifiedAt:     FieldValue.serverTimestamp(),
      });
      // Flag the session as compromised
      await db.doc(`sessions/${sessionId}`).update({
        integrityStatus: 'COMPROMISED',
        compromisedAt:   FieldValue.serverTimestamp(),
      });
      return;
    }

    // Mark as verified
    await event.data.ref.update({
      _serverVerified: true,
      _tamperDetected: false,
      _verifiedAt:     FieldValue.serverTimestamp(),
    });

    // ── b. Anomaly Detection ──────────────────────────────────────────────
    const anomalies = [];

    // Check timestamp plausibility (not in the future, not older than 1 hour)
    const eventTime = new Date(data.timestamp);
    const now       = new Date();
    const oneHourAgo = new Date(now.getTime() - 60 * 60 * 1000);

    if (eventTime > now) {
      anomalies.push('FUTURE_TIMESTAMP');
    }
    if (eventTime < oneHourAgo) {
      anomalies.push('STALE_TIMESTAMP');
    }

    // Check sequence monotonicity (would need to read prev log — expensive,
    // so we do this in the chain-verification function instead)

    if (anomalies.length > 0) {
      await event.data.ref.update({ _anomalies: anomalies });
    }

    // ── c. Update session aggregation counters ────────────────────────────
    const incrementField = `counters.${data.type}`;
    const sessionRef = db.doc(`sessions/${sessionId}`);
    await sessionRef.update({
      [incrementField]:  FieldValue.increment(1),
      'counters._total': FieldValue.increment(1),
      lastEventAt:       FieldValue.serverTimestamp(),
    });

    // ── d. Alert on CRITICAL events ───────────────────────────────────────
    if (data.severity === 'CRITICAL') {
      // Write to a top-level alerts collection for proctor dashboard
      await db.collection('alerts').add({
        sessionId,
        logId,
        type:       data.type,
        severity:   data.severity,
        source:     data.source,
        metadata:   data.metadata || {},
        timestamp:  data.timestamp,
        createdAt:  FieldValue.serverTimestamp(),
        acknowledged: false,
      });
    }
  }
);

// ═══════════════════════════════════════════════════════════════════════════════
//  3. onSessionEnd — Compute integrity report when session status → COMPLETED
// ═══════════════════════════════════════════════════════════════════════════════

exports.onSessionEnd = onDocumentUpdated(
  { document: 'sessions/{sessionId}', secrets: [HMAC_SECRET] },
  async (event) => {
    const before = event.data.before.data();
    const after  = event.data.after.data();

    // Only trigger when status transitions to COMPLETED
    if (before.status === 'COMPLETED' || after.status !== 'COMPLETED') return;

    const sessionId = event.params.sessionId;
    const secret    = HMAC_SECRET.value();

    // Read all logs in order and verify the hash chain
    const logsSnap = await db
      .collection(`sessions/${sessionId}/logs`)
      .orderBy('seq', 'asc')
      .get();

    let prevHash     = '0'.repeat(64);
    let chainValid   = true;
    let totalEvents  = 0;
    let brokenSeq    = null;
    let tamperedLogs = 0;

    logsSnap.forEach((doc) => {
      totalEvents++;
      const data = doc.data();

      if (data._tamperDetected) tamperedLogs++;

      // Verify chain link
      const { hmac, hash, firestoreTimestamp, syncedAt,
              _serverVerified, _tamperDetected, _verifiedAt, _anomalies,
              ...base } = data;
      const expectedHash = createHash('sha256')
        .update(JSON.stringify(base) + hmac, 'utf8')
        .digest('hex');

      if (hash !== expectedHash || data.prevHash !== prevHash) {
        if (chainValid) {
          chainValid = false;
          brokenSeq  = data.seq;
        }
      }
      prevHash = hash;
    });

    // Write the integrity report
    await db.doc(`sessions/${sessionId}`).update({
      integrityReport: {
        chainValid,
        totalEvents,
        brokenSeq,
        tamperedLogs,
        verifiedAt: FieldValue.serverTimestamp(),
      },
      integrityStatus: chainValid && tamperedLogs === 0 ? 'VERIFIED' : 'COMPROMISED',
    });

    console.info(
      `[IntegrityReport] session=${sessionId} events=${totalEvents} ` +
      `chain=${chainValid ? 'OK' : 'BROKEN@' + brokenSeq} tampered=${tamperedLogs}`
    );
  }
);

// ═══════════════════════════════════════════════════════════════════════════════
//  4. getExamConfig — Sanitized exam config for the Electron client
// ═══════════════════════════════════════════════════════════════════════════════
//
// The client calls this INSTEAD of reading the exam document directly,
// so we can strip internal fields and validate the request.

exports.getExamConfig = onRequest(async (req, res) => {
  if (req.method !== 'GET') {
    res.status(405).json({ error: 'Method not allowed' });
    return;
  }

  // Verify the Firebase ID token from the Authorization header
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) {
    res.status(401).json({ error: 'Missing or invalid Authorization header' });
    return;
  }

  let decodedToken;
  try {
    decodedToken = await getAuth().verifyIdToken(authHeader.split('Bearer ')[1]);
  } catch (err) {
    res.status(401).json({ error: 'Invalid token', message: err.message });
    return;
  }

  const examId = decodedToken.examId;
  if (!examId) {
    res.status(403).json({ error: 'No examId in token claims' });
    return;
  }

  const examSnap = await db.doc(`exams/${examId}`).get();
  if (!examSnap.exists) {
    res.status(404).json({ error: 'Exam not found' });
    return;
  }

  const exam = examSnap.data();

  // Return only the fields the client needs — never expose internal admin fields
  res.status(200).json({
    examId,
    title:          exam.title,
    duration:       exam.duration,
    allowedDomains: exam.allowedDomains || [],
    allowedUrl:     exam.allowedUrl,
    paused:         exam.paused || false,
    terminated:     exam.terminated || false,
    config:         exam.config || {},
  });
});
