/**
 * sync-client.js — Audit Log Sync Client
 *
 * Event pipeline:  Generation → Disk (NDJSON) → SyncClient → Backend API
 *
 * Design:
 *   - Reads pending (un-synced) events from EventLogger in batches
 *   - Signs each batch envelope with HMAC so the server can verify origin
 *   - Sends via HTTP POST to the configured endpoint
 *   - On success: marks events as synced in sync-state.json
 *   - On failure: retries with exponential back-off (non-blocking)
 *   - Runs on a periodic timer OR can be triggered manually (e.g. on submit)
 *
 * ─── Batch envelope schema ────────────────────────────────────────────────────
 *  {
 *    "batchId":   string   — UUID per transmission attempt
 *    "sessionId": string   — exam session identifier
 *    "sentAt":    string   — ISO-8601 UTC
 *    "eventCount": number
 *    "events":    Event[]  — from event-logger NDJSON (each already HMAC-signed)
 *    "batchHmac": string   — HMAC-SHA256(secret, batchId+sessionId+sentAt+eventCount)
 *                           server uses this to authenticate the envelope itself
 *  }
 */

'use strict';

const { createHmac, randomUUID } = require('crypto');
const { EventEmitter } = require('events');

// net module for checking connectivity (pure Node.js, no npm needed)
const dns = require('dns').promises;

class SyncClient extends EventEmitter {
  /**
   * @param {import('./event-logger').EventLogger} logger
   * @param {object} config
   * @param {string}  config.endpoint         — POST URL, e.g. "https://api.company.com/exam/logs"
   * @param {string}  config.hmacSecret       — must match event-logger secret
   * @param {string}  config.apiKey           — Bearer token / API key header value
   * @param {number}  [config.batchSize=50]   — events per POST
   * @param {number}  [config.intervalMs=30000] — periodic sync interval
   * @param {number}  [config.maxRetries=5]
   */
  constructor(logger, config = {}) {
    super();
    this._logger      = logger;
    this._endpoint    = config.endpoint    || null;
    this._secret      = config.hmacSecret  || 'seb-audit-key-v1-CHANGE-IN-PRODUCTION';
    this._apiKey      = config.apiKey      || '';
    this._batchSize   = config.batchSize   ?? 50;
    this._intervalMs  = config.syncIntervalMs ?? 30_000;
    this._maxRetries  = config.maxRetries  ?? 5;
    this._retryDelay  = 2000;              // base back-off in ms (doubles each retry)
    this._timer       = null;
    this._syncing     = false;
  }

  /** Start periodic background sync. */
  start() {
    if (!this._endpoint) {
      console.info('[SyncClient] No endpoint configured — offline mode only');
      return;
    }
    this._scheduleNext();
    console.info(`[SyncClient] Periodic sync started — every ${this._intervalMs / 1000}s → ${this._endpoint}`);
  }

  /** Stop the sync timer. */
  stop() {
    if (this._timer) { clearTimeout(this._timer); this._timer = null; }
  }

  /**
   * Trigger an immediate sync (e.g. called on exam submission).
   * Returns a promise that resolves when all pending events are flushed or
   * max retries are exhausted.
   */
  async flush() {
    await this._doSync();
  }

  // ─── Internal ──────────────────────────────────────────────────────────────

  _scheduleNext() {
    this._timer = setTimeout(async () => {
      await this._doSync();
      this._scheduleNext();
    }, this._intervalMs);
  }

  async _doSync() {
    if (this._syncing || !this._endpoint) return;
    this._syncing = true;

    try {
      // Connectivity check (fast DNS lookup)
      const online = await this._isOnline();
      if (!online) {
        console.info('[SyncClient] No connectivity — deferring sync');
        this.emit('offline');
        return;
      }

      // Drain all pending events in batches
      let pending;
      while ((pending = this._logger.getPendingBatch(this._batchSize)).length > 0) {
        const sent = await this._sendWithRetry(pending);
        if (!sent) break;  // network failure even after retries — stop draining
      }
    } finally {
      this._syncing = false;
    }
  }

  async _sendWithRetry(events) {
    let delay = this._retryDelay;
    for (let attempt = 1; attempt <= this._maxRetries; attempt++) {
      try {
        await this._post(events);
        this._logger.markSynced(events.map(e => e.id));
        this.emit('synced', { count: events.length });
        return true;
      } catch (err) {
        console.warn(`[SyncClient] Attempt ${attempt}/${this._maxRetries} failed: ${err.message}`);
        if (attempt < this._maxRetries) {
          await this._sleep(delay);
          delay = Math.min(delay * 2, 60_000); // cap at 60 s
        }
      }
    }
    this.emit('sync-failed', { count: events.length });
    return false;
  }

  async _post(events) {
    const batchId   = randomUUID();
    const sentAt    = new Date().toISOString();
    const sessionId = this._logger.getSessionId();

    // Sign the batch envelope (separate from per-event HMAC)
    const envelopeSeed = batchId + sessionId + sentAt + events.length;
    const batchHmac    = createHmac('sha256', this._secret).update(envelopeSeed).digest('hex');

    const payload = {
      batchId,
      sessionId,
      sentAt,
      eventCount: events.length,
      events,
      batchHmac,
    };

    const response = await fetch(this._endpoint, {
      method:  'POST',
      headers: {
        'Content-Type':  'application/json',
        'Authorization': `Bearer ${this._apiKey}`,
        'X-Session-Id':  sessionId,
        'X-Batch-Id':    batchId,
      },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(15_000), // 15 s timeout
    });

    if (!response.ok) {
      const body = await response.text().catch(() => '');
      throw new Error(`HTTP ${response.status}: ${body.slice(0, 200)}`);
    }

    return response;
  }

  async _isOnline() {
    try {
      await dns.lookup('8.8.8.8');
      return true;
    } catch {
      return false;
    }
  }

  _sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

module.exports = SyncClient;
