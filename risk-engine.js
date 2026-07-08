/**
 * risk-engine.js — Session Risk Scoring Engine
 *
 * ════════════════════════════════════════════════════════════════════════════
 *  Design goals
 * ════════════════════════════════════════════════════════════════════════════
 *
 *  1. INTERPRETABLE  — every score point traces back to a specific event;
 *                      the proctor can see WHY the score is what it is.
 *
 *  2. CONFIGURABLE   — all weights, thresholds, decay, and cooldowns are
 *                      set via a config object.  Different exam types can
 *                      have completely different scoring profiles.
 *
 *  3. NOISE-RESILIENT — a single focus-loss blip (< 2s) doesn't flag an
 *                       exam.  Cooldown windows, decay, and grace periods
 *                       distinguish legitimate interruptions from cheating.
 *
 *  4. CLIENT + SERVER — the client computes a LIVE score for immediate UI
 *                       feedback (warnings, auto-terminate).  The server
 *                       recomputes from the audit log for the official record.
 *                       They use the exact same algorithm — this file.
 *
 * ════════════════════════════════════════════════════════════════════════════
 *  Scoring algorithm
 * ════════════════════════════════════════════════════════════════════════════
 *
 *  score = Σ  weight(event) × multiplier(frequency) − decay(time)
 *
 *  ┌─ Base weight ──────────────────────────────────────────────────────────┐
 *  │ Each event type has a base weight (points). Configured per-event.     │
 *  └────────────────────────────────────────────────────────────────────────┘
 *
 *  ┌─ Frequency multiplier ─────────────────────────────────────────────────┐
 *  │ Repeated events of the SAME type within a cooldown window are scaled: │
 *  │   occurrence 1:  ×1.0                                                 │
 *  │   occurrence 2:  ×1.2                                                 │
 *  │   occurrence 3+: ×1.5                                                 │
 *  │ This makes persistent cheating behaviour score higher than a one-off. │
 *  └────────────────────────────────────────────────────────────────────────┘
 *
 *  ┌─ Time decay ───────────────────────────────────────────────────────────┐
 *  │ Every `decayIntervalMs` (default 60 s), the cumulative score decays   │
 *  │ by `decayPoints` (default 2).  This ensures a single focus-loss early │
 *  │ in a 3-hour exam doesn't doom the candidate.                          │
 *  │ The score never decays below 0.                                       │
 *  └────────────────────────────────────────────────────────────────────────┘
 *
 *  ┌─ Grace periods (noise handling) ───────────────────────────────────────┐
 *  │ FOCUS_LOSS:      Only scores if the blur lasted > `focusGraceMs`      │
 *  │                  (default 2000 ms).  A sub-2s Alt+Tab on Windows      │
 *  │                  (e.g. toast notification) is ignored.                 │
 *  │                                                                       │
 *  │ NO_FACE:         Only scores after `noFaceGraceCount` consecutive     │
 *  │                  NO_FACE detections (default 2).  A single missed     │
 *  │                  frame from bad lighting doesn't count.               │
 *  │                                                                       │
 *  │ FACE_PRESENT:    Worth 0 points and resets the NO_FACE counter.       │
 *  │                  This rewards the candidate for returning to frame.   │
 *  └────────────────────────────────────────────────────────────────────────┘
 *
 * ════════════════════════════════════════════════════════════════════════════
 *  Thresholds → Actions
 * ════════════════════════════════════════════════════════════════════════════
 *
 *  ┌─────────────┬────────┬──────────────────────────────────────────────┐
 *  │ Level       │ Score  │ Action                                       │
 *  ├─────────────┼────────┼──────────────────────────────────────────────┤
 *  │ LOW         │ 0–29   │ Normal — no action                           │
 *  │ MEDIUM      │ 30–59  │ WARNING — banner shown to candidate          │
 *  │ HIGH        │ 60–89  │ FLAG — session flagged for proctor review     │
 *  │ CRITICAL    │ 90+    │ TERMINATE — auto-end the exam                │
 *  └─────────────┴────────┴──────────────────────────────────────────────┘
 *
 *  All thresholds are configurable.  The TERMINATE action can be disabled
 *  (`autoTerminate: false`) so the proctor makes the final call.
 */

'use strict';

const { EventEmitter } = require('events');

// ─── Default scoring configuration ──────────────────────────────────────────

const DEFAULT_CONFIG = Object.freeze({

  // ── Per-event weights (points) ────────────────────────────────────────────
  weights: {
    FOCUS_LOSS:          10,
    CLOSE_ATTEMPT:       20,
    FULLSCREEN_EXIT:      5,

    PROCESS_DETECTED:    25,   // HIGH — screen recorder, remote access, etc.
    PROCESS_RESOLVED:    -5,   // Reward: candidate closed the flagged app

    FACE_NO_FACE:        15,   // After grace period
    FACE_MULTIPLE:       30,   // Someone else visible — strong cheating signal
    FACE_PRESENT:         0,   // Normal — resets NO_FACE counter
    FACE_ERROR:           5,   // Generic face detection error
    CAMERA_OFF:          20,   // Camera denied / disabled / disconnected
    DISPLAY_CHANGE:       5,   // Monitor metrics changed (less severe)

    NAV_BLOCKED:          8,
    SHORTCUT_BLOCKED:     3,

    // Low-noise events that aren't scored directly
    SESSION_START:        0,
    SESSION_END:          0,
    FOCUS_RESTORED:       0,
    REQUEST_BLOCKED:      0,
    WARNING:              0,
    ADMIN_ACTION:         0,
    FACE_ERROR:           5,
  },

  // ── Frequency multiplier tiers ────────────────────────────────────────────
  frequencyMultipliers: [
    { min: 1, max: 1, multiplier: 1.0 },
    { min: 2, max: 2, multiplier: 1.2 },
    { min: 3, max: Infinity, multiplier: 1.5 },
  ],

  // ── Cooldown: how long (ms) before repeated events of the same type
  //    reset their frequency counter.  If 120s pass without another
  //    FOCUS_LOSS, the next one is treated as occurrence 1 again.
  cooldownMs: 120_000,  // 2 minutes

  // ── Time decay ────────────────────────────────────────────────────────────
  decayEnabled:      true,
  decayIntervalMs:   60_000,  // every 60 seconds
  decayPoints:       2,       // subtract 2 points per interval

  // ── Grace periods (noise suppression) ─────────────────────────────────────
  focusGraceMs:      2000,    // ignore blur < 2s
  noFaceGraceCount:  2,       // need 2 consecutive NO_FACE before scoring

  // ── Thresholds ────────────────────────────────────────────────────────────
  thresholds: {
    LOW:      0,
    MEDIUM:   30,
    HIGH:     60,
    CRITICAL: 90,
  },

  // ── Actions ───────────────────────────────────────────────────────────────
  autoTerminate: false,   // true = auto-quit when CRITICAL threshold hit
  maxScore:      150,     // hard cap to prevent runaway scores
});

// ─── Risk levels ────────────────────────────────────────────────────────────

const RISK_LEVELS = Object.freeze({
  LOW:      'LOW',
  MEDIUM:   'MEDIUM',
  HIGH:     'HIGH',
  CRITICAL: 'CRITICAL',
});

// ─── RiskEngine class ───────────────────────────────────────────────────────

class RiskEngine extends EventEmitter {
  /**
   * @param {object} [config] — merged with DEFAULT_CONFIG
   */
  constructor(config = {}) {
    super();

    // Deep merge: user config overrides defaults
    this._config = {
      ...DEFAULT_CONFIG,
      ...config,
      weights:    { ...DEFAULT_CONFIG.weights,    ...config.weights },
      thresholds: { ...DEFAULT_CONFIG.thresholds, ...config.thresholds },
      frequencyMultipliers: config.frequencyMultipliers || DEFAULT_CONFIG.frequencyMultipliers,
    };

    // ── State ─────────────────────────────────────────────────────────────
    this._score          = 0;
    this._level          = RISK_LEVELS.LOW;
    this._history        = [];     // { timestamp, type, points, score, level, reason }
    this._typeCounts     = {};     // type → { count, lastSeen }
    this._blurStart      = null;   // timestamp of last blur (for grace period)
    this._noFaceStreak   = 0;      // consecutive NO_FACE detections
    this._decayTimer     = null;
    this._startTime      = Date.now();
  }

  // ─── Lifecycle ──────────────────────────────────────────────────────────

  /** Start the decay timer.  Call after the exam session begins. */
  start() {
    if (this._config.decayEnabled) {
      this._decayTimer = setInterval(() => this._applyDecay(), this._config.decayIntervalMs);
    }
    this._startTime = Date.now();
  }

  /** Stop the decay timer.  Call when the exam ends. */
  stop() {
    if (this._decayTimer) {
      clearInterval(this._decayTimer);
      this._decayTimer = null;
    }
  }

  // ─── Core event ingestion ───────────────────────────────────────────────

  /**
   * Ingest an event from the EventLogger.
   * Returns the score entry { points, score, level, reason, action }.
   *
   * @param {object} event — an event object from event-logger.js
   */
  ingest(event) {
    const { type, metadata = {} } = event;

    // ── Map event type + metadata to a scoring key ──────────────────────
    let scoringKey = type;
    if (type === 'FACE_STATUS') {
      // Sub-classify based on metadata.status
      if      (metadata.status === 'NO_FACE')        scoringKey = 'FACE_NO_FACE';
      else if (metadata.status === 'MULTIPLE_FACES') scoringKey = 'FACE_MULTIPLE';
      else                                           scoringKey = 'FACE_PRESENT';
    }
    // Camera errors (denied / disconnected) score as CAMERA_OFF
    if (type === 'FACE_ERROR' && (metadata.phase === 'camera' || metadata.status === 'CAMERA_ERROR')) {
      scoringKey = 'CAMERA_OFF';
    }

    // ── Look up base weight ─────────────────────────────────────────────
    const baseWeight = this._config.weights[scoringKey] ?? 0;
    if (baseWeight === 0 && scoringKey !== 'FACE_PRESENT') {
      // Zero-weight event — record but don't score
      return this._record(event, 0, 'not scored');
    }

    // ── Grace period checks ─────────────────────────────────────────────
    // Focus loss grace
    if (type === 'FOCUS_LOSS') {
      this._blurStart = Date.now();
      // Don't score yet — wait for FOCUS_RESTORED to measure duration
      return this._record(event, 0, 'awaiting duration measurement');
    }

    if (type === 'FOCUS_RESTORED') {
      if (this._blurStart) {
        const blurDuration = Date.now() - this._blurStart;
        this._blurStart = null;
        if (blurDuration < this._config.focusGraceMs) {
          return this._record(event, 0,
            `focus restored in ${blurDuration}ms (< ${this._config.focusGraceMs}ms grace)`);
        }
        // Score the blur NOW (deferred from FOCUS_LOSS)
        const points = this._computePoints('FOCUS_LOSS', baseWeight);
        return this._applyScore(event, points,
          `focus lost for ${blurDuration}ms (> ${this._config.focusGraceMs}ms grace)`, 'FOCUS_LOSS');
      }
      return this._record(event, 0, 'focus restored (no matching blur)');
    }

    // No-face grace: need consecutive detections
    if (scoringKey === 'FACE_NO_FACE') {
      this._noFaceStreak++;
      if (this._noFaceStreak < this._config.noFaceGraceCount) {
        return this._record(event, 0,
          `no face #${this._noFaceStreak} (grace: need ${this._config.noFaceGraceCount} consecutive)`);
      }
      // Passed grace — score it
      const points = this._computePoints(scoringKey, baseWeight);
      return this._applyScore(event, points,
        `no face streak: ${this._noFaceStreak} consecutive (threshold: ${this._config.noFaceGraceCount})`, scoringKey);
    }

    // Face present resets the no-face counter
    if (scoringKey === 'FACE_PRESENT') {
      if (this._noFaceStreak > 0) {
        this._noFaceStreak = 0;
        return this._record(event, 0, 'face returned — no-face streak reset');
      }
      return this._record(event, 0, 'face present (normal)');
    }

    // Process resolved gives negative points (reward)
    if (scoringKey === 'PROCESS_RESOLVED') {
      const points = baseWeight; // negative
      return this._applyScore(event, points, 'suspicious process closed — reward', scoringKey);
    }

    // ── Standard scoring ────────────────────────────────────────────────
    const points = this._computePoints(scoringKey, baseWeight);
    const reason = this._buildReason(scoringKey, metadata);
    return this._applyScore(event, points, reason, scoringKey);
  }

  // ─── Score computation helpers ──────────────────────────────────────────

  _computePoints(scoringKey, baseWeight) {
    const freq       = this._getFrequency(scoringKey);
    const multiplier = this._getMultiplier(freq);
    return Math.round(baseWeight * multiplier);
  }

  _getFrequency(scoringKey) {
    const now   = Date.now();
    const entry = this._typeCounts[scoringKey];

    if (!entry || (now - entry.lastSeen) > this._config.cooldownMs) {
      // Cooldown expired or first occurrence — reset counter
      this._typeCounts[scoringKey] = { count: 1, lastSeen: now };
      return 1;
    }

    entry.count++;
    entry.lastSeen = now;
    return entry.count;
  }

  _getMultiplier(frequency) {
    for (const tier of this._config.frequencyMultipliers) {
      if (frequency >= tier.min && frequency <= tier.max) {
        return tier.multiplier;
      }
    }
    return 1.0;
  }

  _applyScore(event, points, reason, scoringKey) {
    const prevScore = this._score;
    const prevLevel = this._level;

    this._score = Math.max(0, Math.min(this._config.maxScore, this._score + points));
    this._level = this._computeLevel();

    const entry = {
      timestamp:  event.timestamp || new Date().toISOString(),
      eventId:    event.id,
      type:       event.type,
      scoringKey,
      points,
      score:      this._score,
      prevScore,
      level:      this._level,
      reason,
      action:     this._determineAction(prevLevel, this._level),
    };

    this._history.push(entry);
    if (this._history.length > 1000) this._history.shift(); // cap memory

    // Emit level-change events
    if (this._level !== prevLevel) {
      this.emit('level-change', {
        from:   prevLevel,
        to:     this._level,
        score:  this._score,
        action: entry.action,
        reason,
      });
    }

    // Emit on every scored event (for real-time UI updates)
    this.emit('score-update', entry);

    return entry;
  }

  _record(event, points, reason) {
    const entry = {
      timestamp:  event.timestamp || new Date().toISOString(),
      eventId:    event.id,
      type:       event.type,
      points,
      score:      this._score,
      level:      this._level,
      reason,
      action:     null,
    };
    this._history.push(entry);
    if (this._history.length > 1000) this._history.shift();
    return entry;
  }

  // ─── Level + action resolution ──────────────────────────────────────────

  _computeLevel() {
    const t = this._config.thresholds;
    if (this._score >= t.CRITICAL) return RISK_LEVELS.CRITICAL;
    if (this._score >= t.HIGH)     return RISK_LEVELS.HIGH;
    if (this._score >= t.MEDIUM)   return RISK_LEVELS.MEDIUM;
    return RISK_LEVELS.LOW;
  }

  _determineAction(prevLevel, newLevel) {
    if (newLevel === prevLevel) return null;
    switch (newLevel) {
      case RISK_LEVELS.MEDIUM:   return 'WARNING';
      case RISK_LEVELS.HIGH:     return 'FLAG';
      case RISK_LEVELS.CRITICAL: return this._config.autoTerminate ? 'TERMINATE' : 'FLAG_CRITICAL';
      default:                   return null; // de-escalated back to LOW
    }
  }

  // ─── Time decay ─────────────────────────────────────────────────────────

  _applyDecay() {
    if (this._score <= 0) return;
    const prevScore = this._score;
    const prevLevel = this._level;

    this._score = Math.max(0, this._score - this._config.decayPoints);
    this._level = this._computeLevel();

    if (this._level !== prevLevel) {
      this.emit('level-change', {
        from:   prevLevel,
        to:     this._level,
        score:  this._score,
        action: null,
        reason: `time decay: −${this._config.decayPoints} points`,
      });
    }

    this.emit('decay', {
      prevScore,
      score:    this._score,
      level:    this._level,
      decayed:  prevScore - this._score,
    });
  }

  // ─── Reason builder (interpretability) ──────────────────────────────────

  _buildReason(scoringKey, metadata) {
    switch (scoringKey) {
      case 'FOCUS_LOSS':
        return 'candidate switched away from the exam window';
      case 'CLOSE_ATTEMPT':
        return 'candidate attempted to close the secure browser';
      case 'FULLSCREEN_EXIT':
        return 'candidate exited fullscreen mode';
      case 'PROCESS_DETECTED':
        return `suspicious process detected: ${metadata.name || 'unknown'} [${metadata.category || ''}]`;
      case 'FACE_MULTIPLE':
        return `${metadata.faceCount || '2+'} faces detected — possible third-party assistance`;
      case 'FACE_NO_FACE':
        return 'candidate not visible on camera';
      case 'DISPLAY_VIOLATION':
        return `${metadata.count || 2} monitors detected — multi-display violation`;
      case 'DISPLAY_CHANGE':
        return 'display configuration changed';
      case 'NAV_BLOCKED':
        return `navigation attempt blocked: ${metadata.url || 'unknown URL'}`;
      case 'SHORTCUT_BLOCKED':
        return `keyboard shortcut blocked: ${metadata.key || 'unknown key'}`;
      default:
        return scoringKey;
    }
  }

  // ─── Accessors ──────────────────────────────────────────────────────────

  getScore()   { return this._score; }
  getLevel()   { return this._level; }
  getHistory() { return [...this._history]; }
  getConfig()  { return { ...this._config }; }

  /** Full snapshot for proctor dashboard or session summary. */
  getSummary() {
    const criticalEvents = this._history.filter(e => e.points >= 20);
    const breakdown = {};
    for (const entry of this._history) {
      if (entry.points > 0) {
        const key = entry.scoringKey || entry.type;
        breakdown[key] = (breakdown[key] || 0) + entry.points;
      }
    }

    return {
      score:          this._score,
      level:          this._level,
      totalEvents:    this._history.length,
      criticalEvents: criticalEvents.length,
      breakdown,
      elapsedMs:      Date.now() - this._startTime,
      config: {
        thresholds:   this._config.thresholds,
        autoTerminate: this._config.autoTerminate,
      },
    };
  }
}

module.exports = { RiskEngine, RISK_LEVELS, DEFAULT_CONFIG };
