/**
 * config-manager.js — Dynamic Configuration System
 *
 * ════════════════════════════════════════════════════════════════════════════
 *  Design Principles
 * ════════════════════════════════════════════════════════════════════════════
 *
 *  1. Single Source of Truth
 *     All subsystems query this manager instead of reading config.json directly.
 *
 *  2. Merge Hierarchy
 *     Hardcoded Defaults < config.json (Base) < Backend Exam Config (Overrides)
 *
 *  3. Reactivity
 *     Extends EventEmitter. When a config value changes (e.g., via Firebase push),
 *     it emits `update:category.key` so subsystems can adjust policies live.
 *
 *  4. Deep Merging
 *     Objects and arrays are merged intelligently.
 *
 * ════════════════════════════════════════════════════════════════════════════
 */

'use strict';

const fs = require('fs');
const { EventEmitter } = require('events');

const DEFAULT_CONFIG = {
  general: {
    windowTitle: 'Secure Assessment Browser',
    fullscreen: true,
    kiosk: false,
    adminExitShortcut: 'CommandOrControl+Alt+Q',
    refocusDelayMs: 200,
    logViolations: true,
  },
  exam: {
    allowedUrl: 'https://example.com',
    allowedDomains: ['example.com'],
    allowedCDNs: [],
  },
  security: {
    processMonitoring: true,
    processCheckIntervalMs: 5000,
    blockMultipleDisplays: true,
    allowClipboard: false,
    displayCheckIntervalMs: 10000,
  },
  proctoring: {
    enabled: true,
    intervalMs: 5000,
  },
  networkGuard: {
    autoAllowSubdomains: true,
    injectCSP: true,
    stripHeaders: true,
    blockDataNav: true,
  },
  riskScoring: {
    autoTerminate: false,
    maxScore: 150,
    decayEnabled: true,
    decayIntervalMs: 60000,
    decayPoints: 2,
    focusGraceMs: 2000,
    noFaceGraceCount: 2,
    thresholds: {
      LOW: 0,
      MEDIUM: 30,
      HIGH: 60,
      CRITICAL: 90,
    },
  },
  sync: {
    endpoint: null,
    apiKey: '',
    intervalMs: 30000,
    hmacSecret: 'seb-audit-key-v1-CHANGE-IN-PRODUCTION',
  },
};

class ConfigManager extends EventEmitter {
  constructor() {
    super();
    this._config = this._deepClone(DEFAULT_CONFIG);
  }

  /**
   * Load base JSON and apply any initial overrides.
   * @param {string} jsonPath - Path to config.json
   * @param {object} [backendOverrides] - Exam-specific config from API/Firebase
   */
  async load(jsonPath, backendOverrides = {}) {
    let baseConfig = {};
    try {
      if (fs.existsSync(jsonPath)) {
        baseConfig = JSON.parse(fs.readFileSync(jsonPath, 'utf8'));
      }
    } catch (err) {
      console.error('[ConfigManager] Failed to read base config.json:', err.message);
    }

    // Merge: Defaults <- config.json <- Backend
    let merged = this._deepMerge(DEFAULT_CONFIG, baseConfig);
    merged = this._deepMerge(merged, backendOverrides);

    this._updateState(merged);
    console.info('[ConfigManager] Configuration loaded.');
    return this.getAll();
  }

  /**
   * Apply a partial runtime update and emit change events.
   * @param {object} partialConfig
   */
  update(partialConfig) {
    const updated = this._deepMerge(this._config, partialConfig);
    this._updateState(updated);
  }

  /** Get the entire configuration object. */
  getAll() {
    return this._deepClone(this._config);
  }

  /** Get a specific configuration section (e.g., 'exam'). */
  get(section) {
    return this._config[section] ? this._deepClone(this._config[section]) : null;
  }

  /** Get a specific value using dot notation (e.g., 'security.allowClipboard'). */
  getValue(path, defaultValue) {
    const keys = path.split('.');
    let current = this._config;
    for (const key of keys) {
      if (current === undefined || current === null) return defaultValue;
      current = current[key];
    }
    return current !== undefined ? current : defaultValue;
  }

  // ─── Private Helpers ────────────────────────────────────────────────────────

  _updateState(newConfig) {
    const diffs = this._findDiffs(this._config, newConfig);
    this._config = this._deepClone(newConfig);

    // Emit fine-grained events for every changed path
    for (const { path, newValue } of diffs) {
      this.emit(`update:${path}`, newValue);
    }
    if (diffs.length > 0) {
      this.emit('update', this.getAll());
    }
  }

  _deepMerge(target, source) {
    const result = this._deepClone(target);
    if (!source || typeof source !== 'object') return result;

    for (const key in source) {
      if (!Object.prototype.hasOwnProperty.call(source, key)) continue;

      const val = source[key];
      if (Array.isArray(val)) {
        result[key] = [...val]; // Overwrite arrays entirely (cleaner for domains)
      } else if (val !== null && typeof val === 'object') {
        result[key] = this._deepMerge(result[key] || {}, val);
      } else {
        result[key] = val;
      }
    }
    return result;
  }

  _findDiffs(oldObj, newObj, pathPrefix = '') {
    const diffs = [];
    const keys = new Set([...Object.keys(oldObj || {}), ...Object.keys(newObj || {})]);

    for (const key of keys) {
      const oldVal = oldObj?.[key];
      const newVal = newObj?.[key];
      const currentPath = pathPrefix ? `${pathPrefix}.${key}` : key;

      if (JSON.stringify(oldVal) !== JSON.stringify(newVal)) {
        diffs.push({ path: currentPath, newValue: newVal });
        if (oldVal !== null && typeof oldVal === 'object' && newVal !== null && typeof newVal === 'object' && !Array.isArray(newVal)) {
          diffs.push(...this._findDiffs(oldVal, newVal, currentPath));
        }
      }
    }
    return diffs;
  }

  _deepClone(obj) {
    if (obj === undefined) return undefined;
    return JSON.parse(JSON.stringify(obj));
  }
}

// Singleton export
module.exports = new ConfigManager();
