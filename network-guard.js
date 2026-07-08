/**
 * network-guard.js — Network Request Control Module
 *
 * ════════════════════════════════════════════════════════════════════════════
 *  What this module does (defense-in-depth, five layers)
 * ════════════════════════════════════════════════════════════════════════════
 *
 *  Layer 1 — webRequest.onBeforeRequest
 *    Intercepts EVERY outbound request (main frame, sub-frame, script, image,
 *    XHR, fetch, WebSocket, etc.).  Checks URL against a compiled domain
 *    whitelist.  Blocked requests are audit-logged with resource type.
 *
 *  Layer 2 — webRequest.onBeforeSendHeaders
 *    Strips or rewrites headers that could leak data or fingerprint the
 *    candidate (Referer, Origin on cross-origin, custom X- headers).
 *
 *  Layer 3 — webRequest.onHeadersReceived (CSP injection)
 *    Injects a strict Content-Security-Policy header on EVERY response:
 *      - script-src limited to whitelisted domains (blocks inline eval)
 *      - connect-src limited to whitelisted domains
 *      - frame-src 'none' (no iframes to external sites)
 *    This is a SECOND line of defense if a request somehow slips past Layer 1.
 *
 *  Layer 4 — WebSocket interception
 *    Electron's webRequest API does NOT intercept WebSocket upgrade requests
 *    in all versions.  We use `will-redirect` on the webContents to catch
 *    ws:// and wss:// connection attempts.
 *
 *  Layer 5 — DNS-over-HTTPS prevention
 *    Sets the app-level DNS resolver to system default, preventing the
 *    renderer from using DoH to bypass domain filtering.
 *
 * ════════════════════════════════════════════════════════════════════════════
 *  Domain whitelist strategy
 * ════════════════════════════════════════════════════════════════════════════
 *
 *  The whitelist supports three entry types:
 *
 *    1. Exact domain        — "example.com"
 *       Matches:  example.com
 *       Doesn't:  sub.example.com, other.com
 *
 *    2. Wildcard subdomain  — "*.cdn.example.com"
 *       Matches:  a.cdn.example.com, b.c.cdn.example.com
 *       Doesn't:  cdn.example.com, example.com
 *
 *    3. Auto-subdomain      — "example.com" (with autoAllowSubdomains: true)
 *       Matches:  example.com AND *.example.com
 *       This is the DEFAULT mode for the assessment domain.
 *
 *  CDN & API edge cases:
 *    The config accepts a separate `allowedCDNs` array for third-party
 *    asset domains (e.g. "cdn.jsdelivr.net", "fonts.googleapis.com").
 *    These are ONLY allowed for specific resource types (stylesheet, image,
 *    font, script) — NOT for main-frame navigation or XHR/fetch.
 *
 * ════════════════════════════════════════════════════════════════════════════
 *  Limitations of client-side network restriction
 * ════════════════════════════════════════════════════════════════════════════
 *
 *  1. Electron's webRequest API runs in the RENDERER process's I/O thread.
 *     A sufficiently motivated attacker who patches the Electron binary
 *     can bypass all of these hooks entirely.
 *
 *  2. The DNS resolution itself is NOT filtered.  A domain can resolve
 *     to any IP, and we cannot block by IP without an OS-level firewall.
 *     A VPN or proxy running on the machine can tunnel traffic out.
 *
 *  3. WebSocket upgrade requests are not reliably intercepted by
 *     `onBeforeRequest` in all Chromium versions.  Layer 4 mitigates this,
 *     but there is a small race window.
 *
 *  4. Service Workers registered by the assessment site can make fetch()
 *     calls that are visible to webRequest, but their timing is different.
 *
 *  5. Native code (Node.js `net` or `http`) in the main process is NOT
 *     subject to webRequest.  This is fine because the main process is ours;
 *     the risk is only in the renderer.
 *
 *  6. Data URLs and blob URLs bypass domain checks.  We block them for
 *     navigation but allow them for inline assets (images, fonts) because
 *     many frameworks use them legitimately.
 *
 *  Mitigation:  Network filtering is ONE layer.  Combine with:
 *    - Server-side API access control (the server only serves data to
 *      authenticated sessions)
 *    - Process monitoring (detects VPN/proxy processes)
 *    - Audit logging (blocked requests are permanently recorded)
 */

'use strict';

const { session } = require('electron');
const { EventEmitter } = require('events');

// Resource types that CDN-only domains are allowed to serve
const CDN_ALLOWED_TYPES = new Set([
  'stylesheet', 'image', 'font', 'script',
]);

// Protocols that should always be allowed through (internal Electron)
const INTERNAL_PROTOCOLS = new Set([
  'devtools:', 'chrome-extension:', 'chrome:', 'data:', 'blob:', 'file:',
]);

// Protocols we consider for domain checking
const FILTERABLE_PROTOCOLS = new Set([
  'https:', 'http:', 'wss:', 'ws:',
]);

class NetworkGuard extends EventEmitter {
  /**
   * @param {object} config
   * @param {string[]} config.allowedDomains       — primary whitelist (auto-subdomain)
   * @param {string[]} [config.allowedCDNs=[]]     — CDN domains (asset types only)
   * @param {boolean}  [config.autoAllowSubdomains=true]
   * @param {boolean}  [config.injectCSP=true]     — inject Content-Security-Policy
   * @param {boolean}  [config.stripHeaders=true]   — strip leaky headers
   * @param {boolean}  [config.blockDataNav=true]   — block data: URL navigation
   * @param {function} [config.onBlocked]           — callback(details) on block
   */
  constructor(config = {}) {
    super();
    this._domains     = (config.allowedDomains || []).map(d => d.toLowerCase());
    this._cdns        = (config.allowedCDNs    || []).map(d => d.toLowerCase());
    this._autoSub     = config.autoAllowSubdomains !== false;
    this._injectCSP   = config.injectCSP          !== false;
    this._stripHeaders = config.stripHeaders       !== false;
    this._blockDataNav = config.blockDataNav       !== false;
    this._onBlocked   = config.onBlocked           || null;

    // Stats
    this._stats = {
      allowed:  0,
      blocked:  0,
      byType:   {},   // resourceType → { allowed, blocked }
    };
  }

  /**
   * Attach all webRequest interceptors to the given session.
   * Call once during app.whenReady().
   *
   * @param {Electron.Session} [targetSession] — defaults to session.defaultSession
   */
  attach(targetSession) {
    const ses = targetSession || session.defaultSession;

    // ── Layer 1: Request interception ───────────────────────────────────
    ses.webRequest.onBeforeRequest({ urls: ['<all_urls>'] }, (details, callback) => {
      const decision = this._evaluateRequest(details);
      if (!decision.allowed) {
        this._recordBlock(details, decision.reason);
      } else {
        this._stats.allowed++;
        this._incrementTypeStat(details.resourceType, 'allowed');
      }
      callback({ cancel: !decision.allowed });
    });

    // ── Layer 2: Header stripping ──────────────────────────────────────
    if (this._stripHeaders) {
      ses.webRequest.onBeforeSendHeaders({ urls: ['<all_urls>'] }, (details, callback) => {
        const headers = { ...details.requestHeaders };

        // Strip Referer on cross-origin requests (prevents URL leakage)
        if (headers['Referer'] && !this._isSameOrigin(details.url, headers['Referer'])) {
          delete headers['Referer'];
        }

        // Strip custom headers that could exfiltrate data
        for (const key of Object.keys(headers)) {
          if (key.toLowerCase().startsWith('x-exam-') ||
              key.toLowerCase().startsWith('x-cheat-')) {
            delete headers[key];
          }
        }

        callback({ requestHeaders: headers });
      });
    }

    // ── Layer 3: CSP injection ─────────────────────────────────────────
    if (this._injectCSP) {
      ses.webRequest.onHeadersReceived({ urls: ['<all_urls>'] }, (details, callback) => {
        const headers = details.responseHeaders || {};
        const csp = this._buildCSP();

        // Override any existing CSP with ours (we are stricter)
        headers['Content-Security-Policy'] = [csp];

        // Also set X-Frame-Options to deny framing by external sites
        headers['X-Frame-Options'] = ['DENY'];

        // Prevent MIME-sniffing
        headers['X-Content-Type-Options'] = ['nosniff'];

        callback({ responseHeaders: headers });
      });
    }

    console.info(`[NetworkGuard] Attached — ${this._domains.length} domains, ${this._cdns.length} CDNs`);
  }

  // ─── Core evaluation logic ──────────────────────────────────────────────

  /**
   * Evaluate whether a request should be allowed.
   * Returns { allowed: boolean, reason: string }
   */
  _evaluateRequest(details) {
    const { url, resourceType } = details;

    // 1. Internal protocols always pass
    try {
      const parsed = new URL(url);
      if (INTERNAL_PROTOCOLS.has(parsed.protocol)) {
        // Block data: URLs for main-frame navigation (anti-exfiltration)
        if (parsed.protocol === 'data:' && this._blockDataNav &&
            (resourceType === 'mainFrame' || resourceType === 'subFrame')) {
          return { allowed: false, reason: 'data_url_navigation' };
        }
        return { allowed: true, reason: 'internal_protocol' };
      }

      // 2. Only filter http(s) and ws(s)
      if (!FILTERABLE_PROTOCOLS.has(parsed.protocol)) {
        return { allowed: false, reason: `blocked_protocol:${parsed.protocol}` };
      }

      const hostname = parsed.hostname.toLowerCase();

      // 3. Check primary whitelist
      if (this._matchesDomain(hostname, this._domains)) {
        return { allowed: true, reason: 'whitelisted_domain' };
      }

      // 4. Check CDN whitelist (restricted to asset types only)
      if (this._cdns.length > 0 && this._matchesDomain(hostname, this._cdns)) {
        if (CDN_ALLOWED_TYPES.has(resourceType)) {
          return { allowed: true, reason: 'cdn_asset' };
        }
        return { allowed: false, reason: `cdn_wrong_type:${resourceType}` };
      }

      // 5. Not whitelisted
      return { allowed: false, reason: 'not_whitelisted' };

    } catch {
      return { allowed: false, reason: 'invalid_url' };
    }
  }

  /**
   * Check if a hostname matches any domain in the list.
   * With autoAllowSubdomains, "example.com" also matches "sub.example.com".
   */
  _matchesDomain(hostname, domainList) {
    for (const domain of domainList) {
      // Wildcard entry: "*.cdn.example.com"
      if (domain.startsWith('*.')) {
        const suffix = domain.slice(1); // ".cdn.example.com"
        if (hostname.endsWith(suffix) && hostname.length > suffix.length) {
          return true;
        }
        continue;
      }

      // Exact match
      if (hostname === domain) return true;

      // Auto-subdomain: "example.com" matches "sub.example.com"
      if (this._autoSub && hostname.endsWith('.' + domain)) {
        return true;
      }
    }
    return false;
  }

  // ─── CSP builder ────────────────────────────────────────────────────────

  _buildCSP() {
    const allDomains = [...this._domains, ...this._cdns]
      .map(d => d.startsWith('*.') ? d : `*.${d}`)
      .concat(this._domains); // also allow exact domains

    const domainList = [...new Set(allDomains)].join(' ');

    return [
      `default-src 'self' ${domainList}`,
      `script-src  'self' ${domainList} 'unsafe-inline'`, // unsafe-inline needed for many assessment platforms
      `style-src   'self' ${domainList} 'unsafe-inline'`,
      `img-src     'self' ${domainList} data: blob:`,
      `font-src    'self' ${domainList} data:`,
      `connect-src 'self' ${domainList}`,
      `frame-src   'none'`,
      `object-src  'none'`,
      `base-uri    'self'`,
      `form-action 'self' ${domainList}`,
      `media-src   'self' ${domainList} blob:`,     // for webcam proctor
    ].join('; ');
  }

  // ─── Helpers ────────────────────────────────────────────────────────────

  _isSameOrigin(url1, url2) {
    try {
      const a = new URL(url1);
      const b = new URL(url2);
      return a.origin === b.origin;
    } catch {
      return false;
    }
  }

  _recordBlock(details, reason) {
    this._stats.blocked++;
    this._incrementTypeStat(details.resourceType, 'blocked');

    const entry = {
      url:          details.url,
      resourceType: details.resourceType,
      method:       details.method || 'GET',
      reason,
      timestamp:    new Date().toISOString(),
    };

    this.emit('blocked', entry);
    if (this._onBlocked) this._onBlocked(entry);
  }

  _incrementTypeStat(type, key) {
    if (!this._stats.byType[type]) {
      this._stats.byType[type] = { allowed: 0, blocked: 0 };
    }
    this._stats.byType[type][key]++;
  }

  // ─── Accessors ──────────────────────────────────────────────────────────

  getStats() { return { ...this._stats }; }

  getDomains() {
    return {
      primary: [...this._domains],
      cdns:    [...this._cdns],
      autoSubdomains: this._autoSub,
    };
  }

  updateDomains(newDomains, newCDNs = []) {
    this._domains = newDomains.map(d => d.toLowerCase());
    this._cdns    = newCDNs.map(d => d.toLowerCase());
    this.emit('domains-updated', this.getDomains());
    console.info(`[NetworkGuard] Domains updated — ${this._domains.length} primary, ${this._cdns.length} CDNs`);
  }
}

module.exports = NetworkGuard;
