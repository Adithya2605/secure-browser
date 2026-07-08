/**
 * download-model.js — Download BlazeFace TF.js model weights locally.
 * Run once:  node download-model.js
 *
 * Saves to:
 *   assets/blazeface-model/model.json
 *   assets/blazeface-model/group1-shard1of1.bin   (≈ 400 KB)
 */

'use strict';

const https  = require('https');
const http   = require('http');
const zlib   = require('zlib');
const fs     = require('fs');
const path   = require('path');

const BASE_URL = 'https://tfhub.dev/tensorflow/tfjs-model/blazeface/1/default/1';
const OUT_DIR  = path.join(__dirname, 'assets', 'blazeface-model');

fs.mkdirSync(OUT_DIR, { recursive: true });

// ─── HTTP helper with full redirect tracing + gzip decode ────────────────────

function fetchBuffer(url, redirectCount = 0) {
  return new Promise((resolve, reject) => {
    if (redirectCount > 10) return reject(new Error('Too many redirects: ' + url));

    const client = url.startsWith('https') ? https : http;

    const reqHeaders = {
      // Mimic a real browser / TF.js client
      'User-Agent':      'Mozilla/5.0 (compatible; tfjs-downloader/1.0)',
      'Accept':          '*/*',
      // Ask for no compression so we get raw bytes
      'Accept-Encoding': 'identity',
    };

    console.log(`  [${redirectCount === 0 ? 'GET' : 'REDIRECT ' + redirectCount}] ${url}`);

    client.get(url, { headers: reqHeaders }, (res) => {
      const { statusCode, headers } = res;

      // Follow any redirect
      if (statusCode >= 300 && statusCode < 400 && headers.location) {
        res.resume(); // drain response body
        const next = new URL(headers.location, url).href;
        return fetchBuffer(next, redirectCount + 1).then(resolve, reject);
      }

      if (statusCode !== 200) {
        res.resume();
        return reject(new Error(`HTTP ${statusCode} for ${url}`));
      }

      // Collect raw chunks
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('error', reject);
      res.on('end', () => {
        let buf = Buffer.concat(chunks);

        // Decompress if server ignored Accept-Encoding: identity
        const enc = (headers['content-encoding'] || '').toLowerCase();
        if (enc === 'gzip' || (buf[0] === 0x1f && buf[1] === 0x8b)) {
          try { buf = zlib.gunzipSync(buf); } catch (_) {}
        } else if (enc === 'deflate') {
          try { buf = zlib.inflateSync(buf); } catch (_) {}
        } else if (enc === 'br') {
          try { buf = zlib.brotliDecompressSync(buf); } catch (_) {}
        }

        // Detect HTML responses (TFHub auth/consent wall)
        const preview = buf.slice(0, 16).toString('utf8');
        if (preview.includes('<!') || preview.includes('<html') || preview.trim().startsWith('\r\n')) {
          return reject(new Error(
            `Server returned HTML instead of binary (got: "${preview.trim().slice(0, 60)}"). ` +
            `URL: ${url}`
          ));
        }

        resolve(buf);
      });
    }).on('error', reject);
  });
}

function save(outPath, buf) {
  fs.writeFileSync(outPath, buf);
  const kb = (buf.length / 1024).toFixed(1);
  console.log(`  ✔ Saved ${path.relative(__dirname, outPath)} (${kb} KB)\n`);
}

// ─── Try multiple known CDN/storage URL patterns ─────────────────────────────

const SHARD_URL_CANDIDATES = (shardName) => [
  // Primary: TFHub redirect (may fail)
  `${BASE_URL}/${shardName}`,
  // storage.googleapis.com — TFHub's backing store (various known paths)
  `https://storage.googleapis.com/tfhub-modules/tensorflow/tfjs-model/blazeface/1/default/1/${shardName}`,
  `https://storage.googleapis.com/tfjs-models/savedmodel/blazeface/${shardName}`,
];

async function fetchWithFallback(urlCandidates, description) {
  for (const url of urlCandidates) {
    try {
      const buf = await fetchBuffer(url);
      return buf;
    } catch (err) {
      console.warn(`  ⚠ Fallback: ${err.message.split('\n')[0]}`);
    }
  }
  throw new Error(`All URL candidates failed for: ${description}`);
}

// ─── Main ─────────────────────────────────────────────────────────────────────

async function main() {
  console.log('═══════════════════════════════════════════════════════');
  console.log(' BlazeFace model downloader');
  console.log('═══════════════════════════════════════════════════════\n');

  // ── 1. model.json ──────────────────────────────────────────────────────────
  console.log('→ Fetching model.json …');
  const modelJsonUrl = `${BASE_URL}/model.json?tfjs-format=file`;
  let modelJsonBuf;
  try {
    modelJsonBuf = await fetchBuffer(modelJsonUrl);
  } catch (err) {
    // Fallback path
    console.warn(`  ⚠ Primary failed: ${err.message.split('\n')[0]}`);
    modelJsonBuf = await fetchBuffer(
      'https://storage.googleapis.com/tfhub-modules/tensorflow/tfjs-model/blazeface/1/default/1/model.json?tfjs-format=file'
    );
  }

  // Validate JSON
  let manifest;
  try {
    manifest = JSON.parse(modelJsonBuf.toString('utf8'));
  } catch {
    throw new Error('model.json is not valid JSON — server likely returned HTML');
  }

  save(path.join(OUT_DIR, 'model.json'), modelJsonBuf);

  // ── 2. Weight shards ────────────────────────────────────────────────────────
  const shardPaths = [];
  for (const group of (manifest.weightsManifest || [])) {
    if (Array.isArray(group.paths)) shardPaths.push(...group.paths);
  }

  if (shardPaths.length === 0) {
    console.warn('No weight shards in manifest — weights may be embedded in model.json.');
  }

  for (const shard of shardPaths) {
    console.log(`→ Fetching shard: ${shard} …`);
    const candidates = SHARD_URL_CANDIDATES(shard);
    const buf = await fetchWithFallback(candidates, shard);

    // Sanity check — must be binary (not HTML) and a reasonable size
    const preview = buf.slice(0, 8).toString('hex');
    console.log(`  First 8 bytes (hex): ${preview}`);

    if (buf.byteLength < 1000) {
      throw new Error(`Shard file suspiciously small (${buf.byteLength} bytes) — download likely failed.`);
    }

    save(path.join(OUT_DIR, shard), buf);
  }

  // ── 3. Validate total byte count ────────────────────────────────────────────
  let totalExpected = 0;
  for (const group of (manifest.weightsManifest || [])) {
    for (const w of group.weights) {
      const elems = (w.shape || []).reduce((a, b) => a * b, 1) || 1;
      const dtype = w.dtype === 'float32' ? 4 : w.dtype === 'int32' ? 4 : 1;
      totalExpected += elems * dtype;
    }
  }

  const totalActual = shardPaths.reduce((sum, s) =>
    sum + fs.statSync(path.join(OUT_DIR, s)).size, 0);

  console.log(`Expected weight bytes : ${totalExpected}`);
  console.log(`Downloaded shard bytes: ${totalActual}`);

  if (totalActual !== totalExpected) {
    throw new Error(
      `Size mismatch! Expected ${totalExpected} bytes but got ${totalActual}. ` +
      `The downloaded weights are incomplete or corrupted.`
    );
  }

  console.log('\n✅ BlazeFace model downloaded and verified successfully.');
  console.log(`   Output: ${OUT_DIR}`);
}

main().catch(err => {
  console.error('\n❌ Download failed:', err.message);
  process.exit(1);
});
