import {
  createPrivateKey,
  createPublicKey,
  randomUUID,
  timingSafeEqual,
} from 'node:crypto';
import { Buffer } from 'node:buffer';
import {
  APP_ID,
  createLicenseCode,
  deviceIdFromPublicKey,
  licenseDigest,
  makeLease,
  newNonce,
  newRequestId,
  publicKeyFingerprint,
  signLease,
  verifyDeviceRequest,
} from '../license-core-reference.mjs';

const BODY_LIMIT = 16 * 1024;
const CHALLENGE_TTL_MS = 120_000;
const rateBuckets = new Map();
let schemaReady;
let keyConfigPromise;

function json(status, value, headers = {}) {
  return new Response(JSON.stringify(value), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer',
      ...headers,
    },
  });
}

async function readJson(request) {
  if (!request.headers.get('content-type')?.toLowerCase().startsWith('application/json')) {
    throw new Error('Expected application/json');
  }
  const declaredLength = Number(request.headers.get('content-length') ?? 0);
  if (declaredLength > BODY_LIMIT) throw new Error('Request body too large');
  if (!request.body) return {};
  const reader = request.body.getReader();
  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > BODY_LIMIT) {
      await reader.cancel();
      throw new Error('Request body too large');
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return JSON.parse(new TextDecoder().decode(bytes));
}

function requestLimit(request, key, limit, windowMs = 60_000) {
  const address = request.headers.get('cf-connecting-ip') ?? 'unknown';
  const bucketKey = `${key}:${address}`;
  const now = Date.now();
  let bucket = rateBuckets.get(bucketKey);
  if (!bucket || bucket.resetAt <= now) {
    bucket = { count: 0, resetAt: now + windowMs };
    rateBuckets.set(bucketKey, bucket);
  }
  if (bucket.count >= limit) return Math.max(1, Math.ceil((bucket.resetAt - now) / 1000));
  bucket.count += 1;
  if (rateBuckets.size > 10_000) {
    for (const [oldKey, oldBucket] of rateBuckets) {
      if (oldBucket.resetAt <= now) rateBuckets.delete(oldKey);
    }
  }
  return 0;
}

function rateLimited(seconds) {
  return json(429, { error: 'rate_limited', retryAfterSeconds: seconds }, { 'retry-after': String(seconds) });
}

async function ensureSchema(db) {
  if (!schemaReady) {
    schemaReady = db.batch([
      db.prepare(`CREATE TABLE IF NOT EXISTS licenses (
        id TEXT PRIMARY KEY,
        digest TEXT NOT NULL UNIQUE,
        features_json TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        revoked INTEGER NOT NULL DEFAULT 0,
        device_id TEXT,
        activated_at TEXT
      )`),
      db.prepare('CREATE INDEX IF NOT EXISTS licenses_digest_idx ON licenses(digest)'),
      db.prepare('CREATE INDEX IF NOT EXISTS licenses_expiry_idx ON licenses(expires_at)'),
      db.prepare(`CREATE TABLE IF NOT EXISTS challenges (
        nonce TEXT PRIMARY KEY,
        device_id TEXT NOT NULL,
        public_key TEXT NOT NULL,
        request_id TEXT NOT NULL,
        expires_at INTEGER NOT NULL
      )`),
      db.prepare('CREATE INDEX IF NOT EXISTS challenges_expiry_idx ON challenges(expires_at)'),
      db.prepare(`CREATE TABLE IF NOT EXISTS device_bindings (
        device_id TEXT PRIMARY KEY,
        license_id TEXT NOT NULL
      )`),
    ]).catch((error) => {
      schemaReady = undefined;
      throw error;
    });
  }
  await schemaReady;
}

function getKeyConfig(env) {
  if (!keyConfigPromise) {
    keyConfigPromise = Promise.resolve().then(() => {
      const encoded = env.PALDOBOG_LICENSE_PRIVATE_KEY_B64;
      const pepper = env.PALDOBOG_LICENSE_PEPPER;
      if (!encoded) throw new Error('PALDOBOG_LICENSE_PRIVATE_KEY_B64 is not configured');
      if (!pepper || Buffer.byteLength(pepper) < 32) throw new Error('PALDOBOG_LICENSE_PEPPER must contain at least 32 bytes');
      const privateKey = createPrivateKey({ key: Buffer.from(encoded, 'base64'), format: 'der', type: 'pkcs8' });
      if (privateKey.asymmetricKeyType !== 'rsa' || privateKey.asymmetricKeyDetails?.modulusLength < 2048) {
        throw new Error('License signing identity must be RSA-2048 or stronger');
      }
      const publicKey = createPublicKey(privateKey);
      const publicKeyDer = publicKey.export({ type: 'spki', format: 'der' });
      return {
        privateKey,
        pepper,
        publicKeyBase64: Buffer.from(publicKeyDer).toString('base64'),
        publicKeyFingerprint: publicKeyFingerprint(publicKey),
      };
    }).catch((error) => {
      keyConfigPromise = undefined;
      throw error;
    });
  }
  return keyConfigPromise;
}

function authorized(request, expectedToken) {
  const header = request.headers.get('authorization') ?? '';
  if (!header.startsWith('Bearer ')) return false;
  const actual = Buffer.from(header.slice(7), 'utf8');
  const expected = Buffer.from(expectedToken, 'utf8');
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

function isActive(record, now = Date.now()) {
  return record && !record.revoked && Date.parse(record.expires_at) > now;
}

function parseFeatures(record) {
  try {
    const features = JSON.parse(record.features_json);
    return Array.isArray(features) ? features : [];
  } catch {
    return [];
  }
}

async function getLicenseByDigest(db, digest) {
  return db.prepare(`SELECT id, digest, features_json, expires_at, revoked, device_id, activated_at
    FROM licenses WHERE digest = ? LIMIT 1`).bind(digest).first();
}

async function getLicenseById(db, id) {
  return db.prepare(`SELECT id, digest, features_json, expires_at, revoked, device_id, activated_at
    FROM licenses WHERE id = ? LIMIT 1`).bind(id).first();
}

async function issueLicense(request, env, config) {
  const body = await readJson(request);
  if (!body || typeof body !== 'object' || Array.isArray(body)) return json(400, { error: 'invalid_request' });
  const days = Number(body.days);
  const features = Array.isArray(body.features) ? [...new Set(body.features)] : [];
  if (!Number.isInteger(days) || days < 1 || days > 3650) return json(400, { error: 'days_must_be_between_1_and_3650' });
  if (features.length === 0 || features.some((value) => typeof value !== 'string' || !/^[a-z][a-z0-9:_-]{0,63}$/.test(value))) {
    return json(400, { error: 'features_invalid' });
  }

  const code = createLicenseCode();
  const digest = licenseDigest(code, config.pepper);
  const id = randomUUID();
  const expiresAt = new Date(Date.now() + days * 24 * 60 * 60 * 1000).toISOString();
  await env.DB.prepare(`INSERT INTO licenses (id, digest, features_json, expires_at, revoked, device_id, activated_at)
    VALUES (?, ?, ?, ?, 0, NULL, NULL)`).bind(id, digest, JSON.stringify(features.sort()), expiresAt).run();
  return json(201, { code, id, expiresAt, features });
}

async function adminHandler(request, url, env, config) {
  const retryAfter = requestLimit(request, 'admin', 30);
  if (retryAfter) return rateLimited(retryAfter);
  const expected = env.PALDOBOG_ADMIN_TOKEN;
  if (!expected || Buffer.byteLength(expected) < 32) return json(503, { error: 'admin_service_not_configured' });
  if (!authorized(request, expected)) return json(401, { error: 'admin_unauthorized' });

  if (request.method === 'POST' && url.pathname === '/admin/v1/licenses') {
    try {
      return await issueLicense(request, env, config);
    } catch (error) {
      if (error instanceof SyntaxError || error.message === 'Expected application/json' || error.message === 'Request body too large') {
        return json(400, { error: 'invalid_request' });
      }
      throw error;
    }
  }

  if (request.method === 'GET' && url.pathname === '/admin/v1/licenses') {
    const result = await env.DB.prepare(`SELECT id, features_json, expires_at, revoked, device_id
      FROM licenses ORDER BY expires_at DESC LIMIT 1000`).all();
    const licenses = result.results.map((row) => ({
      id: row.id,
      status: row.revoked ? 'revoked' : Date.parse(row.expires_at) <= Date.now() ? 'expired' : 'active',
      expiresAt: row.expires_at,
      features: parseFeatures(row),
      deviceBound: Boolean(row.device_id),
    }));
    return json(200, { licenses });
  }

  const revoke = url.pathname.match(/^\/admin\/v1\/licenses\/([0-9a-f-]{36})\/revoke$/i);
  if (request.method === 'POST' && revoke) {
    const result = await env.DB.prepare('UPDATE licenses SET revoked = 1 WHERE id = ?').bind(revoke[1]).run();
    if (result.meta.changes !== 1) return json(404, { error: 'license_not_found' });
    return json(200, { id: revoke[1], status: 'revoked' });
  }
  return json(404, { error: 'not_found' });
}

async function challengeHandler(request, env) {
  const body = await readJson(request);
  try {
    const deviceId = deviceIdFromPublicKey(body?.publicKey);
    const nonce = newNonce();
    const requestId = newRequestId();
    const expiresAt = Date.now() + CHALLENGE_TTL_MS;
    await env.DB.batch([
      env.DB.prepare('DELETE FROM challenges WHERE expires_at <= ?').bind(Date.now()),
      env.DB.prepare(`INSERT INTO challenges (nonce, device_id, public_key, request_id, expires_at)
        VALUES (?, ?, ?, ?, ?)`).bind(nonce, deviceId, body.publicKey, requestId, expiresAt),
    ]);
    return json(200, { nonce, requestId });
  } catch {
    return json(400, { error: 'invalid_device_key' });
  }
}

async function consumeChallenge(db, nonce) {
  if (typeof nonce !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(nonce)) return null;
  const result = await db.prepare(`DELETE FROM challenges
    WHERE nonce = ? AND expires_at > ?
    RETURNING device_id, public_key, request_id, expires_at`).bind(nonce, Date.now()).all();
  return result.results[0] ?? null;
}

async function signedLicenseHandler(request, url, env, config) {
  const body = await readJson(request);
  const challenge = await consumeChallenge(env.DB, body?.nonce);
  if (!challenge || challenge.public_key !== body?.publicKey) return json(401, { error: 'challenge_invalid_or_expired' });

  let signatureValid = false;
  try {
    signatureValid = verifyDeviceRequest({
      path: url.pathname,
      nonce: body.nonce,
      payload: body.payload,
      signature: body.signature,
      publicKey: body.publicKey,
    }, body.publicKey);
  } catch {
    signatureValid = false;
  }
  if (!signatureValid) return json(401, { error: 'device_signature_invalid' });

  let signedRequest;
  try {
    if (typeof body.payload !== 'string' || Buffer.byteLength(body.payload, 'utf8') > 8192) throw new Error('Invalid signed payload');
    signedRequest = JSON.parse(body.payload);
  } catch {
    return json(400, { error: 'signed_payload_invalid' });
  }
  if (signedRequest.app !== APP_ID || signedRequest.requestId !== challenge.request_id) return json(400, { error: 'request_binding_mismatch' });
  if (typeof signedRequest.feature !== 'string' || !/^[a-z][a-z0-9:_-]{0,63}$/.test(signedRequest.feature)) return json(400, { error: 'feature_invalid' });

  const deviceId = challenge.device_id;
  let record;
  if (url.pathname === '/v1/activate') {
    try {
      record = await getLicenseByDigest(env.DB, licenseDigest(signedRequest.licenseKey, config.pepper));
    } catch {
      record = null;
    }
    if (!record) return json(403, { error: 'license_invalid' });
    if (!isActive(record)) return json(403, { error: 'license_inactive' });
    const features = parseFeatures(record);
    if (!features.includes(signedRequest.feature)) return json(403, { error: 'feature_not_licensed' });
    if (record.device_id && record.device_id !== deviceId) return json(403, { error: 'license_bound_to_another_device' });

    const activatedAt = new Date().toISOString();
    const update = await env.DB.prepare(`UPDATE licenses
      SET device_id = COALESCE(device_id, ?), activated_at = COALESCE(activated_at, ?)
      WHERE id = ? AND revoked = 0 AND expires_at > ? AND (device_id IS NULL OR device_id = ?)`)
      .bind(deviceId, activatedAt, record.id, activatedAt, deviceId).run();
    if (update.meta.changes !== 1) return json(403, { error: 'license_bound_to_another_device' });
    await env.DB.prepare(`INSERT INTO device_bindings (device_id, license_id) VALUES (?, ?)
      ON CONFLICT(device_id) DO UPDATE SET license_id = excluded.license_id`).bind(deviceId, record.id).run();
    record = { ...record, device_id: deviceId, activated_at: record.activated_at ?? activatedAt };
  } else {
    if (typeof signedRequest.license !== 'string') return json(400, { error: 'license_id_invalid' });
    record = await getLicenseById(env.DB, signedRequest.license);
    if (!record || !isActive(record)) return json(403, { error: 'license_inactive' });
    const binding = await env.DB.prepare('SELECT license_id FROM device_bindings WHERE device_id = ? LIMIT 1').bind(deviceId).first();
    if (record.device_id !== deviceId || binding?.license_id !== record.id) return json(403, { error: 'device_not_activated' });
    if (!parseFeatures(record).includes(signedRequest.feature)) return json(403, { error: 'feature_not_licensed' });
  }

  const leaseClaims = makeLease({
    license: { id: record.id, expiresAt: record.expires_at, features: parseFeatures(record) },
    deviceId,
    requestId: challenge.request_id,
    feature: signedRequest.feature,
  });
  const lease = signLease(leaseClaims, config.privateKey);
  return json(200, { lease: { ...lease, publicKey: config.publicKeyBase64 } });
}

async function configuredResponse(request, env, url) {
  const config = await getKeyConfig(env);
  if (url.pathname === '/.well-known/paldobog-license.json' && request.method === 'GET') {
    return json(200, {
      service: 'paldobog-license-v1',
      appId: APP_ID,
      apiBasePath: '/v1',
      publicKey: config.publicKeyBase64,
      publicKeyFingerprint: config.publicKeyFingerprint,
    });
  }
  if (url.pathname.startsWith('/admin/')) return adminHandler(request, url, env, config);
  if (request.method === 'POST' && url.pathname === '/v1/challenge') {
    const retryAfter = requestLimit(request, 'challenge', 300);
    if (retryAfter) return rateLimited(retryAfter);
    try {
      return await challengeHandler(request, env);
    } catch (error) {
      if (error instanceof SyntaxError || error.message === 'Expected application/json' || error.message === 'Request body too large') {
        return json(400, { error: 'invalid_request' });
      }
      throw error;
    }
  }
  if (request.method === 'POST' && ['/v1/activate', '/v1/refresh', '/v1/permit'].includes(url.pathname)) {
    const retryAfter = requestLimit(request, url.pathname, 120);
    if (retryAfter) return rateLimited(retryAfter);
    try {
      return await signedLicenseHandler(request, url, env, config);
    } catch (error) {
      if (error instanceof SyntaxError || error.message === 'Expected application/json' || error.message === 'Request body too large') {
        return json(400, { error: 'invalid_request' });
      }
      throw error;
    }
  }
  return json(404, { error: 'not_found' });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === 'GET' && url.pathname === '/healthz') {
      try {
        await ensureSchema(env.DB);
        return json(200, { ok: true, service: 'paldobog-license-v1' });
      } catch {
        return json(503, { ok: false, error: 'database_not_ready' });
      }
    }
    try {
      await ensureSchema(env.DB);
      return await configuredResponse(request, env, url);
    } catch (error) {
      console.error('Paldobog license request failed:', error?.message ?? 'unknown error');
      return json(500, { error: 'license_service_error' });
    }
  },
};
