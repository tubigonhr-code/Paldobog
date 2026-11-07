var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// src/index.mjs
import {
  createHash as createHash2,
  createPrivateKey as createPrivateKey2,
  createPublicKey as createPublicKey2,
  randomUUID,
  sign as cryptoSign2,
  timingSafeEqual
} from "node:crypto";
import { Buffer as Buffer2 } from "node:buffer";

// license-core-reference.mjs
import {
  createHash,
  createHmac,
  randomBytes,
  sign as cryptoSign,
  verify as cryptoVerify,
  createPublicKey,
  createPrivateKey
} from "node:crypto";
var APP_ID = "com.cybergym.mutants_companion";
var LEASE_ISSUER = "paldobog";
function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const entries = Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`);
  return `{${entries.join(",")}}`;
}
__name(canonicalJson, "canonicalJson");
function normalizeLicenseCode(code) {
  if (typeof code !== "string") return "";
  return code.trim().toUpperCase().replace(/[\s-]/g, "");
}
__name(normalizeLicenseCode, "normalizeLicenseCode");
function createLicenseCode() {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let accumulator = 0;
  let bits = 0;
  let encoded = "";
  for (const byte of randomBytes(27)) {
    accumulator = accumulator << 8 | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      encoded += alphabet[accumulator >>> bits & 31];
    }
  }
  if (bits > 0) encoded += alphabet[accumulator << 5 - bits & 31];
  const groups = encoded.slice(0, 42).match(/.{6}/g);
  return `NX-${groups.join("-")}`;
}
__name(createLicenseCode, "createLicenseCode");
function licenseDigest(code, pepper) {
  if (typeof pepper !== "string" || Buffer.byteLength(pepper) < 32) {
    throw new Error("PALDOBOG_LICENSE_PEPPER must contain at least 32 bytes");
  }
  const normalized = normalizeLicenseCode(code);
  if (normalized.length < 32) throw new Error("Invalid Paldobog license code");
  return createHmac("sha256", pepper).update(normalized, "utf8").digest("hex");
}
__name(licenseDigest, "licenseDigest");
function deviceIdFromPublicKey(publicKeyBase64) {
  const der = Buffer.from(publicKeyBase64, "base64");
  if (der.length < 64 || der.length > 1024) throw new Error("Invalid device public key size");
  const key = createPublicKey({ key: der, format: "der", type: "spki" });
  if (key.asymmetricKeyType !== "ec" || key.asymmetricKeyDetails?.namedCurve !== "prime256v1") {
    throw new Error("Device key must be an Android Keystore P-256 public key");
  }
  return createHash("sha256").update(der).digest("hex");
}
__name(deviceIdFromPublicKey, "deviceIdFromPublicKey");
function canonicalDeviceRequest({ path, nonce, payload }) {
  if (!["/v1/activate", "/v1/refresh", "/v1/permit"].includes(path)) {
    throw new Error("Unsupported signed request path");
  }
  if (typeof nonce !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(nonce)) {
    throw new Error("Invalid challenge nonce");
  }
  if (typeof payload !== "string" || Buffer.byteLength(payload) > 8192) {
    throw new Error("Invalid request payload");
  }
  return `${path}
${nonce}
${payload}`;
}
__name(canonicalDeviceRequest, "canonicalDeviceRequest");
function verifyDeviceRequest({ path, nonce, payload, signature, publicKey }, publicKeyBase64) {
  if (publicKey !== publicKeyBase64) return false;
  const keyBytes = Buffer.from(publicKey, "base64");
  const key = createPublicKey({ key: keyBytes, format: "der", type: "spki" });
  if (key.asymmetricKeyType !== "ec" || key.asymmetricKeyDetails?.namedCurve !== "prime256v1") return false;
  const sig = Buffer.from(signature ?? "", "base64");
  if (sig.length < 64 || sig.length > 80) return false;
  return cryptoVerify("sha256", Buffer.from(canonicalDeviceRequest({ path, nonce, payload })), key, sig);
}
__name(verifyDeviceRequest, "verifyDeviceRequest");
function signLease(payload, privateKeyPem) {
  const privateKey = privateKeyPem?.type === "private" ? privateKeyPem : createPrivateKey(privateKeyPem);
  if (privateKey.asymmetricKeyType !== "rsa" || privateKey.asymmetricKeyDetails?.modulusLength < 2048) {
    throw new Error("Lease signing key must be RSA-2048 or stronger");
  }
  const bytes = Buffer.from(canonicalJson(payload), "utf8");
  const signature = cryptoSign("sha256", bytes, privateKey).toString("base64");
  return { payload: bytes.toString("utf8"), signature };
}
__name(signLease, "signLease");
function makeLease({ license, deviceId, requestId, feature, nowMs = Date.now(), leaseSeconds = 300 }) {
  const now = Math.floor(nowMs / 1e3);
  const licenseExpiry = Math.floor(new Date(license.expiresAt).getTime() / 1e3);
  const expiry = license.neverExpires ? now + leaseSeconds : Math.min(now + leaseSeconds, licenseExpiry);
  return {
    app: APP_ID,
    device: deviceId,
    exp: expiry,
    feature,
    features: [...license.features].sort(),
    iat: now,
    iss: LEASE_ISSUER,
    lease: Math.max(0, expiry - now),
    license: license.id,
    licenseExpires: new Date(licenseExpiry * 1e3).toISOString(),
    permit: license.features.includes(feature),
    requestAgeSeconds: 0,
    requestId,
    type: "lease"
  };
}
__name(makeLease, "makeLease");
function publicKeyFingerprint(publicKeyPem) {
  const key = publicKeyPem?.type === "public" ? publicKeyPem : createPublicKey(publicKeyPem);
  const der = key.export({ type: "spki", format: "der" });
  return createHash("sha256").update(der).digest("hex");
}
__name(publicKeyFingerprint, "publicKeyFingerprint");
function newRequestId() {
  return randomBytes(18).toString("base64url");
}
__name(newRequestId, "newRequestId");
function newNonce() {
  return randomBytes(32).toString("base64url");
}
__name(newNonce, "newNonce");

// src/index.mjs
var BODY_LIMIT = 16 * 1024;
var CHALLENGE_TTL_MS = 12e4;
var APK_ROUTE_PREFIX = "/paldobog-v021-license-config-20261102xxx";
var V02_ROUTE_PREFIX = "/paldobog-v02-license-config-20261103xxxx";
var LEGACY_ACCOUNT_ID = "97d231ec-6062-4ed6-ab7a-0791716e4aa4";
var LEGACY_PRODUCT_ID = "77a22fe2-e440-4aab-b74a-06ba73ce9cab";
var LEGACY_PROXY_HOST = "xq7.pages.dev";
var LEGACY_PROXY_AUTH_HEADER = "x-pbd-proxy-auth";
var LEGACY_PROXY_HOST_HEADER = "x-pbd-original-host";
var rateBuckets = /* @__PURE__ */ new Map();
var schemaReady;
var keyConfigPromises = /* @__PURE__ */ new Map();
function json(status, value, headers = {}) {
  return new Response(JSON.stringify(value), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
      "referrer-policy": "no-referrer",
      ...headers
    }
  });
}
__name(json, "json");
async function readJson(request) {
  const contentType = request.headers.get("content-type")?.toLowerCase().split(";", 1)[0].trim();
  if (!["application/json", "application/vnd.api+json"].includes(contentType)) {
    throw new Error("Expected application/json");
  }
  const declaredLength = Number(request.headers.get("content-length") ?? 0);
  if (declaredLength > BODY_LIMIT) throw new Error("Request body too large");
  if (!request.body) return {};
  const reader = request.body.getReader();
  const chunks = [];
  let total = 0;
  for (; ; ) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > BODY_LIMIT) {
      await reader.cancel();
      throw new Error("Request body too large");
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
__name(readJson, "readJson");
function requestLimit(request, key, limit, windowMs = 6e4) {
  const address = request.headers.get("cf-connecting-ip") ?? "unknown";
  const bucketKey = `${key}:${address}`;
  const now = Date.now();
  let bucket = rateBuckets.get(bucketKey);
  if (!bucket || bucket.resetAt <= now) {
    bucket = { count: 0, resetAt: now + windowMs };
    rateBuckets.set(bucketKey, bucket);
  }
  if (bucket.count >= limit) return Math.max(1, Math.ceil((bucket.resetAt - now) / 1e3));
  bucket.count += 1;
  if (rateBuckets.size > 1e4) {
    for (const [oldKey, oldBucket] of rateBuckets) {
      if (oldBucket.resetAt <= now) rateBuckets.delete(oldKey);
    }
  }
  return 0;
}
__name(requestLimit, "requestLimit");
function rateLimited(seconds) {
  return json(429, { error: "rate_limited", retryAfterSeconds: seconds }, { "retry-after": String(seconds) });
}
__name(rateLimited, "rateLimited");
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
      db.prepare("CREATE INDEX IF NOT EXISTS licenses_digest_idx ON licenses(digest)"),
      db.prepare("CREATE INDEX IF NOT EXISTS licenses_expiry_idx ON licenses(expires_at)"),
      db.prepare(`CREATE TABLE IF NOT EXISTS challenges (
        nonce TEXT PRIMARY KEY,
        device_id TEXT NOT NULL,
        public_key TEXT NOT NULL,
        request_id TEXT NOT NULL,
        expires_at INTEGER NOT NULL
      )`),
      db.prepare("CREATE INDEX IF NOT EXISTS challenges_expiry_idx ON challenges(expires_at)"),
      db.prepare(`CREATE TABLE IF NOT EXISTS device_bindings (
        device_id TEXT PRIMARY KEY,
        license_id TEXT NOT NULL
      )`),
      db.prepare(`CREATE TABLE IF NOT EXISTS keygen_machines (
        id TEXT NOT NULL UNIQUE,
        license_id TEXT NOT NULL,
        fingerprint TEXT NOT NULL,
        platform TEXT NOT NULL,
        name TEXT NOT NULL,
        created_at TEXT NOT NULL,
        last_seen_at TEXT NOT NULL,
        PRIMARY KEY (license_id, fingerprint)
      )`)
    ]).catch((error) => {
      schemaReady = void 0;
      throw error;
    });
  }
  await schemaReady;
}
__name(ensureSchema, "ensureSchema");
function getKeyConfig(env, secretName = "PALDOBOG_LICENSE_PRIVATE_KEY_B64") {
  if (!keyConfigPromises.has(secretName)) {
    const configPromise = Promise.resolve().then(() => {
      const encoded = env[secretName];
      const pepper = env.PALDOBOG_LICENSE_PEPPER;
      if (!encoded) throw new Error(`${secretName} is not configured`);
      if (!pepper || Buffer2.byteLength(pepper) < 32) throw new Error("PALDOBOG_LICENSE_PEPPER must contain at least 32 bytes");
      const privateKey = createPrivateKey2({ key: Buffer2.from(encoded, "base64"), format: "der", type: "pkcs8" });
      if (privateKey.asymmetricKeyType !== "rsa" || privateKey.asymmetricKeyDetails?.modulusLength < 2048) {
        throw new Error("License signing identity must be RSA-2048 or stronger");
      }
      const publicKey = createPublicKey2(privateKey);
      const publicKeyDer = publicKey.export({ type: "spki", format: "der" });
      return {
        privateKey,
        pepper,
        publicKeyBase64: Buffer2.from(publicKeyDer).toString("base64"),
        publicKeyFingerprint: publicKeyFingerprint(publicKey)
      };
    }).catch((error) => {
      keyConfigPromises.delete(secretName);
      throw error;
    });
    keyConfigPromises.set(secretName, configPromise);
  }
  return keyConfigPromises.get(secretName);
}
__name(getKeyConfig, "getKeyConfig");
function authorized(request, expectedToken) {
  const header = request.headers.get("authorization") ?? "";
  if (!header.startsWith("Bearer ")) return false;
  const actual = Buffer2.from(header.slice(7), "utf8");
  const expected = Buffer2.from(expectedToken, "utf8");
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}
__name(authorized, "authorized");
function trustedLegacyProxyHost(request, env) {
  const expectedToken = env.PALDOBOG_PROXY_AUTH;
  const suppliedToken = request.headers.get(LEGACY_PROXY_AUTH_HEADER) ?? "";
  const suppliedHost = (request.headers.get(LEGACY_PROXY_HOST_HEADER) ?? "").toLowerCase();
  if (!expectedToken || suppliedHost !== LEGACY_PROXY_HOST) return null;
  const actual = Buffer2.from(suppliedToken, "utf8");
  const expected = Buffer2.from(expectedToken, "utf8");
  return actual.length === expected.length && timingSafeEqual(actual, expected) ? LEGACY_PROXY_HOST : null;
}
__name(trustedLegacyProxyHost, "trustedLegacyProxyHost");
// Lifetime records use an explicit reserved expiry marker understood by all owner routes.
// Existing Android clients still receive an ISO date; online access leases stay short.
const UNLIMITED_EXPIRY = "9999-12-31T23:59:59.000Z";
const MAX_FINITE_EXPIRY_MS = Date.parse("9999-12-30T00:00:00.000Z");
function isUnlimited(record) { return record?.expires_at === UNLIMITED_EXPIRY; }
function durationMaximumDays(baseMs = Date.now()) {
  return Math.max(0, Math.floor((MAX_FINITE_EXPIRY_MS - baseMs) / 86400000));
}
function durationExpiry(body, baseMs = Date.now()) {
  if (body.neverExpires === true) {
    if (Object.prototype.hasOwnProperty.call(body, "days")) throw new RangeError("provide_days_or_never_expires");
    return UNLIMITED_EXPIRY;
  }
  if (body.neverExpires !== undefined && body.neverExpires !== false) throw new RangeError("never_expires_must_be_boolean");
  if (typeof body.days !== "number" || !Number.isSafeInteger(body.days) || body.days < 1 || body.days > durationMaximumDays(baseMs)) {
    throw new RangeError("duration_out_of_range");
  }
  return new Date(baseMs + body.days * 86400000).toISOString();
}
function ownerLicenseSummary(record) {
  return {
    id: record.id,
    status: record.revoked ? "revoked" : !isUnlimited(record) && Date.parse(record.expires_at) <= Date.now() ? "expired" : "active",
    expiresAt: record.expires_at,
    neverExpires: isUnlimited(record),
    features: parseFeatures(record),
    deviceBound: Boolean(record.device_id || record.legacy_fingerprint)
  };
}
async function changeDuration(request, env, id) {
  let body;
  try { body = await readJson(request); }
  catch (error) {
    if (error instanceof SyntaxError || error.message === "Expected application/json" || error.message === "Request body too large") return json(400, {error:"invalid_request"});
    throw error;
  }
  if (!body || typeof body !== "object" || Array.isArray(body)) return json(400, {error:"invalid_request"});
  if (!["set", "extend", "unlimited"].includes(body.mode)) return json(400, {error:"duration_mode_invalid"});
  if (typeof body.expectedExpiresAt !== "string") return json(400, {error:"expected_expiry_required"});
  const record = await getLicenseById(env.DB, id.toLowerCase());
  if (!record) return json(404, {error:"license_not_found"});
  if (record.revoked) return json(409, {error:"license_revoked"});
  if (record.expires_at !== body.expectedExpiresAt) return json(409, {error:"license_changed_refresh"});
  if (body.mode === "extend" && isUnlimited(record)) return json(409, {error:"license_already_unlimited"});
  const now = Date.now();
  const base = body.mode === "extend" ? Math.max(now, Date.parse(record.expires_at)) : now;
  let expiresAt;
  try {
    if (body.mode === "unlimited") {
      if (Object.prototype.hasOwnProperty.call(body,"days")) return json(400,{error:"provide_days_or_never_expires"});
      expiresAt = durationExpiry({neverExpires:true}, now);
    } else expiresAt = durationExpiry({days:body.days}, base);
  } catch (error) {
    if (error instanceof RangeError) return json(400, {error:error.message, maxDays:durationMaximumDays(base)});
    throw error;
  }
  // Concurrency guard prevents an intervening edit or revocation being overwritten.
  const result = await env.DB.prepare("UPDATE licenses SET expires_at = ? WHERE id = ? AND revoked = 0 AND expires_at = ?")
    .bind(expiresAt, record.id, record.expires_at).run();
  if (result.meta.changes !== 1) return json(409, {error:"license_changed_refresh"});
  const updated = await getLicenseById(env.DB, record.id);
  return json(200, {license:ownerLicenseSummary(updated)});
}
async function bulkDurationSummary(db, nowIso = new Date().toISOString()) {
  const row = await db.prepare(`SELECT
      COUNT(*) AS total,
      COALESCE(SUM(CASE WHEN revoked = 0 THEN 1 ELSE 0 END), 0) AS nonRevoked,
      COALESCE(SUM(CASE WHEN revoked != 0 THEN 1 ELSE 0 END), 0) AS revoked,
      COALESCE(SUM(CASE WHEN revoked = 0 AND expires_at = ? THEN 1 ELSE 0 END), 0) AS unlimited,
      COALESCE(SUM(CASE WHEN revoked = 0 AND expires_at != ? AND expires_at <= ? THEN 1 ELSE 0 END), 0) AS expired
    FROM licenses`).bind(UNLIMITED_EXPIRY, UNLIMITED_EXPIRY, nowIso).first();
  const nonRevoked = Number(row?.nonRevoked ?? 0);
  const expired = Number(row?.expired ?? 0);
  return {
    total: Number(row?.total ?? 0),
    nonRevoked,
    revoked: Number(row?.revoked ?? 0),
    unlimited: Number(row?.unlimited ?? 0),
    expired,
    active: nonRevoked - expired
  };
}
async function bulkDurationPreview(request, env) {
  let body;
  try { body = await readJson(request); }
  catch (error) {
    if (error instanceof SyntaxError || error.message === "Expected application/json" || error.message === "Request body too large") return json(400, {error:"invalid_request"});
    throw error;
  }
  if (!body || typeof body !== "object" || Array.isArray(body)) return json(400, {error:"invalid_request"});
  return json(200, await bulkDurationSummary(env.DB));
}
async function bulkChangeDuration(request, env) {
  let body;
  try { body = await readJson(request); }
  catch (error) {
    if (error instanceof SyntaxError || error.message === "Expected application/json" || error.message === "Request body too large") return json(400, {error:"invalid_request"});
    throw error;
  }
  if (!body || typeof body !== "object" || Array.isArray(body)) return json(400, {error:"invalid_request"});
  if (body.confirmAll !== true) return json(400, {error:"bulk_confirmation_required"});
  if (!["set", "extend", "unlimited"].includes(body.mode)) return json(400, {error:"duration_mode_invalid"});
  if (!Number.isSafeInteger(body.expectedNonRevoked) || body.expectedNonRevoked < 0) return json(400, {error:"expected_count_required"});
  if (!Number.isSafeInteger(body.expectedUnlimited) || body.expectedUnlimited < 0 || body.expectedUnlimited > body.expectedNonRevoked) return json(400, {error:"expected_count_required"});
  const now = Date.now();
  const nowIso = new Date(now).toISOString();
  const snapshot = await bulkDurationSummary(env.DB, nowIso);
  if (snapshot.nonRevoked !== body.expectedNonRevoked || snapshot.unlimited !== body.expectedUnlimited) return json(409, {error:"license_count_changed_refresh", currentCount:snapshot.nonRevoked, currentUnlimited:snapshot.unlimited});
  let expiresAt = null;
  let result;
  if (body.mode === "unlimited") {
    if (Object.prototype.hasOwnProperty.call(body, "days")) return json(400, {error:"provide_days_or_never_expires"});
    expiresAt = UNLIMITED_EXPIRY;
    result = await env.DB.prepare(`UPDATE licenses SET expires_at = ?
      WHERE revoked = 0
        AND (SELECT COUNT(*) FROM licenses WHERE revoked = 0) = ?`)
      .bind(expiresAt, snapshot.nonRevoked).run();
  } else if (body.mode === "set") {
    try { expiresAt = durationExpiry({days:body.days}, now); }
    catch (error) {
      if (error instanceof RangeError) return json(400, {error:error.message,maxDays:durationMaximumDays(now)});
      throw error;
    }
    result = await env.DB.prepare(`UPDATE licenses SET expires_at = ?
      WHERE revoked = 0
        AND (SELECT COUNT(*) FROM licenses WHERE revoked = 0) = ?`)
      .bind(expiresAt, snapshot.nonRevoked).run();
  } else {
    if (!Number.isSafeInteger(body.days) || body.days < 1) return json(400, {error:"duration_out_of_range",maxDays:durationMaximumDays(now)});
    const latest = await env.DB.prepare(`SELECT MAX(expires_at) AS expires_at FROM licenses
      WHERE revoked = 0 AND expires_at != ?`).bind(UNLIMITED_EXPIRY).first();
    const latestMs = latest?.expires_at ? Date.parse(latest.expires_at) : now;
    const base = Math.max(now, Number.isFinite(latestMs) ? latestMs : now);
    try { durationExpiry({days:body.days}, base); }
    catch (error) {
      if (error instanceof RangeError) return json(400, {error:error.message,maxDays:durationMaximumDays(base)});
      throw error;
    }
    const modifier = `+${body.days} days`;
    result = await env.DB.prepare(`UPDATE licenses
      SET expires_at = strftime('%Y-%m-%dT%H:%M:%fZ', CASE WHEN expires_at > ? THEN expires_at ELSE ? END, ?)
      WHERE revoked = 0 AND expires_at != ?
        AND (SELECT COUNT(*) FROM licenses WHERE revoked = 0) = ?
        AND (SELECT COUNT(*) FROM licenses WHERE revoked = 0 AND expires_at = ?) = ?`)
      .bind(nowIso, nowIso, modifier, UNLIMITED_EXPIRY, snapshot.nonRevoked, UNLIMITED_EXPIRY, snapshot.unlimited).run();
  }
  const expectedChanges = body.mode === "extend" ? snapshot.nonRevoked - snapshot.unlimited : snapshot.nonRevoked;
  if (result.meta.changes !== expectedChanges) return json(409, {error:"license_set_changed_refresh"});
  return json(200, {
    mode: body.mode,
    updated: result.meta.changes,
    skippedRevoked: snapshot.revoked,
    skippedUnlimited: body.mode === "extend" ? snapshot.unlimited : 0,
    expiresAt
  });
}
function isActive(record, now = Date.now()) {
  return record && !record.revoked && (isUnlimited(record) || Date.parse(record.expires_at) > now);
}
__name(isActive, "isActive");
function parseFeatures(record) {
  try {
    const features = JSON.parse(record.features_json);
    return Array.isArray(features) ? features : [];
  } catch {
    return [];
  }
}
__name(parseFeatures, "parseFeatures");
function allowsFeature(record, feature) {
  const features = parseFeatures(record);
  return features.includes(feature) || features.includes("all");
}
__name(allowsFeature, "allowsFeature");
async function getLicenseByDigest(db, digest) {
  return db.prepare(`SELECT id, digest, features_json, expires_at, revoked, device_id, activated_at,
      legacy_fingerprint
    FROM licenses WHERE digest = ? LIMIT 1`).bind(digest).first();
}
__name(getLicenseByDigest, "getLicenseByDigest");
async function getLicenseById(db, id) {
  return db.prepare(`SELECT id, digest, features_json, expires_at, revoked, device_id, activated_at,
      legacy_fingerprint
    FROM licenses WHERE id = ? LIMIT 1`).bind(id).first();
}
__name(getLicenseById, "getLicenseById");
function keygenSignedResponse(request, body, config, status = 200) {
  const externalUrl = new URL(request.url);
  const rawBody = JSON.stringify(body);
  const date = (/* @__PURE__ */ new Date()).toUTCString();
  const host = (config.signatureHost ?? request.headers.get("host") ?? externalUrl.host).toLowerCase();
  const requestTarget = `${externalUrl.pathname}${externalUrl.search}`;
  const digest = `sha-256=${createHash2("sha256").update(rawBody, "utf8").digest("base64")}`;
  const signingData = [
    `(request-target): ${request.method.toLowerCase()} ${requestTarget}`,
    `host: ${host}`,
    `date: ${date}`,
    `digest: ${digest}`
  ].join("\n");
  const signature = cryptoSign2("RSA-SHA256", Buffer2.from(signingData, "utf8"), config.privateKey).toString("base64");
  const keygenSignature = `keyid="${LEGACY_ACCOUNT_ID}", algorithm="rsa-sha256", signature="${signature}", headers="(request-target) host date digest"`;
  return new Response(rawBody, {
    status,
    headers: {
      "content-type": "application/vnd.api+json; charset=utf-8",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
      "referrer-policy": "no-referrer",
      date,
      digest,
      "keygen-signature": keygenSignature
    }
  });
}
__name(keygenSignedResponse, "keygenSignedResponse");
function keygenMeta({ valid, code, detail, nonce, scope }) {
  const meta = {
    ts: (/* @__PURE__ */ new Date()).toISOString(),
    valid,
    detail,
    code
  };
  if (nonce !== void 0) meta.nonce = nonce;
  if (scope && typeof scope === "object") meta.scope = scope;
  return meta;
}
__name(keygenMeta, "keygenMeta");
function keygenLicenseResource(record, licenseKey, machineCount = 0) {
  const prefix = `${APK_ROUTE_PREFIX}/v1/accounts/${LEGACY_ACCOUNT_ID}`;
  const now = (/* @__PURE__ */ new Date()).toISOString();
  const expired = !isUnlimited(record) && Date.parse(record.expires_at) <= Date.now();
  return {
    id: record.id,
    type: "licenses",
    links: { self: `${prefix}/licenses/${record.id}` },
    attributes: {
      name: "Paldobog License",
      key: licenseKey,
      expiry: record.expires_at,
      status: record.revoked ? "SUSPENDED" : expired ? "EXPIRED" : "ACTIVE",
      uses: 0,
      protected: false,
      version: "v0.2",
      suspended: Boolean(record.revoked),
      scheme: null,
      encrypted: false,
      floating: false,
      strict: false,
      maxMachines: 1,
      maxProcesses: null,
      maxUsers: null,
      maxCores: null,
      maxMemory: null,
      maxDisk: null,
      maxUses: null,
      requireHeartbeat: false,
      requireCheckIn: false,
      lastValidated: now,
      lastCheckOut: null,
      lastCheckIn: null,
      nextCheckIn: null,
      permissions: ["license.read", "license.validate", "machine.create"],
      metadata: { features: parseFeatures(record) },
      created: record.activated_at ?? now,
      updated: now
    },
    relationships: {
      account: { data: { type: "accounts", id: LEGACY_ACCOUNT_ID } },
      product: { data: { type: "products", id: LEGACY_PRODUCT_ID } },
      policy: { data: null },
      machines: { meta: { count: machineCount } }
    }
  };
}
__name(keygenLicenseResource, "keygenLicenseResource");
function keygenValidationBody({ valid, code, detail, nonce, scope, record, licenseKey, machineCount = 0 }) {
  const body = {
    meta: keygenMeta({ valid, code, detail, nonce, scope })
  };
  if (record && licenseKey) body.data = keygenLicenseResource(record, licenseKey, machineCount);
  return body;
}
__name(keygenValidationBody, "keygenValidationBody");
async function keygenValidateKeyHandler(request, url, env, config, accountId) {
  const retryAfter = requestLimit(request, "keygen-validate", 120);
  if (retryAfter) return rateLimited(retryAfter);
  if (accountId !== LEGACY_ACCOUNT_ID) {
    return keygenSignedResponse(request, { errors: [{ title: "Account not found", code: "ACCOUNT_NOT_FOUND" }] }, config, 404);
  }
  try {
    const body = await readJson(request);
    const meta = body?.meta;
    const scope = meta?.scope;
    const nonce = meta?.nonce;
    const licenseKey = typeof meta?.key === "string" ? meta.key.trim() : "";
    const fingerprint = typeof scope?.fingerprint === "string" ? scope.fingerprint.trim() : "";
    if (!licenseKey || licenseKey.length > 512 || !nonce || !fingerprint || fingerprint.length > 256) {
      return keygenSignedResponse(request, keygenValidationBody({
        valid: false,
        code: "VALIDATION_FAILED",
        detail: "A license key, nonce, and device fingerprint are required.",
        nonce,
        scope
      }), config);
    }
    if (scope.product !== LEGACY_PRODUCT_ID) {
      return keygenSignedResponse(request, keygenValidationBody({
        valid: false,
        code: "PRODUCT_SCOPE_MISMATCH",
        detail: "The license does not belong to the requested product.",
        nonce,
        scope
      }), config);
    }
    let record = null;
    try {
      record = await getLicenseByDigest(env.DB, licenseDigest(licenseKey, config.pepper));
    } catch {
      record = null;
    }
    if (!record) {
      return keygenSignedResponse(request, keygenValidationBody({
        valid: false,
        code: "NOT_FOUND",
        detail: "The license key was not found.",
        nonce,
        scope
      }), config);
    }
    if (record.revoked) {
      return keygenSignedResponse(request, keygenValidationBody({
        valid: false,
        code: "SUSPENDED",
        detail: "The license has been revoked.",
        nonce,
        scope,
        record,
        licenseKey
      }), config);
    }
    if (!isUnlimited(record) && Date.parse(record.expires_at) <= Date.now()) {
      return keygenSignedResponse(request, keygenValidationBody({
        valid: false,
        code: "EXPIRED",
        detail: "The license has expired.",
        nonce,
        scope,
        record,
        licenseKey
      }), config);
    }
    if (!allowsFeature(record, "all")) {
      return keygenSignedResponse(request, keygenValidationBody({
        valid: false,
        code: "FEATURE_NOT_LICENSED",
        detail: "The license does not include all v0.2 features.",
        nonce,
        scope,
        record,
        licenseKey
      }), config);
    }
    if (record.legacy_fingerprint && record.legacy_fingerprint !== fingerprint) {
      return keygenSignedResponse(request, keygenValidationBody({
        valid: false,
        code: "FINGERPRINT_SCOPE_MISMATCH",
        detail: "The license is already bound to another device.",
        nonce,
        scope,
        record,
        licenseKey
      }), config);
    }
    const activatedAt = (/* @__PURE__ */ new Date()).toISOString();
    const bound = await env.DB.prepare(`UPDATE licenses
      SET legacy_fingerprint = COALESCE(legacy_fingerprint, ?), activated_at = COALESCE(activated_at, ?)
      WHERE id = ? AND revoked = 0 AND (expires_at = '9999-12-31T23:59:59.000Z' OR expires_at > ?)
        AND (legacy_fingerprint IS NULL OR legacy_fingerprint = ?)`).bind(fingerprint, activatedAt, record.id, activatedAt, fingerprint).run();
    if (bound.meta.changes !== 1) {
      const current2 = await getLicenseById(env.DB, record.id);
      return keygenSignedResponse(request, keygenValidationBody({
        valid: false,
        code: "FINGERPRINT_SCOPE_MISMATCH",
        detail: "The license is already bound to another device.",
        nonce,
        scope,
        record: current2 ?? record,
        licenseKey
      }), config);
    }
    const machineId = randomUUID();
    await env.DB.prepare(`INSERT INTO keygen_machines (id, license_id, fingerprint, platform, name, created_at, last_seen_at)
      VALUES (?, ?, ?, 'android', 'Nixware Android', ?, ?)
      ON CONFLICT(license_id, fingerprint) DO UPDATE SET last_seen_at = excluded.last_seen_at`).bind(machineId, record.id, fingerprint, activatedAt, activatedAt).run();
    const machine = await env.DB.prepare("SELECT id FROM keygen_machines WHERE license_id = ? AND fingerprint = ? LIMIT 1").bind(record.id, fingerprint).first();
    const current = await getLicenseById(env.DB, record.id);
    return keygenSignedResponse(request, keygenValidationBody({
      valid: true,
      code: "VALID",
      detail: "The license is active for this device.",
      nonce,
      scope,
      record: current ?? { ...record, legacy_fingerprint: fingerprint, activated_at: activatedAt },
      licenseKey,
      machineCount: machine ? 1 : 0
    }), config);
  } catch (error) {
    if (error instanceof SyntaxError || error.message === "Expected application/json" || error.message === "Request body too large") {
      return keygenSignedResponse(request, { errors: [{ title: "Invalid request", code: "INVALID_REQUEST" }] }, config, 400);
    }
    throw error;
  }
}
__name(keygenValidateKeyHandler, "keygenValidateKeyHandler");
function keygenAuthCode(request) {
  const header = request.headers.get("authorization") ?? "";
  const match = header.match(/^License\s+(.+)$/i);
  return match?.[1]?.trim() ?? "";
}
__name(keygenAuthCode, "keygenAuthCode");
async function keygenMachineHandler(request, env, config) {
  const retryAfter = requestLimit(request, "keygen-machine", 120);
  if (retryAfter) return rateLimited(retryAfter);
  try {
    const body = await readJson(request);
    const licenseKey = keygenAuthCode(request);
    const fingerprint = body?.data?.attributes?.fingerprint;
    const licenseId = body?.data?.relationships?.license?.data?.id;
    if (!licenseKey || typeof fingerprint !== "string" || !fingerprint || fingerprint.length > 256 || typeof licenseId !== "string") {
      return keygenSignedResponse(request, { errors: [{ title: "Invalid machine request", code: "INVALID_REQUEST" }] }, config, 400);
    }
    let record;
    try {
      record = await getLicenseByDigest(env.DB, licenseDigest(licenseKey, config.pepper));
    } catch {
      record = null;
    }
    if (!record || record.id !== licenseId) {
      return keygenSignedResponse(request, { errors: [{ title: "License authorization failed", code: "LICENSE_NOT_FOUND" }] }, config, 401);
    }
    if (!isActive(record) || !allowsFeature(record, "all")) {
      return keygenSignedResponse(request, { errors: [{ title: "License is inactive", code: record.revoked ? "SUSPENDED" : "EXPIRED" }] }, config, 403);
    }
    if (record.legacy_fingerprint !== fingerprint) {
      return keygenSignedResponse(request, { errors: [{ title: "Device fingerprint does not match", code: "FINGERPRINT_SCOPE_MISMATCH" }] }, config, 403);
    }
    const existing = await env.DB.prepare("SELECT id FROM keygen_machines WHERE license_id = ? AND fingerprint = ? LIMIT 1").bind(record.id, fingerprint).first();
    const machineId = existing?.id ?? randomUUID();
    const now = (/* @__PURE__ */ new Date()).toISOString();
    await env.DB.prepare(`INSERT INTO keygen_machines (id, license_id, fingerprint, platform, name, created_at, last_seen_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(license_id, fingerprint) DO UPDATE SET platform = excluded.platform, name = excluded.name, last_seen_at = excluded.last_seen_at`).bind(
      machineId,
      record.id,
      fingerprint,
      typeof body.data.attributes.platform === "string" ? body.data.attributes.platform.slice(0, 64) : "android",
      typeof body.data.attributes.name === "string" ? body.data.attributes.name.slice(0, 128) : "Paldobog Android",
      now,
      now
    ).run();
    const machine = await env.DB.prepare("SELECT id, fingerprint, platform, name, created_at FROM keygen_machines WHERE license_id = ? AND fingerprint = ? LIMIT 1").bind(record.id, fingerprint).first();
    return keygenSignedResponse(request, {
      data: {
        type: "machines",
        id: machine.id,
        attributes: {
          fingerprint: machine.fingerprint,
          platform: machine.platform,
          name: machine.name,
          status: "ACTIVE",
          created: machine.created_at,
          updated: now
        },
        relationships: { license: { data: { type: "licenses", id: record.id } } }
      }
    }, config, existing ? 200 : 201);
  } catch (error) {
    if (error instanceof SyntaxError || error.message === "Expected application/json" || error.message === "Request body too large") {
      return keygenSignedResponse(request, { errors: [{ title: "Invalid request", code: "INVALID_REQUEST" }] }, config, 400);
    }
    throw error;
  }
}
__name(keygenMachineHandler, "keygenMachineHandler");
async function keygenValidateLicenseHandler(request, env, config, accountId, licenseId) {
  const retryAfter = requestLimit(request, "keygen-validate-license", 120);
  if (retryAfter) return rateLimited(retryAfter);
  if (accountId !== LEGACY_ACCOUNT_ID) {
    return keygenSignedResponse(request, { errors: [{ title: "Account not found", code: "ACCOUNT_NOT_FOUND" }] }, config, 404);
  }
  try {
    const body = await readJson(request);
    const licenseKey = keygenAuthCode(request);
    let record = null;
    try {
      record = licenseKey ? await getLicenseByDigest(env.DB, licenseDigest(licenseKey, config.pepper)) : null;
    } catch {
      record = null;
    }
    const scope = body?.meta?.scope;
    const nonce = body?.meta?.nonce;
    const valid = Boolean(record && record.id === licenseId && isActive(record) && allowsFeature(record, "all") && record.legacy_fingerprint && record.legacy_fingerprint === scope?.fingerprint);
    const code = valid ? "VALID" : record && !isActive(record) ? record.revoked ? "SUSPENDED" : "EXPIRED" : "FINGERPRINT_SCOPE_MISMATCH";
    const detail = valid ? "The license is active for this device." : "The license or device binding is not valid.";
    return keygenSignedResponse(request, keygenValidationBody({
      valid,
      code,
      detail,
      nonce,
      scope,
      record: record?.id === licenseId ? record : null,
      licenseKey,
      machineCount: record?.legacy_fingerprint ? 1 : 0
    }), config);
  } catch (error) {
    if (error instanceof SyntaxError || error.message === "Expected application/json" || error.message === "Request body too large") {
      return keygenSignedResponse(request, { errors: [{ title: "Invalid request", code: "INVALID_REQUEST" }] }, config, 400);
    }
    throw error;
  }
}
__name(keygenValidateLicenseHandler, "keygenValidateLicenseHandler");
async function issueLicense(request, env, config) {
  const body = await readJson(request);
  if (!body || typeof body !== "object" || Array.isArray(body)) return json(400, { error: "invalid_request" });
  let expiresAt;
  try { expiresAt = durationExpiry(body); }
  catch (error) { if (error instanceof RangeError) return json(400, {error:error.message,maxDays:durationMaximumDays()}); throw error; }
  const features = Array.isArray(body.features) ? [...new Set(body.features)] : [];
  if (features.length === 0 || features.some((value) => typeof value !== "string" || !/^[a-z][a-z0-9:_-]{0,63}$/.test(value))) {
    return json(400, { error: "features_invalid" });
  }
  const code = createLicenseCode();
  const digest = licenseDigest(code, config.pepper);
  const id = randomUUID();
  await env.DB.prepare(`INSERT INTO licenses (id, digest, features_json, expires_at, revoked, device_id, activated_at)
    VALUES (?, ?, ?, ?, 0, NULL, NULL)`).bind(id, digest, JSON.stringify(features.sort()), expiresAt).run();
  return json(201, { code, id, expiresAt, neverExpires: expiresAt === UNLIMITED_EXPIRY, features });
}
__name(issueLicense, "issueLicense");
async function adminHandler(request, url, env, config) {
  const retryAfter = requestLimit(request, "admin", 30);
  if (retryAfter) return rateLimited(retryAfter);
  const expected = env.PALDOBOG_ADMIN_TOKEN;
  if (!expected || Buffer2.byteLength(expected) < 32) return json(503, { error: "admin_service_not_configured" });
  if (!authorized(request, expected)) return json(401, { error: "admin_unauthorized" });
  if (request.method === "POST" && url.pathname === "/admin/v1/licenses") {
    try {
      return await issueLicense(request, env, config);
    } catch (error) {
      if (error instanceof SyntaxError || error.message === "Expected application/json" || error.message === "Request body too large") {
        return json(400, { error: "invalid_request" });
      }
      throw error;
    }
  }
  // Owner-only lookup: reads existing records without activating or binding a device.
  if (request.method === "POST" && url.pathname === "/admin/v1/licenses/lookup") {
    let body;
    try { body = await readJson(request); }
    catch (error) {
      if (error instanceof SyntaxError || error.message === "Expected application/json" || error.message === "Request body too large") {
        return json(400, { error: "invalid_request" });
      }
      throw error;
    }
    if (!body || typeof body !== "object" || Array.isArray(body)) return json(400, { error: "invalid_request" });
    const hasCode = Object.prototype.hasOwnProperty.call(body, "code");
    const hasId = Object.prototype.hasOwnProperty.call(body, "id");
    if (hasCode === hasId) return json(400, { error: "provide_code_or_id" });
    let record;
    if (hasCode) {
      if (typeof body.code !== "string" || body.code.length > 128 || !/^NX[A-HJ-NP-Z2-9]{42}$/.test(normalizeLicenseCode(body.code))) {
        return json(400, { error: "invalid_license_code" });
      }
      record = await getLicenseByDigest(env.DB, licenseDigest(body.code, config.pepper));
    } else {
      if (typeof body.id !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(body.id)) {
        return json(400, { error: "invalid_license_id" });
      }
      record = await getLicenseById(env.DB, body.id.toLowerCase());
    }
    if (!record) return json(404, { error: "license_not_found" });
    return json(200, { license: ownerLicenseSummary(record) });
  }
  if (request.method === "GET" && url.pathname === "/admin/v1/licenses") {
    const result = await env.DB.prepare(`SELECT id, features_json, expires_at, revoked, device_id, legacy_fingerprint
      FROM licenses ORDER BY expires_at DESC LIMIT 1000`).all();
    const licenses = result.results.map(ownerLicenseSummary);
    return json(200, { licenses });
  }
  if (request.method === "POST" && url.pathname === "/admin/v1/licenses/duration/bulk/preview") {
    return bulkDurationPreview(request, env);
  }
  if (request.method === "POST" && url.pathname === "/admin/v1/licenses/duration/bulk") {
    return bulkChangeDuration(request, env);
  }
  const duration = url.pathname.match(/^\/admin\/v1\/licenses\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\/duration$/i);
  if (request.method === "POST" && duration) return changeDuration(request, env, duration[1]);
  const revoke = url.pathname.match(/^\/admin\/v1\/licenses\/([0-9a-f-]{36})\/revoke$/i);
  if (request.method === "POST" && revoke) {
    const result = await env.DB.prepare("UPDATE licenses SET revoked = 1 WHERE id = ?").bind(revoke[1]).run();
    if (result.meta.changes !== 1) return json(404, { error: "license_not_found" });
    return json(200, { id: revoke[1], status: "revoked" });
  }
  return json(404, { error: "not_found" });
}
__name(adminHandler, "adminHandler");
async function challengeHandler(request, env) {
  const body = await readJson(request);
  try {
    const deviceId = deviceIdFromPublicKey(body?.publicKey);
    const nonce = newNonce();
    const requestId = newRequestId();
    const expiresAt = Date.now() + CHALLENGE_TTL_MS;
    await env.DB.batch([
      env.DB.prepare("DELETE FROM challenges WHERE expires_at <= ?").bind(Date.now()),
      env.DB.prepare(`INSERT INTO challenges (nonce, device_id, public_key, request_id, expires_at)
        VALUES (?, ?, ?, ?, ?)`).bind(nonce, deviceId, body.publicKey, requestId, expiresAt)
    ]);
    return json(200, { nonce, requestId });
  } catch {
    return json(400, { error: "invalid_device_key" });
  }
}
__name(challengeHandler, "challengeHandler");
async function consumeChallenge(db, nonce) {
  if (typeof nonce !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(nonce)) return null;
  const result = await db.prepare(`DELETE FROM challenges
    WHERE nonce = ? AND expires_at > ?
    RETURNING device_id, public_key, request_id, expires_at`).bind(nonce, Date.now()).all();
  return result.results[0] ?? null;
}
__name(consumeChallenge, "consumeChallenge");
async function signedLicenseHandler(request, url, env, config) {
  const body = await readJson(request);
  const challenge = await consumeChallenge(env.DB, body?.nonce);
  if (!challenge || challenge.public_key !== body?.publicKey) return json(401, { error: "challenge_invalid_or_expired" });
  let signatureValid = false;
  try {
    signatureValid = verifyDeviceRequest({
      path: url.pathname,
      nonce: body.nonce,
      payload: body.payload,
      signature: body.signature,
      publicKey: body.publicKey
    }, body.publicKey);
  } catch {
    signatureValid = false;
  }
  if (!signatureValid) return json(401, { error: "device_signature_invalid" });
  let signedRequest;
  try {
    if (typeof body.payload !== "string" || Buffer2.byteLength(body.payload, "utf8") > 8192) throw new Error("Invalid signed payload");
    signedRequest = JSON.parse(body.payload);
  } catch {
    return json(400, { error: "signed_payload_invalid" });
  }
  if (signedRequest.app !== APP_ID || signedRequest.requestId !== challenge.request_id) return json(400, { error: "request_binding_mismatch" });
  if (typeof signedRequest.feature !== "string" || !/^[a-z][a-z0-9:_-]{0,63}$/.test(signedRequest.feature)) return json(400, { error: "feature_invalid" });
  const deviceId = challenge.device_id;
  const submittedLicense = [
    signedRequest.licenseKey,
    signedRequest.licenseCode,
    signedRequest.key,
    typeof signedRequest.license === "string" && !/^[0-9a-f-]{36}$/i.test(signedRequest.license) ? signedRequest.license : null
  ].find((value) => typeof value === "string" && value.length > 0);
  const licenseId = signedRequest.licenseId ?? (typeof signedRequest.license === "string" && /^[0-9a-f-]{36}$/i.test(signedRequest.license) ? signedRequest.license : null);
  let record;
  const isCodeActivation = url.pathname === "/v1/activate" || url.pathname === "/v1/permit" && Boolean(submittedLicense);
  if (isCodeActivation) {
    if (!submittedLicense) return json(400, { error: "license_key_required" });
    try {
      record = await getLicenseByDigest(env.DB, licenseDigest(submittedLicense, config.pepper));
    } catch {
      record = null;
    }
    if (!record) return json(403, { error: "license_invalid" });
    if (!isActive(record)) return json(403, { error: "license_inactive" });
    if (!allowsFeature(record, signedRequest.feature)) return json(403, { error: "feature_not_licensed" });
    if (record.device_id && record.device_id !== deviceId) return json(403, { error: "license_bound_to_another_device" });
    const activatedAt = (/* @__PURE__ */ new Date()).toISOString();
    const update = await env.DB.prepare(`UPDATE licenses
      SET device_id = COALESCE(device_id, ?), activated_at = COALESCE(activated_at, ?)
      WHERE id = ? AND revoked = 0 AND (expires_at = '9999-12-31T23:59:59.000Z' OR expires_at > ?) AND (device_id IS NULL OR device_id = ?)`).bind(deviceId, activatedAt, record.id, activatedAt, deviceId).run();
    if (update.meta.changes !== 1) return json(403, { error: "license_bound_to_another_device" });
    await env.DB.prepare(`INSERT INTO device_bindings (device_id, license_id) VALUES (?, ?)
      ON CONFLICT(device_id) DO UPDATE SET license_id = excluded.license_id`).bind(deviceId, record.id).run();
    record = { ...record, device_id: deviceId, activated_at: record.activated_at ?? activatedAt };
  } else {
    if (typeof licenseId !== "string") return json(400, { error: "license_id_invalid" });
    record = await getLicenseById(env.DB, licenseId);
    if (!record || !isActive(record)) return json(403, { error: "license_inactive" });
    const binding = await env.DB.prepare("SELECT license_id FROM device_bindings WHERE device_id = ? LIMIT 1").bind(deviceId).first();
    if (record.device_id !== deviceId || binding?.license_id !== record.id) return json(403, { error: "device_not_activated" });
    if (!allowsFeature(record, signedRequest.feature)) return json(403, { error: "feature_not_licensed" });
  }
  const leaseClaims = makeLease({
    license: { id: record.id, expiresAt: record.expires_at, neverExpires: isUnlimited(record), features: parseFeatures(record) },
    deviceId,
    requestId: challenge.request_id,
    feature: signedRequest.feature
  });
  leaseClaims.permit = allowsFeature(record, signedRequest.feature);
  const lease = signLease({ claims: leaseClaims }, config.privateKey);
  return json(200, { lease: { ...lease, publicKey: config.publicKeyBase64 } });
}
__name(signedLicenseHandler, "signedLicenseHandler");
async function configuredResponse(request, env, url, secretName) {
  const baseConfig = await getKeyConfig(env, secretName);
  const signatureHost = trustedLegacyProxyHost(request, env);
  const config = signatureHost ? { ...baseConfig, signatureHost } : baseConfig;
  if ((url.pathname === "/" || url.pathname === "/.well-known/paldobog-license.json") && request.method === "GET") {
    return json(200, {
      service: "paldobog-license-v1",
      appId: APP_ID,
      apiBasePath: "/v1",
      publicKey: config.publicKeyBase64,
      publicKeyFingerprint: config.publicKeyFingerprint
    });
  }
  if (url.pathname.startsWith("/admin/")) return adminHandler(request, url, env, config);
  const keygenValidateKey = url.pathname.match(/^\/v1\/accounts\/([^/]+)\/licenses\/actions\/validate-key$/);
  if (request.method === "POST" && keygenValidateKey) {
    return keygenValidateKeyHandler(request, url, env, config, keygenValidateKey[1]);
  }
  const keygenValidateLicense = url.pathname.match(/^\/v1\/accounts\/([^/]+)\/licenses\/([^/]+)\/actions\/validate$/);
  if (request.method === "POST" && keygenValidateLicense) {
    return keygenValidateLicenseHandler(request, env, config, keygenValidateLicense[1], keygenValidateLicense[2]);
  }
  const keygenMachines = url.pathname.match(/^\/v1\/accounts\/([^/]+)\/machines$/);
  if (request.method === "POST" && keygenMachines) {
    if (keygenMachines[1] !== LEGACY_ACCOUNT_ID) {
      return keygenSignedResponse(request, { errors: [{ title: "Account not found", code: "ACCOUNT_NOT_FOUND" }] }, config, 404);
    }
    return keygenMachineHandler(request, env, config);
  }
  if (request.method === "POST" && url.pathname === "/v1/challenge") {
    const retryAfter = requestLimit(request, "challenge", 300);
    if (retryAfter) return rateLimited(retryAfter);
    try {
      return await challengeHandler(request, env);
    } catch (error) {
      if (error instanceof SyntaxError || error.message === "Expected application/json" || error.message === "Request body too large") {
        return json(400, { error: "invalid_request" });
      }
      throw error;
    }
  }
  if (request.method === "POST" && ["/v1/activate", "/v1/refresh", "/v1/permit"].includes(url.pathname)) {
    const retryAfter = requestLimit(request, url.pathname, 120);
    if (retryAfter) return rateLimited(retryAfter);
    try {
      return await signedLicenseHandler(request, url, env, config);
    } catch (error) {
      if (error instanceof SyntaxError || error.message === "Expected application/json" || error.message === "Request body too large") {
        return json(400, { error: "invalid_request" });
      }
      throw error;
    }
  }
  return json(404, { error: "not_found" });
}
__name(configuredResponse, "configuredResponse");
var index_default = {
  async fetch(request, env) {
    const url = new URL(request.url);
    const originalPath = url.pathname;
    let signingKeyName = "PALDOBOG_LICENSE_PRIVATE_KEY_B64";
    if (url.pathname === V02_ROUTE_PREFIX) {
      signingKeyName = "PALDOBOG_V02_LICENSE_PRIVATE_KEY_B64";
      url.pathname = "/";
    } else if (url.pathname.startsWith(`${V02_ROUTE_PREFIX}/`)) {
      signingKeyName = "PALDOBOG_V02_LICENSE_PRIVATE_KEY_B64";
      url.pathname = url.pathname.slice(V02_ROUTE_PREFIX.length);
    } else if (url.pathname === APK_ROUTE_PREFIX) {
      url.pathname = "/";
    } else if (url.pathname.startsWith(`${APK_ROUTE_PREFIX}/`)) {
      url.pathname = url.pathname.slice(APK_ROUTE_PREFIX.length);
    } else if (url.pathname === "/" && request.method === "GET") {
      signingKeyName = "PALDOBOG_V02_LICENSE_PRIVATE_KEY_B64";
    }
    if (trustedLegacyProxyHost(request, env) || url.pathname.startsWith(`/v1/accounts/${LEGACY_ACCOUNT_ID}/`)) {
      signingKeyName = "PALDOBOG_V02_LICENSE_PRIVATE_KEY_B64";
    }
    if (request.method === "GET" && url.pathname === "/healthz") {
      try {
        await ensureSchema(env.DB);
        return json(200, { ok: true, service: "paldobog-license-v1" });
      } catch {
        return json(503, { ok: false, error: "database_not_ready" });
      }
    }
    try {
      await ensureSchema(env.DB);
      const response = await configuredResponse(request, env, url, signingKeyName);
      console.log("license-route", request.method, originalPath, response.status);
      return response;
    } catch (error) {
      console.error("Paldobog license request failed:", request.method, originalPath, error?.message ?? "unknown error");
      return json(500, { error: "license_service_error" });
    }
  }
};
export {
  index_default as default
};
