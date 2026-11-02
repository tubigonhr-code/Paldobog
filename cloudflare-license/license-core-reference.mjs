import {
  createHash,
  createHmac,
  randomBytes,
  sign as cryptoSign,
  verify as cryptoVerify,
  createPublicKey,
  createPrivateKey,
} from 'node:crypto';

export const APP_ID = 'com.cybergym.mutants_companion';
export const LEASE_ISSUER = 'paldobog';

export function canonicalJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const entries = Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`);
  return `{${entries.join(',')}}`;
}

export function normalizeLicenseCode(code) {
  if (typeof code !== 'string') return '';
  return code.trim().toUpperCase().replace(/[\s-]/g, '');
}

export function createLicenseCode() {
  // 192 bits of entropy in an alphabet that avoids visually ambiguous characters.
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let accumulator = 0;
  let bits = 0;
  let encoded = '';
  for (const byte of randomBytes(24)) {
    accumulator = (accumulator << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      encoded += alphabet[(accumulator >>> bits) & 31];
    }
  }
  if (bits > 0) encoded += alphabet[(accumulator << (5 - bits)) & 31];
  return `PBDG-${encoded}`;
}

export function licenseDigest(code, pepper) {
  if (typeof pepper !== 'string' || Buffer.byteLength(pepper) < 32) {
    throw new Error('PALDOBOG_LICENSE_PEPPER must contain at least 32 bytes');
  }
  const normalized = normalizeLicenseCode(code);
  if (normalized.length < 32) throw new Error('Invalid Paldobog license code');
  return createHmac('sha256', pepper).update(normalized, 'utf8').digest('hex');
}

export function deviceIdFromPublicKey(publicKeyBase64) {
  const der = Buffer.from(publicKeyBase64, 'base64');
  if (der.length < 64 || der.length > 1024) throw new Error('Invalid device public key size');
  const key = createPublicKey({ key: der, format: 'der', type: 'spki' });
  if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1') {
    throw new Error('Device key must be an Android Keystore P-256 public key');
  }
  return createHash('sha256').update(der).digest('hex');
}

export function canonicalDeviceRequest({ path, nonce, payload }) {
  if (!['/v1/activate', '/v1/refresh', '/v1/permit'].includes(path)) {
    throw new Error('Unsupported signed request path');
  }
  if (typeof nonce !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(nonce)) {
    throw new Error('Invalid challenge nonce');
  }
  if (typeof payload !== 'string' || Buffer.byteLength(payload) > 8192) {
    throw new Error('Invalid request payload');
  }
  return `${path}\n${nonce}\n${payload}`;
}

export function verifyDeviceRequest({ path, nonce, payload, signature, publicKey }, publicKeyBase64) {
  if (publicKey !== publicKeyBase64) return false;
  const keyBytes = Buffer.from(publicKey, 'base64');
  const key = createPublicKey({ key: keyBytes, format: 'der', type: 'spki' });
  if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1') return false;
  const sig = Buffer.from(signature ?? '', 'base64');
  if (sig.length < 64 || sig.length > 80) return false;
  return cryptoVerify('sha256', Buffer.from(canonicalDeviceRequest({ path, nonce, payload })), key, sig);
}

export function signLease(payload, privateKeyPem) {
  const privateKey = privateKeyPem?.type === 'private' ? privateKeyPem : createPrivateKey(privateKeyPem);
  if (privateKey.asymmetricKeyType !== 'rsa' || privateKey.asymmetricKeyDetails?.modulusLength < 2048) {
    throw new Error('Lease signing key must be RSA-2048 or stronger');
  }
  const bytes = Buffer.from(canonicalJson(payload), 'utf8');
  const signature = cryptoSign('sha256', bytes, privateKey).toString('base64');
  return { payload: bytes.toString('utf8'), signature };
}

export function verifyLease(lease, publicKeyPem, expected = {}) {
  if (!lease || typeof lease.payload !== 'string' || typeof lease.signature !== 'string') return false;
  const publicKey = publicKeyPem?.type === 'public' ? publicKeyPem : createPublicKey(publicKeyPem);
  if (publicKey.asymmetricKeyType !== 'rsa' || publicKey.asymmetricKeyDetails?.modulusLength < 2048) return false;
  const signature = Buffer.from(lease.signature, 'base64');
  if (!cryptoVerify('sha256', Buffer.from(lease.payload, 'utf8'), publicKey, signature)) return false;
  let claims;
  try { claims = JSON.parse(lease.payload); } catch { return false; }
  const now = Math.floor((expected.nowMs ?? Date.now()) / 1000);
  if (claims.app !== APP_ID || claims.iss !== LEASE_ISSUER) return false;
  if (typeof claims.iat !== 'number' || typeof claims.exp !== 'number' || claims.iat > now + 60 || claims.exp <= now) return false;
  if (expected.deviceId && claims.device !== expected.deviceId) return false;
  if (expected.requestId && claims.requestId !== expected.requestId) return false;
  if (expected.feature && !claims.features?.includes(expected.feature)) return false;
  return true;
}

export function makeLease({ license, deviceId, requestId, feature, nowMs = Date.now(), leaseSeconds = 300 }) {
  const now = Math.floor(nowMs / 1000);
  const licenseExpiry = Math.floor(new Date(license.expiresAt).getTime() / 1000);
  const expiry = Math.min(now + leaseSeconds, licenseExpiry);
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
    licenseExpires: new Date(licenseExpiry * 1000).toISOString(),
    permit: license.features.includes(feature),
    requestAgeSeconds: 0,
    requestId,
    type: 'lease',
  };
}

export function publicKeyFingerprint(publicKeyPem) {
  const key = publicKeyPem?.type === 'public' ? publicKeyPem : createPublicKey(publicKeyPem);
  const der = key.export({ type: 'spki', format: 'der' });
  return createHash('sha256').update(der).digest('hex');
}

export function newRequestId() {
  return randomBytes(18).toString('base64url');
}

export function newNonce() {
  return randomBytes(32).toString('base64url');
}
