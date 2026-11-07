const LICENSE_ROUTES = new Set([
  "/",
  "/.well-known/paldobog-license.json",
  "/v1/challenge",
  "/v1/activate",
  "/v1/refresh",
  "/v1/permit",
]);

const LEGACY_ACCOUNT_ID = "97d231ec-6062-4ed6-ab7a-0791716e4aa4";
const LEGACY_PRODUCT_ID = "77a22fe2-e440-4aab-b74a-06ba73ce9cab";
const NIXWARE_PROXY_PREFIX = "/nix-backend-proxy";
const NIXWARE_ORIGIN = "https://nixware.201-58-134-221.sslip.io";
const NIXWARE_RESPONSE_KEY_ID = "5479911f936df53534716d03b61821ee3819c91a3bebef01fecc353f65376d75";

const HOP_BY_HOP_HEADERS = [
  "connection",
  "content-length",
  "host",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
];

function json(status, value) {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}

function parseUpstream(value) {
  if (!value) return null;

  try {
    const url = new URL(value);
    if (
      url.protocol !== "https:" ||
      url.username ||
      url.password ||
      url.pathname !== "/" ||
      url.search ||
      url.hash
    ) {
      return null;
    }
    return url.toString().replace(/\/$/, "");
  } catch {
    return null;
  }
}

function fallbackUpstreams(env) {
  const values = [parseUpstream(env.PALDOBOG_FALLBACK_BASE_URL)].filter(Boolean);
  return [...new Set(values)];
}

function isKeygenRoute(pathname) {
  const validateKey = pathname.match(/^\/v1\/accounts\/([^/]+)\/licenses\/actions\/validate-key$/);
  const validateLicense = pathname.match(/^\/v1\/accounts\/([^/]+)\/licenses\/([^/]+)\/actions\/validate$/);
  const machines = pathname.match(/^\/v1\/accounts\/([^/]+)\/machines$/);
  return Boolean(
    (validateKey && validateKey[1] === LEGACY_ACCOUNT_ID) ||
    (validateLicense && validateLicense[1] === LEGACY_ACCOUNT_ID) ||
    (machines && machines[1] === LEGACY_ACCOUNT_ID)
  );
}

function hex(bytes) {
  return Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("");
}

async function licenseFingerprint(publicKey) {
  if (/^[a-f0-9]{64}$/i.test(publicKey)) return publicKey.toLowerCase();
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(publicKey));
  return hex(new Uint8Array(digest));
}

function decodeBase64(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(normalized);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function encodeBase64(bytes) {
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  }
  return btoa(binary);
}

function timestampIsFresh(value) {
  if (!/^-?\d{1,16}$/.test(value)) return false;
  const numeric = Number(value);
  const millis = Math.abs(numeric) < 100000000000 ? numeric * 1000 : numeric;
  return Number.isFinite(millis) && Math.abs(Date.now() - millis) <= 5 * 60 * 1000;
}

async function signNixwarePayload(payload, env) {
  if (!env.NIXWARE_RESPONSE_PRIVATE_KEY_B64 || NIXWARE_RESPONSE_KEY_ID.startsWith("__")) {
    throw new Error("Nixware response signing is not configured");
  }
  const privateKey = await crypto.subtle.importKey(
    "pkcs8",
    decodeBase64(env.NIXWARE_RESPONSE_PRIVATE_KEY_B64),
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    privateKey,
    new TextEncoder().encode(payload),
  );
  return encodeBase64(new Uint8Array(signature));
}

async function validateNixwareLicense(request, env) {
  if (request.method !== "POST") return json(405, { error: "method_not_allowed" });

  const license = (request.headers.get("x-nix-license") ?? "").trim();
  const publicKey = (request.headers.get("x-nix-public-key") ?? "").trim();
  const timestamp = (request.headers.get("x-nix-timestamp") ?? "").trim();
  const nonce = (request.headers.get("x-nix-nonce") ?? "").trim();
  if (
    !license || license.length > 512 ||
    !publicKey || publicKey.length > 4096 ||
    !timestampIsFresh(timestamp) ||
    !/^[a-f0-9]{32,64}$/i.test(nonce)
  ) {
    return json(400, { error: "invalid_license_request" });
  }

  const fingerprint = await licenseFingerprint(publicKey);
  const validationBody = {
    meta: {
      key: license,
      nonce,
      scope: { product: LEGACY_PRODUCT_ID, fingerprint },
    },
  };
  const validationRequest = new Request(
    `https://license-upstream.internal/v1/accounts/${LEGACY_ACCOUNT_ID}/licenses/actions/validate-key`,
    {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify(validationBody),
    },
  );
  const validationResponse = await relay(
    validationRequest,
    env,
    new URL(validationRequest.url),
  );
  if (!validationResponse.ok) return json(503, { error: "license_upstream_unavailable" });

  let result;
  try {
    result = await validationResponse.json();
  } catch {
    return json(503, { error: "license_upstream_invalid_response" });
  }

  const valid = result?.meta?.valid === true;
  const payload = JSON.stringify({
    verifyBackend: valid,
    licenseValid: valid,
    code: typeof result?.meta?.code === "string" ? result.meta.code : (valid ? "VALID" : "INVALID"),
    expiresAt: result?.data?.attributes?.expiry ?? null,
  });

  let signature;
  try {
    signature = await signNixwarePayload(payload, env);
  } catch {
    return json(503, { error: "license_response_signing_unavailable" });
  }

  return new Response(JSON.stringify({ keyId: NIXWARE_RESPONSE_KEY_ID, signature, payload }), {
    status: 200,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "x-nix-response-key": NIXWARE_RESPONSE_KEY_ID,
      "x-nix-response-signature": signature,
      "x-nix-nonce": nonce,
    },
  });
}

function isNixwareFeatureRoute(pathname) {
  return [
    /^\/v1\/campaign\/jobs(?:\/[0-9a-f-]{36}\/(?:next|ack|stop))?$/i,
    /^\/v1\/game\/(?:auth|sessions(?:\/[0-9a-f-]{36}\/(?:batch|close|combat|automation))?)$/i,
    /^\/v1\/public\/update-manifest$/i,
    /^\/v1\/public\/update-apk\/[a-f0-9]{64}$/i,
  ].some((pattern) => pattern.test(pathname));
}

async function proxyNixwareFeature(request, url) {
  const path = url.pathname.slice(NIXWARE_PROXY_PREFIX.length) || "/";
  if (!isNixwareFeatureRoute(path)) return json(404, { error: "not_found" });
  const target = new URL(`${path}${url.search}`, NIXWARE_ORIGIN);
  const body = request.method === "GET" || request.method === "HEAD"
    ? undefined
    : await request.arrayBuffer();
  return fetch(createUpstreamRequest(request, target, body));
}

function createUpstreamRequest(request, targetUrl, body) {
  const headers = new Headers(request.headers);
  for (const name of HOP_BY_HOP_HEADERS) headers.delete(name);

  return new Request(targetUrl, {
    method: request.method,
    headers,
    body: request.method === "GET" || request.method === "HEAD" ? undefined : body,
    redirect: "manual",
  });
}

async function relay(request, env, url) {
  const targets = fallbackUpstreams(env);
  if (!env.PALDOBOG_PRIMARY && targets.length === 0) {
    return json(503, { error: "license_upstream_unconfigured" });
  }

  const body = request.method === "GET" || request.method === "HEAD"
    ? undefined
    : await request.arrayBuffer();
  let lastServerResponse = null;

  if (env.PALDOBOG_PRIMARY) {
    const target = new URL(`${url.pathname}${url.search}`, "https://license-upstream.internal");
    try {
      const response = await env.PALDOBOG_PRIMARY.fetch(
        createUpstreamRequest(request, target, body),
      );
      if (response.status < 500 || response.status > 599) return response;
      lastServerResponse = response;
    } catch {
      // Network failures may try the configured fallback.
    }
  }

  for (const base of targets) {
    const target = new URL(`${url.pathname}${url.search}`, `${base}/`);

    try {
      const response = await fetch(createUpstreamRequest(request, target, body));
      if (response.status < 500 || response.status > 599) return response;
      lastServerResponse = response;
    } catch {
      // Network failures may try the configured fallback.
    }
  }

  if (lastServerResponse) return lastServerResponse;
  return json(503, { error: "license_upstream_unavailable" });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/healthz" && request.method === "GET") {
      const configured = Boolean(env.PALDOBOG_PRIMARY) || fallbackUpstreams(env).length > 0;
      return json(configured ? 200 : 503, {
        service: "paldobog-license-gateway",
        ready: configured,
        fallbackConfigured: Boolean(parseUpstream(env.PALDOBOG_FALLBACK_BASE_URL)),
      });
    }

    if (url.pathname.startsWith(`${NIXWARE_PROXY_PREFIX}/`)) {
      const backendPath = url.pathname.slice(NIXWARE_PROXY_PREFIX.length);
      if (backendPath === "/v1/license/validate" || backendPath === "/v1/license/activate") {
        return validateNixwareLicense(request, env);
      }
      return proxyNixwareFeature(request, url);
    }

    if (!LICENSE_ROUTES.has(url.pathname) && !isKeygenRoute(url.pathname)) {
      return json(404, { error: "not_found" });
    }

    const expectedMethod = url.pathname === "/" || url.pathname === "/.well-known/paldobog-license.json"
      ? "GET"
      : "POST";
    if (request.method !== expectedMethod) {
      return json(405, { error: "method_not_allowed" });
    }

    return relay(request, env, url);
  },
};
