const LICENSE_ROUTES = new Set([
  "/.well-known/paldobog-license.json",
  "/v1/challenge",
  "/v1/activate",
  "/v1/refresh",
  "/v1/permit",
]);

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

    if (!LICENSE_ROUTES.has(url.pathname)) {
      return json(404, { error: "not_found" });
    }

    const expectedMethod = url.pathname === "/.well-known/paldobog-license.json"
      ? "GET"
      : "POST";
    if (request.method !== expectedMethod) {
      return json(405, { error: "method_not_allowed" });
    }

    return relay(request, env, url);
  },
};
