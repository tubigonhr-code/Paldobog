const GATEWAY_ORIGIN = "https://paldobog-nixware-license-gateway.paldobog-free-license-host.workers.dev";

export default {
  async fetch(request) {
    const incoming = new URL(request.url);
    const target = new URL(`${incoming.pathname}${incoming.search}`, GATEWAY_ORIGIN);
    const headers = new Headers(request.headers);
    headers.delete("host");
    const body = request.method === "GET" || request.method === "HEAD"
      ? undefined
      : await request.arrayBuffer();

    return fetch(new Request(target, {
      method: request.method,
      headers,
      body,
      redirect: "manual",
    }));
  },
};
