# Paldobog License Gateway for Nixware

This is a separate Cloudflare Worker project for routing the Paldobog license API. It does not
change the existing license Worker or the Mutant Forge command Worker.

The gateway forwards the Paldobog API request and response unchanged. It reaches the primary
license Worker through a Cloudflare service binding and tries `PALDOBOG_FALLBACK_BASE_URL` only
when the primary fails at the network layer or returns a 5xx response. License decisions such as
invalid, expired, revoked, or unlicensed (4xx responses) are returned directly and do not trigger
failover.

## Supported paths

- `GET /.well-known/paldobog-license.json`
- `POST /v1/challenge`
- `POST /v1/activate`
- `POST /v1/refresh`
- `POST /v1/permit`
- `GET /healthz`

Administrative routes are not forwarded.

## Configuration

The primary Worker is configured by the `PALDOBOG_PRIMARY` service binding in `wrangler.jsonc`.
To configure an optional fallback, set this Worker variable:

- `PALDOBOG_FALLBACK_BASE_URL` — optional HTTPS base URL for a second Paldobog-compatible API.

The primary must remain the authoritative issuer so existing Paldobog license keys stay valid.
The fallback must share the same license records and signing trust to return compatible results.

## Nixware v0.2.3 integration status

This gateway speaks the Paldobog API contract. It is deployed at
`https://paldobog-nixware-license-gateway.paldobog-free-license-host.workers.dev` and currently
uses the existing Paldobog license Worker as its primary through a service binding. No fallback is
configured yet. Its health and public metadata endpoints have been checked.

Nixware v0.2.3 is not yet integrated: its active licensing calls still use Keygen and the legacy
Nixware API, and its Paldobog verifier pins a different public key from the current Worker. Do not
treat the APK as install-ready until the licensing client is converted and verified.
