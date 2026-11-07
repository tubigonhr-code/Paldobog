# Paldobog License Gateway for Nixware

This is a separate Cloudflare Worker project for routing the Paldobog license API. It does not
change the existing license Worker or the Mutant Forge command Worker.

The gateway forwards the Paldobog API request and response unchanged. It reaches the primary
license Worker through a Cloudflare service binding and tries `PALDOBOG_FALLBACK_BASE_URL` only
when the primary fails at the network layer or returns a 5xx response. License decisions such as
invalid, expired, revoked, or unlicensed (4xx responses) are returned directly and do not trigger
failover.

## Supported paths

- `GET /`
- `GET /.well-known/paldobog-license.json`
- `POST /v1/challenge`
- `POST /v1/activate`
- `POST /v1/refresh`
- `POST /v1/permit`
- Nixware v0.2.3 Keygen compatibility routes for the Paldobog account
- `POST /nix-backend-proxy/v1/license/validate` and `/activate`, checked against Paldobog
- Allowlisted non-license Nixware feature routes proxied to the existing Nixware feature service
- `GET /healthz`

Administrative routes are not forwarded.

The Pages alias in `pages-alias/public/_worker.js` provides `n7x.pages.dev`, the short host needed
by the APK's fixed-length URL constants. It forwards requests to this Worker.

## Configuration

The primary Worker is configured by the `PALDOBOG_PRIMARY` service binding in `wrangler.jsonc`.
To configure an optional fallback, set this Worker variable:

- `PALDOBOG_FALLBACK_BASE_URL` — optional HTTPS base URL for a second Paldobog-compatible API.

The primary must remain the authoritative issuer so existing Paldobog license keys stay valid.
The fallback must share the same license records and signing trust to return compatible results.

## Nixware v0.2.3 integration status

This Worker uses the existing Paldobog license API as primary and its public Workers.dev endpoint
as an alternate path for network failures or 5xx responses. Both paths use the authoritative
Paldobog license records.

The v0.2.3 client endpoints were patched in its Flutter libraries and rebuilt as an installable
APK. Its update-manifest signing key and update host were preserved while the separate license
response pins were changed. The replacement APK uses a new signing certificate because the
original private signing key was not available; Android will require uninstalling the old-signed
package before installing this one, which deletes that package's local app data.

The APK's legacy license validation route is adapted to Paldobog and its compatibility response is
signed by the gateway's private key, stored only as a Cloudflare Worker secret. The Keygen
compatibility routes also relay to Paldobog. A dummy invalid-key request was rejected by Paldobog,
and a dummy compatibility response's signature verified against the new public key. Valid-key
activation and on-device runtime behavior have not been checked.
