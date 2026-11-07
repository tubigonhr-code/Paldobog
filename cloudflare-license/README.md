# Paldobog free license host

This is a Cloudflare Worker backed by D1. It uses Cloudflare's free Workers and D1 plans and does not need a paid Render server or a custom domain. Cloudflare assigns a `workers.dev` HTTPS URL when it is deployed.

The API uses the Paldobog license protocol from the companion project. It does not use Nixware Keygen. Its public app endpoints are separate from the MGG game server.

## Free plan capacity

Cloudflare currently lists 100,000 Worker requests per day, 5 million D1 rows read per day, 100,000 D1 rows written per day, 5 GB total free D1 storage, and a 500 MB per-database limit. Those are provider limits, not guarantees of unlimited availability. If a daily limit is reached, license requests can fail until it resets.

## Deploy

1. Install Node.js 20 or newer on the Windows computer that will deploy the service.
2. From this folder, run `npm install`.
3. Run `scripts\Generate-Host-Secrets.ps1` once. It creates a signing key, pepper, and admin token in a Windows-protected file under Documents\Codex\PaldobogLicenseSecrets. Do not delete this file or generate a second key after the app is configured.
4. Run `scripts\Deploy-Free-License-Host.ps1`. Sign in to Cloudflare in the browser when prompted. Wrangler deploys the Worker, creates the D1 binding from `wrangler.jsonc`, and uploads the protected secrets without printing them.
5. Open the `workers.dev` URL printed after deployment and check `/healthz`.
6. Open `/.well-known/paldobog-license.json` and save the public-key fingerprint. It is safe to publish; it is required when rebuilding the APK.

Cloudflare encrypts D1 data at rest. The Worker stores license codes only as keyed digests. The generated private key, pepper, and admin token are uploaded as Worker secrets and are not committed to GitHub.

## Endpoints

- `GET /healthz`
- `GET /.well-known/paldobog-license.json`
- `POST /v1/challenge`
- `POST /v1/activate`
- `POST /v1/refresh`
- `POST /v1/permit`
- Owner-only `POST /admin/v1/licenses`, `GET /admin/v1/licenses`, and `POST /admin/v1/licenses/{id}/revoke`
- Owner-only `POST /admin/v1/licenses/duration/bulk/preview` and `POST /admin/v1/licenses/duration/bulk` for previewed bulk expiry changes

The bulk preview reports counts for the full D1 license table, including licenses beyond the 1,000-record list view. A bulk change must confirm the previewed non-revoked and unlimited counts; if those counts changed, the Worker rejects the operation so the owner can refresh and confirm again. `set` assigns the chosen number of days from the change time to every non-revoked license (including expired and unlimited records). `extend` adds days to finite non-revoked licenses, starting expired licenses from today and skipping unlimited licenses. `unlimited` removes the expiry from every non-revoked license. Revoked records are never changed by these operations.

The owner admin token is in the protected local secret bundle. The APK must never receive it. License codes are returned only by the authenticated issue request.

## APK integration

The license host alone does not remove the license screen. The APK client must be rebuilt with the deployed Worker URL and the matching fingerprint from `/.well-known/paldobog-license.json`. The current v0.2.1 APK does not have this host configured.

The GitHub `latest.json` updater feed is not used as the license API.
