# JUAN VPN cloud server

Your own "Save to cloud" service. The app encrypts each config on the phone (AES-256-GCM, key derived from the
8-character cloud key). This server stores only ciphertext under a hashed lookup token, so it cannot read configs.

Modes: **Normal** (kept 180 days by default), **Burn after import** (deleted atomically on first import),
**Set expiry date** (deleted after that date, max 1 year).

## Deploy from your phone (Cloudflare dashboard, free plan)

1. Cloudflare dashboard -> **Storage & Databases -> D1 -> Create database**, name it `juan-cloud`.
   Open it -> **Console**, paste the contents of `schema.sql`, run it.
2. **Workers & Pages -> Create -> Create Worker**, name it `juan-cloud`, Deploy, then **Edit code**:
   replace everything with `worker.js`, Deploy.
3. Worker -> **Settings -> Bindings -> Add -> D1 database**: variable name `DB`, database `juan-cloud`. Save/Deploy.
4. Open `https://juan-cloud.<your-subdomain>.workers.dev/api/health`. You should see `{"ok":true,"service":"juan-cloud"}`.
5. In JUAN VPN: **Settings -> Cloud server**, paste that address, **Save**, then **Test server**.

## Deploy with Wrangler (PC)

    cd cloud-server
    npx wrangler d1 create juan-cloud          # copy database_id into wrangler.toml
    npx wrangler d1 execute juan-cloud --remote --file=schema.sql
    npx wrangler deploy

## Short links

A custom domain gives short links like `https://yourdomain/pbEw2URa`: add the domain to Cloudflare, then
Worker -> Settings -> Domains & Routes -> Add custom domain. Use that address as the Cloud server in the app.

## What users get

Save to cloud shows a link, a key, an emoji key and a `juanvpn://` app link. To import: Servers -> Import from
cloud key (paste any of them), or open the link page and tap **Open in JUAN VPN**. The key and emoji key alone only
work with the server saved in the app's Settings; the link and app link carry the server address.

## Limits you should know

- Anyone who knows a key can import that config (a password-locked .HJ still needs its password). Use Burn for one-time sharing.
- An 8-character key is convenient, not strong against someone who has the server database. For sensitive configs enable
  "Lock config" so the .HJ itself is password-encrypted.
- Add a Cloudflare rate-limiting rule for `/api/put` if the server is public.
