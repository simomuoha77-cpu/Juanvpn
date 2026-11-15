// JUAN VPN cloud server - Cloudflare Worker + D1.
// Stores only ciphertext (the app encrypts on the phone) under a hashed lookup token.
// Modes: normal (kept NORMAL_TTL_DAYS), burn (deleted atomically on first fetch), expiry (deleted after a date).

const CORS = { 'access-control-allow-origin': '*', 'access-control-allow-methods': 'GET,POST,OPTIONS', 'access-control-allow-headers': 'content-type' };
const J = (obj, status = 200) => new Response(JSON.stringify(obj), {
  status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store', ...CORS },
});
const MAX_BODY = 262144;               // 256 KB
const MAX_EXPIRY_DAYS = 366;
const HEX64 = /^[0-9a-f]{64}$/;
const B64 = /^[A-Za-z0-9+/=]+$/;

async function sha256hex(text) {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return [...new Uint8Array(d)].map(b => b.toString(16).padStart(2, '0')).join('');
}

function page(title, body) {
  return new Response(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title}</title><style>body{font-family:system-ui,sans-serif;background:#0a111f;color:#e8eefc;margin:0;padding:24px;max-width:520px;margin:auto}
.c{background:#121c30;border:1px solid #22304d;border-radius:14px;padding:20px;margin-top:20px}code{display:block;font-size:22px;letter-spacing:1px;color:#23d5ab;margin:10px 0}
a.b{display:block;text-align:center;background:#23d5ab;color:#06231c;font-weight:700;padding:14px;border-radius:26px;text-decoration:none;margin-top:16px}p{color:#b7c3dd;line-height:1.5}</style></head>
<body><h2>JUAN VPN</h2><div class="c">${body}</div></body></html>`,
    { headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' } });
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const path = url.pathname;
    const now = Math.floor(Date.now() / 1000);
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });

    try {
      if (path === '/api/health') return J({ ok: true, service: 'juan-cloud' });

      if (path === '/api/put' && req.method === 'POST') {
        const raw = await req.text();
        if (raw.length > MAX_BODY) return J({ error: 'Config is too large' }, 413);
        let b;
        try { b = JSON.parse(raw); } catch { return J({ error: 'Bad request' }, 400); }
        if (!b || typeof b.token !== 'string' || !HEX64.test(b.token)) return J({ error: 'Bad token' }, 400);
        if (typeof b.data !== 'string' || b.data.length < 40 || !B64.test(b.data)) return J({ error: 'Bad data' }, 400);
        if (!['normal', 'burn', 'expiry'].includes(b.mode)) return J({ error: 'Bad mode' }, 400);

        let expires;
        if (b.mode === 'expiry') {
          expires = Math.floor(Number(b.expires));
          if (!Number.isFinite(expires) || expires <= now + 60) return J({ error: 'Expiry date must be in the future' }, 400);
          if (expires > now + MAX_EXPIRY_DAYS * 86400) return J({ error: 'Expiry date is too far away (max 1 year)' }, 400);
        } else {
          const days = Math.min(Math.max(parseInt(env.NORMAL_TTL_DAYS || '180', 10) || 180, 1), 3650);
          expires = now + days * 86400;
        }

        await env.DB.prepare('DELETE FROM configs WHERE expires <= ?').bind(now).run();   // housekeeping
        try {
          await env.DB.prepare('INSERT INTO configs (token, data, mode, expires, created) VALUES (?, ?, ?, ?, ?)')
            .bind(b.token, b.data, b.mode, expires, now).run();
        } catch (e) {
          if (/UNIQUE|constraint/i.test(String(e && e.message))) return J({ error: 'Key already used' }, 409);
          throw e;
        }
        return J({ ok: true, expires });
      }

      if (path.startsWith('/api/get/') && req.method === 'GET') {
        const token = path.slice('/api/get/'.length);
        if (!HEX64.test(token)) return J({ error: 'Not found' }, 404);
        const sel = await env.DB.prepare('SELECT mode FROM configs WHERE token = ? AND expires > ?').bind(token, now).first();
        if (!sel) return J({ error: 'Not found' }, 404);
        // Burn: one atomic statement, so two phones can never both receive the config.
        const row = sel.mode === 'burn'
          ? await env.DB.prepare('DELETE FROM configs WHERE token = ? AND expires > ? RETURNING data').bind(token, now).first()
          : await env.DB.prepare('SELECT data FROM configs WHERE token = ? AND expires > ?').bind(token, now).first();
        if (!row) return J({ error: 'Not found' }, 404);
        return J({ ok: true, data: row.data });
      }

      // Share page: https://your-server/KEY  (never consumes the config)
      const m = path.match(/^\/([A-Za-z0-9]{8})$/);
      if (m && req.method === 'GET') {
        const key = m[1];
        const exists = await env.DB.prepare('SELECT mode FROM configs WHERE token = ? AND expires > ?')
          .bind(await sha256hex('juancloud-lookup|' + key), now).first();
        if (!exists) return page('Config not found', '<h3>Config not found</h3><p>This config has expired, was already used (one-time), or the key is wrong.</p>');
        const deep = `juanvpn://import?key=${key}&server=${encodeURIComponent(url.origin)}`;
        return page('JUAN VPN config', `<h3>JUAN VPN cloud config</h3><p>Key</p><code>${key}</code>
<a class="b" href="${deep}">Open in JUAN VPN</a>
<p style="margin-top:18px">Or open JUAN VPN, go to <b>Servers &rarr; Import from cloud key</b> and paste this link or the key.${exists.mode === 'burn' ? '<br><b>One-time config:</b> it is deleted after the first import.' : ''}</p>`);
      }

      if (path === '/') return page('JUAN VPN cloud', '<h3>JUAN VPN cloud server</h3><p>This server is running. Set its address in the app under Settings &rarr; Cloud server.</p>');
      return J({ error: 'Not found' }, 404);
    } catch (e) {
      return J({ error: 'Server error' }, 500);
    }
  },
};
