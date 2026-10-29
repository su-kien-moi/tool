// server.js — Node 18+, express ^4.19, chạy: npm i && node server.js
const express = require('express');
const crypto = require('node:crypto');
const path = require('node:path');

const app = express();
const SECRET = process.env.GATE_SECRET || crypto.randomBytes(32).toString('hex'); // FILL: set qua env khi deploy thật
const TOKEN_TTL_MS = 60_000; // token sống 60s — đủ một lần redirect
const PORT = process.env.PORT || 3000;
const ALLOWED_HOSTS = (process.env.ALLOWED_HOSTS || '').split(',').map(s => s.trim()).filter(Boolean); // FILL: whitelist host đích, rỗng = cho mọi http/https

app.use(express.static(path.join(__dirname, 'public')));

function sign(target) {
  const exp = Date.now() + TOKEN_TTL_MS;
  const payload = `${target}|${exp}`;
  const sig = crypto.createHmac('sha256', SECRET).update(payload).digest('base64url');
  return Buffer.from(`${payload}|${sig}`).toString('base64url');
}

function verify(token) {
  let raw;
  try { raw = Buffer.from(token, 'base64url').toString('utf8'); } catch { return null; }
  const parts = raw.split('|');
  if (parts.length !== 3) return null;
  const [target, expStr, sig] = parts;
  const exp = Number(expStr);
  if (!Number.isFinite(exp) || Date.now() > exp) return null;
  const expected = crypto.createHmac('sha256', SECRET).update(`${target}|${exp}`).digest('base64url');
  const a = Buffer.from(sig), b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  return target;
}

function targetAllowed(target) {
  if (!/^https?:\/\//i.test(target)) return false;
  if (ALLOWED_HOSTS.length === 0) return true;
  try {
    const host = new URL(target).host;
    return ALLOWED_HOSTS.includes(host);
  } catch { return false; }
}

app.get('/go', (req, res) => {
  const target = String(req.query.to || '');
  if (!targetAllowed(target)) return res.status(400).json({ error: 'bad target' });
  const token = sign(target);
  res.redirect(302, `/landing.html?t=${encodeURIComponent(token)}`);
});

app.get('/api/resolve', (req, res) => {
  const target = verify(String(req.query.t || ''));
  if (!target) return res.status(410).json({ error: 'expired or tampered' });
  res.json({ target });
});

app.listen(PORT, () => console.log(`gate up on :${PORT}`));
