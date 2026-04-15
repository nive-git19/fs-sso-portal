const express = require('express');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');
const https = require('https');
const http = require('http');
const { URL } = require('url');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ─────────────────────────────────────────
// Load private key
// ─────────────────────────────────────────
let PRIVATE_KEY;
if (process.env.PRIVATE_KEY) {
  PRIVATE_KEY = process.env.PRIVATE_KEY.replace(/\\n/g, '\n');
  console.log('✅ Private key loaded from environment');
} else {
  try {
    PRIVATE_KEY = fs.readFileSync(path.join(__dirname, 'private.key'), 'utf8');
    console.log('✅ Private key loaded from file');
  } catch (err) {
    console.error('❌ No private key found!');
    process.exit(1);
  }
}

const FRESHSERVICE_URL = 'https://nive-959766391470843394.myfreshworks.com';
const OIDC_REDIRECT_URL = 'https://nive-959766391470843394.myfreshworks.com/sp/OIDC/964459105499003173/implicit';

// ─────────────────────────────────────────
// Agent whitelist
// ─────────────────────────────────────────
const AGENTS = {
  'niveditha@oskloud.com': {
    password: 'Nivedemo@1234',
    workspace: 'amazon',
    given_name: 'Niveditha',
    family_name: 'Agent'
  },
  'nivetestfw@gmail.com': {
    password: 'Nivedemo@1234',
    workspace: 'netflix',
    given_name: 'Netflix',
    family_name: 'Agent'
  }
};

// ─────────────────────────────────────────
// Helper: fetch OIDC state + nonce from Freshservice (server-side)
//
// How it works:
// 1. Server makes HTTP GET to Freshservice URL
// 2. Freshservice sees no session → redirects to our Authorization URL
//    with ?client_id=...&state=...&nonce=...
// 3. We intercept that redirect (don't follow it to our own server)
//    and extract state + nonce from the Location header
// ─────────────────────────────────────────
function fetchOIDCParams() {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('Timeout')), 15000);

    function follow(url, depth) {
      if (depth > 15) { clearTimeout(timer); return reject(new Error('Too many redirects')); }

      const parsed = new URL(url);
      const client = parsed.protocol === 'https:' ? https : http;

      const req = client.get(url, {
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        },
        timeout: 10000
      }, (res) => {
        // If redirect, check if it points to our auth URL with state/nonce
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          const loc = res.headers.location;
          res.resume(); // drain response

          // Check if this redirect contains our OIDC params
          try {
            const locUrl = loc.startsWith('http') ? new URL(loc) : new URL(loc, url);
            const state = locUrl.searchParams.get('state');
            const nonce = locUrl.searchParams.get('nonce');

            if (state && nonce) {
              clearTimeout(timer);
              console.log('[OIDC] ✅ Got params from redirect Location header');
              return resolve({ state, nonce });
            }

            // Not our target redirect — follow it
            return follow(locUrl.href, depth + 1);
          } catch (e) {
            // If URL parse fails on relative URL, try resolving
            const next = loc.startsWith('http') ? loc : new URL(loc, url).href;
            return follow(next, depth + 1);
          }
        }

        // Not a redirect — check response body for state/nonce
        // (some Freshworks flows use JS/meta redirects)
        let body = '';
        res.setEncoding('utf8');
        res.on('data', (chunk) => { body += chunk; });
        res.on('end', () => {
          clearTimeout(timer);

          // Try to find state and nonce in the body (JS redirect, meta refresh, or form)
          const stateMatch = body.match(/[?&]state=([^&"'\s<>]+)/);
          const nonceMatch = body.match(/[?&]nonce=([^&"'\s<>]+)/);

          if (stateMatch && nonceMatch) {
            console.log('[OIDC] ✅ Got params from response body');
            return resolve({ state: stateMatch[1], nonce: nonceMatch[1] });
          }

          // Also check for window.location or href patterns
          const hrefMatch = body.match(/href=["'][^"']*[?&]state=([^&"']+)[^"']*[?&]nonce=([^&"']+)/);
          if (hrefMatch) {
            console.log('[OIDC] ✅ Got params from href in body');
            return resolve({ state: hrefMatch[1], nonce: hrefMatch[2] });
          }

          console.error('[OIDC] ❌ Could not find state/nonce. Status:', res.statusCode);
          console.error('[OIDC] Body preview:', body.substring(0, 500));
          reject(new Error('Could not extract OIDC params'));
        });
      });

      req.on('error', (err) => { clearTimeout(timer); reject(err); });
      req.on('timeout', () => { req.destroy(); clearTimeout(timer); reject(new Error('Request timeout')); });
    }

    follow(FRESHSERVICE_URL, 0);
  });
}

// ─────────────────────────────────────────
// ROUTES — Always serve login pages directly. No redirects. No bouncing.
// ─────────────────────────────────────────
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'amazon.html')));
app.get('/amazon', (req, res) => res.sendFile(path.join(__dirname, 'public', 'amazon.html')));
app.get('/netflix', (req, res) => res.sendFile(path.join(__dirname, 'public', 'netflix.html')));

// ─────────────────────────────────────────
// POST /login — validate creds → fetch OIDC params server-side → sign JWT → redirect
// ─────────────────────────────────────────
app.post('/login', async (req, res) => {
  const { email, password, portal } = req.body;

  console.log(`[LOGIN] email=${email} portal=${portal}`);

  // GUARD 1: credentials must be provided
  if (!email || !password) {
    return res.status(400).send(`
      <!DOCTYPE html><html><head><title>Error</title>
      <style>body{font-family:sans-serif;max-width:600px;margin:60px auto;padding:20px;background:#0d1117;color:#f0f0f0}
      h2{color:#ff6b6b}a{color:#FF9900}</style></head>
      <body><h2>Email and password are required</h2>
      <p><a href="javascript:history.back()">← Go back</a></p></body></html>
    `);
  }

  // GUARD 2: agent must exist and password must match
  const agentKey = email.toLowerCase().trim();
  const agent = AGENTS[agentKey];

  if (!agent || agent.password !== password) {
    console.warn(`[LOGIN] ❌ Invalid credentials for ${agentKey}`);
    return res.status(401).send(`
      <!DOCTYPE html><html><head><title>Login Failed</title>
      <style>body{font-family:sans-serif;max-width:600px;margin:60px auto;padding:20px;background:#0d1117;color:#f0f0f0}
      h2{color:#ff6b6b}a{color:#FF9900}</style></head>
      <body><h2>Invalid email or password</h2>
      <p><a href="javascript:history.back()">← Go back and try again</a></p></body></html>
    `);
  }

  // GUARD 3: portal exclusivity
  if (portal && agent.workspace !== portal) {
    console.warn(`[LOGIN] ❌ Agent ${agentKey} (${agent.workspace}) tried to access ${portal} portal`);
    return res.status(403).send(`
      <!DOCTYPE html><html><head><title>Access Denied</title>
      <style>body{font-family:sans-serif;max-width:600px;margin:60px auto;padding:20px;background:#0d1117;color:#f0f0f0}
      h2{color:#ff6b6b}a{color:#FF9900}</style></head>
      <body><h2>Access Denied</h2>
      <p>You are not authorized to access the <strong>${portal}</strong> portal.</p>
      <p><a href="javascript:history.back()">← Go back</a></p></body></html>
    `);
  }

  // ─── Fetch OIDC state + nonce from Freshservice (server-side) ───
  let state, nonce;
  try {
    console.log('[LOGIN] Fetching OIDC params from Freshservice...');
    const params = await fetchOIDCParams();
    state = params.state;
    nonce = params.nonce;
    console.log(`[LOGIN] ✅ Got state=${state.substring(0, 15)}... nonce=${nonce.substring(0, 15)}...`);
  } catch (err) {
    console.error('[LOGIN] ❌ Failed to fetch OIDC params:', err.message);
    return res.status(500).send(`
      <!DOCTYPE html><html><head><title>Connection Error</title>
      <style>body{font-family:sans-serif;max-width:600px;margin:60px auto;padding:20px;background:#0d1117;color:#f0f0f0}
      h2{color:#FF9900}a{color:#FF9900}</style></head>
      <body><h2>Could not connect to Freshservice</h2>
      <p>Please try again in a moment. If this keeps happening, contact support.</p>
      <p><a href="javascript:history.back()">← Go back and retry</a></p></body></html>
    `);
  }

  // ─── Build JWT ───
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    sub: agentKey,
    email: agentKey,
    given_name: agent.given_name,
    family_name: agent.family_name,
    iat: now,
    nonce: nonce
  };

  console.log('[LOGIN] JWT payload:', JSON.stringify(payload));

  let token;
  try {
    token = jwt.sign(payload, PRIVATE_KEY, { algorithm: 'RS256' });
  } catch (err) {
    console.error('[LOGIN] ❌ JWT signing error:', err.message);
    return res.status(500).send('Authentication error. Please contact support.');
  }

  // ─── Redirect to Freshworks OIDC endpoint ───
  const redirectUrl = `${OIDC_REDIRECT_URL}?state=${encodeURIComponent(state)}&id_token=${token}`;
  console.log(`[LOGIN] ✅ Redirecting ${agentKey} to Freshworks dashboard`);

  return res.redirect(302, redirectUrl);
});

// Health check
app.get('/health', (req, res) => res.json({ status: 'ok', time: new Date().toISOString() }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ SSO Portal running on port ${PORT}`);
  console.log(`   Routes: /amazon, /netflix, /login, /health`);
});
