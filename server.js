const express = require('express');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');

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

const OIDC_REDIRECT_URL = 'https://nive-959766391470843394.myfreshworks.com/sp/OIDC/964459105499003173/implicit';

// ─────────────────────────────────────────
// Agent whitelist (server-side enforcement)
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
// Helper: render branded portal page with state/nonce as hidden inputs
// state and nonce now travel WITH the user in the form, immune to cold starts
// ─────────────────────────────────────────
function renderPortalPage(req, res, htmlFileName, portalName) {
  const state = req.query.state || '';
  const nonce = req.query.nonce || '';
  const clientId = req.query.client_id || '';

  console.log(`[${portalName.toUpperCase()}] Incoming request`);
  console.log(`  state    = ${state}`);
  console.log(`  nonce    = ${nonce}`);
  console.log(`  client_id= ${clientId}`);

  if (!state || !nonce) {
    console.warn(`[${portalName.toUpperCase()}] ⚠️ Missing state or nonce — user may have visited directly`);
  }

  const filePath = path.join(__dirname, 'public', htmlFileName);
  let html = fs.readFileSync(filePath, 'utf8');

  // Inject state, nonce, and portal as hidden form fields
  html = html.replace(
    '<!-- SESSION_PLACEHOLDER -->',
    `<input type="hidden" name="state" value="${state}"/>
     <input type="hidden" name="nonce" value="${nonce}"/>
     <input type="hidden" name="portal" value="${portalName}"/>`
  );

  res.send(html);
}

// ─────────────────────────────────────────
// Branded portal routes
// ─────────────────────────────────────────
app.get('/amazon', (req, res) => renderPortalPage(req, res, 'amazon.html', 'amazon'));
app.get('/netflix', (req, res) => renderPortalPage(req, res, 'netflix.html', 'netflix'));

// Default route → Amazon (or change as needed)
app.get('/', (req, res) => renderPortalPage(req, res, 'amazon.html', 'amazon'));

// ─────────────────────────────────────────
// POST /login — authenticate and redirect to Freshworks with signed JWT
// ─────────────────────────────────────────
app.post('/login', (req, res) => {
  const { email, password, portal, state, nonce } = req.body;

  console.log(`[LOGIN] email=${email} portal=${portal}`);
  console.log(`  state=${state}`);
  console.log(`  nonce=${nonce}`);

  // ─────────────────────────────────────
  // GUARD 1: state and nonce MUST be present (no silent fallbacks)
  // ─────────────────────────────────────
  if (!state || !nonce) {
    console.error('[LOGIN] ❌ Missing state or nonce in form submission');
    return res.status(400).send(`
      <!DOCTYPE html>
      <html><head><title>Session Error</title>
      <style>body{font-family:sans-serif;max-width:600px;margin:60px auto;padding:20px;background:#0d1117;color:#f0f0f0}
      h2{color:#FF9900}a{color:#FF9900}</style></head>
      <body>
        <h2>Session expired or invalid entry</h2>
        <p>The login session is missing required parameters. This usually means:</p>
        <ul>
          <li>You visited this page directly instead of being redirected from Freshworks</li>
          <li>Your session expired (more than 10 minutes since the redirect)</li>
        </ul>
        <p>Please start over by going to your Freshworks login URL.</p>
      </body></html>
    `);
  }

  // ─────────────────────────────────────
  // GUARD 2: credentials must be provided
  // ─────────────────────────────────────
  if (!email || !password) {
    return res.status(400).send('Email and password are required.');
  }

  // ─────────────────────────────────────
  // GUARD 3: agent must exist and password must match
  // ─────────────────────────────────────
  const agentKey = email.toLowerCase().trim();
  const agent = AGENTS[agentKey];

  if (!agent || agent.password !== password) {
    console.warn(`[LOGIN] ❌ Invalid credentials for ${agentKey}`);
    return res.status(401).send(`
      <!DOCTYPE html>
      <html><head><title>Login Failed</title>
      <style>body{font-family:sans-serif;max-width:600px;margin:60px auto;padding:20px;background:#0d1117;color:#f0f0f0}
      h2{color:#ff6b6b}a{color:#FF9900}</style></head>
      <body>
        <h2>Invalid email or password</h2>
        <p><a href="javascript:history.back()">← Go back and try again</a></p>
      </body></html>
    `);
  }

  // ─────────────────────────────────────
  // GUARD 4: portal exclusivity — agent must belong to this portal
  // ─────────────────────────────────────
  if (portal && agent.workspace !== portal) {
    console.warn(`[LOGIN] ❌ Agent ${agentKey} (${agent.workspace}) tried to access ${portal} portal`);
    return res.status(403).send(`
      <!DOCTYPE html>
      <html><head><title>Access Denied</title>
      <style>body{font-family:sans-serif;max-width:600px;margin:60px auto;padding:20px;background:#0d1117;color:#f0f0f0}
      h2{color:#ff6b6b}a{color:#FF9900}</style></head>
      <body>
        <h2>Access Denied</h2>
        <p>You are not authorized to access the <strong>${portal}</strong> portal.</p>
        <p><a href="javascript:history.back()">← Go back</a></p>
      </body></html>
    `);
  }

  // ─────────────────────────────────────
  // Build JWT payload — exactly what Freshworks documents as required
  // sub, email, iat, nonce, given_name, family_name
  // ─────────────────────────────────────
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    sub: agentKey,
    email: agentKey,
    given_name: agent.given_name,
    family_name: agent.family_name,
    iat: now,
    nonce: nonce   // ← echo back EXACTLY what Freshworks sent. NO fallback.
  };

  console.log('[LOGIN] JWT payload:', JSON.stringify(payload));

  // ─────────────────────────────────────
  // Sign JWT with RS256
  // ─────────────────────────────────────
  let token;
  try {
    token = jwt.sign(payload, PRIVATE_KEY, { algorithm: 'RS256' });
  } catch (err) {
    console.error('[LOGIN] ❌ JWT signing error:', err.message);
    return res.status(500).send('Authentication error. Please contact support.');
  }

  // ─────────────────────────────────────
  // Redirect to Freshworks with state (in URL) and id_token (the JWT)
  // Format matches Freshworks docs: ?state=X&id_token=JWT
  // ─────────────────────────────────────
  const redirectUrl = `${OIDC_REDIRECT_URL}?state=${encodeURIComponent(state)}&id_token=${token}`;
  console.log(`[LOGIN] ✅ Redirecting to Freshworks for ${agentKey}`);
  console.log(`  Redirect URL length: ${redirectUrl.length} chars`);

  // 302 redirect — keeps browser navigation in one chain, preserves cookies
  return res.redirect(302, redirectUrl);
});

// ─────────────────────────────────────────
// Health check (for UptimeRobot pinger to keep Render warm)
// ─────────────────────────────────────────
app.get('/health', (req, res) => res.json({ status: 'ok', time: new Date().toISOString() }));

// ─────────────────────────────────────────
// Start server
// ─────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ SSO Portal running on port ${PORT}`);
  console.log(`   Routes: /amazon, /netflix, /login, /health`);
});
