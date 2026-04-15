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

const FRESHSERVICE_URL = 'https://nive-959766391470843394.myfreshworks.com';
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
// ─────────────────────────────────────────
function renderPortalPage(req, res, htmlFileName, portalName) {
  const state = req.query.state || '';
  const nonce = req.query.nonce || '';
  const clientId = req.query.client_id || '';

  console.log(`[${portalName.toUpperCase()}] Incoming request`);
  console.log(`  state    = ${state}`);
  console.log(`  nonce    = ${nonce}`);
  console.log(`  client_id= ${clientId}`);

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
// 
// If state & nonce are present → show the branded login page
// If missing → redirect to Freshservice to get them
//   (Freshservice auto-redirects back when JWT SSO is the only login method)
// ─────────────────────────────────────────
app.get('/amazon', (req, res) => {
  if (req.query.state && req.query.nonce) {
    return renderPortalPage(req, res, 'amazon.html', 'amazon');
  }
  console.log('[AMAZON] No OIDC params → redirecting to Freshservice');
  res.redirect(FRESHSERVICE_URL);
});

app.get('/netflix', (req, res) => {
  if (req.query.state && req.query.nonce) {
    return renderPortalPage(req, res, 'netflix.html', 'netflix');
  }
  console.log('[NETFLIX] No OIDC params → redirecting to Freshservice');
  res.redirect(FRESHSERVICE_URL);
});

app.get('/', (req, res) => {
  if (req.query.state && req.query.nonce) {
    return renderPortalPage(req, res, 'amazon.html', 'amazon');
  }
  res.redirect(FRESHSERVICE_URL);
});

// ─────────────────────────────────────────
// POST /login — authenticate and redirect to Freshworks with signed JWT
// ─────────────────────────────────────────
app.post('/login', (req, res) => {
  const { email, password, portal, state, nonce } = req.body;

  console.log(`[LOGIN] email=${email} portal=${portal}`);
  console.log(`  state=${state}`);
  console.log(`  nonce=${nonce}`);

  // GUARD 1: state and nonce MUST be present
  if (!state || !nonce) {
    console.error('[LOGIN] ❌ Missing state or nonce');
    return res.status(400).send(`
      <!DOCTYPE html>
      <html><head><title>Session Error</title>
      <style>body{font-family:sans-serif;max-width:600px;margin:60px auto;padding:20px;background:#0d1117;color:#f0f0f0}
      h2{color:#FF9900}a{color:#FF9900}</style></head>
      <body>
        <h2>Session expired or invalid entry</h2>
        <p>The login session is missing required parameters.</p>
        <p><a href="${FRESHSERVICE_URL}">→ Click here to start login</a></p>
      </body></html>
    `);
  }

  // GUARD 2: credentials must be provided
  if (!email || !password) {
    return res.status(400).send('Email and password are required.');
  }

  // GUARD 3: agent must exist and password must match
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

  // GUARD 4: portal exclusivity
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

  // Build JWT payload
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

  // Sign JWT
  let token;
  try {
    token = jwt.sign(payload, PRIVATE_KEY, { algorithm: 'RS256' });
  } catch (err) {
    console.error('[LOGIN] ❌ JWT signing error:', err.message);
    return res.status(500).send('Authentication error. Please contact support.');
  }

  // Redirect to Freshworks OIDC endpoint
  const redirectUrl = `${OIDC_REDIRECT_URL}?state=${encodeURIComponent(state)}&id_token=${token}`;
  console.log(`[LOGIN] ✅ Redirecting to Freshworks for ${agentKey}`);

  return res.redirect(302, redirectUrl);
});

// Health check
app.get('/health', (req, res) => res.json({ status: 'ok', time: new Date().toISOString() }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ SSO Portal running on port ${PORT}`);
  console.log(`   Routes: /amazon, /netflix, /login, /health`);
});
