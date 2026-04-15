const express = require('express');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ─────────────────────────────────────────
// LOAD PRIVATE KEY
// On Render: stored as environment variable PRIVATE_KEY
// Locally: read from private.key file
// ─────────────────────────────────────────
let PRIVATE_KEY;

if (process.env.PRIVATE_KEY) {
  // Render environment variable
  PRIVATE_KEY = process.env.PRIVATE_KEY.replace(/\\n/g, '\n');
  console.log('✅ Private key loaded from environment variable');
} else {
  // Local file fallback
  try {
    PRIVATE_KEY = fs.readFileSync(path.join(__dirname, 'private.key'), 'utf8');
    console.log('✅ Private key loaded from file');
  } catch (err) {
    console.error('❌ No private key found! Set PRIVATE_KEY env variable on Render.');
    process.exit(1);
  }
}

// ─────────────────────────────────────────
// CONFIG
// ─────────────────────────────────────────
const FRESHSERVICE_REDIRECT_URL = 'https://nive-959766391470843394.myfreshworks.com/sp/OIDC/964459105499003173/implicit';

const AGENTS = {
  'niveditha@oskloud.com': { password: 'Nivedemo@1234', workspace: 'amazon' },
  'nivetestfw@gmail.com':  { password: 'Nivedemo@1234', workspace: 'netflix' }
};

// ─────────────────────────────────────────
// HELPER — Inject state & nonce into HTML
// ─────────────────────────────────────────
function serveHtml(res, filename, state, nonce) {
  const filePath = path.join(__dirname, 'public', filename);
  let html = fs.readFileSync(filePath, 'utf8');
  html = html.replace(
    '<!-- STATE_NONCE_PLACEHOLDER -->',
    `<input type="hidden" name="state" value="${state || ''}"/>
     <input type="hidden" name="nonce" value="${nonce || uuidv4()}"/>`
  );
  res.send(html);
}

// ─────────────────────────────────────────
// ROUTES — Serve login pages
// ─────────────────────────────────────────
app.get('/', (req, res) => {
  const { state, nonce } = req.query;
  serveHtml(res, 'amazon.html', state, nonce);
});

app.get('/amazon', (req, res) => {
  const { state, nonce } = req.query;
  console.log(`[AMAZON] state=${state} nonce=${nonce}`);
  serveHtml(res, 'amazon.html', state, nonce);
});

app.get('/netflix', (req, res) => {
  const { state, nonce } = req.query;
  console.log(`[NETFLIX] state=${state} nonce=${nonce}`);
  serveHtml(res, 'netflix.html', state, nonce);
});

// ─────────────────────────────────────────
// POST /login — Validate + Sign JWT + Redirect
// ─────────────────────────────────────────
app.post('/login', (req, res) => {
  const { email, password, portal, state, nonce } = req.body;

  console.log(`[LOGIN] email=${email} portal=${portal} state=${state} nonce=${nonce}`);

  // Basic validation
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required.' });
  }

  const agentKey = email.toLowerCase().trim();
  const agent = AGENTS[agentKey];

  // Check agent exists
  if (!agent) {
    return res.status(401).json({ error: 'Invalid email or password.' });
  }

  // Check password
  if (agent.password !== password) {
    return res.status(401).json({ error: 'Invalid email or password.' });
  }

  // Check correct portal
  if (portal && agent.workspace !== portal) {
    return res.status(403).json({
      error: `Access denied. You are not authorised for the ${portal} portal.`
    });
  }

  // Build JWT payload
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    sub: agentKey,
    email: agentKey,
    iat: now,
    exp: now + 300,          // expires in 5 mins
    nonce: nonce || uuidv4() // MUST match what Freshservice sent
  };

  // Sign JWT with RS256
  let token;
  try {
    token = jwt.sign(payload, PRIVATE_KEY, { algorithm: 'RS256' });
  } catch (err) {
    console.error('JWT signing error:', err.message);
    return res.status(500).json({ error: 'Authentication error. Contact admin.' });
  }

  // Redirect to Freshservice with token + state
  const redirectUrl = `${FRESHSERVICE_REDIRECT_URL}?id_token=${token}&state=${state || portal}`;
  console.log(`[REDIRECT] ${redirectUrl}`);

  return res.json({ success: true, redirectUrl });
});

// Health check
app.get('/health', (req, res) => res.json({ status: 'ok', time: new Date().toISOString() }));

// ─────────────────────────────────────────
// START
// ─────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`
╔══════════════════════════════════════╗
║   Freshservice SSO Portal — LIVE     ║
╠══════════════════════════════════════╣
║ 🟠 Amazon  → /amazon                ║
║ 🔴 Netflix → /netflix               ║
╚══════════════════════════════════════╝
  `);
});
