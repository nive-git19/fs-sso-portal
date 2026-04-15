const express = require('express');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Load private key
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

// ─────────────────────────────────────────
// CONFIG — as per official Freshworks docs
// ─────────────────────────────────────────
const OIDC_REDIRECT_URL = 'https://nive-959766391470843394.myfreshworks.com/sp/OIDC/964459105499003173/implicit';

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

// Store state+nonce from Freshworks in memory
const sessions = {};

// ─────────────────────────────────────────
// HELPER — Inject state+nonce into HTML
// ─────────────────────────────────────────
function serveHtml(res, filename, state, nonce) {
  const filePath = path.join(__dirname, 'public', filename);
  let html = fs.readFileSync(filePath, 'utf8');
  html = html.replace(
    '<!-- STATE_NONCE_PLACEHOLDER -->',
    `<input type="hidden" name="state" value="${state || ''}"/>
     <input type="hidden" name="nonce" value="${nonce || ''}"/>`
  );
  res.send(html);
}

// ─────────────────────────────────────────
// ROUTES — capture state+nonce when
// Freshworks redirects to our auth URL
// ─────────────────────────────────────────
app.get('/', (req, res) => {
  const { state, nonce } = req.query;
  if (state) sessions[state] = nonce;
  serveHtml(res, 'amazon.html', state, nonce);
});

app.get('/amazon', (req, res) => {
  const { state, nonce } = req.query;
  console.log(`[AMAZON] state=${state} nonce=${nonce}`);
  if (state) sessions[state] = nonce;
  serveHtml(res, 'amazon.html', state, nonce);
});

app.get('/netflix', (req, res) => {
  const { state, nonce } = req.query;
  console.log(`[NETFLIX] state=${state} nonce=${nonce}`);
  if (state) sessions[state] = nonce;
  serveHtml(res, 'netflix.html', state, nonce);
});

// ─────────────────────────────────────────
// POST /login — validate + sign JWT
// ─────────────────────────────────────────
app.post('/login', (req, res) => {
  let { email, password, portal, state, nonce } = req.body;

  // Recover nonce from session storage if not in form
  if (state && sessions[state] && !nonce) {
    nonce = sessions[state];
  }

  console.log(`[LOGIN] email=${email} portal=${portal} state=${state} nonce=${nonce}`);

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required.' });
  }

  const agentKey = email.toLowerCase().trim();
  const agent = AGENTS[agentKey];

  if (!agent) {
    return res.status(401).json({ error: 'Invalid email or password.' });
  }

  if (agent.password !== password) {
    return res.status(401).json({ error: 'Invalid email or password.' });
  }

  if (portal && agent.workspace !== portal) {
    return res.status(403).json({
      error: `Access denied. You are not an agent for the ${portal} portal.`
    });
  }

  // Build JWT payload — as per official Freshworks docs
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    sub: agentKey,
    email: agentKey,
    given_name: agent.given_name,   // ✅ Required by Freshworks
    family_name: agent.family_name, // ✅ Required by Freshworks
    iat: now,
    exp: now + 300,
    nonce: nonce || uuidv4()        // ✅ MUST be the nonce from Freshworks
  };

  let token;
  try {
    token = jwt.sign(payload, PRIVATE_KEY, { algorithm: 'RS256' });
  } catch (err) {
    console.error('JWT signing error:', err.message);
    return res.status(500).json({ error: 'Authentication error.' });
  }

  // Redirect back to Freshworks OIDC endpoint
  // Format: OIDC_URL?state=STATE&id_token=JWT
  const redirectUrl = `${OIDC_REDIRECT_URL}?state=${state || portal}&id_token=${token}`;
  console.log(`[REDIRECT] state=${state} nonce=${nonce}`);

  return res.json({ success: true, redirectUrl });
});

app.get('/health', (req, res) => res.json({ status: 'ok' }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ SSO Portal running on port ${PORT}`));
