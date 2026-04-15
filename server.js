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

// Server-side session store
// Key: sessionId → { state, nonce, portal }
const sessions = {};

// ─────────────────────────────────────────
// ROUTES
// ─────────────────────────────────────────
app.get('/amazon', (req, res) => {
  const { state, nonce } = req.query;
  console.log(`[AMAZON] state=${state} nonce=${nonce}`);

  // Create a session and store state+nonce
  const sessionId = uuidv4();
  sessions[sessionId] = { state, nonce, portal: 'amazon' };

  // Serve HTML with sessionId injected
  const filePath = path.join(__dirname, 'public', 'amazon.html');
  let html = fs.readFileSync(filePath, 'utf8');
  html = html.replace(
    '<!-- SESSION_PLACEHOLDER -->',
    `<input type="hidden" name="sessionId" value="${sessionId}"/>`
  );
  res.send(html);
});

app.get('/netflix', (req, res) => {
  const { state, nonce } = req.query;
  console.log(`[NETFLIX] state=${state} nonce=${nonce}`);

  const sessionId = uuidv4();
  sessions[sessionId] = { state, nonce, portal: 'netflix' };

  const filePath = path.join(__dirname, 'public', 'netflix.html');
  let html = fs.readFileSync(filePath, 'utf8');
  html = html.replace(
    '<!-- SESSION_PLACEHOLDER -->',
    `<input type="hidden" name="sessionId" value="${sessionId}"/>`
  );
  res.send(html);
});

app.get('/', (req, res) => {
  const { state, nonce } = req.query;
  const sessionId = uuidv4();
  sessions[sessionId] = { state, nonce, portal: 'amazon' };

  const filePath = path.join(__dirname, 'public', 'amazon.html');
  let html = fs.readFileSync(filePath, 'utf8');
  html = html.replace(
    '<!-- SESSION_PLACEHOLDER -->',
    `<input type="hidden" name="sessionId" value="${sessionId}"/>`
  );
  res.send(html);
});

// ─────────────────────────────────────────
// POST /login
// ─────────────────────────────────────────
app.post('/login', (req, res) => {
  const { email, password, portal, sessionId } = req.body;

  // Retrieve state+nonce from server session
  const session = sessions[sessionId] || {};
  const state = session.state;
  const nonce = session.nonce;
  const sessionPortal = session.portal || portal;

  console.log(`[LOGIN] email=${email} sessionId=${sessionId} state=${state} nonce=${nonce} portal=${sessionPortal}`);

  // Clean up session
  if (sessionId) delete sessions[sessionId];

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

  if (sessionPortal && agent.workspace !== sessionPortal) {
    return res.status(403).json({
      error: `Access denied. You are not an agent for the ${sessionPortal} portal.`
    });
  }

  const now = Math.floor(Date.now() / 1000);
  const payload = {
    sub: agentKey,
    email: agentKey,
    given_name: agent.given_name,
    family_name: agent.family_name,
    iat: now,
    exp: now + 300,
    nonce: nonce || uuidv4()
  };

  let token;
  try {
    token = jwt.sign(payload, PRIVATE_KEY, { algorithm: 'RS256' });
  } catch (err) {
    console.error('JWT signing error:', err.message);
    return res.status(500).json({ error: 'Authentication error.' });
  }

  const finalState = state || sessionPortal;
  const redirectUrl = `${OIDC_REDIRECT_URL}?state=${finalState}&id_token=${token}`;
  console.log(`[REDIRECT] state=${finalState} nonce=${nonce}`);

  return res.json({ success: true, redirectUrl });
});

app.get('/health', (req, res) => res.json({ status: 'ok' }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ SSO Portal running on port ${PORT}`));
