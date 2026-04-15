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

const FRESHSERVICE_REDIRECT_URL = 'https://nive-959766391470843394.myfreshworks.com/sp/OIDC/964459105499003173/implicit';

const AGENTS = {
  'niveditha@oskloud.com': { password: 'Nivedemo@1234', workspace: 'amazon' },
  'nivetestfw@gmail.com':  { password: 'Nivedemo@1234', workspace: 'netflix' }
};

// Store state+nonce in memory temporarily
const pendingSessions = {};

// Helper — serve HTML with state+nonce injected
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

// Routes
app.get('/', (req, res) => {
  const { state, nonce } = req.query;
  console.log(`[ROOT] state=${state} nonce=${nonce}`);
  // Store for later use
  if (state) pendingSessions[state] = { nonce, portal: 'amazon' };
  serveHtml(res, 'amazon.html', state, nonce);
});

app.get('/amazon', (req, res) => {
  const { state, nonce } = req.query;
  console.log(`[AMAZON] state=${state} nonce=${nonce}`);
  // Store state+nonce so login can retrieve them
  if (state) pendingSessions[state] = { nonce, portal: 'amazon' };
  serveHtml(res, 'amazon.html', state, nonce);
});

app.get('/netflix', (req, res) => {
  const { state, nonce } = req.query;
  console.log(`[NETFLIX] state=${state} nonce=${nonce}`);
  if (state) pendingSessions[state] = { nonce, portal: 'netflix' };
  serveHtml(res, 'netflix.html', state, nonce);
});

// Login
app.post('/login', (req, res) => {
  let { email, password, portal, state, nonce } = req.body;

  // Try to recover state+nonce from memory if missing
  if (state && pendingSessions[state]) {
    const session = pendingSessions[state];
    if (!nonce) nonce = session.nonce;
    if (!portal) portal = session.portal;
    delete pendingSessions[state]; // cleanup
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
      error: `Access denied. You are not authorised for the ${portal} portal.`
    });
  }

  const now = Math.floor(Date.now() / 1000);
  const payload = {
    sub: agentKey,
    email: agentKey,
    iat: now,
    exp: now + 300,
    nonce: nonce || uuidv4()
  };

  let token;
  try {
    token = jwt.sign(payload, PRIVATE_KEY, { algorithm: 'RS256' });
  } catch (err) {
    console.error('JWT signing error:', err.message);
    return res.status(500).json({ error: 'Authentication error. Contact admin.' });
  }

  // MUST send back state that Freshworks originally sent
  const redirectUrl = `${FRESHSERVICE_REDIRECT_URL}?id_token=${token}&state=${state || portal}`;
  console.log(`[REDIRECT] state=${state} nonce=${nonce}`);

  return res.json({ success: true, redirectUrl });
});

app.get('/health', (req, res) => res.json({ status: 'ok' }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ SSO Portal running on port ${PORT}`);
});
