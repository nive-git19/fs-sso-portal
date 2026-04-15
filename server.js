const express = require('express');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// ─────────────────────────────────────────
// CONFIG — All settings in one place
// ─────────────────────────────────────────
const CONFIG = {
  freshservice_url: 'https://nive-959766391470843394.myfreshworks.com',

  // Agents: email → { password, workspace }
  agents: {
    'niveditha@oskloud.com': { password: 'Nivedemo@1234', workspace: 'amazon' },
    'nivetestfw@gmail.com':  { password: 'Nivedemo@1234', workspace: 'netflix' }
  }
};

// Load RSA private key
let PRIVATE_KEY;
try {
  PRIVATE_KEY = process.env.PRIVATE_KEY
    ? process.env.PRIVATE_KEY.replace(/\\n/g, '\n')
    : fs.readFileSync(path.join(__dirname, 'private.key'), 'utf8');
  console.log('✅ Private key loaded successfully');
} catch (err) {
  console.error('❌ Private key not found!');
  process.exit(1);
}

// ─────────────────────────────────────────
// ROUTES
// ─────────────────────────────────────────
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'amazon.html')));
app.get('/amazon', (req, res) => res.sendFile(path.join(__dirname, 'public', 'amazon.html')));
app.get('/netflix', (req, res) => res.sendFile(path.join(__dirname, 'public', 'netflix.html')));

// ─────────────────────────────────────────
// LOGIN — JWT Generation + Portal Restriction
// ─────────────────────────────────────────
app.post('/login', (req, res) => {
  const { email, password, portal } = req.body;

  if (!email || !password) {
    return res.status(400).json({ success: false, error: 'Email and password are required.' });
  }

  const agentKey = email.toLowerCase().trim();
  const agent = CONFIG.agents[agentKey];

  // Agent does not exist
  if (!agent) {
    return res.status(401).json({ success: false, error: 'Invalid email or password.' });
  }

  // Wrong password
  if (agent.password !== password) {
    return res.status(401).json({ success: false, error: 'Invalid email or password.' });
  }

  // ✅ PORTAL RESTRICTION — Netflix agent cannot login via Amazon page
  if (portal && agent.workspace !== portal) {
    return res.status(403).json({
      success: false,
      error: `Access denied. You are not an agent for the ${portal} portal.`
    });
  }

  // Build JWT
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    sub: agentKey,
    email: agentKey,
    iat: now,
    exp: now + 300,
    jti: uuidv4()
  };

  // Sign JWT
  let token;
  try {
    token = jwt.sign(payload, PRIVATE_KEY, { algorithm: 'RS256' });
  } catch (err) {
    console.error('JWT signing error:', err.message);
    return res.status(500).json({ success: false, error: 'Authentication error. Please contact admin.' });
  }

  // ✅ Direct JWT login — bypasses OIDC, goes straight to dashboard
  const redirectUrl = `${CONFIG.freshservice_url}/login/jwt?jwt=${token}`;

  console.log(`✅ Login success: ${agentKey} → ${portal} portal`);
  return res.json({ success: true, redirectUrl });
});

// Health check
app.get('/health', (req, res) => res.json({ status: 'ok' }));

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`
✅ Freshservice SSO Portal running!
🟠 Amazon → http://localhost:${PORT}/amazon
🔴 Netflix → http://localhost:${PORT}/netflix
  `);
});
