const express = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
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
// Agent whitelist
// 'sub' is the Freshworks user ID — grabbed from Neo Admin Center URL
// Niveditha: /users/962962783131722116/accounts
// Netflix:   /users/959782866975283814/accounts
// ─────────────────────────────────────────
const AGENTS = {
  'niveditha@oskloud.com': {
    password: 'Nivedemo@1234',
    workspace: 'amazon',
    given_name: 'Niveditha',
    family_name: 'Agent',
    sub: '962962783131722116'   // ← Niveditha's Freshworks user ID
  },
  'nivetestfw@gmail.com': {
    password: 'Nivedemo@1234',
    workspace: 'netflix',
    given_name: 'Netflix',
    family_name: 'Agent',
    sub: '959782866975283814'   // ← Netflix Agent's Freshworks user ID
  }
};

// ─────────────────────────────────────────
// Render branded portal page (IdP-initiated, no Freshworks handshake)
// ─────────────────────────────────────────
function renderPortalPage(req, res, htmlFileName, portalName) {
  console.log(`[${portalName.toUpperCase()}] Direct visit — IdP-initiated flow`);

  const filePath = path.join(__dirname, 'public', htmlFileName);
  let html = fs.readFileSync(filePath, 'utf8');

  html = html.replace(
    '<!-- SESSION_PLACEHOLDER -->',
    `<input type="hidden" name="portal" value="${portalName}"/>`
  );

  res.send(html);
}

// ─────────────────────────────────────────
// Routes — agents come here directly
// ─────────────────────────────────────────
app.get('/amazon', (req, res) => renderPortalPage(req, res, 'amazon.html', 'amazon'));
app.get('/netflix', (req, res) => renderPortalPage(req, res, 'netflix.html', 'netflix'));
app.get('/', (req, res) => renderPortalPage(req, res, 'amazon.html', 'amazon'));

// ─────────────────────────────────────────
// POST /login — IdP-initiated SSO
// ─────────────────────────────────────────
app.post('/login', (req, res) => {
  const { email, password, portal } = req.body;

  console.log(`[LOGIN] email=${email} portal=${portal}`);

  if (!email || !password) {
    return res.status(400).send(errorPage('Missing credentials', 'Email and password are required.'));
  }

  const agentKey = email.toLowerCase().trim();
  const agent = AGENTS[agentKey];

  if (!agent || agent.password !== password) {
    console.warn(`[LOGIN] ❌ Invalid credentials for ${agentKey}`);
    return res.status(401).send(errorPage('Invalid email or password', 'Please check your credentials and try again.'));
  }

  if (portal && agent.workspace !== portal) {
    console.warn(`[LOGIN] ❌ Agent ${agentKey} (${agent.workspace}) tried to access ${portal} portal`);
    return res.status(403).send(errorPage(
      'Access Denied',
      `You are not authorized to access the <strong>${portal}</strong> portal. Please use your designated portal.`
    ));
  }

  // ─────────────────────────────────────
  // Build JWT — sub is the Freshworks user ID
  // ─────────────────────────────────────
  const now = Math.floor(Date.now() / 1000);
  const ourNonce = crypto.randomBytes(16).toString('hex');

  const payload = {
    sub: agent.sub,                    // ← Freshworks user ID
    email: agentKey,
    given_name: agent.given_name,
    family_name: agent.family_name,
    iat: now,
    nonce: ourNonce
  };

  console.log('[LOGIN] JWT payload:', JSON.stringify(payload));

  let token;
  try {
    token = jwt.sign(payload, PRIVATE_KEY, { algorithm: 'RS256' });
  } catch (err) {
    console.error('[LOGIN] ❌ JWT signing error:', err.message);
    return res.status(500).send(errorPage('Authentication error', 'Please contact support.'));
  }

  const redirectUrl = `${OIDC_REDIRECT_URL}?id_token=${token}`;
  console.log(`[LOGIN] ✅ Redirecting ${agentKey} (sub=${agent.sub}) to Freshworks`);

  return res.redirect(302, redirectUrl);
});

// ─────────────────────────────────────────
// Branded error page helper
// ─────────────────────────────────────────
function errorPage(title, message) {
  return `<!DOCTYPE html>
<html><head><title>${title}</title>
<style>
  body{font-family:'DM Sans',sans-serif;max-width:520px;margin:80px auto;padding:40px;background:#0d1117;color:#f0f0f0;border-radius:16px;border:1px solid rgba(255,153,0,0.2)}
  h2{color:#FF9900;margin-bottom:16px;font-family:'Unbounded',sans-serif}
  p{line-height:1.6;color:rgba(240,240,240,0.7)}
  a{color:#FF9900;text-decoration:none;display:inline-block;margin-top:24px;padding:10px 20px;border:1px solid #FF9900;border-radius:8px;transition:all 0.2s}
  a:hover{background:#FF9900;color:#111}
</style></head>
<body>
  <h2>${title}</h2>
  <p>${message}</p>
  <a href="javascript:history.back()">← Go back</a>
</body></html>`;
}

app.get('/health', (req, res) => res.json({ status: 'ok', time: new Date().toISOString() }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ SSO Portal running on port ${PORT}`);
  console.log(`   Mode: IdP-Initiated (no Freshworks handshake)`);
  console.log(`   Routes: /amazon, /netflix, /login, /health`);
});
