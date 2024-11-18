const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');

const { v4: randomUUID } = require('uuid');

const app = express();
app.use(bodyParser.json());
app.use(cors()); // Enable CORS for all routes

// In-memory storage (not for production)
const users = new Map();

// Routes

// Step 1: Generate registration options
app.get('/register', async (req, res) => {
  const userID = randomUUID();
  const user = {
    id: userID,
    username: `user-${userID}`,
    credentials: [],
  };
  users.set(userID, user);

  const options = await generateRegistrationOptions({
    rpName: 'Passkey Example',
    rpID: 'localhost',
    userID: Buffer.from(user.id, 'utf8'),
    userName: user.username,
    attestationType: 'none',
  });

  user.currentChallenge = options.challenge;
  res.json({ options, userID });
});

// Step 2: Verify registration response
app.post('/register', (req, res) => {
  const { userID, credential } = req.body;
  const user = users.get(userID);

  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  const verification = verifyRegistrationResponse({
    response: credential,
    expectedChallenge: user.currentChallenge,
    expectedOrigin: 'http://localhost:3000',
    expectedRPID: 'localhost',
  });

  if (verification.verified) {
    user.credentials.push(verification.registrationInfo);
    delete user.currentChallenge;
    res.json({ success: true });
  } else {
    res.status(400).json({ error: 'Verification failed' });
  }
});

// Step 3: Generate authentication options
app.get('/login', (req, res) => {
  const { userID } = req.query;
  const user = users.get(userID);

  if (!user || user.credentials.length === 0) {
    return res.status(404).json({ error: 'User not registered or no credentials' });
  }

  const options = generateAuthenticationOptions({
    rpID: 'localhost',
    allowCredentials: user.credentials.map((cred) => ({
      id: cred.credentialID,
      type: 'public-key',
    })),
  });

  user.currentChallenge = options.challenge;
  res.json({ options });
});

// Step 4: Verify authentication response
app.post('/login', (req, res) => {
  const { userID, credential } = req.body;
  const user = users.get(userID);

  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  const verification = verifyAuthenticationResponse({
    response: credential,
    expectedChallenge: user.currentChallenge,
    expectedOrigin: 'http://localhost:3000',
    expectedRPID: 'localhost',
    authenticator: user.credentials[0],
  });

  if (verification.verified) {
    delete user.currentChallenge;
    res.json({ success: true });
  } else {
    res.status(400).json({ error: 'Verification failed' });
  }
});

// Serve the frontend
const path = require('path');
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(3000, () => console.log('Server running on http://localhost:3000'));

