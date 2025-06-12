import express from 'express';
import cors from 'cors';
import fs from 'fs/promises';
import path from 'path';
import jwt from 'jsonwebtoken';

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Async function to read JWKS file
const readJWKSAsync = async () => {
  const jwksPath = path.join(process.cwd(), 'jwks', 'jwks.json');
  const data = await fs.readFile(jwksPath, 'utf8');
  return JSON.parse(data);
};

// Async function to read private key
const readPrivateKeyAsync = async () => {
  const privateKeyPath = path.join(process.cwd(), 'jwks', 'private.pem');
  return await fs.readFile(privateKeyPath, 'utf8');
};

// Async function to read public key (optional - for verification)
const readPublicKeyAsync = async () => {
  const publicKeyPath = path.join(process.cwd(), 'jwks', 'public.pem');
  return await fs.readFile(publicKeyPath, 'utf8');
};

// Root route
app.get('/', (req, res) => {
  res.json({
    message: 'Welcome to Merchant Backend API',
    status: 'Server is running successfully',
    timestamp: new Date().toISOString(),
    endpoints: {
      root: 'GET /',
      health: 'GET /health',
      jwks: 'GET /.well-known/jwks.json',
      generateToken: 'POST /generate-token'
    }
  });
});

// Token generation endpoint
app.post('/generate-token', async (req, res) => {
  try {
    const { user_id = '123456', bot_id = '0376239051105167' } = req.body;
    
    // Validate required fields
    if (!user_id || !bot_id) {
      return res.status(400).json({
        error: 'Bad Request',
        message: 'user_id and bot_id are required'
      });
    }

    // Read private key and JWKS for key ID
    const [privateKey, jwks] = await Promise.all([
      readPrivateKeyAsync(),
      readJWKSAsync()
    ]);

    const kid = jwks.keys[0].kid; // Get key ID from JWKS

    // JWT payload
    const payload = {
      user_id: user_id,
      bot_id: bot_id
    };

    // JWT options
    const options = {
      algorithm: 'RS256',
      expiresIn: '7d',
      issuer: '0179465191114887',
      audience: 'swiftchat',
      keyid: kid // This sets the kid in JWT header
    };

    // Generate JWT token
    const token = jwt.sign(payload, privateKey, options);

    res.json({
      success: true,
      token: token,
      expires_in: '7d',
      token_type: 'Bearer',
      payload: payload,
      header: {
        alg: 'RS256',
        kid: kid
      }
    });

  } catch (error) {
    console.error('Error generating token:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Unable to generate token'
    });
  }
});

// JWKS endpoint for JWT verification
app.get('/.well-known/jwks.json', async (req, res) => {
  try {
    const jwks = await readJWKSAsync();
    
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Cache-Control', 'public, max-age=3600'); // Cache for 1 hour
    res.json(jwks);
  } catch (error) {
    console.error('Error serving JWKS:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Unable to load JWKS'
    });
  }
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'OK',
    uptime: process.uptime(),
    timestamp: new Date().toISOString()
  });
});

// Handle 404 for undefined routes
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Route not found',
    message: `Cannot ${req.method} ${req.originalUrl}`
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    error: 'Internal Server Error',
    message: 'Something went wrong!'
  });
});

// Start the server
app.listen(PORT, () => {
  console.log(`🚀 Server is running on http://localhost:${PORT}`);
  console.log(`📡 Health check available at http://localhost:${PORT}/health`);
});

export default app; 