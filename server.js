import express from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Get JWKS from environment variable
const getJWKS = () => {
  if (!process.env.JWKS_JSON) {
    throw new Error('JWKS_JSON environment variable is not set');
  }
  return JSON.parse(process.env.JWKS_JSON);
};

// Get private key from environment variable
const getPrivateKey = () => {
  if (!process.env.PRIVATE_KEY) {
    throw new Error('PRIVATE_KEY environment variable is not set');
  }
  return process.env.PRIVATE_KEY;
};

// Root route
app.get('/', (req, res) => {
  res.json({
    message: 'Welcome to Merchant Backend API',
    status: 'Server is running successfully',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development',
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

    // Get private key and JWKS
    const privateKey = getPrivateKey();
    const jwks = getJWKS();
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
      message: 'Unable to generate token',
      details: error.message
    });
  }
});

// JWKS endpoint for JWT verification
app.get('/.well-known/jwks.json', async (req, res) => {
  try {
    const jwks = getJWKS();
    
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Cache-Control', 'public, max-age=3600'); // Cache for 1 hour
    res.json(jwks);
  } catch (error) {
    console.error('Error serving JWKS:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Unable to load JWKS',
      details: error.message
    });
  }
});

// Health check endpoint
app.get('/health', async (req, res) => {
  try {
    // Check if environment variables are available
    const hasPrivateKey = !!process.env.PRIVATE_KEY;
    const hasJWKS = !!process.env.JWKS_JSON;

    res.json({
      status: hasPrivateKey && hasJWKS ? 'OK' : 'ERROR',
      uptime: process.uptime(),
      timestamp: new Date().toISOString(),
      environment: {
        hasPrivateKey,
        hasJWKS,
        nodeEnv: process.env.NODE_ENV
      }
    });
  } catch (error) {
    res.status(500).json({
      status: 'ERROR',
      uptime: process.uptime(),
      timestamp: new Date().toISOString(),
      error: error.message
    });
  }
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
  console.error('Unhandled error:', err.stack);
  res.status(500).json({
    error: 'Internal Server Error',
    message: 'Something went wrong!',
    details: err.message
  });
});

// For local development
if (process.env.NODE_ENV !== 'production') {
  app.listen(PORT, () => {
    console.log(`🚀 Server is running on http://localhost:${PORT}`);
    console.log(`📡 Health check available at http://localhost:${PORT}/health`);
  });
}

export default app;