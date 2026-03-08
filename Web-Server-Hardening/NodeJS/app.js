// Node.js Express Application with Helmet.js Security Middleware
// File: app.js or server.js
// 
// Purpose: Express server with comprehensive security headers
// Dependencies: express, helmet, compression

const express = require('express');
const helmet = require('helmet');
const compression = require('compression');
const https = require('https');
const fs = require('fs');
const path = require('path');

const app = express();

// ====================================================
// 1. HELMET.JS - Security Headers Middleware
// ====================================================
app.use(helmet({
  // Prevent MIME-type sniffing
  noSniff: true,
  
  // Clickjacking protection
  frameguard: {
    action: 'deny'
  },
  
  // Content Security Policy
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:"],
      fontSrc: ["'self'"],
      connectSrc: ["'self'"],
      frameAncestors: ["'none'"]
    }
  },
  
  // HSTS - Enforce HTTPS
  hsts: {
    maxAge: 31536000,        // 1 year
    includeSubDomains: true,
    preload: true
  },
  
  // Referrer Policy
  referrerPolicy: {
    policy: 'strict-origin-when-cross-origin'
  },
  
  // Permissions Policy (formerly Feature-Policy)
  permissionsPolicy: {
    geolocation: [],
    microphone: [],
    camera: []
  }
}));

// ====================================================
// 2. ADDITIONAL SECURITY HEADERS
// ====================================================
app.use((req, res, next) => {
  // Cache Control
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate');
  res.set('Pragma', 'no-cache');
  
  // Alternative to helmet for additional headers
  res.set('X-XSS-Protection', '1; mode=block');
  
  next();
});

// ====================================================
// 3. COMPRESSION MIDDLEWARE
// ====================================================
app.use(compression());

// ====================================================
// 4. REQUEST PARSING
// ====================================================
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ limit: '10mb', extended: true }));

// ====================================================
// 5. RATE LIMITING (Optional but Recommended)
// ====================================================
const rateLimit = require('express-rate-limit');

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 100,                   // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.'
});

app.use(limiter);

// ====================================================
// 6. DISABLE HTTP METHOD OVERRIDE
// ====================================================
app.disable('x-powered-by');

// ====================================================
// 7. ROUTES & CONTROLLERS
// ====================================================
app.get('/', (req, res) => {
  res.send('<h1>Welcome - Secure HTTPS Server</h1>');
});

app.get('/api/status', (req, res) => {
  res.json({
    status: 'ok',
    protocol: req.protocol,
    secure: req.secure,
    headers: {
      'Strict-Transport-Security': res.get('Strict-Transport-Security'),
      'X-Content-Type-Options': res.get('X-Content-Type-Options'),
      'X-Frame-Options': res.get('X-Frame-Options')
    }
  });
});

// ====================================================
// 8. 404 & ERROR HANDLING
// ====================================================
app.use((req, res) => {
  res.status(404).json({ error: 'Not Found' });
});

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Internal Server Error' });
});

// ====================================================
// 9. HTTPS SERVER CONFIGURATION
// ====================================================
const httpsOptions = {
  key: fs.readFileSync('path/to/privkey.pem'),
  cert: fs.readFileSync('path/to/fullchain.pem')
};

const PORT = process.env.PORT || 443;

https.createServer(httpsOptions, app).listen(PORT, () => {
  console.log(`HTTPS Server running on port ${PORT}`);
});

// ====================================================
// 10. HTTP REDIRECT (Optional)
// ====================================================
const httpApp = express();
httpApp.use((req, res) => {
  res.redirect(`https://${req.hostname}${req.url}`);
});

httpApp.listen(80, () => {
  console.log('HTTP→HTTPS redirect server running on port 80');
});

module.exports = app;
