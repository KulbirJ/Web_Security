# Node.js/Express Security Hardening - Deployment Guide

## 📋 Prerequisites

- **Node.js**: 18.x or 20.x LTS
- **OS**: Ubuntu 22.04, CentOS 9, or Windows
- **Package Manager**: npm or yarn
- **Certificate**: Valid SSL/TLS certificate (Let's Encrypt)
- **Ports**: 80 (HTTP), 443 (HTTPS)

---

## 🚀 Step 1: Install Node.js

### Ubuntu:
```bash
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install nodejs
```

### macOS:
```bash
brew install node
```

### Windows:
Download installer: https://nodejs.org/

### Verify Installation:
```bash
node --version
npm --version
```

---

## 📦 Step 2: Initialize Project

```bash
mkdir secure-express-app
cd secure-express-app

# Initialize npm project
npm init -y

# Install dependencies
npm install express helmet compression express-rate-limit dotenv
npm install --save-dev nodemon
```

---

## 🏗️ Step 3: Deploy Application Files

### Copy Application Code:
```bash
cp app.js ./
cp package.json ./
```

### Create .env Configuration:
```bash
cat > .env << EOF
PORT=443
NODE_ENV=production
LOG_LEVEL=info
SSL_KEY_PATH=/etc/letsencrypt/live/yourdomain.com/privkey.pem
SSL_CERT_PATH=/etc/letsencrypt/live/yourdomain.com/fullchain.pem
EOF
```

### Update app.js Paths:
```bash
# Edit app.js and update certificate paths:
sed -i "s|path/to/privkey.pem|/etc/letsencrypt/live/yourdomain.com/privkey.pem|g" app.js
sed -i "s|path/to/fullchain.pem|/etc/letsencrypt/live/yourdomain.com/fullchain.pem|g" app.js
```

---

## 🔒 Step 4: Obtain SSL/TLS Certificate

### Using Let's Encrypt:
```bash
sudo apt install certbot

# Request certificate
sudo certbot certonly --standalone \
  -d yourdomain.com \
  -d www.yourdomain.com \
  --agree-tos \
  --email admin@yourdomain.com
```

### Copy Certificate Permissions:
```bash
# Grant Node.js process read access
sudo chown root:root /etc/letsencrypt/live/yourdomain.com/privkey.pem
sudo chmod 644 /etc/letsencrypt/live/yourdomain.com/privkey.pem

# Or use sudo to run the app (not recommended for production)
```

---

## 🚀 Step 5: Run Application

### Development Mode:
```bash
npm run dev
```

### Production Mode (with sudo for port 443):
```bash
sudo npm start

# Or use node directly:
sudo node app.js
```

### Using Process Manager (pm2 - Recommended):
```bash
# Install pm2 globally
sudo npm install -g pm2

# Start with pm2
pm2 start app.js --name "secure-express" --watch

# Save startup config
pm2 startup
pm2 save
```

---

## 🧪 Step 6: Verify Security

### Test HTTPS:
```bash
curl -k https://localhost/

# Should show HTML response and security headers
```

### Check Headers:
```bash
curl -sI https://localhost/ | grep -E "Strict-Transport-Security|X-Content-Type|X-Frame-Options|Content-Security-Policy"
```

### Test HTTP Redirect:
```bash
curl -i http://localhost/

# Should show 301 redirect to HTTPS
```

### Online Verification:
1. Configure port forwarding or use ngrok:
   ```bash
   ngrok http 443 --tls-only
   ```

2. Visit: https://securityheaders.com/
3. Enter your domain
4. Target: A or A+ grade

---

## 📊 Production Deployment

### Using Reverse Proxy (NGINX):

```nginx
upstream nodejs_app {
    server localhost:3000;
}

server {
    listen 443 ssl http2;
    server_name yourdomain.com;
    
    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;
    
    location / {
        proxy_pass http://nodejs_app;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Host $host;
    }
}
```

### Using Docker:

```dockerfile
FROM node:20-alpine

WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production

ENV NODE_ENV=production
ENV PORT=3000

COPY app.js .

EXPOSE 3000
CMD ["node", "app.js"]
```

Build & Run:
```bash
docker build -t secure-express .
docker run -p 3000:3000 \
  -v /etc/letsencrypt:/etc/letsencrypt:ro \
  secure-express
```

---

## 🛡️ Advanced Security Features

### Add Rate Limiting to Specific Routes:
```javascript
const strictLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,  // 1 minute
  max: 5                     // 5 requests per minute
});

app.post('/api/login', strictLimiter, (req, res) => {
  // Login route with stricter rate limit
});
```

### Add CORS Protection:
```bash
npm install cors
```

```javascript
const cors = require('cors');

app.use(cors({
  origin: 'https://yourdomain.com',
  credentials: true
}));
```

---

## ❌ Troubleshooting

| Issue | Solution |
|-------|----------|
| **Permission denied on port 443** | Run with `sudo` or use port 3000 with reverse proxy |
| **Certificate not found** | Verify paths in .env and app.js |
| **Headers missing** | Check Helmet version, reload app |
| **Rate limit blocking legit traffic** | Adjust windowMs and max values |

---

## 🔄 Maintenance

### Certificate Renewal:
```bash
# Auto-renew (runs daily)
sudo certbot renew

# Or manually
sudo certbot renew --force-renewal
```

### Update Dependencies:
```bash
npm outdated
npm update
```

### Monitor Application:
```bash
pm2 monit
pm2 logs secure-express
```

---

**Last Updated**: March 2026 | **Status**: Production Ready
