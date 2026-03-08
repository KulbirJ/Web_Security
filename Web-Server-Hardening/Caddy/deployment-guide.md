# Caddy Web Server - Deployment Guide

## 📋 Prerequisites

- **OS**: Ubuntu 22.04, CentOS 9, macOS, or Windows
- **Caddy Version**: 2.7.x or later
- **Ports**: 80, 443 (or disable firewall restrictions)
- **DNS**: Domain pointing to server's IP address
- **Email**: For Let's Encrypt certificate registration (optional)

---

## 🚀 Step 1: Install Caddy

### Ubuntu/Debian:
```bash
# Install from official repository
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https curl
curl -1sLf 'https://dl.caddy.community/linux/debian/pubkey.gpg' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-archive-keyring.gpg
curl -1sLf 'https://dl.caddy.community/linux/debian/caddy.deb' -o /tmp/c.deb && sudo dpkg -i /tmp/c.deb
```

### CentOS/RHEL:
```bash
sudo dnf install caddy
```

### macOS:
```bash
brew install caddy
```

### Windows:
Download from: https://github.com/caddyserver/caddy/releases

### Verify Installation:
```bash
caddy version
```

---

## 🏗️ Step 2: Create Website Root

```bash
# Create directory structure
sudo mkdir -p /var/www/yourdomain.com/html
sudo mkdir -p /var/log/caddy

# Create test page
echo "<h1>Welcome to yourdomain.com</h1>" | sudo tee /var/www/yourdomain.com/html/index.html

# Set permissions
sudo chown -R caddy:caddy /var/www/yourdomain.com
sudo chown -R caddy:caddy /var/log/caddy
sudo chmod -R 755 /var/www/yourdomain.com
sudo chmod -R 755 /var/log/caddy
```

---

## 📄 Step 3: Deploy Caddyfile

### Copy Configuration:
```bash
sudo cp Caddyfile /etc/caddy/Caddyfile
```

### Edit Caddyfile:
```bash
sudo nano /etc/caddy/Caddyfile
```

Replace:
- `yourdomain.com` with your actual domain
- `/var/www/yourdomain.com/html` with your website root
- `/var/log/caddy` with desired log location

---

## 🔐 Step 4: Let's Encrypt Configuration (Automatic)

Caddy automatically obtains and renews certificates from Let's Encrypt. No configuration needed!

### Specify Email (Optional):
```bash
# Edit Caddyfile global section
{
  email admin@yourdomain.com
}
```

### Manual Certificate (if using different CA):
```bash
# Create custom certificate directory
sudo mkdir -p /etc/caddy/certs
sudo caddy cert {
  cert /path/to/cert.pem
  key /path/to/key.pem
}
```

---

## 🧪 Step 5: Test Configuration

### Validate Caddyfile Syntax:
```bash
caddy validate --config /etc/caddy/Caddyfile
```

### Test Run (no port binding):
```bash
caddy run --config /etc/caddy/Caddyfile
# Press Ctrl+C to stop
```

---

## 🚀 Step 6: Start Caddy Service

### Start Service:
```bash
sudo systemctl start caddy
```

### Check Status:
```bash
sudo systemctl status caddy
```

### View Logs:
```bash
sudo journalctl -u caddy -f
```

### Enable Auto-Start:
```bash
sudo systemctl enable caddy
```

---

## 🧪 Step 7: Verify Configuration

### Test HTTPS:
```bash
curl -I https://yourdomain.com/

# Should show:
# HTTP/2 200
# Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
# X-Content-Type-Options: nosniff
```

### Check Certificate:
```bash
curl -v https://yourdomain.com/ 2>&1 | grep "subject="

# Should show your domain
```

### View Certificate Files:
```bash
# Caddy stores certs in:
ls ~/.local/share/caddy/certificates/yourdomain.com/
# or
sudo ls /var/lib/caddy/.cache/caddy/certificates/
```

### Security Headers Verification:
```bash
curl -s -I https://yourdomain.com/ | grep -E "Strict-Transport|X-Content|X-Frame|Permissions"
```

### Online Testing:
1. **SecurityHeaders.com**: https://securityheaders.com/
2. **SSL Labs**: https://www.ssllabs.com/ssltest/

---

## 🛡️ Advanced Configurations

### 1. Add Rate Limiting

```caddy
https://yourdomain.com {
  # Rate limit configuration
  rate_limit {
    zone default {
      key {http.request.remote.host}
      rate 100 per 1m
    }
  }
  
  root * /var/www/yourdomain.com/html
  file_server
}
```

### 2. Add Custom Error Page

```caddy
https://yourdomain.com {
  handle_errors {
    rewrite * /error.html
    file_server
  }
}
```

### 3. Add Basic Authentication

```caddy
https://yourdomain.com {
  basicauth / {
    user password_hash
  }
  
  root * /var/www/yourdomain.com/html
  file_server
}
```

### 4. Reverse Proxy to Backend

```caddy
https://yourdomain.com {
  reverse_proxy localhost:3000 {
    header_uri X-Forwarded-For {http.request.header.X-Forwarded-For}
    header_uri X-Forwarded-Proto https
    header_uri Host {http.request.header.Host}
  }
}
```

### 5. Enable CORS

```caddy
https://yourdomain.com {
  header Access-Control-Allow-Origin "https://yourdomain.com"
  header Access-Control-Allow-Methods "GET, POST, PUT, DELETE"
  header Access-Control-Allow-Headers "Content-Type"
  
  root * /var/www/yourdomain.com/html
  file_server
}
```

---

## 🛠️ Maintenance & Troubleshooting

### View Certificate Status:
```bash
caddy list-certs
```

### Force Certificate Renewal:
```bash
caddy renew yourdomain.com
```

### Reload Configuration (without restart):
```bash
caddy reload --config /etc/caddy/Caddyfile
```

### Check Service Logs:
```bash
sudo journalctl -u caddy --no-pager | tail -100
```

### Test Reload:
```bash
caddy reload --config /etc/caddy/Caddyfile
```

---

## ❌ Troubleshooting

| Issue | Solution |
|-------|----------|
| **Port 443 blocked** | Check firewall: `sudo ufw allow 443` |
| **DNS not resolving** | Verify domain DNS records point to server IP |
| **Certificate not obtained** | Check email, DNS propagation, port 80 access |
| **Caddy won't restart** | Check syntax: `caddy validate` |
| **Permission denied** | Ensure caddy user owns `/var/log/caddy`, `/var/www/` |

---

## 📝 Key Advantages

- ✅ **Automatic HTTPS**: Let's Encrypt integration
- ✅ **HTTP/2 & HTTP/3**: Built-in
- ✅ **Automatic Renewal**: No manual certificate management
- ✅ **Simple Configuration**: Human-readable Caddyfile
- ✅ **Reload Without Downtime**: Graceful configuration updates

---

**Last Updated**: March 2026 | **Status**: Production Ready
