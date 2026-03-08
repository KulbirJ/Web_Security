# NGINX Web Server Hardening - Deployment Guide

## 📋 Prerequisites

- **OS**: Ubuntu 22.04 LTS or CentOS 9
- **NGINX Version**: 1.24.x or later
- **Certificate**: Valid SSL/TLS certificate (Let's Encrypt recommended)
- **Access**: Root or sudo privileges

---

## 🚀 Step 1: Install NGINX

### Ubuntu:
```bash
sudo apt update
sudo apt install nginx
```

### CentOS:
```bash
sudo dnf install nginx
```

### Verify Installation:
```bash
nginx -v
```

---

## 🔒 Step 2: Install SSL/TLS Certificate

### Automatic Certificate Installation (Recommended)

#### Install Certbot:
```bash
# Ubuntu
sudo apt install certbot python3-certbot-nginx

# CentOS
sudo dnf install certbot python3-certbot-nginx
```

#### Request & Install Certificate:
```bash
sudo certbot --nginx -d yourdomain.com -d www.yourdomain.com

# This will:
# 1. Create certificate request
# 2. Validate domain ownership
# 3. Download certificate
# 4. Modify NGINX config automatically
# 5. Restart NGINX
```

### Manual Certificate Installation

#### Create Directories:
```bash
sudo mkdir -p /etc/nginx/ssl/
```

#### Copy Certificate Files:
```bash
# Copy from your certificate provider
sudo cp /path/to/yourdomain.com.crt /etc/nginx/ssl/
sudo cp /path/to/yourdomain.com.key /etc/nginx/ssl/
sudo cp /path/to/yourdomain.com.chain.pem /etc/nginx/ssl/

# Set permissions
sudo chmod 600 /etc/nginx/ssl/*
```

---

## 🏗️ Step 3: Deploy NGINX Configuration

### Option A: New Site Setup

```bash
# Copy server block configuration
sudo cp server-block.conf /etc/nginx/sites-available/yourdomain.com.conf

# Edit to customize domain names and paths
sudo nano /etc/nginx/sites-available/yourdomain.com.conf

# Replace placeholders:
# - yourdomain.com (your actual domain)
# - /var/www/yourdomain.com/html (your website root)
# - /etc/letsencrypt/live/yourdomain.com/... (certificate paths)
```

### Option B: Update Sites-Available

On Ubuntu:
```bash
# Enable site
sudo ln -s /etc/nginx/sites-available/yourdomain.com.conf /etc/nginx/sites-enabled/yourdomain.com.conf

# Disable default site (optional)
sudo unlink /etc/nginx/sites-enabled/default
```

On CentOS (sites are in `/etc/nginx/conf.d/`):
```bash
# Files in conf.d/ are auto-enabled
sudo cp server-block.conf /etc/nginx/conf.d/yourdomain.com.conf
```

---

## 🔐 Step 4: Include SSL Parameters File

### Create SSL Includes Directory:
```bash
sudo mkdir -p /etc/nginx/includes/
```

### Copy Parameters File:
```bash
sudo cp ssl_params.conf /etc/nginx/includes/
```

### Update Server Block (if needed):
```bash
# Add this to your server block after ssl_certificate lines:
sudo nano /etc/nginx/sites-available/yourdomain.com.conf
# Add: include /etc/nginx/includes/ssl_params.conf;
```

---

## 📄 Step 5: Create Website Root Directory

```bash
# Create directory
sudo mkdir -p /var/www/yourdomain.com/html

# Set permissions
sudo chown -R www-data:www-data /var/www/yourdomain.com/html
sudo chmod -R 755 /var/www/yourdomain.com/html

# Create test page
echo "<h1>Welcome to yourdomain.com</h1>" | sudo tee /var/www/yourdomain.com/html/index.html
```

---

## 🧪 Step 6: Test & Enable Configuration

### Test Syntax:
```bash
sudo nginx -t

# Expected output:
# nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
# nginx: configuration file /etc/nginx/nginx.conf test is successful
```

### Reload NGINX:
```bash
sudo systemctl reload nginx
```

### Check Service Status:
```bash
sudo systemctl status nginx

# Expected: active (running)
```

### View Running Processes:
```bash
ps aux | grep nginx
```

---

## 🧪 Step 7: Verify Security Configuration

### Test HTTPS Connection:
```bash
curl -I https://yourdomain.com

# Should show:
# HTTP/2 200
# Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
# X-Content-Type-Options: nosniff
# X-Frame-Options: DENY
```

### Test HTTP Redirect:
```bash
curl -I http://yourdomain.com

# Should show:
# HTTP/1.1 301 Moved Permanently
# Location: https://yourdomain.com/
```

### Verbose Certificate Check:
```bash
openssl s_client -connect yourdomain.com:443 -tls1_2

# Verify:
# - Certificate chain complete
# - Subject CN matches domain
# - Issuer is trusted CA (Let's Encrypt, etc.)
```

### Security Headers Verification:
```bash
curl -s -I https://yourdomain.com | grep -i "Strict-Transport-Security\|X-Content-Type\|X-Frame-Options\|Content-Security-Policy"
```

### Online Testing:
1. **SecurityHeaders.com**: https://securityheaders.com/
   - Enter: yourdomain.com
   - Target: A or A+ grade

2. **SSL Labs**: https://www.ssllabs.com/ssltest/
   - Enter: yourdomain.com
   - Target: A or A+ grade

---

## 🔄 Step 8: Enable Auto-Start & Auto-Renewal

### Enable NGINX on Boot:
```bash
sudo systemctl enable nginx
```

### Enable Certificate Auto-Renewal:
```bash
# Certbot auto-renewal runs automatically via cron/timer
sudo systemctl status certbot.timer

# Test renewal (dry-run):
sudo certbot renew --dry-run

# Check renewal schedule:
sudo certbot certificates
```

---

## 📊 Monitoring & Logging

### View Access Logs:
```bash
tail -f /var/log/nginx/yourdomain.com.access.log
```

### View Error Logs:
```bash
tail -f /var/log/nginx/yourdomain.com.error.log
```

### Monitor in Real-Time:
```bash
watch -n 1 "sudo tail -20 /var/log/nginx/yourdomain.com.access.log"
```

### Log Rotation Setup:
```bash
# NGINX includes default log rotation in /etc/logrotate.d/nginx
# Verify:
cat /etc/logrotate.d/nginx
```

---

## 🛡️ Advanced Hardening Options

### 1. Rate Limiting

Add to server block:
```nginx
# Define rate limit zone
limit_req_zone $binary_remote_addr zone=general:10m rate=10r/s;
limit_req_zone $binary_remote_addr zone=api:10m rate=100r/s;

# Apply to location
location / {
    limit_req zone=general burst=20 nodelay;
    # ... rest of location block
}

location /api/ {
    limit_req zone=api burst=50 nodelay;
    # ... rest of location block
}
```

### 2. Hide NGINX Version
Already in server-block.conf (`server_tokens off;`)

### 3. Disable Unwanted HTTP Methods
Add to server block:
```nginx
if ($request_method !~ ^(GET|POST|HEAD)$) {
    return 405;
}
```

### 4. Enable Compression
Add to http block (`/etc/nginx/nginx.conf`):
```nginx
gzip on;
gzip_types text/plain text/css text/javascript;
gzip_min_length 1000;
```

### 5. Add Security Module (ModSecurity)
```bash
# Ubuntu
sudo apt install libnginx-mod-security

# Add to nginx.conf:
# include /etc/nginx/modsecurity.conf;
```

---

## ❌ Troubleshooting

| Issue | Solution |
|-------|----------|
| **Port 443 already in use** | `sudo lsof -i :443` → Stop conflicting service |
| **Certificate not renewing** | `sudo certbot renew --force-renewal` or check logs |
| **HTTPS not accessible** | Check firewall: `sudo ufw allow 443` |
| **Headers not appearing** | Clear browser cache, restart NGINX: `sudo systemctl restart nginx` |
| **Redirect loop** | Check for duplicate redirect rules in server block |
| **Permission denied on root** | Verify `chown www-data:www-data` on `/var/www/` |

---

## 🔄 Maintenance Checklist

### Weekly:
- [ ] Monitor access/error logs
- [ ] Check certificate expiration: `certbot certificates`

### Monthly:
- [ ] Review security headers via SecurityHeaders.com
- [ ] Check SSL Labs grade

### Quarterly:
- [ ] Verify firewall rules
- [ ] Review NGINX version for updates

### Annually:
- [ ] Update NGINX to latest stable version
- [ ] Review CSP policy for unused directives
- [ ] Test disaster recovery procedures

---

## 📝 Important Notes

1. **Modify domain names** in all configuration files
2. **Certificate paths** must match your Let's Encrypt installation
3. **Website root** path `/var/www/yourdomain.com/html` is customizable
4. **CSP policy** should be adjusted for your application's requirements
5. **HSTS preload** only enable after confirming HTTPS works perfectly

---

**Last Updated**: March 2026 | **Status**: Production Ready
