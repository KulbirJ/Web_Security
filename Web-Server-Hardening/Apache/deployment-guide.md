# Apache Web Server Hardening - Deployment Guide

## 📋 Prerequisites

- **OS**: Ubuntu 22.04 LTS or CentOS 9
- **Apache Version**: 2.4.58 or later
- **Required Modules**: ssl, headers, rewrite, expires
- **Certificate**: Valid SSL/TLS certificate (Let's Encrypt recommended)
- **Access**: Root or sudo privileges

---

## 🚀 Step 1: Install Apache

### Ubuntu:
```bash
sudo apt update
sudo apt install apache2 apache2-utils
```

### CentOS:
```bash
sudo dnf install httpd httpd-tools
```

### Verify Installation:
```bash
apache2 -v  # Ubuntu
httpd -v    # CentOS
```

---

## 📦 Step 2: Enable Required Modules

### Ubuntu:
```bash
sudo a2enmod ssl
sudo a2enmod headers
sudo a2enmod rewrite
sudo a2enmod expires
```

### CentOS:
```bash
# Modules are typically enabled by default
# Verify in /etc/httpd/conf.modules.d/
ls /etc/httpd/conf.modules.d/ | grep -E "ssl|headers|rewrite"
```

### Verify Modules Loaded:
```bash
apache2ctl -M | grep -E "ssl_module|headers_module|rewrite_module"
```

---

## 🔒 Step 3: Install SSL/TLS Certificate

### Automatic Installation (Recommended)

#### Install Certbot:
```bash
# Ubuntu
sudo apt install certbot python3-certbot-apache

# CentOS
sudo dnf install certbot python3-certbot-apache
```

#### Request & Install Certificate:
```bash
sudo certbot --apache -d yourdomain.com -d www.yourdomain.com

# This will:
# 1. Validate domain ownership
# 2. Download SSL certificate
# 3. Modify VirtualHost config
# 4. Enable HTTPS
# 5. Restart Apache
```

### Manual Certificate Installation

```bash
# Create SSL directory
sudo mkdir -p /etc/ssl/certs

# Copy certificate files
sudo cp yourdomain.com.crt /etc/ssl/certs/
sudo cp yourdomain.com.key /etc/ssl/private/
sudo cp yourdomain.com.chain.pem /etc/ssl/certs/

# Set permissions
sudo chmod 600 /etc/ssl/private/yourdomain.com.key
sudo chmod 644 /etc/ssl/certs/yourdomain.com.crt
```

---

## 🏗️ Step 4: Deploy Apache Configuration

### Create Website Root:
```bash
sudo mkdir -p /var/www/yourdomain.com/html
sudo chown -R www-data:www-data /var/www/yourdomain.com/html
sudo chmod -R 755 /var/www/yourdomain.com/html

# Create test index page
echo "<h1>Welcome to yourdomain.com</h1>" | sudo tee /var/www/yourdomain.com/html/index.html
```

### Copy VirtualHost Configuration:

#### Ubuntu:
```bash
sudo cp virtualhost-https.conf /etc/apache2/sites-available/yourdomain.com.conf
sudo a2ensite yourdomain.com.conf
sudo a2dissite 000-default  # Disable default site (optional)
```

#### CentOS:
```bash
sudo cp virtualhost-https.conf /etc/httpd/conf.d/yourdomain.com.conf
```

### Customize Configuration:
```bash
# Edit to replace placeholders:
sudo nano /etc/apache2/sites-available/yourdomain.com.conf  # Ubuntu
# or
sudo nano /etc/httpd/conf.d/yourdomain.com.conf  # CentOS
```

Replacements needed:
- `yourdomain.com` → your actual domain
- `/var/www/yourdomain.com/html` → your website root
- `/etc/letsencrypt/live/yourdomain.com/...` → certificate paths

---

## 🔐 Step 5: Configure TLS Hardening

### Global SSL Configuration (Optional)

Create `/etc/apache2/mods-available/ssl.conf` customization:

```bash
sudoedit /etc/apache2/mods-available/ssl.conf
```

Add or modify:
```apache
# TLS Protocols
SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1

# Strong ciphers
SSLCipherSuite ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384

# Prefer server ciphers
SSLHonorCipherOrder on

# Session tickets disabled for PFS
SSLSessionTickets off
```

---

## 🧪 Step 6: Test & Enable

### Test Configuration Syntax:
```bash
# Ubuntu
sudo apache2ctl configtest

# CentOS
sudo httpd -t

# Expected output: Syntax OK
```

### Start/Restart Apache:
```bash
# Ubuntu
sudo systemctl restart apache2

# CentOS
sudo systemctl restart httpd
```

### Check Service Status:
```bash
# Ubuntu
sudo systemctl status apache2

# CentOS
sudo systemctl status httpd

# Expected: active (running)
```

---

## 🧪 Step 7: Verify Security

### Test HTTPS Connection:
```bash
curl -I https://yourdomain.com

# Should show security headers
```

### Test HTTP Redirect:
```bash
curl -I http://yourdomain.com

# Should show: HTTP/1.1 301 Moved Permanently
```

### Check Certificate:
```bash
openssl s_client -connect yourdomain.com:443 -tls1_2
```

### Security Headers Test:
```bash
curl -s -I https://yourdomain.com | grep -i "Strict-Transport-Security\|X-Content-Type\|X-Frame-Options"
```

### Online Verification:
1. **SecurityHeaders.com**: https://securityheaders.com/
2. **SSL Labs**: https://www.ssllabs.com/ssltest/

---

## 🔄 Step 8: Enable Auto-Start & Renewal

### Enable Apache on Boot:
```bash
sudo systemctl enable apache2  # Ubuntu
sudo systemctl enable httpd    # CentOS
```

### Enable Certificate Auto-Renewal:
```bash
sudo certbot renew --dry-run

# Renewal runs automatically via cron/systemd timer
sudo systemctl status certbot.timer
```

---

## 📊 Monitoring

### View Access Logs:
```bash
sudo tail -f /var/log/apache2/yourdomain.com-access.log
```

### View Error Logs:
```bash
sudo tail -f /var/log/apache2/yourdomain.com-error.log
```

### Monitor Connections:
```bash
sudo netstat -tlnp | grep apache
```

---

## ❌ Troubleshooting

| Issue | Solution |
|-------|----------|
| **Syntax error in config** | Run `apache2ctl configtest` for details |
| **Port 443 in use** | `sudo lsof -i :443` or `netstat -tlnp` |
| **Certificate not renewing** | `sudo certbot renew --force-renewal` |
| **HTTPS not accessible** | Check firewall: `sudo ufw allow 443` |
| **Headers missing** | Verify mod_headers enabled, restart Apache |
| **Permission denied** | `sudo chown -R www-data:www-data /var/www/` |

---

## 🔄 Maintenance

### Weekly:
- Monitor access/error logs for issues

### Monthly:
- Check certificate expiration: `sudo certbot certificates`
- Verify headers via SecurityHeaders.com

### Quarterly:
- Test SSL grade via SSL Labs
- Review access logs for suspicious activity

### Annually:
- Update Apache to latest stable version
- Review and update security policies

---

**Last Updated**: March 2026 | **Status**: Production Ready
