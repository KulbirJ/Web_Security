# Web Server Hardening Configurations

**Production-Ready Security Headers & HTTPS Configuration Templates for Popular Web Servers**

A comprehensive collection of hardened web server configurations implementing modern security best practices, HTTPS/TLS hardening, and comprehensive security headers to align with zero-trust security principles.

---

## 📋 Supported Web Servers

| Server | Version | Directory | SSL/TLS | Security Headers | Recommendations |
|--------|---------|-----------|---------|-----------------|-----------------|
| **Microsoft IIS** | 10 (Windows Server 2022) | [IIS/](./IIS/) | ✅ | ✅ | web.config configuration |
| **NGINX** | 1.24.x / 1.25.x | [NGINX/](./NGINX/) | ✅ | ✅ | Server block templates |
| **Apache** | 2.4.58 / 2.4.59 | [Apache/](./Apache/) | ✅ | ✅ | VirtualHost configuration |
| **Apache Tomcat** | 10.x / 11.x | [Tomcat/](./Tomcat/) | ✅ | ✅ | server.xml + app deployer |
| **Node.js/Express** | 18.x / 20.x | [NodeJS/](./NodeJS/) | ✅ | ✅ | Helmet.js middleware + config |
| **Caddy** | 2.7.x+ | [Caddy/](./Caddy/) | ✅ | ✅ | Caddyfile templates |
| **HAProxy** | 2.8.x+ | [HAProxy/](./HAProxy/) | ✅ | ✅ | Reverse proxy + headers via lua |

---

## 🔒 Security Headers Implemented

All configurations include the following security headers (where applicable):

### Core Headers
- **X-Content-Type-Options**: `nosniff` — Prevents MIME-type sniffing attacks
- **X-Frame-Options**: `DENY` — Blocks iframe embedding (clickjacking protection)
- **Content-Security-Policy (CSP)**: Limits resource sources to mitigate XSS attacks
- **X-XSS-Protection**: `1; mode=block` — Legacy XSS filter for older browsers

### Transport & Caching
- **Strict-Transport-Security (HSTS)**: Enforces HTTPS for 1 year with preload
- **Cache-Control**: `no-store, no-cache, must-revalidate` — Prevents caching of sensitive content
- **Pragma**: `no-cache` — Additional cache prevention directive

### Privacy & Feature Control
- **Referrer-Policy**: `strict-origin-when-cross-origin` — Controls referrer data sharing
- **Permissions-Policy**: Restricts browser features (geolocation, microphone, camera)
- **Server Token Hiding**: Removes server version banners

### TLS/SSL Hardening
- **Supported Protocols**: TLS 1.2 / TLS 1.3 only (disable TLS 1.0, 1.1, SSL 2.0, 3.0)
- **Preferred Ciphers**: ECDHE-based ciphers with AES-256-GCM
- **Session Management**: Disabled session tickets, secure session cache

---

## 📁 Directory Structure

```
Web-Server-Hardening/
├── README.md (this file)
│
├── IIS/
│   ├── web.config ..................... Main security configuration (XML)
│   ├── security-headers.xml ........... Separate header definitions
│   ├── ssl-cipher-hardening.md ........ TLS 1.2/1.3 setup with IIS Crypto
│   └── deployment-guide.md ............ Step-by-step IIS setup instructions
│
├── NGINX/
│   ├── server-block.conf .............. Complete HTTPS server block
│   ├── ssl-params.conf ................ TLS hardening parameters (include file)
│   ├── security-headers.conf .......... Headers snippet (include file)
│   ├── http-redirect.conf ............ HTTP→HTTPS redirect configuration
│   └── deployment-guide.md ............ NGINX step-by-step instructions
│
├── Apache/
│   ├── virtualhost-https.conf ......... Complete VirtualHost with HTTPS
│   ├── ssl-params.conf ............... TLS hardening parameters (include)
│   ├── security-headers.conf ........ Headers snippet (include)
│   ├── http-redirect.conf ........... HTTP→HTTPS redirect
│   └── deployment-guide.md .......... Apache setup instructions
│
├── Tomcat/
│   ├── server.xml .................... SSL connector + security settings
│   ├── context.xml ................... Application context hardening
│   ├── web.xml ....................... Security headers via filter
│   └── deployment-guide.md ........... Tomcat deployment steps
│
├── NodeJS/
│   ├── express-app.js ................ Express.js + Helmet.js example
│   ├── helmet-config.js .............. Detailed Helmet configuration
│   ├── ssl-options.js ............... TLS hardening parameters
│   ├── package.json .................. Required npm dependencies
│   └── deployment-guide.md .......... Node.js setup instructions
│
├── Caddy/
│   ├── Caddyfile ..................... Main server configuration
│   ├── Caddyfile.modules ............ Advanced header modules
│   └── deployment-guide.md .......... Caddy setup instructions
│
└── HAProxy/
    ├── haproxy.cfg ................... Main HAProxy configuration
    ├── header-rewrite.lua ............ Lua script for security headers
    ├── backend-definition.cfg ........ Backend server configuration
    └── deployment-guide.md .......... HAProxy setup instructions
```

---

## 🚀 Quick Start

### For Each Web Server:

1. **Navigate to the server directory** (e.g., `./NGINX/`)
2. **Read** the `deployment-guide.md` for prerequisites and setup steps
3. **Copy relevant configuration files** to your server
4. **Customize** domain names, paths, and certificate locations
5. **Test** using [SecurityHeaders.com](https://securityheaders.com/) and [SSL Labs](https://www.ssllabs.com/ssltest/)
6. **Reload/restart** the web server

**Example: Deploy NGINX**
```bash
cd NGINX/
cat deployment-guide.md          # Read instructions
sudo cp server-block.conf /etc/nginx/sites-available/yourdomain.com.conf
sudo nginx -t                     # Test syntax
sudo systemctl reload nginx       # Apply changes
```

---

## 📋 Security Header Definitions

### X-Content-Type-Options: nosniff
Prevents browsers from MIME-type sniffing, forcing them to respect declared Content-Type. Protects against drive-by downloads.

### X-Frame-Options: DENY
Blocks the page from being framed in iframes, preventing clickjacking attacks where malicious sites overlay your content.

### Content-Security-Policy (CSP)
```
default-src 'self';
script-src 'self' 'unsafe-inline';
style-src 'self' 'unsafe-inline';
img-src 'self' data:;
font-src 'self';
connect-src 'self';
frame-ancestors 'none';
```
Restricts resource loading to same-origin, mitigating inline script injection and cross-site scripting (XSS).

**Customization**: Adjust `script-src`, `style-src`, and other directives based on your application's legitimate third-party dependencies.

### Strict-Transport-Security (HSTS)
```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```
- **max-age=31536000**: Browser remembers HTTPS for 1 year
- **includeSubDomains**: Applies to all subdomains
- **preload**: Adds site to HSTS preload list (optional, requires registration)

### Referrer-Policy: strict-origin-when-cross-origin
- Sends full URL for same-origin requests
- Sends only origin for cross-site requests
- Improves privacy without breaking valid analytics

### Permissions-Policy
```
geolocation=(), microphone=(), camera=()
```
Explicitly disables browser features your site doesn't need. Reduces attack surface if app is compromised.

---

## 🔐 TLS/SSL Hardening Checklist

- ✅ **Protocols**: TLS 1.2 and 1.3 only (disable older versions)
- ✅ **Ciphers**: Prefer ECDHE with AES-256-GCM
- ✅ **Certificate**: Valid, from trusted CA (Let's Encrypt, DigiCert, etc.)
- ✅ **Session Management**: Disable session tickets (session resumption disabled)
- ✅ **OCSP Stapling**: Enabled (when available)
- ✅ **X.509 Validation**: Proper chain configuration
- ✅ **Cipher Order**: Server controls cipher selection (when possible)

---

## 🧪 Testing & Validation

### 1. Security Headers Test
```bash
curl -i https://yourdomain.com
# Verify all headers present in response
```

### 2. SSL/TLS Grade (A+ Target)
- Visit: https://www.ssllabs.com/ssltest/
- Target score: **A+** or **A**
- Aim for: TLS 1.2/1.3 only, strong ciphers

### 3. Security Headers Score
- Visit: https://securityheaders.com/
- Enter your domain
- Target: **A** or **A+** grade
- Ensure all recommended headers present

### 4. Curl Verification
```bash
# Check specific header
curl -I https://yourdomain.com | grep "Strict-Transport-Security"

# Full header dump
curl -v https://yourdomain.com 2>&1 | grep "^<"
```

### 5. Server Configuration Test
```bash
# NGINX
nginx -t

# Apache
apache2ctl configtest
# or
httpd -t

# Tomcat (syntax only)
# Check catalina.out logs after restart
```

---

## 🎯 OWASP Top 10 Alignment

These configurations directly address:

- **A01:2021 - Broken Access Control**: CORS headers, CSP
- **A02:2021 - Cryptographic Failures**: TLS 1.2+, strong ciphers, HSTS
- **A03:2021 - Injection**: CSP mitigates XSS
- **A05:2021 - Security Misconfiguration**: Server token hiding, secure defaults
- **A06:2021 - Vulnerable Components**: Modern TLS removes obsolete protocols
- **A07:2021 - Identification & Auth Failures**: HSTS ensures authenticated sessions over HTTPS only

---

## 🔄 Common Customizations

### 1. Allow Third-Party CDN
**Modify CSP** to include CDN domain:
```
script-src 'self' cdn.example.com;
style-src 'self' cdn.example.com;
```

### 2. Enable Google Analytics
**Add to CSP**:
```
script-src 'self' www.googletagmanager.com google-analytics.com;
connect-src 'self' www.google-analytics.com;
```

### 3. Disable HSTS for Testing
**Remove or reduce**:
```
Strict-Transport-Security: max-age=0;  # Temporarily remove HSTS
```

### 4. Allow iFrame Embedding
**For public embeddable content**:
```
X-Frame-Options: SAMEORIGIN           # Allow same-origin framing
```

### 5. Reduce HSTS Duration
**For new deployments**:
```
Strict-Transport-Security: max-age=86400;  # Start with 1 day, then increase
```

---

## 📚 Additional Resources

| Resource | Purpose |
|----------|---------|
| [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/) | Comprehensive header guidelines |
| [Mozilla Observatory](https://observatory.mozilla.org/) | Website security scanning |
| [CWE/SANS Top 25](https://cwe.mitre.org/top25/) | Common weakness enumeration |
| [Let's Encrypt](https://letsencrypt.org/) | Free SSL/TLS certificates |
| [CSP Reference](https://content-security-policy.com/) | Content Security Policy documentation |
| [SSL Labs Best Practices](https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices) | TLS hardening guide |

---

## 🤝 Contributing & Updates

To request additional web servers or configurations:
1. Open an issue with the web server name and use case
2. Provide sample configurations or links to references
3. Specify version number and target OS

---

## 📝 Version & Maintenance

**Last Updated**: March 2026
**TLS Standards**: TLS 1.2 / TLS 1.3 (minimum)
**Compliance**: OWASP Top 10 2021, Zero Trust Security Principles

---

## ⚠️ Important Warnings

1. **Test in Non-Production First**: Always validate security header changes in staging environment
2. **Certificate Validity**: Ensure SSL/TLS certificates are from trusted CAs and not self-signed (except dev)
3. **HSTS Preload**: Only enable preload directive after thoroughly testing HTTPS functionality
4. **CSP Strictness**: Overly strict CSP can break application functionality; test thoroughly
5. **Performance**: Security headers add minimal overhead; monitor if additional modules enabled (e.g., WAF)
6. **Regular Updates**: Keep web server software updated for security patches

---

**License**: Open Source | **Status**: Production Ready
