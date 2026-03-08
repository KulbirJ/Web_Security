# HAProxy Reverse Proxy - Load Balancer
# Deployment Guide
# 
# Server: HAProxy 2.8.x+
# Purpose: SSL/TLS termination, load balancing, security headers

## 📋 Prerequisites

- **OS**: Ubuntu 22.04, CentOS 9, or other Linux distributions
- **HAProxy Version**: 2.8.x or later
- **Certificate**: Valid SSL/TLS certificate (Let's Encrypt)
- **Backend Servers**: 2+ web servers to load balance
- **Access**: Root or sudo privileges

---

## 🚀 Step 1: Install HAProxy

### Ubuntu:
```bash
sudo apt update
sudo apt install haproxy

# Enable for container usage
sudo systemctl enable haproxy
```

### CentOS:
```bash
sudo dnf install haproxy

# Or from source for latest version
wget http://www.haproxy.org/downloads/2.8/src/haproxy-2.8.0.tar.gz
tar xzf haproxy-2.8.0.tar.gz
cd haproxy-2.8.0
make
sudo make install
```

### Verify Installation:
```bash
haproxy -v
```

---

## 🏗️ Step 2: Prepare SSL/TLS Certificate

### Convert Let's Encrypt to PEM (HAProxy Format):
```bash
# Combine cert and key into single PEM file
sudo bash -c "cat /etc/letsencrypt/live/yourdomain.com/fullchain.pem \
  /etc/letsencrypt/live/yourdomain.com/privkey.pem > \
  /etc/haproxy/certs/yourdomain.com.pem"

# Set permissions
sudo chmod 600 /etc/haproxy/certs/yourdomain.com.pem
```

---

## 📄 Step 3: Deploy HAProxy Configuration

### Copy Configuration:
```bash
sudo cp haproxy.cfg /etc/haproxy/haproxy.cfg

# Backup original
sudo cp /etc/haproxy/haproxy.cfg /etc/haproxy/haproxy.cfg.bak
```

### Edit Configuration:
```bash
sudo nano /etc/haproxy/haproxy.cfg
```

Update these sections:
- **Certificate paths**: `/etc/letsencrypt/live/yourdomain.com/...`
- **Backend servers**: Replace IP addresses (10.0.1.10:8080, etc.) with your actual backend servers
- **Domain name**: Replace `yourdomain.com` throughout

### Example Backend Configuration:
```
# For single backend server:
server web1 192.168.1.100:80 check

# For multiple backends with health checks:
server web1 192.168.1.100:80 check inter 3000 rise 2 fall 3
server web2 192.168.1.101:80 check inter 3000 rise 2 fall 3
server web3 192.168.1.102:80 check inter 3000 rise 2 fall 3

# For HTTPS backends:
server web1 192.168.1.100:443 check ssl verify none
```

---

## 🔐 Step 4: Configure Let's Encrypt Auto-Renewal

### Create Renewal Hook Script:
```bash
sudo cat > /etc/letsencrypt/renewal-hooks/post/haproxy.sh << 'EOF'
#!/bin/bash

# Combine cert and key for HAProxy
cat /etc/letsencrypt/live/yourdomain.com/fullchain.pem \
    /etc/letsencrypt/live/yourdomain.com/privkey.pem \
    > /etc/haproxy/certs/yourdomain.com.pem

chmod 600 /etc/haproxy/certs/yourdomain.com.pem

# Reload HAProxy
systemctl reload haproxy

echo "HAProxy certificate renewed and reloaded"
EOF

sudo chmod +x /etc/letsencrypt/renewal-hooks/post/haproxy.sh
```

---

## 🧪 Step 5: Test Configuration

### Validate Configuration Syntax:
```bash
sudo haproxy -c -f /etc/haproxy/haproxy.cfg

# Expected output: Configuration file is valid
```

### Test Run (foreground, debug mode):
```bash
sudo haproxy -f /etc/haproxy/haproxy.cfg -d
# Press Ctrl+C to stop
```

---

## 🚀 Step 6: Start HAProxy Service

### Start Service:
```bash
sudo systemctl start haproxy
```

### Check Status:
```bash
sudo systemctl status haproxy
```

### Enable Auto-Start:
```bash
sudo systemctl enable haproxy
```

### View Logs:
```bash
sudo journalctl -u haproxy -f
```

---

## 🧪 Step 7: Verify Configuration

### Test HTTPS Connection:
```bash
curl -I https://yourdomain.com/

# Should show:
# HTTP/1.1 200 OK
# Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
# X-Content-Type-Options: nosniff
```

### Check Backend Health:
```bash
# Access stats page
curl http://localhost:8404/stats
```

### Monitor Real-Time:
```bash
# Via systemctl
sudo systemctl status haproxy -l

# Via socat (if installed)
echo "show stat" | socat stdio /run/haproxy/admin.sock
```

### Load Balancing Test:
```bash
# Make multiple requests and observe server distribution
for i in {1..10}; do
  curl -s https://yourdomain.com/server-id/ | grep "Server:"
done
```

---

## 🛡️ Advanced Features

### 1. Add Rate Limiting

```haproxy
# In frontend https_front section
stick-table type ip size 100k expire 30s store http_req_rate(10s)
http-request track-sc0 src
http-request deny if { sc_http_req_rate(0) gt 50 }
```

### 2. Add Authentication

```haproxy
# Basic auth
acl is_auth http_auth(users)
http-request auth realm "Restricted Area" if !is_auth
```

### 3. URL Path Routing

```haproxy
# Route /api to api backend
acl is_api path_beg /api
use_backend api_backend if is_api

# Route /static to static backend
acl is_static path_beg /static
use_backend static_backend if is_static
```

### 4. Websocket Support

```haproxy
# Backend configuration for websockets
backend websocket_backend
    balance roundrobin
    
    # 5 minute timeout for websockets
    timeout tunnel 3600000
    
    http-response set-header Upgrade websocket
    http-response set-header Connection Upgrade
    
    server web1 192.168.1.100:3000 check
```

---

## 🛠️ Maintenance & Troubleshooting

### Reload Configuration (without restart):
```bash
sudo systemctl reload haproxy

# Or via admin socket:
echo "reload" | socat stdio /run/haproxy/admin.sock
```

### Check Certificate Expiration:
```bash
openssl x509 -in /etc/haproxy/certs/yourdomain.com.pem -noout -enddate
```

### Monitor Backend Status:
```bash
# Check if backends are up/down
echo "show servers state" | socat stdio /run/haproxy/admin.sock
```

### Disable Backend (Maintenance):
```bash
echo "disable server web_backend web1" | socat stdio /run/haproxy/admin.sock
```

### Enable Backend:
```bash
echo "enable server web_backend web1" | socat stdio /run/haproxy/admin.sock
```

---

## ❌ Troubleshooting

| Issue | Solution |
|-------|----------|
| **Backend servers unreachable** | Verify backend IPs/ports, check firewall, test connectivity |
| **Certificate not loading** | Verify PEM format, check file permissions (600), test validity |
| **Health checks failing** | Adjust health check path, verify backend responses |
| **High latency** | Check backend load, increase timeouts, verify network |
| **Port 443 in use** | `sudo lsof -i :443` → stop conflicting service |

---

## 📊 Monitoring

### View Stats Dashboard:
```bash
# Via command line
watch -n 1 'echo "show stat" | socat stdio /run/haproxy/admin.sock | head -20'
```

### Parse Stats:
```bash
# Get frontend stats
echo "show frontend" | socat stdio /run/haproxy/admin.sock
```

### Monitor Throughput:
```bash
# Watch request rates
watch -n 1 'curl -s http://localhost:8404/stats 2>/dev/null | grep "web_backend"'
```

---

## 🔄 Backup & Disaster Recovery

### Backup Configuration:
```bash
sudo cp /etc/haproxy/haproxy.cfg /backup/haproxy.cfg.$(date +%Y%m%d_%H%M%S)
```

### Backup Certificates:
```bash
sudo cp -r /etc/haproxy/certs /backup/haproxy_certs.$(date +%Y%m%d_%H%M%S)
```

---

**Last Updated**: March 2026 | **Status**: Production Ready
