# Apache Tomcat Hardening - Deployment Guide

## 📋 Prerequisites

- **OS**: Ubuntu 22.04 or CentOS 9
- **Tomcat Version**: 10.x or 11.x
- **Java**: OpenJDK 11+ or Oracle JDK 11+
- **Certificate**: Valid SSL/TLS certificate (PKCS12/JKS format)
- **Access**: Root or sudo privileges

---

## 🚀 Step 1: Install Java Runtime

### Ubuntu:
```bash
sudo apt update
sudo apt install openjdk-11-jre-headless
java -version
```

### CentOS:
```bash
sudo dnf install java-11-openjdk-headless
java -version
```

---

## 📦 Step 2: Install Tomcat

### Ubuntu:
```bash
sudo apt install tomcat10 tomcat10-admin-webapps tomcat10-docs-webapps
```

### Manual Installation:
```bash
# Download
cd /opt
sudo wget https://archive.apache.org/dist/tomcat/tomcat-10/v10.1.0/bin/apache-tomcat-10.1.0.tar.gz
sudo tar -xzf apache-tomcat-10.1.0.tar.gz
sudo mv apache-tomcat-10.1.0 tomcat
sudo chown -R tomcat:tomcat /opt/tomcat
```

---

## 🔒 Step 3: Prepare SSL/TLS Certificate

### Convert PEM to PKCS12 Format:
```bash
# If you have PEM format (from Let's Encrypt)
sudo openssl pkcs12 -export \
  -in /etc/letsencrypt/live/yourdomain.com/fullchain.pem \
  -inkey /etc/letsencrypt/live/yourdomain.com/privkey.pem \
  -out /opt/tomcat/conf/keystore.p12 \
  -name tomcat \
  -passout pass:CHANGE_ME

# Set permissions
sudo chown tomcat:tomcat /opt/tomcat/conf/keystore.p12
sudo chmod 600 /opt/tomcat/conf/keystore.p12
```

### Or Create JKS Keystore:
```bash
keytool -importkeystore \
  -srckeystore keystore.p12 \
  -srcstoretype PKCS12 \
  -destkeystore keystore.jks \
  -deststoretype JKS \
  -srcstorepass CHANGE_ME \
  -deststorepass CHANGE_ME
```

---

## 🏗️ Step 4: Deploy Tomcat Configuration

### Edit server.xml:
```bash
sudo nano /opt/tomcat/conf/server.xml
# or /etc/tomcat10/server.xml (Ubuntu)
```

Replace the Connector section with the provided `server.xml` configuration, updating:
- Certificate path: `/path/to/keystore.jks`
- Password: `CHANGE_ME` (use your actual password)
- Port numbers if needed (8443 for HTTPS, 8080 for HTTP)

### Deploy web.xml:
```bash
# Copy to your application ROOT directory
sudo cp web.xml /opt/tomcat/webapps/ROOT/WEB-INF/

# If Ubuntu:
sudo cp web.xml /var/lib/tomcat/webapps/ROOT/WEB-INF/
```

### Compile & Deploy SecurityHeadersFilter:
```bash
# Compile Java filter
sudo mkdir -p /opt/tomcat/webapps/ROOT/WEB-INF/classes
sudo javac -cp /opt/tomcat/lib/* SecurityHeadersFilter.java
sudo mv SecurityHeadersFilter.class /opt/tomcat/webapps/ROOT/WEB-INF/classes/
```

---

## 🧪 Step 5: Start Tomcat

### Start Service:
```bash
sudo systemctl start tomcat10  # Ubuntu
# or
/opt/tomcat/bin/startup.sh     # Manual installation
```

### Check Status:
```bash
sudo systemctl status tomcat10

# Or check logs:
tail -f /opt/tomcat/logs/catalina.out
```

### Verify HTTPS:
```bash
curl -k https://localhost:8443/
```

---

## 🔐 Step 6: Configure Reverse Proxy (Optional)

If using NGINX/Apache as reverse proxy:

### NGINX Configuration:
```nginx
upstream tomcat {
    server localhost:8080;
}

server {
    listen 443 ssl http2;
    server_name yourdomain.com;
    
    # SSL config...
    
    location / {
        proxy_pass http://tomcat;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Host $host;
    }
}
```

### Apache Configuration:
```apache
ProxyPreserveHost On
ProxyPass / http://localhost:8080/
ProxyPassReverse / http://localhost:8080/

RequestHeader set X-Forwarded-Proto https
```

---

## ✅ Verification

### Test HTTPS Connection:
```bash
curl -k https://localhost:8443/
```

### Check Security Headers:
```bash
curl -sI https://localhost:8443/ | grep -E "X-Content-Type|X-Frame|HSTS"
```

### Monitor Tomcat:
```bash
sudo tail -f /opt/tomcat/logs/catalina.out
```

---

**Last Updated**: March 2026 | **Status**: Production Ready
