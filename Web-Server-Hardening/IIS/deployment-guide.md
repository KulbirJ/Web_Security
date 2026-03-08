# Microsoft IIS Web Server Hardening - Deployment Guide

## 📋 Prerequisites

- **OS**: Windows Server 2022 with IIS 10.0
- **Modules Required**: IIS Rewrite Module, IIS URL Rewrite 2.1
- **Certificate**: Valid SSL/TLS certificate (from Let's Encrypt or trusted CA)
- **Access Level**: Administrator privileges on IIS server

---

## 🚀 Step 1: Install IIS Components

### Via Server Manager GUI:
1. Open **Server Manager**
2. Click **Add Roles and Features**
3. Select **Web Server (IIS)** role
4. Include the following role services:
   - Web Server
   - Common HTTP Features
   - Health and Diagnostics
   - Performance
   - **Security** (Critical for hardening)
   - Application Development (if running .NET apps)

### Via PowerShell (Automated):
```powershell
# Run as Administrator
Install-WindowsFeature Web-Server, Web-Cert-Auth, Web-Url-Rewrite, Web-Filtering
```

---

## 🔒 Step 2: Install SSL/TLS Certificate

### Option A: Using Let's Encrypt (Free - Recommended)

#### Prerequisites:
- Install **Certify The Web** or **win-acme** (automated certificate manager)

#### Using Certify The Web:
1. Download: https://certifytheweb.com/
2. Run installer and launch application
3. Click **New Certificate**
4. Enter domain (e.g., `yourdomain.com`)
5. Select IIS binding
6. Click **Request Certificate**
7. Certificate auto-installed in IIS

#### Using win-acme (Command Line):
```powershell
# Download and run wacs.exe
.\wacs.exe
# Select "N" for new certificate
# Choose IIS site and domain
# Accept ACME terms
# Certificate installs automatically
```

### Option B: Using Manual Certificate (GUI)

1. Open **IIS Manager** (`inetmgr`)
2. Select server node (not site)
3. Click **Server Certificates** (in Features view)
4. Click **Import** or **Create Certificate Request**
5. If importing: Select `.pfx` or `.cer` file
6. Enter certificate password if prompted

### Option C: Install Let's Encrypt Manually

```powershell
# Download certificate files from Let's Encrypt
# Convert PEM to PFX format
# Import into IIS

# Example (replace paths):
$pfxPath = "C:\certs\yourdomain.com.pfx"
Import-Certificate -FilePath $pfxPath -CertStoreLocation Cert:\LocalMachine\My\
```

---

## 🏗️ Step 3: Configure HTTPS Binding

### Via IIS Manager GUI:

1. **Open IIS Manager**: `inetmgr`
2. **Expand** server node → Sites
3. **Right-click** your website (e.g., "Default Web Site")
4. Click **Edit Bindings**
5. Click **Add** to create HTTPS binding:
   - **Type**: `https`
   - **IP Address**: `All Unassigned` (or specific IP)
   - **Port**: `443`
   - **Host name**: `yourdomain.com`
   - **SSL Certificate**: (Select installed certificate)
6. **Keep** existing HTTP (port 80) binding for redirect

### Via PowerShell (Automated):

```powershell
$siteName = "Default Web Site"
$domain = "yourdomain.com"
$certThumbprint = "YOUR_CERT_THUMBPRINT"  # Get from Certify The Web or cert details

# Add HTTPS binding
New-IISSiteBinding -Name $siteName -Protocol "https" -BindingInformation "*:443:$domain" -CertificateThumbprint $certThumbprint -CertificateStoreName "My"
```

**To find certificate thumbprint**:
```powershell
Get-ChildItem -Path Cert:\LocalMachine\My\ | Where-Object {$_.Subject -match "yourdomain.com"} | Select-Object Thumbprint
```

---

## 📄 Step 4: Deploy web.config

### Manual Deployment:

1. **Locate** your website root:
   - Default: `C:\inetpub\wwwroot\`
   - Or check IIS Manager → Site → Physical Path

2. **Copy** the `web.config` file from this repository to site root
   ```powershell
   Copy-Item ".\web.config" "C:\inetpub\wwwroot\web.config"
   ```

3. **Set proper permissions** (if needed):
   ```powershell
   icacls "C:\inetpub\wwwroot\web.config" /grant "IIS_IUSRS:(M)"
   ```

### Merge with Existing web.config:

If you have an existing `web.config`, merge these sections:
```xml
<!-- Add to <system.webServer> -->
<httpProtocol>
  <customHeaders>
    <add name="X-Content-Type-Options" value="nosniff" />
    <!-- ... other headers ... -->
  </customHeaders>
</httpProtocol>

<rewrite>
  <rules>
    <rule name="HTTP to HTTPS Redirect" stopProcessing="true">
      <!-- ... redirect rule ... -->
    </rule>
  </rules>
</rewrite>
```

---

## 🔐 Step 5: TLS Hardening (Optional but Recommended)

### Using IIS Crypto GUI:
1. Download **IIS Crypto**: https://www.nartac.com/Products/IISCrypto
2. Run as Administrator
3. Select **Cipher Suites** tab
4. **Disable** older protocols:
   - SSL 2.0 ✗
   - SSL 3.0 ✗
   - TLS 1.0 ✗
   - TLS 1.1 ✗
5. **Enable**:
   - TLS 1.2 ✓
   - TLS 1.3 ✓
6. Reorder ciphers (prefer ECDHE)
7. Click **Apply**
8. **Reboot required**

### Via PowerShell Registry Changes:

```powershell
# Disable SSL 2.0
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -Name "Enabled" -Value 0

# Disable TLS 1.0
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name "Enabled" -Value 0

# Enable TLS 1.3 (Server 2022)
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" -Name "Enabled" -Value 1
```

---

## 🧪 Step 6: Test & Verification

### Test IIS Configuration Syntax:

```bash
# No PowerShell equivalent; syntax is checked on load
# If IIS doesn't restart, check Event Viewer for XML errors
```

### Restart IIS:

```powershell
# Full restart
iisreset /restart

# Or via Services
Restart-Service -Name W3SVC -Force
```

### Test HTTPS Connection:

```powershell
# Test HTTP redirect to HTTPS
$response = Invoke-WebRequest -Uri "http://yourdomain.com" -MaximumRedirection 0 -ErrorAction SilentlyContinue
$response.StatusCode  # Should be 301

# Test HTTPS headers
$response = Invoke-WebRequest -Uri "https://yourdomain.com" -SkipCertificateCheck
$response.Headers
```

### Verify Security Headers:

```bash
# Using curl
curl -I https://yourdomain.com

# Expected headers:
# HTTP/2 200
# Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
# X-Content-Type-Options: nosniff
# X-Frame-Options: DENY
# Content-Security-Policy: ...
```

### Online Security Verification:

1. **SecurityHeaders.com**: https://securityheaders.com/
   - Enter your domain
   - Target grade: **A** or **A+**

2. **SSL Labs**: https://www.ssllabs.com/ssltest/
   - Enter your domain
   - Target grade: **A+** or **A**
   - Verify TLS 1.2/1.3 only

### Check Server Logs:

```powershell
# IIS Logs location
Get-ChildItem -Path "C:\inetpub\logs\LogFiles\W3SVC1\"

# Monitor real-time
Get-Content -Path "C:\inetpub\logs\LogFiles\W3SVC1\[latest].log" -Wait
```

---

## 🎯 Additional Security Configurations

### 1. Disable Directory Browsing

```powershell
# Via PowerShell
Set-IISFeature -Name "Web-Dir-Browsing" -Enabled $false
```

### 2. Remove Server Header Banner

Already included in `web.config` (`<remove name="X-Powered-By" />`), but verify:

```powershell
# Check current setting
Get-IISConfigSection -SectionPath "system.webServer/httpProtocol" | Get-IISConfigElement -Name "customHeaders"
```

### 3. Enable Access Logging

1. IIS Manager → Site → Logging (in Features)
2. Select: **W3C Extended Log File Format**
3. Include fields:
   - Date
   - Time
   - Server IP Address
   - Method
   - URI Stem
   - Status
   - User Principal

### 4. Set Custom Error Pages

```powershell
# Add error page handlers (already in web.config)
# Create custom pages:
# C:\inetpub\wwwroot\404.aspx
# C:\inetpub\wwwroot\500.aspx
```

---

## ❌ Troubleshooting

| Issue | Solution |
|-------|----------|
| **HTTPS not accessible** | Verify binding created, certificate installed, port 443 open on firewall |
| **HTTP redirect not working** | Check `<rewrite>` rule in web.config, verify Rewrite module installed |
| **Headers not appearing** | Clear browser cache, check IIS logs for errors, restart W3SVC service |
| **SSL certificate warning** | Verify domain matches certificate CN/SAN, certificate not expired |
| **Port 443 already in use** | `netstat -ano \| findstr :443`, stop conflicting service |
| **Permission denied on web.config** | Check NTFS permissions, IIS AppPool user needs read access |

---

## 📊 Performance Impact

- **Security Headers**: < 1ms latency
- **HTTP→HTTPS Redirect**: < 5ms (depends on network)
- **TLS Handshake**: 50-100ms (first request)
- **CPU Impact**: < 2% for moderate traffic

---

## 🔄 Maintenance & Updates

### Monthly Tasks:
- ✓ Check certificate renewal status (Let's Encrypt auto-renews 30 days before expiration)
- ✓ Review IIS logs for 4xx/5xx errors
- ✓ Verify security headers present in responses

### Quarterly Tasks:
- ✓ Update Windows Server patches
- ✓ Review OWASP Top 10 for new mitigations
- ✓ Test SSL Labs grade (aim for A+)

### Annually:
- ✓ Review active ciphers (remove deprecated ones)
- ✓ Audit CSP policy for unused directives
- ✓ Test disaster recovery (certificate renewal, site migration)

---

**Last Updated**: March 2026 | **Status**: Production Ready
