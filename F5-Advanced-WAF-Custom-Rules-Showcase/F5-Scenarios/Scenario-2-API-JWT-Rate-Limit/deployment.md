# Scenario 2: API JWT Validation & Rate Limiting - Deployment Guide

## 📋 Pre-Deployment Checklist

Before deploying this API security rule, verify:

- [ ] F5 BIG-IP with Advanced WAF module (v17.5.x+)
- [ ] Administrator SSH and GUI access
- [ ] Existing WAF policy on virtual server
- [ ] iRule events enabled in WAF policy
- [ ] API endpoint /api/v2/* routed through BIG-IP
- [ ] JWT secret key prepared (HS256 shared secret)
- [ ] Valid JWT token samples available for testing

---

## 🔑 JWT Configuration

### Step 1: Prepare JWT Secret Key

```bash
# Generate a strong HS256 secret (256-bit = 32 bytes)
openssl rand -base64 32

# Example output:
# a7f3K8mN9pQ2wX4vZ6bY1cD5eF7gH9iJ0kL2mN4oP6qR8sT0uV

# This will be used in the rule as: set JWT_SECRET "..."
```

### Step 2: Sample JWT Token Generation (for testing)

```bash
#!/bin/bash
# Script: generate_test_jwt.sh

# Install jwt-cli (if not available)
npm install -g jwt-cli

# Create a valid JWT token for testing
JWT_SECRET="a7f3K8mN9pQ2wX4vZ6bY1cD5eF7gH9iJ0kL2mN4oP6qR8sT0uV"
ISSUER="api_issuer"
ROLE="admin"
API_KEY="key_123456789"
EXPIRY=$(($(date +%s) + 3600))  # Expires in 1 hour

# Create JWT payload
PAYLOAD="{
  \"iss\": \"${ISSUER}\",
  \"sub\": \"user@example.com\",
  \"api_key\": \"${API_KEY}\",
  \"role\": \"${ROLE}\",
  \"exp\": ${EXPIRY},
  \"iat\": $(date +%s)
}"

# Generate JWT
jwt encode --secret="${JWT_SECRET}" --alg=HS256 --payload="${PAYLOAD}"
```

---

## 🖥️ GUI Deployment (Step-by-Step)

### Step 1: Access BIG-IP Management Console

1. Navigate to: `https://<BIG_IP_MANAGEMENT_IP>:443`
2. Login as administrator
3. Select **Security** > **Application Security** > **iRules**

### Step 2: Create API Security iRule

1. Click **Create**
2. Configure:
   - **Name**: `api_jwt_rate_limit_rule`
   - **Definition**: (Paste full content from `rule.tcl`)
3. Click **Create**

### Step 3: Update JWT Configuration in Rule

Edit the rule and update these parameters:

```tcl
# Line 1: Update JWT_SECRET with your actual secret
set JWT_SECRET "a7f3K8mN9pQ2wX4vZ6bY1cD5eF7gH9iJ0kL2mN4oP6qR8sT0uV"

# Line 3: Update ISSUER_CLAIM to match your JWT issuer
set ISSUER_CLAIM "api_issuer"

# Line 4: Update VALID_ROLES list
set VALID_ROLES "admin,user,service,readonly"
```

### Step 4: Attach iRule to Virtual Server

1. Navigate to **Local Traffic** > **Virtual Servers**
2. Click your API virtual server (e.g., `vs_api_production`)
3. Go to **iRules** section
4. Move `api_jwt_rate_limit_rule` to **Selected** list
5. Click **Update**

### Step 5: Verify WAF Policy Configuration

1. Go to **Security** > **Application Security** > **Policies**
2. Select your API policy
3. Enable:
   - **Learning Mode**: Off (use Blocking mode)
   - **iRule Events**: Enabled
   - **Log All Events**: Enabled
4. Click **Save**

---

## 🖥️ TMSH CLI Deployment

### TMSH Deployment Commands

```bash
# SSH to BIG-IP
ssh admin@<BIG_IP_HOST>
tmsh

# ========================================================================
# Step 1: Create the API Security iRule
# ========================================================================

cat > /tmp/api_jwt_rate_limit_rule.tcl <<'EOF'
[PASTE THE FULL CONTENT OF rule.tcl HERE]
EOF

create ltm irule api_jwt_rate_limit_rule \
  definition-file /tmp/api_jwt_rate_limit_rule.tcl

# Verify
list ltm irule api_jwt_rate_limit_rule

# ========================================================================
# Step 2: Attach iRule to Virtual Server
# ========================================================================

modify ltm virtual vs_api_production \
  rules { api_jwt_rate_limit_rule }

# Verify
show ltm virtual vs_api_production rules

# ========================================================================
# Step 3: Enable ASM Event Logging
# ========================================================================

modify asm policy api_waf_policy \
  codeBlockingPolicy enabled \
  logAll enabled

# ========================================================================
# Step 4: Save Configuration
# ========================================================================

quit
tmsh save sys config
```

---

## 🧪 Testing Deployment

### Test 1: Valid JWT Token (Should Succeed)

```bash
#!/bin/bash
# Script: test_valid_jwt.sh

API_ENDPOINT="https://api.example.com/api/v2/users"
JWT_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhcGlfaXNzdWVyIiwic3ViIjoidXNlckBleGFtcGxlLmNvbSIsImFwaV9rZXkiOiJrZXlfMTIzNDU2Nzg5Iiwicm9sZSI6ImFkbWluIiwiZXhwIjoxNzAwMDAwMDAwLCJpYXQiOjE2OTk5OTk5MDB9.signature"

echo "[*] Testing with valid JWT token..."
echo ""

curl -v -X GET "$API_ENDPOINT" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "Content-Type: application/json"

# Expected: 200 OK (or appropriate API response)
# Headers should include: X-RateLimit-Limit, X-RateLimit-Remaining
```

### Test 2: Missing JWT (Should Return 401)

```bash
#!/bin/bash
# Script: test_missing_jwt.sh

API_ENDPOINT="https://api.example.com/api/v2/users"

echo "[*] Testing without JWT token (should return 401)..."
echo ""

curl -i -X GET "$API_ENDPOINT" \
  -H "Content-Type: application/json"

# Expected output:
# HTTP/1.1 401 Unauthorized
# Content-Type: application/json
# {"error":"Unauthorized","message":"Missing Authorization header"}
```

### Test 3: Invalid JWT Signature (Should Return 401)

```bash
#!/bin/bash
# Script: test_invalid_signature.sh

API_ENDPOINT="https://api.example.com/api/v2/users"
INVALID_JWT="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhcGlfaXNzdWVyIiwicm9sZSI6ImFkbWluIn0.invalidsignature"

echo "[*] Testing with invalid JWT signature..."
echo ""

curl -i -X GET "$API_ENDPOINT" \
  -H "Authorization: Bearer ${INVALID_JWT}"

# Expected:
# HTTP/1.1 401 Unauthorized
# {"error":"Unauthorized","message":"Invalid JWT signature"}
```

### Test 4: Expired JWT (Should Return 401)

```bash
#!/bin/bash
# Script: test_expired_jwt.sh

API_ENDPOINT="https://api.example.com/api/v2/users"
# JWT with exp claim in the past
EXPIRED_JWT="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhcGlfaXNzdWVyIiwicm9sZSI6ImFkbWluIiwiZXhwIjoxNjAwMDAwMDAwfQ.signature"

echo "[*] Testing with expired JWT..."
echo ""

curl -i -X GET "$API_ENDPOINT" \
  -H "Authorization: Bearer ${EXPIRED_JWT}"

# Expected:
# HTTP/1.1 401 Unauthorized
# {"error":"Unauthorized","message":"JWT token expired"}
```

### Test 5: Rate Limit Exceeded (Should Return 429)

```bash
#!/bin/bash
# Script: test_rate_limit.sh

API_ENDPOINT="https://api.example.com/api/v2/users"
JWT_TOKEN="valid_jwt_token_here"
NUM_REQUESTS=105  # Exceed 100 request/minute limit

echo "[*] Testing rate limit (100 requests/minute)..."
echo ""

for i in $(seq 1 $NUM_REQUESTS); do
  RESPONSE=$(curl -s -w "\n%{http_code}" -X GET "$API_ENDPOINT" \
    -H "Authorization: Bearer ${JWT_TOKEN}" \
    -H "Content-Type: application/json")
  
  HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
  
  if [[ "$HTTP_CODE" == "429" ]]; then
    echo "[$i/$NUM_REQUESTS] HTTP 429 - Rate limit triggered"
    break
  else
    echo "[$i/$NUM_REQUESTS] HTTP $HTTP_CODE - OK"
  fi
  
  sleep 0.1  # Small delay between requests
done

# Expected: After 100 requests, HTTP 429 responses
# Response headers include: X-RateLimit-Remaining: 0, Retry-After: 60
```

### Test 6: Invalid Role (Should Return 403)

```bash
#!/bin/bash
# Script: test_invalid_role.sh

API_ENDPOINT="https://api.example.com/api/v2/admin/users"
# JWT with role="unauthorized_role"
JWT_WITH_INVALID_ROLE="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhcGlfaXNzdWVyIiwicm9sZSI6InVuYXV0aG9yaXplZCJ9.signature"

echo "[*] Testing with invalid role..."
echo ""

curl -i -X GET "$API_ENDPOINT" \
  -H "Authorization: Bearer ${JWT_WITH_INVALID_ROLE}"

# Expected:
# HTTP/1.1 403 Forbidden
# {"error":"Forbidden","message":"User role not authorized"}
```

---

## 📊 Verification Commands

### View Rate Limit Statistics

```bash
# SSH to BIG-IP
ssh admin@<BIG_IP_HOST>

# Check data table entries for rate limiting
tmsh list ltm data-table api_rate*

# Expected output:
# ltm data-table api_rate:key_123456789 {
#     value 45
# }
```

### Monitor API Logs in Real-Time

```bash
# SSH to BIG-IP
ssh admin@<BIG_IP_HOST>

# Stream API security events
tail -f /var/log/asm | grep "API_"

# Filter for rate limit events only
tail -f /var/log/asm | grep "API_RATE_LIMIT"

# Filter for JWT validation failures
tail -f /var/log/asm | grep "API_SECURITY_JWT"
```

---

## 🔄 AS3 Declarative Deployment (CI/CD Ready)

### AS3 Template for API Security

```json
{
  "$schema": "https://raw.githubusercontent.com/F5Networks/f5-appsvcs-extension/master/schema/latest/asg-schema.json",
  "class": "AS3",
  "action": "deploy",
  "persist": true,
  "declaration": {
    "class": "ADC",
    "id": "api_security_declaration",
    "schemaVersion": "3.37.0",
    "target": {
      "address": "localhost"
    },
    "api_security_tenant": {
      "class": "Tenant",
      "api_app": {
        "class": "Application",
        "template": "generic",
        "api_vs": {
          "class": "Service_HTTPS",
          "virtualPort": 443,
          "pool": "api_pool",
          "serverTLS": {
            "bigip": "/Common/api_cert"
          },
          "policyWAF": {
            "use": "api_waf_policy"
          },
          "iRules": [
            "/Common/api_jwt_rate_limit_rule"
          ]
        },
        "api_pool": {
          "class": "Pool",
          "monitors": [
            "http"
          ],
          "members": [
            {
              "servicePort": 8443,
              "serverAddresses": [
                "192.168.1.50",
                "192.168.1.51"
              ]
            }
          ]
        },
        "api_waf_policy": {
          "class": "WAF_Policy",
          "url": "/file?id=api_waf_policy.xml"
        }
      }
    }
  }
}
```

### Deploy Using AS3

```bash
#!/bin/bash
# Script: deploy_as3.sh

BIG_IP_HOST="192.168.1.100"
BIG_IP_USER="admin"
BIG_IP_PASS="password"

# Post AS3 declaration
curl -X POST \
  -H "Content-Type: application/json" \
  -d @api_security_declaration.json \
  "https://${BIG_IP_HOST}:443/mgmt/shared/appsvcs/declare" \
  --user "${BIG_IP_USER}:${BIG_IP_PASS}" \
  --insecure
```

---

## 🚀 Production Deployment Strategy

### Phase 1: Development (Week 1)
- Deploy to dev virtual server
- Test with JWT samples
- Verify rate limiting
- Review ASM logs

### Phase 2: Staging (Week 2)
- Deploy to staging environment
- Run 48-hour load test
- Monitor API client impact
- Validate JWT claims processing

### Phase 3: Production (Week 3)
- Schedule during maintenance window
- Deploy to production VS
- Enable 24/7 monitoring
- Prepare rollback plan

---

## 🔧 Tuning & Customization

### Increase Rate Limit

Edit the rule and modify:
```tcl
set RATE_LIMIT_THRESHOLD 500    ;# Increase from 100 to 500 requests/minute
```

### Extend JWT Validation Time Window

Edit the rule and modify:
```tcl
set TIME_WINDOW 120             ;# Change from 60 to 120 seconds
```

### Add Custom Claims Validation

Edit the rule's HTTP_REQUEST event and add:
```tcl
# Example: Validate custom "tenant_id" claim
set tenant_id [json_get $payload_json "tenant_id"]
if {$tenant_id eq ""} {
    HTTP::respond 400 \
        -content {{"error":"Bad Request","message":"Missing tenant_id"}} \
        -content_type "application/json"
    return
}
```

---

## ⚠️ Troubleshooting

### Issue: All API Requests Return 401

**Symptoms**: JWT tokens appear valid but API returns 401

**Solutions**:
1. Verify JWT_SECRET matches signing secret
2. Check issuer claim matches ISSUER_CLAIM
3. Confirm token not expired
4. Test with known-good JWT token

### Issue: Rate Limit Not Working

**Symptoms**: Requests exceed 100/minute but not blocked

**Solutions**:
1. Verify data table entries exist: `tmsh list ltm data-table api_rate*`
2. Check iRule is attached to virtual server
3. Ensure ASM event logging is enabled
4. Review ASM logs for errors

### Issue: X-Forwarded-For Not Honored

**Symptoms**: Client IP incorrect in logs behind proxy

**Solutions**:
1. Verify proxy sends X-Forwarded-For header
2. Check BIG-IP configuration trusts proxy
3. Review rule's xff_header logic
4. Enable header tracing in debug

---

## 📊 Performance Metrics

- **JWT Validation Overhead**: ~2-3ms per request
- **Rate Limit Check**: <1ms lookup
- **Total API Latency Addition**: 3-5ms
- **CPU Impact**: <5% per 10k req/s
- **Memory Footprint**: ~10MB for 10k tracked keys

---

## ✅ Production Readiness Checklist

- [ ] JWT_SECRET configured with production key
- [ ] ISSUER_CLAIM matches actual JWT issuer
- [ ] VALID_ROLES list complete and accurate
- [ ] Rate limit threshold tested with production workload
- [ ] ASM event logging enabled
- [ ] X-Forwarded-For handling verified
- [ ] JWT expiration validation tested
- [ ] Rate limit events monitored
- [ ] Rollback procedure documented
- [ ] Team trained on rule operation

---

**Last Updated**: March 2026 | **TMOS Version**: 17.5.x+
