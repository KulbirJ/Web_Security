# Scenario 2: API JWT Validation & Rate Limiting - Test Results

## 🧪 Comprehensive Test Suite

This document contains all test cases for JWT validation and rate limiting functionality.

---

## ✅ Test Case 1: Valid JWT Token Access

### Objective
Verify that a valid JWT token grants access to protected API endpoint.

### JWT Token Sample (HS256)

```json
{
  "iss": "api_issuer",
  "sub": "user@example.com",
  "api_key": "key_prod_12345",
  "role": "admin",
  "exp": 2000000000,
  "iat": 1700000000
}
```

### Test Execution

```bash
#!/bin/bash
# Script: test_valid_jwt.sh

API_ENDPOINT="https://api.example.com/api/v2/users"
VALID_JWT="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhcGlfaXNzdWVyIiwic3ViIjoidXNlckBleGFtcGxlLmNvbSIsImFwaV9rZXkiOiJrZXlfcHJvZF8xMjM0NSIsInJvbGUiOiJhZG1pbiIsImV4cCI6MjAwMDAwMDAwMCwiaWF0IjoxNzAwMDAwMDAwfQ.signature"

echo "[Test 1] Valid JWT Token Access"
echo "================================"
echo ""

RESPONSE=$(curl -i -X GET "$API_ENDPOINT" \
  -H "Authorization: Bearer ${VALID_JWT}" \
  -H "Content-Type: application/json" \
  2>&1)

HTTP_CODE=$(echo "$RESPONSE" | grep "^HTTP" | awk '{print $2}')
RATE_LIMIT_HEADER=$(echo "$RESPONSE" | grep "X-RateLimit-Limit")

echo "Response Code: $HTTP_CODE"
echo "Rate Limit Header: $RATE_LIMIT_HEADER"
echo ""

if [[ "$HTTP_CODE" != "401" && "$HTTP_CODE" != "403" ]]; then
  echo "[✓] PASS: Valid JWT accepted (HTTP $HTTP_CODE)"
else
  echo "[✗] FAIL: Valid JWT rejected"
fi
```

### Expected Results
- **HTTP Status**: 200 OK (or appropriate API success code, NOT 401/403)
- **Response Headers**: Include X-RateLimit-Limit, X-RateLimit-Remaining
- **ASM Log Entry**: API_REQUEST_APPROVED
- **Rate Limit Counter**: Incremented for this API key

### ASM Log Verification

```bash
ssh admin@<BIG_IP_HOST>
tail -f /var/log/asm | grep "API_REQUEST_APPROVED"

# Expected:
# API_REQUEST_APPROVED: API request from 192.168.1.100 Method: GET URI: /api/v2/users API_Key: key_prod_12345 Role: admin
```

---

## ✅ Test Case 2: Missing Authorization Header

### Objective
Verify that requests without Authorization header receive 401 response.

### Test Execution

```bash
#!/bin/bash
# Script: test_missing_auth_header.sh

API_ENDPOINT="https://api.example.com/api/v2/users"

echo "[Test 2] Missing Authorization Header"
echo "====================================="
echo ""

RESPONSE=$(curl -i -X GET "$API_ENDPOINT" \
  -H "Content-Type: application/json" \
  2>&1)

HTTP_CODE=$(echo "$RESPONSE" | grep "^HTTP" | awk '{print $2}')
BODY=$(echo "$RESPONSE" | tail -5)

echo "Response Code: $HTTP_CODE"
echo "Response Body:"
echo "$BODY"
echo ""

if [[ "$HTTP_CODE" == "401" ]]; then
  echo "[✓] PASS: Missing header returns 401"
else
  echo "[✗] FAIL: Expected 401, got $HTTP_CODE"
fi
```

### Expected Results
- **HTTP Status**: 401 Unauthorized
- **Response Body**:
  ```json
  {
    "error": "Unauthorized",
    "message": "Missing Authorization header"
  }
  ```
- **Response Headers**: Include WWW-Authenticate: Bearer realm="API"
- **ASM Log**: Missing_Authorization_header event

---

## ✅ Test Case 3: Invalid JWT Signature

### Objective
Verify that JWT with invalid signature is rejected.

### Test Execution

```bash
#!/bin/bash
# Script: test_invalid_signature.sh

API_ENDPOINT="https://api.example.com/api/v2/users"
# Valid token structure but signed with wrong secret
INVALID_JWT="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhcGlfaXNzdWVyIiwicm9sZSI6ImFkbWluIn0.INVALID_SIGNATURE_XXXXXX"

echo "[Test 3] Invalid JWT Signature"
echo "=============================="
echo ""

RESPONSE=$(curl -i -X GET "$API_ENDPOINT" \
  -H "Authorization: Bearer ${INVALID_JWT}" \
  -H "Content-Type: application/json" \
  2>&1)

HTTP_CODE=$(echo "$RESPONSE" | grep "^HTTP" | awk '{print $2}')
BODY=$(echo "$RESPONSE" | tail -5)

echo "Response Code: $HTTP_CODE"
echo "Response Body:"
echo "$BODY"
echo ""

if [[ "$HTTP_CODE" == "401" ]]; then
  echo "[✓] PASS: Invalid signature rejected (401)"
else
  echo "[✗] FAIL: Expected 401, got $HTTP_CODE"
fi
```

### Expected Results
- **HTTP Status**: 401 Unauthorized
- **Response Body**:
  ```json
  {
    "error": "Unauthorized",
    "message": "Invalid JWT signature"
  }
  ```
- **ASM Log**: API_SECURITY_JWT_FAIL event

---

## ✅ Test Case 4: Expired JWT Token

### Objective
Verify that expired JWT tokens are rejected.

### Create Expired JWT

```bash
#!/bin/bash
# JWT with exp claim in the past (expired 1 hour ago)

PAYLOAD="{
  \"iss\": \"api_issuer\",
  \"sub\": \"user@example.com\",
  \"role\": \"admin\",
  \"exp\": $(($(date +%s) - 3600))
}"

# Generate JWT with past expiration
jwt encode --secret="shared_secret" --alg=HS256 --payload="$PAYLOAD"
```

### Test Execution

```bash
#!/bin/bash
# Script: test_expired_jwt.sh

API_ENDPOINT="https://api.example.com/api/v2/users"
EXPIRED_JWT="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhcGlfaXNzdWVyIiwiZXhwIjoxNjk5OTk2NDAwfQ.signature"

echo "[Test 4] Expired JWT Token"
echo "=========================="
echo ""

RESPONSE=$(curl -i -X GET "$API_ENDPOINT" \
  -H "Authorization: Bearer ${EXPIRED_JWT}" \
  2>&1)

HTTP_CODE=$(echo "$RESPONSE" | grep "^HTTP" | awk '{print $2}')
BODY=$(echo "$RESPONSE" | grep "message" | grep -o '"message":"[^"]*"')

echo "Response Code: $HTTP_CODE"
echo "Message: $BODY"
echo ""

if [[ "$HTTP_CODE" == "401" && "$BODY" == *"expired"* ]]; then
  echo "[✓] PASS: Expired JWT rejected (401)"
else
  echo "[✗] FAIL: Expired JWT not properly handled"
fi
```

### Expected Results
- **HTTP Status**: 401 Unauthorized
- **Response Body Contains**: "JWT token expired"
- **ASM Log**: API_SECURITY_EXPIRED event

---

## ✅ Test Case 5: Invalid Issuer Claim

### Objective
Verify that JWT with mismatched issuer claim is rejected.

### Test Execution

```bash
# JWT with wrong issuer claim
WRONG_ISSUER_JWT='eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOid3Jvbmdfc2lnbmVyIiwicm9sZSI6ImFkbWluIn0.signature'

curl -i -X GET "https://api.example.com/api/v2/users" \
  -H "Authorization: Bearer ${WRONG_ISSUER_JWT}"

# Expected: HTTP 401 Unauthorized
# Message: "Invalid issuer"
```

### Expected Results
- **HTTP Status**: 401 Unauthorized
- **Message**: "Invalid issuer"
- **ASM Log**: API_SECURITY_ISSUER event

---

## ✅ Test Case 6: Invalid Role Authorization

### Objective
Verify that users with unauthorized roles are denied (403 Forbidden).

### Test Execution

```bash
# JWT with unauthorized role
UNAUTHORIZED_ROLE_JWT='eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhcGlfaXNzdWVyIiwicm9sZSI6ImhhY2tlciJ9.signature'

curl -i -X GET "https://api.example.com/api/v2/admin/settings" \
  -H "Authorization: Bearer ${UNAUTHORIZED_ROLE_JWT}"

# Expected: HTTP 403 Forbidden
# Message: "User role not authorized"
```

### Expected Results
- **HTTP Status**: 403 Forbidden
- **Message**: "User role not authorized"
- **ASM Log**: API_SECURITY_ROLE event

---

## ✅ Test Case 7: Rate Limit - Threshold Exceeded

### Objective
Verify that rate limit of 100 requests/minute per API key is enforced.

### Test Execution

```bash
#!/bin/bash
# Script: test_rate_limit.sh

API_ENDPOINT="https://api.example.com/api/v2/data"
JWT_TOKEN="valid_jwt_token_here"
NUM_REQUESTS=105

echo "[Test 7] Rate Limit Threshold (100 req/min)"
echo "==========================================="
echo ""

RATE_LIMITED=0

for i in $(seq 1 $NUM_REQUESTS); do
  RESPONSE=$(curl -s -w "\n%{http_code}" -X GET "$API_ENDPOINT" \
    -H "Authorization: Bearer ${JWT_TOKEN}" \
    2>&1)
  
  HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
  
  if [[ "$HTTP_CODE" == "429" && $RATE_LIMITED -eq 0 ]]; then
    RATE_LIMITED=$i
    echo "[$i/$NUM_REQUESTS] Rate limit triggered at request #$i"
  elif [[ $RATE_LIMITED -eq 0 ]]; then
    if [[ $((i % 20)) -eq 0 ]]; then
      echo "[$i/$NUM_REQUESTS] HTTP $HTTP_CODE - OK"
    fi
  fi
done

echo ""
if [[ $RATE_LIMITED -gt 100 && $RATE_LIMITED -le 102 ]]; then
  echo "[✓] PASS: Rate limit enforced at request #$RATE_LIMITED"
else
  echo "[✗] FAIL: Rate limit not enforced correctly (triggered at #$RATE_LIMITED)"
fi
```

### Expected Results
- **Requests 1-100**: HTTP 200 OK or appropriate success code
- **Request 101+**: HTTP 429 Too Many Requests
- **Response Headers**: 
  - X-RateLimit-Limit: 100
  - X-RateLimit-Remaining: 0
  - Retry-After: 60

### ASM Log Entry

```
API_RATE_LIMIT_EXCEED: Rate limit exceeded for API key: key_prod_12345 (requests: 101/100)
```

---

## ✅ Test Case 8: Rate Limit Per API Key (Independent)

### Objective
Verify that rate limiting is tracked per API key independently.

### Test Execution

```bash
#!/bin/bash
# Script: test_rate_limit_per_key.sh

API_ENDPOINT="https://api.example.com/api/v2/data"
JWT_KEY_1="valid_jwt_for_key_1"
JWT_KEY_2="valid_jwt_for_key_2"

echo "[Test 8] Rate Limit Per API Key"
echo "==============================="
echo ""

# Send 100 requests with API Key 1
echo "Sending 100 requests with API Key 1..."
for i in $(seq 1 100); do
  curl -s -X GET "$API_ENDPOINT" \
    -H "Authorization: Bearer ${JWT_KEY_1}" > /dev/null
done

# Send 1 request with API Key 2 (should succeed, not rate limited)
echo "Sending 1 request with API Key 2..."
RESPONSE=$(curl -s -w "%{http_code}" -X GET "$API_ENDPOINT" \
  -H "Authorization: Bearer ${JWT_KEY_2}" | tail -c 3)

# Send 1 more request with API Key 1 (should be rate limited)
echo "Sending 101st request with API Key 1..."
RESPONSE_KEY1=$(curl -s -w "%{http_code}" -X GET "$API_ENDPOINT" \
  -H "Authorization: Bearer ${JWT_KEY_1}" | tail -c 3)

echo ""
echo "API Key 1 (101st request): HTTP $RESPONSE_KEY1 (expected: 429)"
echo "API Key 2 (1st request): HTTP $RESPONSE (expected: NOT 429)"

if [[ "$RESPONSE_KEY1" == "429" && "$RESPONSE" != "429" ]]; then
  echo "[✓] PASS: Per-key rate limiting working"
else
  echo "[✗] FAIL: Per-key tracking not independent"
fi
```

### Expected Results
- **API Key 1 at 101 requests**: HTTP 429 (rate limited)
- **API Key 2 at 1 request**: HTTP 200/appropriate success (not limited)
- **Tracking**: Independent per API key via `api_rate:<api_key>` data table

---

## ✅ Test Case 9: Rate Limit Window Reset

### Objective
Verify that rate limit window resets after 60 seconds.

### Test Execution (Long-Running)

```bash
#!/bin/bash
# Script: test_rate_limit_window_reset.sh

API_ENDPOINT="https://api.example.com/api/v2/data"
JWT_TOKEN="valid_jwt_token_here"

echo "[Test 9] Rate Limit Window Reset (60 seconds)"
echo "=============================================="
echo ""

# Send 100 requests (should succeed)
echo "[1] Sending 100 requests in window 1..."
for i in $(seq 1 100); do
  curl -s -X GET "$API_ENDPOINT" \
    -H "Authorization: Bearer ${JWT_TOKEN}" > /dev/null
done

# 101st request should be blocked
echo "[2] 101st request (should be blocked)..."
RESPONSE_BLOCKED=$(curl -s -w "%{http_code}" -X GET "$API_ENDPOINT" \
  -H "Authorization: Bearer ${JWT_TOKEN}" | tail -c 3)

# Wait for window to reset (61 seconds)
echo "[3] Waiting 61 seconds for window to reset..."
sleep 61

# After reset, should be able to send requests again
echo "[4] Sending request after window reset..."
RESPONSE_AFTER_RESET=$(curl -s -w "%{http_code}" -X GET "$API_ENDPOINT" \
  -H "Authorization: Bearer ${JWT_TOKEN}" | tail -c 3)

echo ""
echo "Before reset (blocked): HTTP $RESPONSE_BLOCKED (expected: 429)"
echo "After reset (should work): HTTP $RESPONSE_AFTER_RESET (expected: NOT 429)"

if [[ "$RESPONSE_BLOCKED" == "429" && "$RESPONSE_AFTER_RESET" != "429" ]]; then
  echo "[✓] PASS: Rate limit window reset correctly"
else
  echo "[✗] FAIL: Window reset not working"
fi
```

### Expected Results
- **Within window**: HTTP 429 after 100 requests
- **After 60s + 1s**: Counter resets, requests allowed again
- **Counter**: Starts fresh cycle from 1

---

## ✅ Test Case 10: X-Forwarded-For Header (Proxy Support)

### Objective
Verify that client IP is correctly logged from X-Forwarded-For header.

### Test Execution

```bash
#!/bin/bash
# Script: test_xff_header.sh

API_ENDPOINT="https://api.example.com/api/v2/users"
JWT_TOKEN="valid_jwt_token_here"
CLIENT_IP="203.0.113.45"

echo "[Test 10] X-Forwarded-For Header Support"
echo "========================================"
echo ""

curl -v -X GET "$API_ENDPOINT" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -H "X-Forwarded-For: ${CLIENT_IP}" \
  2>&1 | grep -E "< HTTP|X-RateLimit"

# SSH to BIG-IP and check ASM log for correct IP
ssh admin@<BIG_IP_HOST> \
  "tail -5 /var/log/asm | grep API_REQUEST_APPROVED | grep ${CLIENT_IP}"
```

### Expected Results
- **ASM Log**: Contains X-Forwarded-For IP (203.0.113.45), not BIG-IP IP
- **Request Processing**: Uses correct client IP for tracking
- **Rate Limit**: Tracked per origin IP correctly

---

## 📊 Security Response Headers Validation

### Verify Response Security Headers

```bash
#!/bin/bash
# Script: test_security_headers.sh

API_ENDPOINT="https://api.example.com/api/v2/users"
JWT_TOKEN="valid_jwt_token_here"

echo "[Test] Security Response Headers"
echo "================================"
echo ""

curl -i -X GET "$API_ENDPOINT" \
  -H "Authorization: Bearer ${JWT_TOKEN}" | grep -E "X-Content-Type-Options|X-Frame-Options|Cache-Control"

# Expected headers:
# X-Content-Type-Options: nosniff
# X-Frame-Options: DENY
# Cache-Control: no-store, no-cache, must-revalidate
```

### Expected Headers Present
- **X-Content-Type-Options**: nosniff
- **X-Frame-Options**: DENY
- **Cache-Control**: no-store, no-cache, must-revalidate

---

## 🔍 ASM Log Analysis

### Real-Time API Event Monitoring

```bash
ssh admin@<BIG_IP_HOST>

# Stream all API security events
tail -f /var/log/asm | grep -E "API_"

# Filter specific event types
tail -f /var/log/asm | grep "API_RATE_LIMIT_EXCEED"
tail -f /var/log/asm | grep "API_SECURITY_JWT"
tail -f /var/log/asm | grep "API_REQUEST_APPROVED"
```

### Sample Log Output

```
API_REQUEST_APPROVED: API request from 192.168.1.100 Method: GET URI: /api/v2/users API_Key: key_prod_12345 Role: admin
API_RATE_LIMIT_OK: API key key_prod_12345: 45/100
API_RATE_LIMIT_EXCEED: Rate limit exceeded for API key: key_prod_12345 (requests: 101/100)
API_SECURITY_JWT_FAIL: JWT signature verification failed for /api/v2/users
API_SECURITY_EXPIRED: JWT expired. Current: 1700100000, Exp: 1600000000
API_SECURITY_ISSUER: JWT issuer mismatch. Expected: api_issuer, Got: wrong_issuer
API_SECURITY_ROLE: Invalid role in JWT: hacker
```

---

## ✅ Test Summary Checklist

```
[ ] Test 1: Valid JWT Token Access
    ├─ [✓ or ✗] HTTP status not 401/403
    ├─ [✓ or ✗] Rate Limit headers present
    └─ [✓ or ✗] ASM log shows API_REQUEST_APPROVED

[ ] Test 2: Missing Authorization Header
    ├─ [✓ or ✗] HTTP 401 returned
    ├─ [✓ or ✗] Error message in response
    └─ [✓ or ✗] WWW-Authenticate header present

[ ] Test 3: Invalid JWT Signature
    ├─ [✓ or ✗] HTTP 401 returned
    ├─ [✓ or ✗] Message: "Invalid JWT signature"
    └─ [✓ or ✗] ASM log shows JWT_FAIL

[ ] Test 4: Expired JWT Token
    ├─ [✓ or ✗] HTTP 401 returned
    ├─ [✓ or ✗] Message: "JWT token expired"
    └─ [✓ or ✗] ASM log shows EXPIRED

[ ] Test 5: Invalid Issuer Claim
    ├─ [✓ or ✗] HTTP 401 returned
    └─ [✓ or ✗] Message: "Invalid issuer"

[ ] Test 6: Invalid Role Authorization
    ├─ [✓ or ✗] HTTP 403 returned
    └─ [✓ or ✗] Message: "User role not authorized"

[ ] Test 7: Rate Limit Enforcement
    ├─ [✓ or ✗] Requests 1-100 succeed
    ├─ [✓ or ✗] Request 101+ returns HTTP 429
    └─ [✓ or ✗] Rate limit headers correct

[ ] Test 8: Per-Key Rate Limiting
    ├─ [✓ or ✗] Key 1 blocked at 100
    ├─ [✓ or ✗] Key 2 independent
    └─ [✓ or ✗] Separate counters tracked

[ ] Test 9: Window Reset After 60s
    ├─ [✓ or ✗] Blocked initially
    ├─ [✓ or ✗] Allowed after reset
    └─ [✓ or ✗] Counter restarts

[ ] Test 10: X-Forwarded-For Support
    ├─ [✓ or ✗] Client IP from header
    ├─ [✓ or ✗] Correct IP in log
    └─ [✓ or ✗] Proxy transparent
```

---

**Test Suite Version**: 1.0 | **Last Updated**: March 2026
