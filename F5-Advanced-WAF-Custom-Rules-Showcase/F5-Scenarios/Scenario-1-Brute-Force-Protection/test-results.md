# Scenario 1: Brute-Force Protection - Test Results & Validation

## 🧪 Test Suite Overview

This document provides comprehensive testing procedures for the brute-force protection rule, including:
- Attack simulation commands
- Expected responses
- ASM log validation
- Success/failure criteria

---

## ✅ Test Case 1: Block After 5 Failed Attempts

### Objective
Verify that an IP address is blocked after exceeding the 5-failed-attempt threshold within a 5-minute window.

### Setup
```bash
# Environment variables
TARGET_HOST="10.20.30.40"
LOGIN_ENDPOINT="/login"
TEST_USERNAME="testuser@example.com"
```

### Execution Steps

#### Step 1: Generate 5 Failed Login Attempts

```bash
#!/bin/bash
# Script: test_case_1_part1.sh

TARGET_HOST="10.20.30.40"
LOGIN_ENDPOINT="/login"

echo "[*] Testing brute-force protection..."
echo "[*] Target: http://${TARGET_HOST}${LOGIN_ENDPOINT}"
echo ""

for i in {1..5}; do
  echo "[$i/5] Sending failed login attempt..."
  
  RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
    "http://${TARGET_HOST}${LOGIN_ENDPOINT}" \
    -d "username=testuser&password=wrongpassword${i}" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -H "User-Agent: TestClient/1.0")
  
  HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
  BODY=$(echo "$RESPONSE" | head -n-1)
  
  echo "  Response Code: $HTTP_CODE"
  echo "  Body Preview: $(echo "$BODY" | head -c 80)..."
  echo ""
  
  # Wait 1 second between attempts to ensure proper timing
  sleep 1
done

echo "[✓] Completed 5 failed attempts"
```

#### Step 2: Verify 6th Attempt is Blocked

```bash
#!/bin/bash
# Script: test_case_1_part2.sh

TARGET_HOST="10.20.30.40"
LOGIN_ENDPOINT="/login"

echo ""
echo "[*] Testing 6th attempt (should be BLOCKED)..."
echo ""

RESPONSE=$(curl -s -w "\n%{http_code}" -i -X POST \
  "http://${TARGET_HOST}${LOGIN_ENDPOINT}" \
  -d "username=testuser&password=anypassword" \
  -H "Content-Type: application/x-www-form-urlencoded")

HTTP_CODE=$(echo "$RESPONSE" | grep "^[0-9]" | awk '{print $2}')
HEADERS=$(echo "$RESPONSE" | grep -E "HTTP|Retry-After|X-RateLimit")

echo "[!] Response:"
echo "$HEADERS"
echo ""

# Test validation
if [[ "$HTTP_CODE" == "429" ]]; then
  echo "[✓] PASS: HTTP 429 received (Too Many Requests)"
  echo "[✓] PASS: IP is blocked as expected"
else
  echo "[✗] FAIL: Expected HTTP 429, got $HTTP_CODE"
fi
```

### Expected Results

| Step | Request # | HTTP Status | Expected Behavior | Pass/Fail |
|------|-----------|-------------|-------------------|-----------|
| 1 | 1st failed | 401/403 | Attempt logged | ✓ or ✗ |
| 1 | 2nd failed | 401/403 | Attempt logged | ✓ or ✗ |
| 1 | 3rd failed | 401/403 | Attempt logged | ✓ or ✗ |
| 1 | 4th failed | 401/403 | Attempt logged | ✓ or ✗ |
| 1 | 5th failed | 401/403 | Attempt logged | ✓ or ✗ |
| 2 | 6th attempt | **429** | **IP BLOCKED** | ✓ or ✗ |

### Response Headers for Blocked Request

```
HTTP/1.1 429 Too Many Requests
Cache-Control: no-cache, no-store, must-revalidate
Pragma: no-cache
Expires: 0
X-RateLimit-Limit: 5
X-RateLimit-Remaining: 0
Retry-After: 900
Content-Type: text/html
Content-Length: 312

Too Many Attempts
Too many failed login attempts from your IP address.
Please try again in 15 minutes.
```

### ASM Log Verification

```bash
# SSH to BIG-IP
ssh admin@<BIG_IP_HOST>

# View brute-force events in real-time
tail -f /var/log/asm | grep "BRUTE_FORCE"

# Expected output pattern:
# [timestamp] BRUTE_FORCE_EVENT: Failed login attempt from IP 192.168.1.100 username testuser attempt_count 1
# [timestamp] BRUTE_FORCE_EVENT: Failed login attempt from IP 192.168.1.100 username testuser attempt_count 2
# ...
# [timestamp] BRUTE_FORCE_BLOCK: IP 192.168.1.100 blocked for 900s. Failed attempts: 5, last username: testuser
```

---

## ✅ Test Case 2: Successful Login After Block Window Expires

### Objective
Verify that an IP address can login successfully after the 15-minute block duration expires.

### Execution Steps

```bash
#!/bin/bash
# Script: test_case_2.sh

TARGET_HOST="10.20.30.40"
LOGIN_ENDPOINT="/login"
WAIT_TIME=901  # 15 minutes + 1 second

echo "[*] Test: Block expiration after 15 minutes"
echo ""
echo "[1] IP is currently blocked (from Test Case 1)"
echo "[2] Waiting ${WAIT_TIME} seconds for block to expire..."

# Option A: Wait the full duration
# sleep $WAIT_TIME

# Option B: For testing, manually clear the block
# (See: Clearing Data Table entries section below)

echo "[3] Attempting login after block expires..."

RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
  "http://${TARGET_HOST}${LOGIN_ENDPOINT}" \
  -d "username=testuser&password=correctpassword" \
  -H "Content-Type: application/x-www-form-urlencoded")

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

echo "Response Code: $HTTP_CODE"

if [[ "$HTTP_CODE" != "429" ]]; then
  echo "[✓] PASS: IP is no longer blocked (not 429)"
  echo "[✓] PASS: Normal login flow resumed"
else
  echo "[✗] FAIL: IP still blocked after expiration"
fi
```

### Expected Results
- **HTTP Status**: NOT 429 (should be 401, 403, or 200 depending on credentials)
- **Block Status**: Cleared, IP can attempt login again
- **Log Entry**: No BRUTE_FORCE_BLOCK events for new attempts

---

## ✅ Test Case 3: Time Window Reset

### Objective
Verify that the 5-minute time window resets, allowing isolated failed attempts without triggering block.

### Execution Steps

```bash
#!/bin/bash
# Script: test_case_3.sh

TARGET_HOST="10.20.30.40"
LOGIN_ENDPOINT="/login"

echo "[*] Test: Time window reset"
echo ""
echo "[1] Sending 2 failed attempts..."

for i in {1..2}; do
  curl -s -X POST "http://${TARGET_HOST}${LOGIN_ENDPOINT}" \
    -d "username=testuser&password=wrong" \
    -H "Content-Type: application/x-www-form-urlencoded" > /dev/null
  echo "  [$i/2] Sent"
  sleep 1
done

echo "[2] Waiting 5+ minutes for time window to expire..."
sleep 301  # 5 minutes + 1 second

echo "[3] After window expires, attempt login (should NOT be blocked)..."

RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
  "http://${TARGET_HOST}${LOGIN_ENDPOINT}" \
  -d "username=testuser&password=wrong" \
  -H "Content-Type: application/x-www-form-urlencoded")

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)

if [[ "$HTTP_CODE" != "429" ]]; then
  echo "[✓] PASS: Time window reset, counter cleared"
else
  echo "[✗] FAIL: Still being rate-limited after window expired"
fi
```

### Expected Results
- After 5 minutes: Counter resets
- Next failed attempt: Treated as first fresh attempt (not blocked)
- Counter restarts from 1

---

## ✅ Test Case 4: Multiple IP Addresses (Independent Tracking)

### Objective
Verify that brute-force tracking is per-IP, not global. Each IP has independent attempt counting.

### Setup
```bash
IP1="192.168.1.100"
IP2="192.168.1.101"
IP3="192.168.1.102"
```

### Execution Steps

```bash
#!/bin/bash
# Script: test_case_4.sh

TARGET_HOST="10.20.30.40"
LOGIN_ENDPOINT="/login"

echo "[*] Test: Independent IP tracking"
echo ""

# Simulate 5 failed attempts from IP1
echo "[1] Sending 5 failed attempts from IP1 (192.168.1.100)..."
for i in {1..5}; do
  curl -s -X POST "http://${TARGET_HOST}${LOGIN_ENDPOINT}" \
    -d "username=testuser&password=wrong" \
    -H "X-Forwarded-For: 192.168.1.100" \
    -H "Content-Type: application/x-www-form-urlencoded" > /dev/null
  sleep 1
done

# Try 6th from IP1 (should be blocked)
echo "[2] 6th attempt from IP1 (should be BLOCKED)..."
RESPONSE_IP1=$(curl -s -w "%{http_code}" -X POST \
  "http://${TARGET_HOST}${LOGIN_ENDPOINT}" \
  -d "username=testuser&password=wrong" \
  -H "X-Forwarded-For: 192.168.1.100" \
  -H "Content-Type: application/x-www-form-urlencoded" | tail -c 3)

# Try from IP2 with only 1 failed attempt (should succeed)
echo "[3] 1st attempt from IP2 (192.168.1.101) - should NOT be blocked..."
RESPONSE_IP2=$(curl -s -w "%{http_code}" -X POST \
  "http://${TARGET_HOST}${LOGIN_ENDPOINT}" \
  -d "username=testuser&password=wrong" \
  -H "X-Forwarded-For: 192.168.1.101" \
  -H "Content-Type: application/x-www-form-urlencoded" | tail -c 3)

# Try from IP3 with only 2 failed attempts (should succeed)
echo "[4] 2nd attempt from IP3 (192.168.1.102) - should NOT be blocked..."
RESPONSE_IP3=$(curl -s -w "%{http_code}" -X POST \
  "http://${TARGET_HOST}${LOGIN_ENDPOINT}" \
  -d "username=testuser&password=wrong" \
  -H "X-Forwarded-For: 192.168.1.102" \
  -H "Content-Type: application/x-www-form-urlencoded" | tail -c 3)

echo ""
echo "[Results]"
echo "IP1 (5 failed + 6th attempt): $RESPONSE_IP1 (expected: 429)"
echo "IP2 (1st attempt): $RESPONSE_IP2 (expected: NOT 429)"
echo "IP3 (2nd attempt): $RESPONSE_IP3 (expected: NOT 429)"

if [[ "$RESPONSE_IP1" == "429" && "$RESPONSE_IP2" != "429" && "$RESPONSE_IP3" != "429" ]]; then
  echo "[✓] PASS: Independent IP tracking working correctly"
else
  echo "[✗] FAIL: IP tracking not independent"
fi
```

### Expected Results

| IP Address | Attempts | 6th Request Status | Blocked? | Result |
|------------|----------|-------------------|----------|--------|
| 192.168.1.100 | 5 failed + 1 | HTTP 429 | YES | ✓ |
| 192.168.1.101 | 1 failed | NOT 429 | NO | ✓ |
| 192.168.1.102 | 2 failed | NOT 429 | NO | ✓ |

---

## ✅ Test Case 5: Username Logging Accuracy

### Objective
Verify that usernames from POST body are extracted and logged correctly for audit trail.

### Execution

```bash
#!/bin/bash
# Script: test_case_5.sh

TARGET_HOST="10.20.30.40"
LOGIN_ENDPOINT="/login"

echo "[*] Test: Username logging accuracy"
echo ""

# Attempt 1: Standard username
echo "[1] Sending attempt with username: admin"
curl -s -X POST "http://${TARGET_HOST}${LOGIN_ENDPOINT}" \
  -d "username=admin&password=wrong" \
  -H "Content-Type: application/x-www-form-urlencoded" > /dev/null

# Attempt 2: Username with special characters
echo "[2] Sending attempt with username: user+test@example.com"
curl -s -X POST "http://${TARGET_HOST}${LOGIN_ENDPOINT}" \
  -d "username=user%2Btest%40example.com&password=wrong" \
  -H "Content-Type: application/x-www-form-urlencoded" > /dev/null

# Attempt 3: URL-encoded username
echo "[3] Sending attempt with username: john doe (encoded)"
curl -s -X POST "http://${TARGET_HOST}${LOGIN_ENDPOINT}" \
  -d "username=john%20doe&password=wrong" \
  -H "Content-Type: application/x-www-form-urlencoded" > /dev/null

echo "[4] Checking ASM logs for correct username extraction..."
echo ""

# SSH to BIG-IP and check logs
ssh admin@<BIG_IP_HOST> \
  "tail -20 /var/log/asm" | grep "BRUTE_FORCE_EVENT"
```

### Expected ASM Log Output

```
BRUTE_FORCE_EVENT: Failed login attempt from IP 192.168.1.100 username admin attempt_count 1
BRUTE_FORCE_EVENT: Failed login attempt from IP 192.168.1.100 username user+test@example.com attempt_count 2
BRUTE_FORCE_EVENT: Failed login attempt from IP 192.168.1.100 username john doe attempt_count 3
```

---

## ✅ Test Case 6: Successful Login (No Blocking)

### Objective
Verify that successful logins (HTTP 200 or 302) do not increment the fail counter.

### Execution

```bash
#!/bin/bash
# Script: test_case_6.sh

TARGET_HOST="10.20.30.40"
LOGIN_ENDPOINT="/login"
VALID_USERNAME="testuser"
VALID_PASSWORD="correctpassword"

echo "[*] Test: Successful logins don't trigger blocking"
echo ""

# Send 4 failed attempts
echo "[1] Sending 4 failed attempts..."
for i in {1..4}; do
  curl -s -X POST "http://${TARGET_HOST}${LOGIN_ENDPOINT}" \
    -d "username=${VALID_USERNAME}&password=wrong${i}" \
    -H "Content-Type: application/x-www-form-urlencoded" > /dev/null
  sleep 1
done

# Send 5 successful logins
echo "[2] Sending 5 successful logins (counter should NOT increment)..."
for i in {1..5}; do
  RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
    "http://${TARGET_HOST}${LOGIN_ENDPOINT}" \
    -d "username=${VALID_USERNAME}&password=${VALID_PASSWORD}" \
    -H "Content-Type: application/x-www-form-urlencoded")
  
  HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
  echo "  [$i/5] Response: $HTTP_CODE"
  sleep 1
done

# Send 1 more failed attempt (should still be allowed, counter at 4, not 9)
echo "[3] Sending 1 more failed attempt (should be 5th fail, not blocked yet)..."
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
  "http://${TARGET_HOST}${LOGIN_ENDPOINT}" \
  -d "username=${VALID_USERNAME}&password=wrongagain" \
  -H "Content-Type: application/x-www-form-urlencoded")

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)

if [[ "$HTTP_CODE" != "429" ]]; then
  echo "[✓] PASS: Successful logins don't increment counter"
  echo "[✓] PASS: Counter remains at expected value"
else
  echo "[✗] FAIL: Counter incremented on successful login"
fi
```

### Expected Results
- Attempts 1-4: Failed (increments counter to 4)
- Attempts 5-9: Successful (counter stays at 4, not incremented)
- Attempt 10 (fail): Counter increments to 5, not blocked
- Attempt 11 (fail): HTTP 429 blocked

---

## 🔍 ASM Log Analysis

### Accessing Logs

```bash
# SSH to BIG-IP
ssh admin@<BIG_IP_HOST>

# Option 1: View last 100 lines
tail -100 /var/log/asm

# Option 2: Real-time stream
tail -f /var/log/asm

# Option 3: Filter for brute-force events
grep "BRUTE_FORCE" /var/log/asm

# Option 4: Count blocked IPs in last 24 hours
tail -n 86400 /var/log/asm | grep "BRUTE_FORCE_BLOCK" | \
  awk '{for(i=7;i<=NF;i++) if($i ~ /^IP/) {split($i,a,"="); print a[2]}}' | \
  sort | uniq -c | sort -rn
```

### Sample Log Entries

```
[Mar  8 14:32:45 bigip audit]: BRUTE_FORCE_EVENT: Failed login attempt from IP 192.168.1.100 username admin attempt_count 1
[Mar  8 14:32:46 bigip audit]: BRUTE_FORCE_EVENT: Failed login attempt from IP 192.168.1.100 username admin attempt_count 2
[Mar  8 14:32:47 bigip audit]: BRUTE_FORCE_EVENT: Failed login attempt from IP 192.168.1.100 username admin attempt_count 3
[Mar  8 14:32:48 bigip audit]: BRUTE_FORCE_EVENT: Failed login attempt from IP 192.168.1.100 username admin attempt_count 4
[Mar  8 14:32:49 bigip audit]: BRUTE_FORCE_EVENT: Failed login attempt from IP 192.168.1.100 username admin attempt_count 5
[Mar  8 14:32:50 bigip audit]: BRUTE_FORCE_BLOCK: IP 192.168.1.100 blocked for 900s. Failed attempts: 5, last username: admin
[Mar  8 14:32:51 bigip audit]: BRUTE_FORCE_BLOCKED_REQUEST: Blocked request from IP 192.168.1.100
```

---

## 📊 TMSH Data Table Inspection

### Viewing Current Data Table Entries

```bash
# SSH to BIG-IP
ssh admin@<BIG_IP_HOST>
tmsh

# List all brute-force tracking entries
list ltm data-table brute_force*

# Expected output:
# ltm data-table brute_force:192.168.1.100 {
#     value BLOCKED
# }
```

### Clearing Data Table (For Testing)

```bash
tmsh

# Delete all brute-force entries
delete ltm data-table brute_force*

# Verify cleared
list ltm data-table brute_force*

# Exit
quit
```

---

## ✅ Comprehensive Test Summary

### Test Execution Checklist

```
[ ] Test Case 1: Block after 5 failed attempts
    ├─ [✓ or ✗] Attempts 1-5 logged
    ├─ [✓ or ✗] Attempt 6 returns HTTP 429
    └─ [✓ or ✗] Response includes "Too many attempts" message

[ ] Test Case 2: Block expires after 15 minutes
    ├─ [✓ or ✗] IP blocked during window
    ├─ [✓ or ✗] IP unblocked after wait
    └─ [✓ or ✗] Can login again post-expiration

[ ] Test Case 3: Time window resets after 5 minutes
    ├─ [✓ or ✗] 2 attempts within window
    ├─ [✓ or ✗] Reset after window expiration
    └─ [✓ or ✗] New fresh attempt cycle

[ ] Test Case 4: Per-IP independent tracking
    ├─ [✓ or ✗] IP1 blocked at 5 attempts
    ├─ [✓ or ✗] IP2 not blocked (fewer attempts)
    └─ [✓ or ✗] IP3 not blocked (fewer attempts)

[ ] Test Case 5: Username logging accuracy
    ├─ [✓ or ✗] Standard usernames logged
    ├─ [✓ or ✗] Special characters preserved
    └─ [✓ or ✗] URL encoding handled

[ ] Test Case 6: Successful logins don't count
    ├─ [✓ or ✗] Successful = No counter increment
    ├─ [✓ or ✗] Failed count remains accurate
    └─ [✓ or ✗] Block threshold still respected
```

---

## 📈 Production Monitoring Queries

### Daily Blocked IP Report

```bash
#!/bin/bash
# Script: daily_brute_force_report.sh

echo "=== Brute-Force Protection Daily Report ==="
echo "Date: $(date)"
echo ""

ssh admin@<BIG_IP_HOST> \
  "grep 'BRUTE_FORCE_BLOCK' /var/log/asm | \
   awk -F'IP ' '{print $2}' | awk '{print $1}' | \
   sort | uniq -c | sort -rn" \
   > brute_force_report_$(date +%Y%m%d).txt

echo "[✓] Report saved to brute_force_report_$(date +%Y%m%d).txt"
```

---

**Test Suite Version**: 1.0 | **Last Updated**: March 2026
