# Scenario 4: Apache Struts OGNL Injection - Test Results

## 🧪 Test Suite

### ✅ Test 1: Content-Type OGNL Injection

```bash
#!/bin/bash
TARGET="http://target.com/app"

echo "[Test 1] Content-Type Header OGNL Injection (CVE-2017-5638)"
echo "=========================================================="

# Actual CVE-2017-5638 exploit payload
PAYLOAD="%{(#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(@java.lang.Runtime@getRuntime().exec('id'))}"

curl -v -X POST "$TARGET" \
  -H "Content-Type: multipart/form-data; ${PAYLOAD}"

# Expected: HTTP 403 Forbidden with X-Violation header
```

### ✅ Test 2: Parameter-Based OGNL

```bash
# OGNL expression in POST parameter
curl -X POST "http://target.com/upload" \
  -d "data=(%23_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)"

# Expected: HTTP 403 Forbidden
```

### ✅ Test 3: URL-Encoded OGNL

```bash
# URL-encoded OGNL pattern
curl -v "http://target.com/app?file=%25%7B%28%23_memberAccess"

# Expected: HTTP 403 Forbidden
```

### ✅ Test 4: Command Execution Pattern

```bash
# Command execution via OGNL
curl -X POST "http://target.com/action" \
  -d "cmd=(%23iswin=@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))"

# Expected: HTTP 403 Forbidden
```

### ✅ Test 5: Legitimate Requests (No False Positives)

```bash
# Normal Struts form submission
curl -X POST "http://target.com/user/register" \
  -d "username=john&email=john@example.com&message=Hello#World"

# Expected: HTTP 200 OK (allowed)
```

---

## 📊 Detection Coverage

| CVE Component | Pattern | Detection | Log Entry |
|--------------|---------|-----------|-----------|
| Member Access | `%23_memberAccess` | ✓ | OGNL_INJECTION_ATTEMPT |
| Runtime Execution | `@java.lang.Runtime` | ✓ | OGNL_INJECTION_ATTEMPT |
| Context Access | `(%23_context` | ✓ | OGNL_INJECTION_ATTEMPT |
| Encoded Bypass | `%23` + patterns | ✓ | OGNL_INJECTION_ATTEMPT |

---

## 🔍 ASM Log Analysis

```bash
ssh admin@<BIG_IP_HOST>
tail -f /var/log/asm | grep "OGNL_"

# Expected output:
# OGNL_INJECTION_ATTEMPT: Client=203.0.113.45 Method=POST URI=/app Location=header:Content-Type Pattern=%23_memberAccess CVE=CVE-2017-5638
# OGNL_BLOCKED: IP 203.0.113.45 blocked for OGNL injection
```

---

## ✅ Test Checklist

- [ ] Content-Type header OGNL blocked
- [ ] Parameter-based OGNL blocked
- [ ] URL-encoded variants detected
- [ ] Command execution patterns blocked
- [ ] Legitimate traffic allowed
- [ ] ASM logs contain CVE reference
- [ ] Response includes X-CVE header
- [ ] Performance <1ms overhead verified

---

**Test Suite Version**: 1.0 | **TMOS**: 17.5.x+
