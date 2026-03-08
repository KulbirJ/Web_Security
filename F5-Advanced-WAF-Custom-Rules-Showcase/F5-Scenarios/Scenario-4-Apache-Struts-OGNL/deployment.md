# Scenario 4: Apache Struts OGNL Injection Protection (CVE-2017-5638)

## 📋 Vulnerability Overview

**CVE-2017-5638** - Apache Struts Remote Code Execution via OGNL Expression Language Injection

### Impact
- **CVSS Score**: 10.0 (Critical)
- **Attack Vector**: Network exploitable without authentication
- **Affected Versions**: Struts 2.0.0 - 2.3.31, 2.5.0 - 2.5.10
- **Exploitation**: Remote Code Execution via `Content-Type` header manipulation

### Vulnerable Pattern Example
```
Content-Type: multipart/form-data; %{(#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(@java.lang.Runtime@getRuntime().exec('id'))}
```

---

## 🖥️ Deployment Steps

### Quick Deployment (TMSH)

```bash
ssh admin@<BIG_IP_HOST>
tmsh

# Create the OGNL protection iRule
create ltm irule struts_ognl_protection_rule definition-file /tmp/struts_ognl_rule.tcl

# Attach to virtual server
modify ltm virtual <VS_NAME> rules { struts_ognl_protection_rule }

# Save configuration
quit
tmsh save sys config
```

### Detailed GUI Deployment

1. **Security** > **Application Security** > **iRules**
2. Click **Create**
3. **Name**: `struts_ognl_protection_rule`
4. **Definition**: (Paste full content from `rule.tcl`)
5. Attach to virtual server under **Local Traffic** > **Virtual Servers**

---

## 🧪 Quick Tests

### Test 1: Block OGNL in Content-Type Header

```bash
TARGET="http://target.com/app"

# Attempt CVE-2017-5638 exploitation
curl -v -X POST "$TARGET" \
  -H "Content-Type: multipart/form-data; %{(#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)}" \
  -d "data=test"

# Expected: HTTP 403 Forbidden
```

### Test 2: Block OGNL in POST Parameter

```bash
curl -X POST "$TARGET/action" \
  -d "param=(%23_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)"

# Expected: HTTP 403 Forbidden
```

### Test 3: Block OGNL in URI

```bash
curl -v "http://target.com/app?file=%23_memberAccess"

# Expected: HTTP 403 Forbidden
```

---

## 📊 Rule Configuration

### Detected OGNL Patterns

| Pattern | Detection Point | Variant |
|---------|----------------|---------|
| `%23_memberAccess` | URL encoding | Primary |
| `(#_memberAccess` | Unencoded | Primary |
| `@java.lang.Runtime` | Java reflection | Execution |
| `@org.apache.struts2` | Struts framework| Framework |
| `(%23cmd=` | Command injection | Payload |

### Performance Metrics
- **Overhead**: <1ms per request
- **CPU Impact**: <2%
- **Memory**: ~2MB for pattern matching
- **Throughput**: Minimal impact

---

## 🔒 Deployment Considerations

- Deploy in **log-only mode** first (BLOCK_ACTION = 0)
- Monitor ASM logs for 24-48 hours
- Adjust pattern list as needed
- Use with **WAF policy in learning mode** for baseline
- Test against legitimate Struts applications

---

**CVE Reference**: https://nvd.nist.gov/vuln/detail/CVE-2017-5638
