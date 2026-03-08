# Scenario 5: Apache Struts File Upload - Test Results

## 🧪 Test Suite

### ✅ Test 1: Block Executable File Upload

```bash
#!/bin/bash
TARGET="http://target.com/upload"

echo "[Test 1] Block .EXE File Upload"
echo "================================"

# Create fake EXE file
echo "MZ" > malware.exe

RESPONSE=$(curl -s -w "\n%{http_code}" -F "file=@malware.exe" "$TARGET")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)

if [[ "$HTTP_CODE" == "400" ]]; then
  echo "[✓] PASS: Executable blocked (HTTP 400)"
else
  echo "[✗] FAIL: Expected 400, got $HTTP_CODE"
fi
```

### ✅ Test 2: Block Shell Script Upload

```bash
# Create shell script
cat > shell.sh << 'EOF'
#!/bin/bash
rm -rf /
EOF

curl -F "file=@shell.sh" "$TARGET"

# Expected: HTTP 400 Bad Request
# Log Entry: "Blocked file extension: sh"
```

### ✅ Test 3: Block JSP File Upload

```bash
# Create JSP file
cat > exploit.jsp << 'EOF'
<% Runtime.getRuntime().exec("id"); %>
EOF

curl -F "file=@exploit.jsp" "$TARGET"

# Expected: HTTP 400 Bad Request
# Message: "File type .jsp not permitted"
```

### ✅ Test 4: Block Oversized Upload

```bash
# Create 15MB file (exceeds 10MB limit)
dd if=/dev/zero of=large.jpg bs=1M count=15

curl -F "file=@large.jpg" "$TARGET"

# Expected: HTTP 413 Payload Too Large
# Header: X-Max-Size: 10485760
```

### ✅ Test 5: Block Path Traversal

```bash
# Attempt to write outside upload directory
curl -F "file=@image.jpg;filename=../../etc/passwd" "$TARGET"

# Expected: HTTP 400 Bad Request
# Log: "Suspicious filename pattern"
```

### ✅ Test 6: Block OGNL in Upload Payload

```bash
# Create file with OGNL injection payload
cat > payload.zip << 'EOF'
(%23_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)
EOF

curl -F "file=@payload.zip" "$TARGET"

# Expected: HTTP 400 Bad Request
# Log: "OGNL pattern detected in upload"
```

### ✅ Test 7: Block Dangerous Content-Type

```bash
# Upload with suspicious Content-Type
curl -F "file=@data.sh;type=text/x-shellscript" "$TARGET"

# Expected: HTTP 400 Bad Request
# Log: "Dangerous Content-Type detected"
```

### ✅ Test 8: Allow Legitimate Image Upload

```bash
# Create valid JPEG
echo "JPEG_DATA" > photo.jpg

RESPONSE=$(curl -s -w "\n%{http_code}" -F "file=@photo.jpg" "$TARGET")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)

if [[ "$HTTP_CODE" != "400" && "$HTTP_CODE" != "413" ]]; then
  echo "[✓] PASS: Legitimate image allowed (HTTP $HTTP_CODE)"
else
  echo "[✗] FAIL: Legitimate upload was blocked"
fi
```

### ✅ Test 9: Allow PDF Upload

```bash
# Create minimal PDF
echo "%PDF-1.4" > document.pdf

curl -F "file=@document.pdf" "$TARGET"

# Expected: HTTP 200 OK
# Log: "FILE_UPLOAD_ALLOWED"
```

### ✅ Test 10: Content-Type Mismatch Detection

```bash
# Upload JPG file with PDF Content-Type
echo "FAKE_CONTENT" > notapdf.jpg

curl -F "file=@notapdf.jpg;type=application/pdf" "$TARGET"

# Expected: HTTP 400 Bad Request (if strict validation enabled)
# Depends on ENFORCE_CONTENT_TYPE setting
```

---

## 📊 Detection Coverage

| Attack Vector | Pattern | Detection | Log Entry |
|---------------|---------|-----------|-----------|
| Shell Upload | `.sh` extension | ✓ | FILE_UPLOAD_BLOCKED_EXT |
| JSP Upload | `.jsp` extension | ✓ | FILE_UPLOAD_BLOCKED_EXT |
| EXE Upload | `.exe` extension | ✓ | FILE_UPLOAD_BLOCKED_EXT |
| Path Traversal | `../` in filename | ✓ | FILE_UPLOAD_SUSPICIOUS |
| OGNL in Upload | `(%23_memberAccess` | ✓ | FILE_UPLOAD_OGNL |
| Oversized Upload | > 10MB | ✓ | FILE_UPLOAD_TOO_LARGE |
| Dangerous Type | `text/x-shellscript` | ✓ | FILE_UPLOAD_DANGEROUS_CT |

---

## 🔍 ASM Log Analysis

```bash
ssh admin@<BIG_IP_HOST>
tail -f /var/log/asm | grep "FILE_UPLOAD"

# Expected outputs:
# FILE_UPLOAD_REQUEST: IP=192.168.1.100 Filename=photo.jpg Extension=jpg
# FILE_UPLOAD_BLOCKED_EXT: Blocked file extension: exe from 203.0.113.45
# FILE_UPLOAD_TOO_LARGE: Upload exceeds max size: 15728640 bytes
# FILE_UPLOAD_OGNL: OGNL pattern detected in upload
# FILE_UPLOAD_ALLOWED: File upload allowed from 192.168.1.100: photo.jpg
```

---

## ✅ Test Checklist

- [ ] .jsp files blocked
- [ ] .exe files blocked
- [ ] .sh files blocked
- [ ] .asp files blocked
- [ ] Oversized files rejected (HTTP 413)
- [ ] Path traversal blocked
- [ ] OGNL patterns in uploads detected
- [ ] Dangerous Content-Types blocked
- [ ] Legitimate image uploads allowed
- [ ] PDF uploads allowed
- [ ] ASM logs contain upload details
- [ ] File extension logged for each upload
- [ ] Performance <2ms verified
- [ ] False positive rate: 0%

---

**Test Suite Version**: 1.0 | **TMOS**: 17.5.x+
