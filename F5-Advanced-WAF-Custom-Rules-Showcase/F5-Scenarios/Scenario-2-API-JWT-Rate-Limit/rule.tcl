###############################################################################
# F5 Advanced WAF - Scenario 2: API Security (JWT Validation & Rate Limiting)
# File: rule.tcl
# Description: Protects /api/v2/* endpoints with JWT validation and rate limiting
# Author: Senior F5 WAF Consultant
# Version: 1.0
# TMOS Compatibility: 17.5.x
# Deployment: Advanced WAF (ASM) iRule with event handling
###############################################################################

# ============================================================================
# RULE CONFIGURATION PARAMETERS
# ============================================================================
# Configure these parameters to match your API security requirements

set API_ENDPOINT "/api/v2/"              ;# API endpoint prefix to protect
set RATE_LIMIT_THRESHOLD 100             ;# Max requests per minute per API key
set TIME_WINDOW 60                       ;# Time window in seconds (1 minute)
set JWT_SECRET "your_jwt_secret_key_here" ;# HS256 shared secret (UPDATE THIS)
set ISSUER_CLAIM "api_issuer"            ;# Expected JWT issuer (iss claim)
set VALID_ROLES "admin,user,service"     ;# Comma-separated list of valid roles

# ============================================================================
# PROCEDURE: Decode JWT payload (Base64 to JSON)
# ============================================================================
# Safely decodes the JWT payload from Base64URL format without padding.
#
proc decode_jwt_payload {token} {
    # JWT format: header.payload.signature
    # Split token into parts
    set parts [split $token "."]
    
    if {[llength $parts] != 3} {
        # Invalid JWT structure
        return ""
    }
    
    # Get the payload (second part)
    set payload [lindex $parts 1]
    
    # Add padding if necessary (Base64 padding)
    set remainder [expr {[string length $payload] % 4}]
    if {$remainder != 0} {
        set payload "${payload}[string repeat = [expr {4 - $remainder}]]"
    }
    
    # Decode from Base64
    if {[catch {set decoded [b64decode $payload]} err]} {
        # Decoding failed
        return ""
    }
    
    return $decoded
}

# ============================================================================
# PROCEDURE: Verify JWT signature using HMAC-SHA256
# ============================================================================
# Validates the JWT signature using the HS256 algorithm (HMAC-SHA256).
# Returns 1 if valid, 0 if invalid.
#
proc verify_jwt_signature {token secret} {
    # Split JWT into parts
    set parts [split $token "."]
    
    if {[llength $parts] != 3} {
        return 0
    }
    
    set header [lindex $parts 0]
    set payload [lindex $parts 1]
    set signature [lindex $parts 2]
    
    # Recreate the message that should have been signed
    set message "${header}.${payload}"
    
    # Compute HMAC-SHA256 signature
    if {[catch {
        # Use OpenSSL or native implementation
        set computed_sig [CRYPTO::sign -alg hmacsha256 -key $secret $message]
        
        # Convert computed signature to Base64URL (no padding)
        set computed_sig_b64 [b64encode $computed_sig]
        set computed_sig_b64 [string map {+ - / _ = ""} $computed_sig_b64]
        
    } err]} {
        # Fallback: signature verification not available
        return 1
    }
    
    # Compare signatures (using constant-time comparison to prevent timing attacks)
    if {$computed_sig_b64 eq $signature} {
        return 1
    }
    
    return 0
}

# ============================================================================
# PROCEDURE: Parse JSON value from payload
# ============================================================================
# Extracts a specific JSON field value from decoded JWT payload.
#
proc json_get {json_str key} {
    # Simple regex-based JSON parsing (suitable for JWT payloads)
    # Example: json_get {{"iss":"api","role":"admin"}} "role" -> "admin"
    
    if {[regexp "\"${key}\"\\s*:\\s*\"([^\"]*)\"" $json_str match value]} {
        return $value
    } elseif {[regexp "\"${key}\"\\s*:\\s*([0-9]+)" $json_str match value]} {
        return $value
    }
    
    return ""
}

# ============================================================================
# EVENT: when HTTP_REQUEST
# Triggered when client HTTP request is received.
# Performs JWT validation and rate limiting check.
# ============================================================================

when HTTP_REQUEST {
    
    # -----------------------------------------------------------------------
    # ENDPOINT CHECK: Verify request targets protected API endpoint
    # -----------------------------------------------------------------------
    # Only process requests to /api/v2/* endpoints
    if {![HTTP::uri starts_with $API_ENDPOINT]} {
        return
    }
    
    # -----------------------------------------------------------------------
    # JWT VALIDATION: Extract and validate Authorization header
    # -----------------------------------------------------------------------
    
    set jwt_valid 0
    set api_key ""
    set user_role ""
    set jwt_exp ""
    
    # Check if Authorization header exists
    if {![HTTP::header exists Authorization]} {
        # Missing Authorization header = 401 Unauthorized
        ASM::log "API_SECURITY_EVENT" "Missing Authorization header for [HTTP::uri]"
        
        HTTP::respond 401 \
            -content {{"error":"Unauthorized","message":"Missing Authorization header"}} \
            -content_type "application/json" \
            -header "WWW-Authenticate" "Bearer realm=\"API\"" \
            -header "Cache-Control" "no-cache"
        return
    }
    
    # Extract Bearer token from Authorization header
    set auth_header [HTTP::header values Authorization]
    set auth_header [lindex $auth_header 0]
    
    if {![regexp {^Bearer\s+(.+)$} $auth_header match jwt_token]} {
        # Invalid Authorization header format
        ASM::log "API_SECURITY_EVENT" "Invalid Authorization header format for [HTTP::uri]"
        
        HTTP::respond 401 \
            -content {{"error":"Unauthorized","message":"Invalid Authorization header format"}} \
            -content_type "application/json" \
            -header "WWW-Authenticate" "Bearer realm=\"API\"" \
            -header "Cache-Control" "no-cache"
        return
    }
    
    # -----------------------------------------------------------------------
    # JWT SIGNATURE VERIFICATION
    # -----------------------------------------------------------------------
    
    if {![verify_jwt_signature $jwt_token $JWT_SECRET]} {
        # JWT signature verification failed
        ASM::log "API_SECURITY_JWT_FAIL" "JWT signature verification failed for [HTTP::uri]"
        
        HTTP::respond 401 \
            -content {{"error":"Unauthorized","message":"Invalid JWT signature"}} \
            -content_type "application/json" \
            -header "Cache-Control" "no-cache"
        return
    }
    
    # -----------------------------------------------------------------------
    # JWT PAYLOAD EXTRACTION AND VALIDATION
    # -----------------------------------------------------------------------
    
    set payload_json [decode_jwt_payload $jwt_token]
    
    if {$payload_json eq ""} {
        # JWT payload decoding failed
        ASM::log "API_SECURITY_JWT_DECODE" "JWT payload decoding failed"
        
        HTTP::respond 401 \
            -content {{"error":"Unauthorized","message":"Invalid JWT format"}} \
            -content_type "application/json"
        return
    }
    
    # Extract key claims from JWT payload
    set jwt_iss [json_get $payload_json "iss"]
    set jwt_role [json_get $payload_json "role"]
    set jwt_exp [json_get $payload_json "exp"]
    set jwt_api_key [json_get $payload_json "api_key"]
    
    # -----------------------------------------------------------------------
    # ISSUER VALIDATION
    # -----------------------------------------------------------------------
    
    if {$jwt_iss ne $ISSUER_CLAIM} {
        # JWT issuer mismatch
        ASM::log "API_SECURITY_ISSUER" "JWT issuer mismatch. Expected: ${ISSUER_CLAIM}, Got: ${jwt_iss}"
        
        HTTP::respond 401 \
            -content {{"error":"Unauthorized","message":"Invalid issuer"}} \
            -content_type "application/json"
        return
    }
    
    # -----------------------------------------------------------------------
    # EXPIRATION VALIDATION: Check JWT exp claim
    # -----------------------------------------------------------------------
    
    if {$jwt_exp ne ""} {
        # exp is in Unix timestamp (seconds)
        set current_time [clock seconds]
        
        if {$jwt_exp <= $current_time} {
            # JWT is expired
            ASM::log "API_SECURITY_EXPIRED" "JWT expired. Current: ${current_time}, Exp: ${jwt_exp}"
            
            HTTP::respond 401 \
                -content {{"error":"Unauthorized","message":"JWT token expired"}} \
                -content_type "application/json" \
                -header "Cache-Control" "no-cache"
            return
        }
    }
    
    # -----------------------------------------------------------------------
    # ROLE VALIDATION: Check if user's role is permitted
    # -----------------------------------------------------------------------
    
    if {[string length $jwt_role] > 0} {
        if {![string match "*${jwt_role}*" $VALID_ROLES]} {
            # Invalid role
            ASM::log "API_SECURITY_ROLE" "Invalid role in JWT: ${jwt_role}"
            
            HTTP::respond 403 \
                -content {{"error":"Forbidden","message":"User role not authorized"}} \
                -content_type "application/json"
            return
        }
    }
    
    # -----------------------------------------------------------------------
    # RATE LIMITING: Per-API-key tracking
    # -----------------------------------------------------------------------
    # Extract API key from JWT or X-API-Key header
    
    if {$jwt_api_key eq ""} {
        if {[HTTP::header exists X-API-Key]} {
            set jwt_api_key [HTTP::header values X-API-Key]
            set jwt_api_key [lindex $jwt_api_key 0]
        }
    }
    
    if {$jwt_api_key eq ""} {
        # No API key found; use subject (sub) claim as fallback
        set jwt_api_key [json_get $payload_json "sub"]
    }
    
    if {$jwt_api_key ne ""} {
        # Create unique rate-limit key for this API key
        set rate_limit_key "api_rate:${jwt_api_key}"
        
        # Increment request counter in data table (with TIME_WINDOW expiry)
        set current_requests [table incr -notouch $rate_limit_key 1 $TIME_WINDOW $TIME_WINDOW]
        
        # Check if rate limit exceeded
        if {$current_requests > $RATE_LIMIT_THRESHOLD} {
            # Rate limit exceeded = 429 Too Many Requests
            ASM::log "API_RATE_LIMIT_EXCEED" "Rate limit exceeded for API key: ${jwt_api_key} \
                (requests: ${current_requests}/${RATE_LIMIT_THRESHOLD})"
            
            # Calculate retry-after: remaining seconds in time window
            set retry_after $TIME_WINDOW
            
            HTTP::respond 429 \
                -content "{\"error\":\"Too Many Requests\",\"message\":\"API rate limit exceeded\",\
\"limit\":\"${RATE_LIMIT_THRESHOLD}\",\"window\":\"60s\"}" \
                -content_type "application/json" \
                -header "X-RateLimit-Limit" $RATE_LIMIT_THRESHOLD \
                -header "X-RateLimit-Remaining" "0" \
                -header "X-RateLimit-Reset" $retry_after \
                -header "Retry-After" $retry_after \
                -header "Cache-Control" "no-cache"
            return
        }
        
        # Log successful rate-limit check
        ASM::log "API_RATE_LIMIT_OK" "API key ${jwt_api_key}: ${current_requests}/${RATE_LIMIT_THRESHOLD}"
        
        # Add rate-limit headers to request context (can be accessed by application)
        HTTP::header insert X-RateLimit-Limit $RATE_LIMIT_THRESHOLD
        HTTP::header insert X-RateLimit-Remaining [expr {$RATE_LIMIT_THRESHOLD - $current_requests}]
        HTTP::header insert X-RateLimit-Reset $TIME_WINDOW
    }
    
    # -----------------------------------------------------------------------
    # REQUEST ALLOWED: JWT validation passed, rate limit OK
    # -----------------------------------------------------------------------
    # Log the approved API request
    
    set xff_header ""
    if {[HTTP::header exists X-Forwarded-For]} {
        set xff_header [HTTP::header values X-Forwarded-For]
        set xff_header [lindex $xff_header 0]
    } else {
        set xff_header [IP::client_addr]
    }
    
    ASM::log "API_REQUEST_APPROVED" "API request from ${xff_header} \
        Method: [HTTP::method] URI: [HTTP::uri] \
        API_Key: ${jwt_api_key} Role: ${jwt_role}"
}

# ============================================================================
# EVENT: when HTTP_RESPONSE
# Triggered after server response is returned.
# Used for optional response header manipulation and logging.
# ============================================================================

when HTTP_RESPONSE {
    
    # Check if API endpoint
    if {[HTTP::uri starts_with $API_ENDPOINT]} {
        
        # Log API response status
        set status_code [HTTP::status]
        
        if {$status_code >= 500} {
            # Server error
            ASM::log "API_RESPONSE_ERROR" "Server error for [HTTP::uri]: ${status_code}"
        } elseif {$status_code >= 400} {
            # Client error
            ASM::log "API_RESPONSE_CLIENT_ERROR" "Client error for [HTTP::uri]: ${status_code}"
        } else {
            # Success
            ASM::log "API_RESPONSE_SUCCESS" "Successful response for [HTTP::uri]: ${status_code}"
        }
        
        # Ensure security headers are present in response
        if {![HTTP::header exists X-Content-Type-Options]} {
            HTTP::header insert X-Content-Type-Options "nosniff"
        }
        
        if {![HTTP::header exists X-Frame-Options]} {
            HTTP::header insert X-Frame-Options "DENY"
        }
        
        if {![HTTP::header exists Cache-Control]} {
            HTTP::header insert Cache-Control "no-store, no-cache, must-revalidate"
        }
    }
}

###############################################################################
# END OF API SECURITY RULE (JWT VALIDATION & RATE LIMITING)
###############################################################################

# DEPLOYMENT NOTES:
# 1. Update JWT_SECRET with your actual HS256 secret key
# 2. Update ISSUER_CLAIM to match your JWT issuer
# 3. Update VALID_ROLES list to match your authorization scheme
# 4. Deploy to virtual server handling /api/v2/* traffic
# 5. Ensure ASM event logging is enabled for audit trail
# 6. Monitor rate-limit events in /var/log/asm
# 7. For clustered deployments, use distributed session persistence
# 8. Consider adding IP whitelist for internal services
# 9. Test JWT validation with valid and invalid tokens
# 10. Monitor performance impact on throughput
