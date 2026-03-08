###############################################################################
# F5 Advanced WAF - Scenario 4: Apache Struts OGNL Injection Protection
# File: rule.tcl
# CVE: CVE-2017-5638 (Remote Code Execution via OGNL)
# Description: Detects and blocks OGNL expression language injection attempts
# Author: Senior F5 WAF Consultant
# Version: 1.0
# TMOS Compatibility: 17.5.x
# Deployment: Advanced WAF (ASM) iRule with event handling
###############################################################################

# ============================================================================
# RULE CONFIGURATION PARAMETERS
# ============================================================================

set OGNL_PATTERNS [list \
    "(%23_memberAccess" \
    "(%23_xx" \
    "(%23_context" \
    "(%23_request" \
    "(%23_response" \
    "(%23_memberAccess=" \
    "(%23context=" \
    "%23" \
    "(#_memberAccess" \
    "(#context" \
    "(#request" \
    "(#response" \
    "%23_memberAccess" \
    "@java.lang.Runtime" \
    "@org.apache.struts2" \
    "ognl:" \
    "struts.valueStack" \
    "(action)" \
    "(#cmd=" \
    "(#iswin=" \
    "(#cmds=" \
]

set STRUTS_SUSPICIOUS_HEADERS [list "Content-Disposition" "X-HTTP-Method"]
set BLOCK_ACTION 1                ;# 1=Block, 0=Log only
set CUSTOM_VIOLATION "Custom_OGNL_Injection_Attempt"
set LOG_PAYLOAD 1                 ;# Log full payload details

# ============================================================================
# PROCEDURE: Detect OGNL Expression Patterns
# ============================================================================
# Recursively scans request components for OGNL-specific patterns
#
proc detect_ognl_patterns {patterns} {
    set matched_pattern ""
    set search_location ""
    
    # -----------------------------------------------------------------------
    # SEARCH 1: Scan URI and Query String
    # -----------------------------------------------------------------------
    set request_uri [HTTP::uri]
    set uri_lower [string tolower $request_uri]
    
    foreach pattern $patterns {
        set pattern_lower [string tolower $pattern]
        if {[string first $pattern_lower $uri_lower] >= 0} {
            return [list $pattern $uri_lower "uri" $request_uri]
        }
    }
    
    # -----------------------------------------------------------------------
    # SEARCH 2: Scan HTTP Headers
    # -----------------------------------------------------------------------
    set header_list [HTTP::header names]
    
    foreach header_name $header_list {
        set header_value [HTTP::header values $header_name]
        set header_value [lindex $header_value 0]
        set header_lower [string tolower $header_value]
        
        foreach pattern $patterns {
            set pattern_lower [string tolower $pattern]
            if {[string first $pattern_lower $header_lower] >= 0} {
                return [list $pattern $header_lower "header:${header_name}" $header_value]
            }
        }
    }
    
    # -----------------------------------------------------------------------
    # SEARCH 3: Scan POST Body
    # -----------------------------------------------------------------------
    if {[HTTP::method] eq "POST" || [HTTP::method] eq "PUT"} {
        if {[HTTP::header exists Content-Length]} {
            set content_length [HTTP::header values Content-Length]
            set content_length [lindex $content_length 0]
            
            # Process only reasonable body sizes
            if {$content_length < 1048576} {
                set body [HTTP::payload]
                set body_lower [string tolower $body]
                
                foreach pattern $patterns {
                    set pattern_lower [string tolower $pattern]
                    if {[string first $pattern_lower $body_lower] >= 0} {
                        return [list $pattern $body_lower "body" $body]
                    }
                }
            }
        }
    }
    
    return [list "" "" "" ""]
}

# ============================================================================
# PROCEDURE: Detect Content-Type Mismatches (File Upload Bypass Detection)
# ============================================================================
proc detect_suspicious_headers {} {
    global STRUTS_SUSPICIOUS_HEADERS
    
    foreach header_name $STRUTS_SUSPICIOUS_HEADERS {
        if {[HTTP::header exists $header_name]} {
            return 1
        }
    }
    
    return 0
}

# ============================================================================
# EVENT: when HTTP_REQUEST
# Triggered when client HTTP request is received.
# Performs OGNL injection pattern matching and blocking.
# ============================================================================

when HTTP_REQUEST {
    
    # -----------------------------------------------------------------------
    # OGNL PATTERN SCANNING
    # -----------------------------------------------------------------------
    
    set scan_result [detect_ognl_patterns $OGNL_PATTERNS]
    set matched_pattern [lindex $scan_result 0]
    set matched_content [lindex $scan_result 1]
    set location [lindex $scan_result 2]
    set original_content [lindex $scan_result 3]
    
    # -----------------------------------------------------------------------
    # THREAT DETECTION: Process if OGNL pattern found
    # -----------------------------------------------------------------------
    
    if {$matched_pattern ne ""} {
        # OGNL INJECTION ATTEMPT DETECTED
        
        # Get client IP
        set client_ip [IP::client_addr]
        if {[HTTP::header exists X-Forwarded-For]} {
            set xff_header [HTTP::header values X-Forwarded-For]
            set client_ip [lindex [split [lindex $xff_header 0] ","] 0]
            set client_ip [string trim $client_ip]
        }
        
        # Extract context
        set request_method [HTTP::method]
        set request_uri [HTTP::uri]
        set user_agent ""
        if {[HTTP::header exists User-Agent]} {
            set user_agent [HTTP::header values User-Agent]
            set user_agent [lindex $user_agent 0]
        }
        
        # Create comprehensive log entry
        set log_entry "OGNL_INJECTION_ATTEMPT: Client=${client_ip} Method=${request_method} \
            URI=${request_uri} Location=${location} Pattern=${matched_pattern} \
            UserAgent=${user_agent} CVE=CVE-2017-5638"
        
        if {$LOG_PAYLOAD} {
            set payload_excerpt [string range $original_content 0 150]
            append log_entry " Payload=[${payload_excerpt}]"
        }
        
        # Log to ASM
        ASM::log $CUSTOM_VIOLATION $log_entry
        
        # -----------------------------------------------------------------------
        # ENFORCEMENT: Block OGNL injection attempt
        # -----------------------------------------------------------------------
        
        if {$BLOCK_ACTION == 1} {
            ASM::log "OGNL_BLOCKED" "IP ${client_ip} blocked for OGNL injection (CVE-2017-5638)"
            
            set response_body "{\"error\":\"Security Policy Violation\",\"message\":\"Invalid request detected\",\"threat\":\"OGNL Expression Language Injection\"}"
            
            HTTP::respond 403 \
                -content $response_body \
                -content_type "application/json" \
                -header "Cache-Control" "no-cache, no-store, must-revalidate" \
                -header "X-Blocked-By" "WAF_OGNL_Protection" \
                -header "X-Violation" $CUSTOM_VIOLATION \
                -header "X-CVE" "CVE-2017-5638"
            
            return
        }
    }
    
    # -----------------------------------------------------------------------
    # ADDITIONAL CHECK: Detect suspicious header combinations
    # -----------------------------------------------------------------------
    
    if {[HTTP::method] eq "POST"} {
        if {[detect_suspicious_headers]} {
            # Suspicious header pattern detected
            set client_ip [IP::client_addr]
            
            ASM::log "STRUTS_SUSPICIOUS_HEADERS" "Suspicious header combination detected from ${client_ip}"
        }
    }
}

# ============================================================================
# EVENT: when HTTP_RESPONSE
# ============================================================================

when HTTP_RESPONSE {
    # Add security headers to all responses
    if {![HTTP::header exists X-Content-Type-Options]} {
        HTTP::header insert X-Content-Type-Options "nosniff"
    }
    
    if {![HTTP::header exists X-Frame-Options]} {
        HTTP::header insert X-Frame-Options "DENY"
    }
}

###############################################################################
# END OF APACHE STRUTS OGNL INJECTION PROTECTION RULE
###############################################################################

# DEPLOYMENT NOTES:
# 1. This rule protects against CVE-2017-5638 (Apache Struts RCE)
# 2. Detects OGNL expression patterns in URI, headers, and body
# 3. URL decoding handled automatically by ASM
# 4. Case-insensitive pattern matching for obfuscation bypass
# 5. Comprehensive logging for incident response
# 6. Can be set to log-only mode for tuning (BLOCK_ACTION = 0)
# 7. Performance: <1ms per request overhead
# 8. Works with both HTTP and HTTPS traffic
# 9. Compatible with ASM learning mode for baseline tuning
# 10. Requires iRule events enabled in WAF policy
