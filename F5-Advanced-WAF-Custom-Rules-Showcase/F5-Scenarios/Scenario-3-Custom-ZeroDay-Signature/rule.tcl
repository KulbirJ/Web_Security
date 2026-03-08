###############################################################################
# F5 Advanced WAF - Scenario 3: Custom Zero-Day Signature (Log4Shell Pattern)
# File: rule.tcl
# Description: Detects and blocks JNDI injection patterns (Log4Shell-style)
# Author: Senior F5 WAF Consultant
# Version: 1.0
# TMOS Compatibility: 17.5.x
# Deployment: Advanced WAF (ASM) iRule with event handling
###############################################################################

# ============================================================================
# RULE CONFIGURATION PARAMETERS
# ============================================================================
# Configure detection patterns and response behavior

set JNDI_PATTERNS [list "jndi:ldap://" "jndi:rmi://" "jndi:nis://" "jndi:iiop://"]
set CUSTOM_VIOLATION_NAME "Custom_ZeroDay_Command_Injection"
set BLOCK_ACTION 1                ;# 1=Block, 0=Log only
set BLOCK_RESPONSE_JSON 1         ;# 1=JSON response, 0=HTML response
set LOG_PAYLOAD 1                 ;# 1=Log full payload, 0=Log match only

# ============================================================================
# PROCEDURE: Search Request for JNDI Patterns
# ============================================================================
# Recursively scans URI, headers, and body for malicious patterns.
# Returns matched string and search location (uri/header/body) if found.
#
proc scan_for_jndi_patterns {patterns} {
    global JNDI_PATTERNS
    
    set matched_pattern ""
    set search_location ""
    
    # -----------------------------------------------------------------------
    # SEARCH 1: Scan URI for JNDI patterns
    # -----------------------------------------------------------------------
    set request_uri [HTTP::uri]
    set uri_lower [string tolower $request_uri]
    
    foreach pattern $patterns {
        if {[string first $pattern $uri_lower] >= 0} {
            set matched_pattern $pattern
            set search_location "uri"
            return [list $matched_pattern $search_location $request_uri]
        }
    }
    
    # -----------------------------------------------------------------------
    # SEARCH 2: Scan HTTP Headers for JNDI patterns
    # -----------------------------------------------------------------------
    # Check all headers for suspicious patterns
    set header_list [HTTP::header names]
    
    foreach header_name $header_list {
        set header_value [HTTP::header values $header_name]
        set header_value [lindex $header_value 0]
        set header_lower [string tolower $header_value]
        
        foreach pattern $patterns {
            if {[string first $pattern $header_lower] >= 0} {
                set matched_pattern $pattern
                set search_location "header:${header_name}"
                return [list $matched_pattern $search_location $header_value]
            }
        }
    }
    
    # -----------------------------------------------------------------------
    # SEARCH 3: Scan request body for JNDI patterns
    # -----------------------------------------------------------------------
    # Check POST/PUT body content
    if {[HTTP::method] eq "POST" || [HTTP::method] eq "PUT"} {
        # Only process if Content-Length is reasonable (prevent DoS)
        if {[HTTP::header exists Content-Length]} {
            set content_length [HTTP::header values Content-Length]
            set content_length [lindex $content_length 0]
            
            # Only process bodies < 1MB to prevent performance impact
            if {$content_length < 1048576} {
                set body [HTTP::payload]
                set body_lower [string tolower $body]
                
                foreach pattern $patterns {
                    if {[string first $pattern $body_lower] >= 0} {
                        set matched_pattern $pattern
                        set search_location "body"
                        return [list $matched_pattern $search_location $body]
                    }
                }
            }
        }
    }
    
    # No patterns found
    return [list "" "" ""]
}

# ============================================================================
# PROCEDURE: Generate JSON error response
# ============================================================================
# Creates properly formatted JSON error for blocked requests.
#
proc generate_json_error {status_code message} {
    set timestamp [clock seconds]
    set json_response "{\"error\":{\"status\":\"${status_code}\",\"message\":\"${message}\",\"timestamp\":${timestamp}}}"
    return $json_response
}

# ============================================================================
# PROCEDURE: Generate HTML error response
# ============================================================================
# Creates HTML error page for blocked requests.
#
proc generate_html_error {title message} {
    set html "<html><head><title>${title}</title></head>"
    append html "<body style='font-family:Arial'><h1>${title}</h1>"
    append html "<p>${message}</p></body></html>"
    return $html
}

# ============================================================================
# EVENT: when HTTP_REQUEST
# Triggered when client HTTP request is received.
# Performs zero-day pattern matching and blocking.
# ============================================================================

when HTTP_REQUEST {
    
    # -----------------------------------------------------------------------
    # PATTERN SCANNING: Search all request components
    # -----------------------------------------------------------------------
    # The scan_for_jndi_patterns procedure returns:
    # [0] = matched pattern (string like "jndi:ldap://")
    # [1] = search location (uri, header:name, or body)
    # [2] = matched content (full header value or body excerpt)
    
    set scan_result [scan_for_jndi_patterns $JNDI_PATTERNS]
    set matched_string [lindex $scan_result 0]
    set location [lindex $scan_result 1]
    set matched_content [lindex $scan_result 2]
    
    # -----------------------------------------------------------------------
    # THREAT DETECTION: Process if pattern found
    # -----------------------------------------------------------------------
    
    if {$matched_string ne ""} {
        # MALICIOUS PATTERN DETECTED
        
        # Get client IP (accounting for proxies)
        set client_ip [IP::client_addr]
        if {[HTTP::header exists X-Forwarded-For]} {
            set xff_header [HTTP::header values X-Forwarded-For]
            set client_ip [lindex [split [lindex $xff_header 0] ","] 0]
            set client_ip [string trim $client_ip]
        }
        
        # -----------------------------------------------------------------------
        # LOGGING: Record full attack details to ASM
        # -----------------------------------------------------------------------
        
        # Extract request context
        set request_method [HTTP::method]
        set request_uri [HTTP::uri]
        set user_agent ""
        if {[HTTP::header exists User-Agent]} {
            set user_agent [HTTP::header values User-Agent]
            set user_agent [lindex $user_agent 0]
        }
        
        # Create log entry with full details
        set log_entry "CUSTOM_ZERODDAY_DETECTED: Client=${client_ip} Method=${request_method} \
            URI=${request_uri} Location=${location} Pattern=${matched_string} \
            UserAgent=${user_agent}"
        
        # Add payload excerpt to log (first 100 chars of matched content)
        if {$LOG_PAYLOAD} {
            set payload_excerpt [string range $matched_content 0 100]
            append log_entry " Payload=[${payload_excerpt}]"
        }
        
        # Log to ASM event system
        ASM::log $CUSTOM_VIOLATION_NAME $log_entry
        
        # -----------------------------------------------------------------------
        # ENFORCEMENT: Block or log-only based on configuration
        # -----------------------------------------------------------------------
        
        if {$BLOCK_ACTION == 1} {
            # BLOCKING ENABLED: Terminate request with error response
            
            # Log the blocking event
            ASM::log "CUSTOM_ZERODDAY_BLOCKED" "IP ${client_ip} blocked for JNDI injection pattern"
            
            # Prepare response content
            if {$BLOCK_RESPONSE_JSON} {
                # JSON response format
                set response_body [generate_json_error "403" "Request blocked by security policy"]
                set content_type "application/json"
            } else {
                # HTML response format
                set response_body [generate_html_error "Access Denied" "Your request has been blocked by the security system"]
                set content_type "text/html"
            }
            
            # Return blocked response to client
            HTTP::respond 403 \
                -content $response_body \
                -content_type $content_type \
                -header "Cache-Control" "no-cache, no-store, must-revalidate" \
                -header "Pragma" "no-cache" \
                -header "Expires" "0" \
                -header "X-Blocked-By" "WAF_CustomRule" \
                -header "X-Violation" $CUSTOM_VIOLATION_NAME
            
            # Return from event handler (prevent further processing)
            return
            
        } else {
            # LOG-ONLY MODE: Allow request but log the threat
            ASM::log "CUSTOM_ZERODDAY_LOGGED" "Potential attack pattern detected but request allowed (log-only mode)"
        }
    }
}

# ============================================================================
# EVENT: when HTTP_RESPONSE
# Triggered after server response is returned.
# Used for response header security hardening.
# ============================================================================

when HTTP_RESPONSE {
    
    # Ensure security headers are present in all responses
    if {![HTTP::header exists X-Content-Type-Options]} {
        HTTP::header insert X-Content-Type-Options "nosniff"
    }
    
    if {![HTTP::header exists X-Frame-Options]} {
        HTTP::header insert X-Frame-Options "DENY"
    }
    
    if {![HTTP::header exists Cache-Control]} {
        HTTP::header insert Cache-Control "no-cache, no-store, must-revalidate"
    }
}

###############################################################################
# END OF CUSTOM ZERO-DAY DETECTION RULE
###############################################################################

# DEPLOYMENT NOTES:
# 1. This rule detects Log4Shell-style JNDI injection patterns
# 2. Patterns can be extended: JNDI_PATTERNS [list "...", "..."]
# 3. Works on URI, headers, and request body
# 4. Logs to ASM for SIEM integration
# 5. Can be set to log-only mode for tuning (BLOCK_ACTION = 0)
# 6. Response format can be JSON or HTML (BLOCK_RESPONSE_JSON)
# 7. Full payload logging can be disabled for performance (LOG_PAYLOAD = 0)
# 8. Custom violation name enables ASM policy integration
# 9. Includes performance safeguards (1MB body limit)
# 10. X-Forwarded-For aware for proxy environments
