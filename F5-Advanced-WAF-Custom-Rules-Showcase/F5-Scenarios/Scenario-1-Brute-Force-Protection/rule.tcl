###############################################################################
# F5 Advanced WAF - Scenario 1: Brute-Force & Credential Stuffing Protection
# File: rule.tcl
# Description: Protects /login endpoint against brute-force attacks
# Author: Kulbir Jaglan
# Version: 1.0
# TMOS Compatibility: 17.5.x
# Deployment: Advanced WAF (ASM) iRule with event handling
###############################################################################

# ============================================================================
# RULE CONFIGURATION PARAMETERS
# ============================================================================
# These parameters control the behavior of the brute-force protection mechanism.
# Modify these values to suit your security policy:

set FAILED_LOGIN_LIMIT 5             ;# Maximum failed attempts allowed per IP
set TIME_WINDOW 300                  ;# Time window in seconds (5 minutes)
set BLOCK_DURATION 900               ;# Blocking duration in seconds (15 minutes)
set LOGIN_ENDPOINT "/login"          ;# Target endpoint for protection
set USERNAME_FIELD "username"        ;# POST body field name for username
set PASSWORD_FIELD "password"        ;# POST body field name for password

# ============================================================================
# PROCEDURE: Extract username from POST data
# ============================================================================
# This procedure safely extracts the username field from URL-encoded POST body.
# Used for detailed security logging and audit trail.
#
proc extract_username {post_data} {
    # Search for the username field in POST data
    # Example: "username=adminuser&password=xxx" -> returns "adminuser"
    
    if {[regexp {username=([^&]+)} $post_data match username]} {
        # URL decode the captured username (convert %20 to space, etc.)
        set username [HTTP::decode $username]
        return $username
    }
    # Return empty string if username not found in POST body
    return ""
}

# ============================================================================
# PROCEDURE: Get current IP address from client
# ============================================================================
# Retrieves the client IP address, considering proxied requests.
# Prioritizes X-Forwarded-For header if present (for reverse proxy scenarios).
#
proc get_client_ip {} {
    # Check for X-Forwarded-For header (common in reverse proxy/CDN setups)
    if {[HTTP::header exists X-Forwarded-For]} {
        # Extract the first IP address from X-Forwarded-For list
        # Example: "1.2.3.4, 5.6.7.8" -> returns "1.2.3.4"
        set xff_header [HTTP::header values X-Forwarded-For]
        set first_ip [lindex [split [lindex $xff_header 0] ","] 0]
        return [string trim $first_ip]
    }
    # Fall back to direct client IP if no proxy header present
    return [IP::client_addr]
}

# ============================================================================
# EVENT: when HTTP_RESPONSE
# Triggered after server response is returned to the client.
# Used to detect failed login attempts based on response status code.
# ============================================================================

when HTTP_RESPONSE {
    
    # -----------------------------------------------------------------------
    # CONTEXT CHECK: Verify this is a /login endpoint POST request
    # -----------------------------------------------------------------------
    # Only process POST requests to /login endpoint to reduce overhead
    if {([HTTP::method] eq "POST") && ([HTTP::uri] starts_with $LOGIN_ENDPOINT)} {
        
        # Get client IP address (accounting for proxies)
        set client_ip [get_client_ip]
        
        # Create a unique key for this IP address in the data table
        # data table persists across requests on the BIG-IP system
        set ip_key "brute_force:${client_ip}"
        
        # -----------------------------------------------------------------------
        # FAILED LOGIN DETECTION: Check HTTP response status code
        # -----------------------------------------------------------------------
        # HTTP 401 (Unauthorized), 403 (Forbidden), or custom failure indicator
        # indicates authentication failure. Successful auth typically returns 200 or 302.
        
        if {[HTTP::status] >= 400} {
            # This is a failed login attempt
            
            # Extract the attempted username from the POST body for logging
            set post_body [HTTP::payload]
            set attempted_username [extract_username $post_body]
            
            # -----------------------------------------------------------------------
            # DATA TABLE: Track failed attempts per IP
            # -----------------------------------------------------------------------
            # Increment the fail count in the data table with time window
            # If entry doesn't exist, it starts at 0; we increment to 1
            
            set current_failures [table incr -notouch $ip_key 1 $TIME_WINDOW $TIME_WINDOW]
            
            # Log the failed attempt to ASM event logs for SIEM integration
            ASM::log "BRUTE_FORCE_EVENT" "Failed login attempt from IP ${client_ip} \
                username ${attempted_username} attempt_count ${current_failures}"
            
            # -----------------------------------------------------------------------
            # THRESHOLD CHECK: Verify if failed attempts exceed limit
            # -----------------------------------------------------------------------
            # Compare current failure count against threshold
            
            if {$current_failures >= $FAILED_LOGIN_LIMIT} {
                # LIMIT EXCEEDED: IP has too many failed attempts
                
                # Set IP reputation to blocked (for integration with other ASM rules)
                table add -notouch $ip_key "BLOCKED" $BLOCK_DURATION
                
                # Log the violation to ASM security event
                ASM::log "BRUTE_FORCE_BLOCK" "IP ${client_ip} blocked for ${BLOCK_DURATION}s. \
                    Failed attempts: ${current_failures}, last username: ${attempted_username}"
                
                # Define custom response page for blocked users
                set response_body "<!DOCTYPE html>
                <html>
                <head><title>Access Denied</title></head>
                <body style='font-family:Arial'>
                <h2>Too Many Attempts</h2>
                <p>Too many failed login attempts from your IP address.</p>
                <p>Please try again in 15 minutes.</p>
                <p>Contact support if you believe this is an error.</p>
                </body>
                </html>"
                
                # Set HTTP response status to 429 (Too Many Requests)
                HTTP::respond 429 \
                    -content $response_body \
                    -content_type "text/html" \
                    -header "Cache-Control" "no-cache, no-store, must-revalidate" \
                    -header "Pragma" "no-cache" \
                    -header "Expires" "0" \
                    -header "X-RateLimit-Limit" $FAILED_LOGIN_LIMIT \
                    -header "X-RateLimit-Remaining" "0" \
                    -header "Retry-After" $BLOCK_DURATION
            }
        }
    }
}

# ============================================================================
# EVENT: when HTTP_REQUEST
# Triggered when client HTTP request is received (before response).
# Used to check if client IP is currently in the blocked list.
# ============================================================================

when HTTP_REQUEST {
    
    # -----------------------------------------------------------------------
    # CONTEXT CHECK: Verify this is a /login endpoint request
    # -----------------------------------------------------------------------
    # Check if request is targeting the protected /login endpoint
    if {[HTTP::uri] starts_with $LOGIN_ENDPOINT} {
        
        # Get client IP address (accounting for proxies)
        set client_ip [get_client_ip]
        
        # Create the same unique key used in HTTP_RESPONSE handler
        set ip_key "brute_force:${client_ip}"
        
        # -----------------------------------------------------------------------
        # BLOCKED IP CHECK: Lookup if IP is currently blocked
        # -----------------------------------------------------------------------
        # Check the data table for a "BLOCKED" entry for this IP
        # Table entries automatically expire after BLOCK_DURATION seconds
        
        set block_status [table lookup $ip_key]
        
        if {$block_status eq "BLOCKED"} {
            # IP is currently blocked; deny the request
            
            # Log the blocked attempt
            ASM::log "BRUTE_FORCE_BLOCKED_REQUEST" "Blocked request from IP ${client_ip}"
            
            # Define the blocking response page
            set response_body "<!DOCTYPE html>
            <html>
            <head><title>Access Denied</title></head>
            <body style='font-family:Arial'>
            <h2>Too Many Attempts</h2>
            <p>Too many failed login attempts from your IP address.</p>
            <p>Please try again in 15 minutes.</p>
            <p>Contact support if you believe this is an error.</p>
            </body>
            </html>"
            
            # Return 429 (Too Many Requests) response and block the connection
            HTTP::respond 429 \
                -content $response_body \
                -content_type "text/html" \
                -header "Cache-Control" "no-cache, no-store, must-revalidate" \
                -header "Pragma" "no-cache" \
                -header "Expires" "0" \
                -header "Retry-After" $BLOCK_DURATION
        }
    }
}

###############################################################################
# END OF BRUTE-FORCE PROTECTION RULE
###############################################################################

# NOTES:
# 1. This rule uses the F5 data table feature for in-memory tracking
# 2. Data table entries automatically expire based on timeout values
# 3. The rule handles both HTTP and HTTPS (transparent to iRule)
# 4. Recommended to enable "iRule events" in ASM policy for ASM:: logging
# 5. For clustered deployments, ensure distributed session sharing is enabled
# 6. Performance impact is minimal due to efficient hash-table lookups
# 7. Consider implementing IP whitelist for administrative accounts
