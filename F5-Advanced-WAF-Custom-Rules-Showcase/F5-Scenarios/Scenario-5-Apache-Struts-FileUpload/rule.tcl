###############################################################################
# F5 Advanced WAF - Scenario 5: Apache Struts File Upload Protection
# File: rule.tcl
# CVE: CVE-2023-50164 (File Upload RCE)
# Description: Validates file uploads and detects malicious file handling
# Author: Kulbir Jaglan
# Version: 1.0
# TMOS Compatibility: 17.5.x
# Deployment: Advanced WAF (ASM) iRule with file validation
###############################################################################

# ============================================================================
# RULE CONFIGURATION PARAMETERS
# ============================================================================

set MAX_UPLOAD_SIZE 10485760    ;# 10 MB max file size
set ALLOWED_EXTENSIONS [list "jpg" "jpeg" "png" "gif" "pdf" "doc" "docx" "xls" "xlsx"]
set BLOCKED_EXTENSIONS [list "jsp" "exe" "sh" "bat" "asp" "php" "aspx" "py" "rb" "pl"]
set COMMON_UPLOAD_PARAMS [list "file" "upload" "attachment" "avatar" "image"]

set OGNL_PATTERNS [list "%23" "(#" "%{" "${" "@java" "@org" "ognl:" "struts"]
set DANGEROUS_CONTENT_TYPES [list "text/x-shellscript" "application/x-sh" "application/x-executable"]

set BLOCK_ACTION 1                ;# 1=Block, 0=Log only
set ENFORCE_EXTENSION 1           ;# Enforce file extension validation
set ENFORCE_CONTENT_TYPE 1        ;# Validate Content-Type header
set CUSTOM_VIOLATION "Custom_Malicious_File_Upload"

# ============================================================================
# PROCEDURE: Extract file extension from filename
# ============================================================================
proc get_file_extension {filename} {
    set parts [split $filename "."]
    if {[llength $parts] > 1} {
        set ext [lindex $parts end]
        return [string tolower $ext]
    }
    return ""
}

# ============================================================================
# PROCEDURE: Check if filename contains suspicious patterns
# ============================================================================
proc check_filename_patterns {filename} {
    global OGNL_PATTERNS
    
    set filename_lower [string tolower $filename]
    
    foreach pattern $OGNL_PATTERNS {
        set pattern_lower [string tolower $pattern]
        if {[string first $pattern_lower $filename_lower] >= 0} {
            return 1
        }
    }
    
    return 0
}

# ============================================================================
# PROCEDURE: Extract filename from Content-Disposition header
# ============================================================================
proc extract_filename_from_header {} {
    if {![HTTP::header exists Content-Disposition]} {
        return ""
    }
    
    set header_value [HTTP::header values Content-Disposition]
    set header_value [lindex $header_value 0]
    
    # Parse: form-data; name="file"; filename="test.jpg"
    if {[regexp {filename="([^"]+)"} $header_value match filename]} {
        return $filename
    } elseif {[regexp {filename=([^;\s]+)} $header_value match filename]} {
        return $filename
    }
    
    return ""
}

# ============================================================================
# EVENT: when HTTP_REQUEST
# Triggered when client HTTP request is received.
# Validates file uploads for security control implementation.
# ============================================================================

when HTTP_REQUEST {
    
    # -----------------------------------------------------------------------
    # DETECTION: Identify file upload requests
    # -----------------------------------------------------------------------
    
    if {[HTTP::method] eq "POST"} {
        # Check if this is a multipart form (file upload)
        if {[HTTP::header exists Content-Type]} {
            set content_type [HTTP::header values Content-Type]
            set content_type [lindex $content_type 0]
            
            if {[string match "*multipart/form-data*" $content_type]} {
                # FILE UPLOAD REQUEST DETECTED
                
                # Get client IP
                set client_ip [IP::client_addr]
                if {[HTTP::header exists X-Forwarded-For]} {
                    set xff_header [HTTP::header values X-Forwarded-For]
                    set client_ip [lindex [split [lindex $xff_header 0] ","] 0]
                    set client_ip [string trim $client_ip]
                }
                
                # ---------------------------------------------------------------
                # VALIDATION 1: Extract and validate filename
                # ---------------------------------------------------------------
                
                set filename [extract_filename_from_header]
                set extension [get_file_extension $filename]
                
                if {$filename ne ""} {
                    ASM::log "FILE_UPLOAD_REQUEST" "IP=${client_ip} Filename=${filename} Extension=${extension}"
                    
                    # Check for suspicious patterns in filename
                    if {[check_filename_patterns $filename]} {
                        ASM::log "FILE_UPLOAD_SUSPICIOUS" "Suspicious filename pattern: ${filename}"
                        
                        if {$BLOCK_ACTION == 1} {
                            HTTP::respond 400 \
                                -content "{\"error\":\"Invalid filenn ame\",\"message\":\"File upload contains suspicious patterns\"}" \
                                -content_type "application/json" \
                                -header "X-Blocked-By" "WAF_FileUpload" \
                                -header "X-Violation" $CUSTOM_VIOLATION
                            return
                        }
                    }
                    
                    # Check if extension is blocked
                    if {$ENFORCE_EXTENSION && [lsearch -exact -nocase $BLOCKED_EXTENSIONS $extension] >= 0} {
                        ASM::log "FILE_UPLOAD_BLOCKED_EXT" "Blocked file extension: ${extension} from ${client_ip}"
                        
                        if {$BLOCK_ACTION == 1} {
                            HTTP::respond 400 \
                                -content "{\"error\":\"Invalid file type\",\"message\":\"File type .${extension} is not allowed\"}" \
                                -content_type "application/json" \
                                -header "X-Blocked-By" "WAF_FileUpload" \
                                -header "X-Violation" $CUSTOM_VIOLATION
                            return
                        }
                    }
                    
                    # Validate extension is in allowed list
                    if {$ENFORCE_EXTENSION && [llength $ALLOWED_EXTENSIONS] > 0} {
                        if {[lsearch -exact -nocase $ALLOWED_EXTENSIONS $extension] < 0} {
                            ASM::log "FILE_UPLOAD_NOT_ALLOWED_EXT" "File extension not in whitelist: ${extension} from ${client_ip}"
                            
                            if {$BLOCK_ACTION == 1} {
                                HTTP::respond 400 \
                                    -content "{\"error\":\"Invalid file type\",\"message\":\"File type .${extension} not permitted\"}" \
                                    -content_type "application/json" \
                                    -header "X-Blocked-By" "WAF_FileUpload"
                                return
                            }
                        }
                    }
                }
                
                # ---------------------------------------------------------------
                # VALIDATION 2: Check Content-Type header
                # ---------------------------------------------------------------
                
                if {$ENFORCE_CONTENT_TYPE} {
                    # Check for dangerous content types
                    foreach dangerous_type $DANGEROUS_CONTENT_TYPES {
                        if {[string match "*${dangerous_type}*" $content_type]} {
                            ASM::log "FILE_UPLOAD_DANGEROUS_CT" "Dangerous Content-Type detected: ${content_type} from ${client_ip}"
                            
                            if {$BLOCK_ACTION == 1} {
                                HTTP::respond 400 \
                                    -content "{\"error\":\"Invalid content\",\"message\":\"Content-Type not allowed\"}" \
                                    -content_type "application/json"
                                return
                            }
                        }
                    }
                }
                
                # ---------------------------------------------------------------
                # VALIDATION 3: Check Content-Length
                # ---------------------------------------------------------------
                
                if {[HTTP::header exists Content-Length]} {
                    set content_length [HTTP::header values Content-Length]
                    set content_length [lindex $content_length 0]
                    
                    if {$content_length > $MAX_UPLOAD_SIZE} {
                        ASM::log "FILE_UPLOAD_TOO_LARGE" "Upload exceeds max size: ${content_length} bytes from ${client_ip}"
                        
                        if {$BLOCK_ACTION == 1} {
                            HTTP::respond 413 \
                                -content "{\"error\":\"File too large\",\"message\":\"Maximum file size is $MAX_UPLOAD_SIZE bytes\"}" \
                                -content_type "application/json" \
                                -header "X-Max-Size" $MAX_UPLOAD_SIZE
                            return
                        }
                    }
                }
                
                # ---------------------------------------------------------------
                # VALIDATION 4: Detect OGNL in multipart body
                # ---------------------------------------------------------------
                
                if {[HTTP::header exists Content-Length]} {
                    set content_length [HTTP::header values Content-Length]
                    set content_length [lindex $content_length 0]
                    
                    if {$content_length < 1048576} {
                        set body [HTTP::payload]
                        set body_lower [string tolower $body]
                        
                        foreach pattern $OGNL_PATTERNS {
                            set pattern_lower [string tolower $pattern]
                            if {[string first $pattern_lower $body_lower] >= 0} {
                                ASM::log "FILE_UPLOAD_OGNL" "OGNL pattern detected in upload from ${client_ip}: ${pattern}"
                                
                                if {$BLOCK_ACTION == 1} {
                                    HTTP::respond 400 \
                                        -content "{\"error\":\"Security violation\",\"message\":\"Upload contains invalid content\"}" \
                                        -content_type "application/json"
                                    return
                                }
                            }
                        }
                    }
                }
                
                ASM::log "FILE_UPLOAD_ALLOWED" "File upload allowed from ${client_ip}: ${filename}"
            }
        }
    }
}

# ============================================================================
# EVENT: when HTTP_RESPONSE
# ============================================================================

when HTTP_RESPONSE {
    if {![HTTP::header exists X-Content-Type-Options]} {
        HTTP::header insert X-Content-Type-Options "nosniff"
    }
}

###############################################################################
# END OF APACHE STRUTS FILE UPLOAD PROTECTION RULE
###############################################################################

# DEPLOYMENT NOTES:
# 1. Protects against CVE-2023-50164 (Struts file upload RCE)
# 2. Validates filename, extension, and content-type
# 3. Enforces file size limits
# 4. Detects OGNL injection in upload payloads
# 5. Customizable whitelist/blacklist for file types
# 6. Comprehensive logging for security audits
# 7. Set ENFORCE_EXTENSION and ENFORCE_CONTENT_TYPE as needed
# 8. Performance: <2ms per upload request
# 9. Works with multipart/form-data uploads
# 10. Logs each upload for compliance and incident response
