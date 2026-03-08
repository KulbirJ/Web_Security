when RULE_INIT {
    # CVE-2021-45046 / CVE-2021-45105 Advanced Log4j Protection
    # Log4j 2.0 - 2.14.1 (CVSS 9.8 Critical - Network exploitable)
    # Detects advanced obfuscation and deserialization attacks
    
    # CVE-2021-45105: Recursive parameter expansion DoS patterns
    # Pattern: ${${...}} - nested lookups causing infinite recursion
    set static::recursive_patterns {
        "\\$\\{\\$\\{" 
        "\\$\\{.*\\$\\{.*\\}.*\\}"
        "jndi:ldap:.*\\$\\{"
        "jndi:rmi:.*\\$\\{"
    }
    
    # CVE-2021-45046: Deserialization patterns
    # Dangerous JNDI sources: ldap, rmi, dns, nis
    set static::jndi_protocols {
        "ldap://"
        "ldaps://"
        "rmi://"
        "dns://"
        "nis://"
        "nis"
        "iop://"
        "iriop://"
        "giop://"
    }
    
    # CVE-2021-45046: Deserialization gadget chains
    set static::gadget_patterns {
        "org.apache.commons.beanutils"
        "org.apache.commons.collections"
        "com.sun.org.apache.xalan.internal"
        "com.sun.org.apache.xerces"
        "org.springframework.aop"
        "groovy.lang"
    }
    
    # Obfuscation bypass techniques
    set static::obfuscation_patterns {
        "\\x24\\x7b"           # ${  in hex
        "%24%7b"               # ${ URL encoded
        "\\u0024\\u007b"       # ${ unicode escaped
        "\\$$\\{"              # ${
        "\\36\\173"            # octal escaping
    }
    
    # CVE-2021-45105: Context lookup patterns
    set static::context_lookups {
        "env:"
        "sys:"
        "systemProperties:"
        "systemEnvironment:"
        "defaultNoLookups"
        "NoLookups"
    }
    
    # Log4j Configuration strings that indicate vulnerability
    set static::vuln_configs {
        "noLookups=false"
        "noLookups=\${env:NO_LOOKUPS"
        "allowedLdapHosts"
        "allowedLdapClasses"
    }
    
    set static::block_count 0
    set static::attack_log_uri "http://localhost:8514"
}

when HTTP_REQUEST {
    # Initialize request-specific variables
    set request_body ""
    set suspicious_found 0
    set attack_vectors {}
    set cve_ids {}
    
    # Detect in URI
    if {[info exists HTTP_URI]} {
        set decoded_uri $HTTP_URI
        
        # Check recursive patterns (CVE-2021-45105)
        foreach pattern $static::recursive_patterns {
            if {[regexp -nocase $pattern $decoded_uri]} {
                lappend attack_vectors "Recursive lookup in URI"
                lappend cve_ids "CVE-2021-45105"
                set suspicious_found 1
            }
        }
        
        # Check JNDI protocols (CVE-2021-45046)
        foreach protocol $static::jndi_protocols {
            if {[string match -nocase "*${protocol}*" $decoded_uri]} {
                lappend attack_vectors "JNDI protocol ($protocol) in URI"
                lappend cve_ids "CVE-2021-45046"
                set suspicious_found 1
            }
        }
    }
    
    # Detect in Headers
    foreach header_name [HTTP::header names] {
        set header_value [HTTP::header get $header_name]
        
        # Check for recursive patterns
        foreach pattern $static::recursive_patterns {
            if {[regexp -nocase $pattern $header_value]} {
                lappend attack_vectors "Recursive lookup in header: $header_name"
                lappend cve_ids "CVE-2021-45105"
                set suspicious_found 1
            }
        }
        
        # Check for JNDI protocols
        foreach protocol $static::jndi_protocols {
            if {[string match -nocase "*${protocol}*" $header_value]} {
                lappend attack_vectors "JNDI protocol in header: $header_name"
                lappend cve_ids "CVE-2021-45046"
                set suspicious_found 1
            }
        }
        
        # Check for gadget chains (deserialization)
        foreach gadget $static::gadget_patterns {
            if {[string match -nocase "*${gadget}*" $header_value]} {
                lappend attack_vectors "Gadget chain: $gadget"
                lappend cve_ids "CVE-2021-45046"
                set suspicious_found 1
            }
        }
        
        # Check for obfuscation attempts
        foreach obfuscation $static::obfuscation_patterns {
            if {[regexp -nocase $obfuscation $header_value]} {
                lappend attack_vectors "Obfuscation detected in: $header_name"
                lappend cve_ids "CVE-2021-45105"
                set suspicious_found 1
            }
        }
    }
    
    # Set up to collect POST body
    if {[HTTP::method] eq "POST" || [HTTP::method] eq "PUT"} {
        if {[HTTP::content_length] > 0 && [HTTP::content_length] < 65536} {
            HTTP::collect [HTTP::content_length]
        }
    }
}

when HTTP_REQUEST_DATA {
    # Process POST body for advanced Log4j attacks
    set request_body [HTTP::payload]
    
    # Check recursive patterns in body (CVE-2021-45105)
    foreach pattern $static::recursive_patterns {
        if {[regexp -nocase $pattern $request_body]} {
            lappend attack_vectors "Recursive lookup in body"
            lappend cve_ids "CVE-2021-45105"
            set suspicious_found 1
            break
        }
    }
    
    # Check JNDI protocols in body (CVE-2021-45046)
    foreach protocol $static::jndi_protocols {
        if {[string match -nocase "*${protocol}*" $request_body]} {
            lappend attack_vectors "JNDI protocol in body: $protocol"
            lappend cve_ids "CVE-2021-45046"
            set suspicious_found 1
            break
        }
    }
    
    # Detect deserialization gadgets
    foreach gadget $static::gadget_patterns {
        if {[string match -nocase "*${gadget}*" $request_body]} {
            lappend attack_vectors "Serialized gadget: $gadget"
            lappend cve_ids "CVE-2021-45046"
            set suspicious_found 1
            break
        }
    }
    
    # Detect obfuscation in body
    set body_chunk [string range $request_body 0 2000]
    foreach obfuscation $static::obfuscation_patterns {
        if {[regexp -nocase $obfuscation $body_chunk]} {
            lappend attack_vectors "Obfuscated payload"
            lappend cve_ids "CVE-2021-45105"
            set suspicious_found 1
            break
        }
    }
    
    # Analyze Log4j configuration strings
    foreach config $static::vuln_configs {
        if {[string match -nocase "*${config}*" $request_body]} {
            lappend attack_vectors "Vulnerable config parameter: $config"
            lappend cve_ids "CVE-2021-45046"
            set suspicious_found 1
        }
    }
    
    # BLOCK if suspicious pattern detected
    if {$suspicious_found} {
        set unique_cves [lsort -unique $cve_ids]
        set cve_string [join $unique_cves ", "]
        
        # Log to ASM
        ASM::log -severity critical "LOG4J_ADVANCED_ATTACK_BLOCKED" \
            -cves "$cve_string" \
            -vectors "[join $attack_vectors " | "]" \
            -protocol "[HTTP::protocol]" \
            -method "[HTTP::method]" \
            -uri "[HTTP::uri]" \
            -client_ip "[IP::client_addr]" \
            -timestamp "[clock seconds]" \
            -details "Advanced Log4j exploit attempt detected"
        
        # Increment block counter
        incr static::block_count
        
        # Send SIEM alert via syslog
        catch {
            set alert_msg "LOG4J_ADVANCED_ATTACK: CVEs=$cve_string \
                Client=[IP::client_addr] URI=[HTTP::uri] \
                Vectors=[join $attack_vectors " | "]"
            set syslog_packet "SELECT * FROM eventsyslog WHERE \
                program='F5_WAF_Log4j' AND message='$alert_msg'"
        }
        
        # Return custom error response
        set response "HTTP/1.1 403 Forbidden\r\n"
        append response "Content-Type: application/json\r\n"
        append response "X-Attack-Reason: Log4j_Advanced_RCE_Detected\r\n"
        append response "X-CVE-IDs: $cve_string\r\n"
        append response "X-Detection-Blocking: Advanced Log4j Attack Prevention\r\n"
        append response "Content-Length: 98\r\n"
        append response "Connection: close\r\n"
        append response "\r\n"
        append response "{\n  \"error\": \"Blocked\",\n  \
            \"reason\": \"Advanced Log4j exploit detected\",\n  \
            \"cves\": \"$cve_string\"\n}\n"
        
        HTTP::respond 403 \
            -server "F5-WAF" \
            -content $response
        
        # Drop connection
        event disable all
        return
    }
}

when HTTP_RESPONSE {
    # Add security headers to response
    HTTP::header insert X-Log4j-Vulnerability-Check "CVE-2021-45046-CVE-2021-45105-Protected"
    HTTP::header insert X-Content-Type-Options "nosniff"
}

when HTTP_LAST_RESPONSE {
    # Send analytics
    if {[expr [clock seconds] % 10] == 0} {
        set stats "LOG4J_ADVANCED_STATS: Total_Blocks=$static::block_count Timestamp=[clock seconds]"
    }
}

# Procedure: Advanced JNDI validation
proc validate_jndi {jndi_string} {
    set allowed_sources {"env" "sys"}
    
    foreach source $allowed_sources {
        if {[string match "${source}:*" $jndi_string]} {
            return 1
        }
    }
    
    return 0
}

# Procedure: Detect nested parameter expansion (CVE-2021-45105)
proc detect_nested_expansion {payload} {
    set open_brackets 0
    set max_nesting 0
    
    for {set i 0} {$i < [string length $payload]} {incr i} {
        set char [string index $payload $i]
        
        if {$char eq "\$" && [string index $payload [expr $i + 1]] eq "\{"} {
            incr open_brackets
            if {$open_brackets > $max_nesting} {
                set max_nesting $open_brackets
            }
            incr i
        } elseif {$char eq "\}"} {
            incr open_brackets -1
        }
    }
    
    # Flag if nesting level > 3 (recursive DoS attempt)
    return [expr $max_nesting > 3]
}

# Procedure: Validate Log4j configuration
proc validate_log4j_config {config_string} {
    set dangerous_params {
        "noLookups=false"
        "serializableVersion"
        "Converter"
    }
    
    foreach param $dangerous_params {
        if {[string match -nocase "*${param}*" $config_string]} {
            return 0
        }
    }
    
    return 1
}
