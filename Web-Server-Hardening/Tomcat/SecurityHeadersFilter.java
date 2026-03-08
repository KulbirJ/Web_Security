// Tomcat Security Headers Filter - Java Implementation
// File: src/SecurityHeadersFilter.java
// 
// Purpose: Servlet filter to add security headers to all responses

import java.io.IOException;
import javax.servlet.*;
import javax.servlet.http.HttpServletResponse;

public class SecurityHeadersFilter implements Filter {

    public void init(FilterConfig filterConfig) throws ServletException {
    }

    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        
        if (response instanceof HttpServletResponse) {
            HttpServletResponse httpResponse = (HttpServletResponse) response;
            
            // Prevent MIME-type sniffing
            httpResponse.setHeader("X-Content-Type-Options", "nosniff");
            
            // Clickjacking protection
            httpResponse.setHeader("X-Frame-Options", "DENY");
            
            // Content Security Policy
            httpResponse.setHeader("Content-Security-Policy", 
                "default-src 'self'; script-src 'self' 'unsafe-inline'; " +
                "style-src 'self' 'unsafe-inline'; img-src 'self' data:; " +
                "font-src 'self'; connect-src 'self'; frame-ancestors 'none';");
            
            // Legacy XSS filter
            httpResponse.setHeader("X-XSS-Protection", "1; mode=block");
            
            // HSTS - Enforce HTTPS
            httpResponse.setHeader("Strict-Transport-Security", 
                "max-age=31536000; includeSubDomains; preload");
            
            // Referrer Policy
            httpResponse.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
            
            // Cache Control
            httpResponse.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
            httpResponse.setHeader("Pragma", "no-cache");
            
            // Permissions Policy
            httpResponse.setHeader("Permissions-Policy", 
                "geolocation=(), microphone=(), camera=()");
        }
        
        chain.doFilter(request, response);
    }

    public void destroy() {
    }
}
