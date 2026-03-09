#!/bin/bash
###############################################################################
# F5 Advanced WAF Custom Rules - Automated Deployment Script
# File: deploy-all.sh
# Description: Orchestrates deployment of all three scenarios to BIG-IP
# Author: Kulbir Jaglan
# Version: 1.0
# Usage: ./deploy-all.sh <BIG_IP_HOST> <USERNAME> <PASSWORD> <POLICY_NAME>
###############################################################################

set -e  # Exit on error

# ============================================================================
# CONFIGURATION & PARAMETERS
# ============================================================================

# Check command-line arguments
if [[ $# -lt 4 ]]; then
    echo "Usage: $0 <BIG_IP_HOST> <USERNAME> <PASSWORD> <POLICY_NAME>"
    echo ""
    echo "Example:"
    echo "  $0 192.168.1.100 admin mypassword production_waf_policy"
    echo ""
    echo "Arguments:"
    echo "  BIG_IP_HOST   - Management IP address of BIG-IP"
    echo "  USERNAME      - Administrator username"
    echo "  PASSWORD      - Administrator password"
    echo "  POLICY_NAME   - Name of WAF policy to attach rules"
    echo ""
    exit 1
fi

BIG_IP_HOST="$1"
BIG_IP_USER="$2"
BIG_IP_PASS="$3"
POLICY_NAME="$4"
VS_NAME="${5:-}"  # Optional: Virtual server name

# Derived variables
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARENT_DIR="$(dirname "$SCRIPT_DIR")"
TEMP_DIR="/tmp/f5_deploy_$$"

# SSH options
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10"

# Color output for clarity
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'  # No Color

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Cleanup on exit
cleanup() {
    if [[ -d "$TEMP_DIR" ]]; then
        rm -rf "$TEMP_DIR"
        log_info "Cleaned up temporary directory: $TEMP_DIR"
    fi
}
trap cleanup EXIT

# Execute TMSH command via SSH
tmsh_execute() {
    local command="$1"
    local description="$2"
    
    log_info "Executing: $description"
    
    # Use sshpass for automated authentication, or use key-based auth if available
    if command -v sshpass &> /dev/null; then
        sshpass -p "$BIG_IP_PASS" ssh $SSH_OPTS \
            "${BIG_IP_USER}@${BIG_IP_HOST}" \
            "tmsh <<'EOF'
${command}
quit
EOF" || return 1
    else
        log_warning "sshpass not found; attempting SSH key authentication"
        ssh $SSH_OPTS "${BIG_IP_USER}@${BIG_IP_HOST}" \
            "tmsh <<'EOF'
${command}
quit
EOF" || return 1
    fi
    
    log_success "Completed: $description"
    return 0
}

# Copy file to BIG-IP via SCP
copy_to_bigip() {
    local local_file="$1"
    local remote_path="$2"
    
    log_info "Copying $local_file to BIG-IP:$remote_path"
    
    if command -v sshpass &> /dev/null; then
        sshpass -p "$BIG_IP_PASS" scp $SSH_OPTS \
            "$local_file" "${BIG_IP_USER}@${BIG_IP_HOST}:${remote_path}" || return 1
    else
        scp $SSH_OPTS "$local_file" "${BIG_IP_USER}@${BIG_IP_HOST}:${remote_path}" || return 1
    fi
    
    log_success "File copied successfully"
    return 0
}

# ============================================================================
# PRE-FLIGHT CHECKS
# ============================================================================

echo ""
echo "========================================================================="
echo "F5 Advanced WAF Custom Rules - Automated Deployment"
echo "========================================================================="
echo ""

log_info "Starting pre-flight checks..."

# Check required tools
for tool in ssh scp; do
    if ! command -v $tool &> /dev/null; then
        log_error "Required tool not found: $tool"
        exit 1
    fi
done

if ! command -v sshpass &> /dev/null; then
    log_warning "sshpass not installed; script will use SSH key authentication"
    log_warning "Ensure SSH key is configured for ${BIG_IP_USER}@${BIG_IP_HOST}"
fi

# Verify scenario directories exist
for scenario in "Scenario-1-Brute-Force-Protection" "Scenario-2-API-JWT-Rate-Limit" "Scenario-3-Custom-ZeroDay-Signature"; do
    if [[ ! -d "$PARENT_DIR/$scenario" ]]; then
        log_error "Scenario directory not found: $PARENT_DIR/$scenario"
        exit 1
    fi
done

log_success "Pre-flight checks passed"

# ============================================================================
# CONNECTIVITY TEST
# ============================================================================

echo ""
log_info "Testing connectivity to BIG-IP at $BIG_IP_HOST..."

if command -v sshpass &> /dev/null; then
    if ! sshpass -p "$BIG_IP_PASS" ssh $SSH_OPTS -o ConnectTimeout=5 \
        "${BIG_IP_USER}@${BIG_IP_HOST}" "tmsh show sys version" > /dev/null 2>&1; then
        log_error "Unable to connect to BIG-IP at $BIG_IP_HOST"
        log_error "Verify host, username, password, and network connectivity"
        exit 1
    fi
else
    if ! ssh $SSH_OPTS -o ConnectTimeout=5 \
        "${BIG_IP_USER}@${BIG_IP_HOST}" "tmsh show sys version" > /dev/null 2>&1; then
        log_error "Unable to connect to BIG-IP at $BIG_IP_HOST using key auth"
        exit 1
    fi
fi

log_success "Connected to BIG-IP successfully"

# ============================================================================
# DEPLOYMENT START
# ============================================================================

echo ""
echo "========================================================================="
echo "DEPLOYMENT CONFIGURATION"
echo "========================================================================="
echo "BIG-IP Host:     $BIG_IP_HOST"
echo "Username:        $BIG_IP_USER"
echo "WAF Policy:      $POLICY_NAME"
echo "Virtual Server:  ${VS_NAME:-Not specified}"
echo "========================================================================="
echo ""

# Create temporary directory for rule files
mkdir -p "$TEMP_DIR"
log_info "Created temporary directory: $TEMP_DIR"

# ============================================================================
# SCENARIO 1: BRUTE-FORCE PROTECTION
# ============================================================================

echo ""
echo "========================================================================="
echo "SCENARIO 1: Brute-Force Protection iRule"
echo "========================================================================="
echo ""

SCENARIO_1_RULE="$PARENT_DIR/Scenario-1-Brute-Force-Protection/rule.tcl"
if [[ ! -f "$SCENARIO_1_RULE" ]]; then
    log_error "Scenario 1 rule not found: $SCENARIO_1_RULE"
    exit 1
fi

log_info "Deploying Scenario 1 iRule..."

# Copy rule to BIG-IP
copy_to_bigip "$SCENARIO_1_RULE" "/tmp/brute_force_rule.tcl" || {
    log_error "Failed to copy Scenario 1 rule to BIG-IP"
    exit 1
}

# Create the iRule on BIG-IP
tmsh_execute "create ltm irule brute_force_protection_rule definition-file /tmp/brute_force_rule.tcl" \
    "Create Scenario 1 iRule" || {
    log_warning "Scenario 1 iRule may already exist, attempting to update..."
    tmsh_execute "modify ltm irule brute_force_protection_rule definition-file /tmp/brute_force_rule.tcl" \
        "Update Scenario 1 iRule" || {
        log_error "Failed to create/update Scenario 1 iRule"
        exit 1
    }
}

log_success "Scenario 1 iRule deployed successfully"

# ============================================================================
# SCENARIO 2: API SECURITY (JWT + RATE LIMITING)
# ============================================================================

echo ""
echo "========================================================================="
echo "SCENARIO 2: API Security (JWT + Rate Limiting) iRule"
echo "========================================================================="
echo ""

SCENARIO_2_RULE="$PARENT_DIR/Scenario-2-API-JWT-Rate-Limit/rule.tcl"
if [[ ! -f "$SCENARIO_2_RULE" ]]; then
    log_error "Scenario 2 rule not found: $SCENARIO_2_RULE"
    exit 1
fi

log_info "Deploying Scenario 2 iRule..."

# Copy rule to BIG-IP
copy_to_bigip "$SCENARIO_2_RULE" "/tmp/api_jwt_rate_limit_rule.tcl" || {
    log_error "Failed to copy Scenario 2 rule to BIG-IP"
    exit 1
}

# Create the iRule on BIG-IP
tmsh_execute "create ltm irule api_jwt_rate_limit_rule definition-file /tmp/api_jwt_rate_limit_rule.tcl" \
    "Create Scenario 2 iRule" || {
    log_warning "Scenario 2 iRule may already exist, attempting to update..."
    tmsh_execute "modify ltm irule api_jwt_rate_limit_rule definition-file /tmp/api_jwt_rate_limit_rule.tcl" \
        "Update Scenario 2 iRule" || {
        log_error "Failed to create/update Scenario 2 iRule"
        exit 1
    }
}

log_warning "NOTE: Remember to update JWT_SECRET, ISSUER_CLAIM, and VALID_ROLES in the rule!"

log_success "Scenario 2 iRule deployed successfully"

# ============================================================================
# SCENARIO 3: ZERO-DAY DETECTION (JNDI INJECTION)
# ============================================================================

echo ""
echo "========================================================================="
echo "SCENARIO 3: Custom Zero-Day Detection (JNDI Injection)"
echo "========================================================================="
echo ""

SCENARIO_3_RULE="$PARENT_DIR/Scenario-3-Custom-ZeroDay-Signature/rule.tcl"
SCENARIO_3_SIG="$PARENT_DIR/Scenario-3-Custom-ZeroDay-Signature/attack-signature.xml"

if [[ ! -f "$SCENARIO_3_RULE" ]]; then
    log_error "Scenario 3 rule not found: $SCENARIO_3_RULE"
    exit 1
fi

if [[ ! -f "$SCENARIO_3_SIG" ]]; then
    log_error "Scenario 3 signature not found: $SCENARIO_3_SIG"
    exit 1
fi

log_info "Deploying Scenario 3 iRule..."

# Copy rule to BIG-IP
copy_to_bigip "$SCENARIO_3_RULE" "/tmp/zerodday_rule.tcl" || {
    log_error "Failed to copy Scenario 3 rule to BIG-IP"
    exit 1
}

# Create the iRule on BIG-IP
tmsh_execute "create ltm irule custom_zerodday_detection_rule definition-file /tmp/zerodday_rule.tcl" \
    "Create Scenario 3 iRule" || {
    log_warning "Scenario 3 iRule may already exist, attempting to update..."
    tmsh_execute "modify ltm irule custom_zerodday_detection_rule definition-file /tmp/zerodday_rule.tcl" \
        "Update Scenario 3 iRule" || {
        log_error "Failed to create/update Scenario 3 iRule"
        exit 1
    }
}

log_success "Scenario 3 iRule deployed successfully"

# Deploy attack signatures (optional)
log_info "Deploying Scenario 3 attack signatures..."

copy_to_bigip "$SCENARIO_3_SIG" "/tmp/attack-signature.xml" || {
    log_error "Failed to copy Scenario 3 signatures to BIG-IP"
    exit 1
}

log_warning "Attack signatures uploaded. Import them manually via GUI: Security > Attack Signatures > User-Defined Signatures > Import"

# ============================================================================
# ATTACH iRULES TO POLICY (IF SPECIFIED)
# ============================================================================

if [[ -n "$POLICY_NAME" ]]; then
    echo ""
    echo "========================================================================="
    echo "ATTACHING iRULES TO WAF POLICY"
    echo "========================================================================="
    echo ""
    
    log_info "Attempting to attach iRules to policy: $POLICY_NAME"
    
    # Note: ASM policies don't directly attach iRules, but they can be attached to virtual servers
    # This is informational; actual attachment depends on your deployment topology
    log_warning "iRules must be attached to virtual servers, not directly to WAF policies"
    log_warning "Attach the following iRules to your virtual server(s):"
    echo "  1. brute_force_protection_rule"
    echo "  2. api_jwt_rate_limit_rule"
    echo "  3. custom_zerodday_detection_rule"
fi

# ============================================================================
# ENABLE ASM EVENT LOGGING
# ============================================================================

echo ""
echo "========================================================================="
echo "ENABLING ASM EVENT LOGGING"
echo "========================================================================="
echo ""

if [[ -n "$POLICY_NAME" ]]; then
    log_info "Enabling ASM event logging for policy: $POLICY_NAME"
    
    tmsh_execute "modify asm policy ${POLICY_NAME} codeBlockingPolicy enabled logAll enabled" \
        "Enable ASM event logging" || {
        log_warning "Could not enable ASM event logging (policy may not exist or insufficient permissions)"
    }
    
    log_success "ASM event logging configuration completed"
fi

# ============================================================================
# POST-DEPLOYMENT SUMMARY
# ============================================================================

echo ""
echo "========================================================================="
echo "DEPLOYMENT SUMMARY"
echo "========================================================================="
echo ""

log_success "All iRules deployed successfully!"

echo ""
echo "Deployed iRules:"
echo "  ✓ brute_force_protection_rule         (Scenario 1: Brute-Force)"
echo "  ✓ api_jwt_rate_limit_rule             (Scenario 2: API Security)"
echo "  ✓ custom_zerodday_detection_rule      (Scenario 3: Zero-Day)"
echo ""

echo "Next Steps:"
echo "  1. Attach iRules to your virtual server(s):"
echo "     GUI: Local Traffic > Virtual Servers > [VS_NAME] > iRules"
echo "     TMSH: modify ltm virtual [VS_NAME] rules { brute_force_protection_rule }"
echo ""
echo "  2. For Scenario 2 (API Security):"
echo "     Update JWT configuration in rule: edit the api_jwt_rate_limit_rule"
echo "     Set: JWT_SECRET, ISSUER_CLAIM, VALID_ROLES"
echo ""
echo "  3. For Scenario 3 (Zero-Day):"
echo "     Import attack signatures via GUI: Security > Attack Signatures > User-Defined"
echo "     Select: /tmp/attack-signature.xml on BIG-IP"
echo ""
echo "  4. Verify Deployment:"
echo "     Log in to BIG-IP and check:"
echo "     Security > Application Security > iRules > [Rules listed above]"
echo ""
echo "  5. Test Deployments:"
echo "     Refer to test-results.md in each scenario folder"
echo ""

echo "Documentation:"
echo "  Scenario 1: ./Scenario-1-Brute-Force-Protection/deployment.md"
echo "  Scenario 2: ./Scenario-2-API-JWT-Rate-Limit/deployment.md"
echo "  Scenario 3: ./Scenario-3-Custom-ZeroDay-Signature/deployment.md"
echo ""

echo "========================================================================="
log_success "Deployment script completed successfully!"
echo "========================================================================="
echo ""
