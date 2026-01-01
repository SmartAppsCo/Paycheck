#!/usr/bin/env bash
#
# rotate-master-key.sh - Rotate the Paycheck master encryption key
#
# This script safely rotates the master key used for envelope encryption of
# project private keys and payment provider configs. It handles the full workflow:
#   1. Validates the current key file exists and is accessible
#   2. Generates a new key with secure permissions
#   3. Stops the Paycheck service
#   4. Re-encrypts all project keys and payment configs with the new master key
#   5. Replaces the old key with the new one
#   6. Restarts the service
#
# USAGE:
#   ./rotate-master-key.sh [OPTIONS]
#
# OPTIONS:
#   -k, --key-file PATH     Path to current master key (default: /etc/paycheck/master.key)
#   -s, --service NAME      Systemd service name (default: paycheck)
#   -d, --database PATH     Database path (default: from DATABASE_PATH env or paycheck.db)
#   -b, --binary PATH       Path to paycheck binary (default: searches PATH, then ./target/release)
#   -n, --no-service        Skip service stop/start (for manual service management)
#   -y, --yes               Skip confirmation prompts
#   -h, --help              Show this help message
#
# REQUIREMENTS:
#   - openssl (for key generation)
#   - shred (for secure deletion, optional but recommended)
#   - The current master key file must exist and be readable
#   - Must be run as a user with permission to read/write the key file
#   - Must be run as a user with permission to stop/start the service (or use -n)
#
# EXAMPLES:
#   # Standard rotation with defaults
#   sudo ./rotate-master-key.sh
#
#   # Custom key path and service
#   sudo ./rotate-master-key.sh -k /opt/paycheck/master.key -s paycheck-prod
#
#   # Manual service management (e.g., in Docker)
#   ./rotate-master-key.sh -n -k /data/master.key
#
# EXIT CODES:
#   0 - Success
#   1 - Error (missing dependencies, permission denied, rotation failed, etc.)
#
# SAFETY:
#   - Creates backup of old key before deletion
#   - Validates new key works before removing old key
#   - Uses secure file permissions throughout
#   - Atomic key swap using mv
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Defaults
KEY_FILE="/etc/paycheck/master.key"
SERVICE_NAME="paycheck"
DATABASE_PATH="${DATABASE_PATH:-paycheck.db}"
BINARY_PATH=""
SKIP_SERVICE=false
SKIP_CONFIRM=false

# Logging functions
info() { echo -e "${BLUE}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[OK]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }
fatal() { error "$*"; exit 1; }

# Show usage
usage() {
    sed -n '3,46p' "$0" | sed 's/^#//' | sed 's/^ //'
    exit 0
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -k|--key-file)
            KEY_FILE="$2"
            shift 2
            ;;
        -s|--service)
            SERVICE_NAME="$2"
            shift 2
            ;;
        -d|--database)
            DATABASE_PATH="$2"
            shift 2
            ;;
        -b|--binary)
            BINARY_PATH="$2"
            shift 2
            ;;
        -n|--no-service)
            SKIP_SERVICE=true
            shift
            ;;
        -y|--yes)
            SKIP_CONFIRM=true
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            fatal "Unknown option: $1 (use --help for usage)"
            ;;
    esac
done

# Find paycheck binary
find_binary() {
    if [[ -n "$BINARY_PATH" ]]; then
        echo "$BINARY_PATH"
    elif command -v paycheck &>/dev/null; then
        command -v paycheck
    elif [[ -x "./target/release/paycheck" ]]; then
        echo "./target/release/paycheck"
    elif [[ -x "./target/debug/paycheck" ]]; then
        echo "./target/debug/paycheck"
    else
        fatal "Cannot find paycheck binary. Use -b to specify path."
    fi
}

# Check dependencies
check_deps() {
    info "Checking dependencies..."

    command -v openssl &>/dev/null || fatal "openssl is required but not found"

    if ! command -v shred &>/dev/null; then
        warn "shred not found - will use rm for deletion (less secure)"
    fi

    PAYCHECK_BIN=$(find_binary)
    [[ -x "$PAYCHECK_BIN" ]] || fatal "Paycheck binary not executable: $PAYCHECK_BIN"

    success "Dependencies OK (using $PAYCHECK_BIN)"
}

# Validate current key file
validate_current_key() {
    info "Validating current key file..."

    [[ -f "$KEY_FILE" ]] || fatal "Key file not found: $KEY_FILE"
    [[ -r "$KEY_FILE" ]] || fatal "Key file not readable: $KEY_FILE"

    # Check permissions
    local perms
    perms=$(stat -c "%a" "$KEY_FILE" 2>/dev/null || stat -f "%Lp" "$KEY_FILE" 2>/dev/null)
    if [[ "$perms" != "400" ]]; then
        warn "Current key file has permissions $perms (expected 400)"
    fi

    success "Current key file OK: $KEY_FILE"
}

# Generate new key
generate_new_key() {
    NEW_KEY_FILE="${KEY_FILE}.new"

    info "Generating new master key..."

    # Generate key
    openssl rand -base64 32 > "$NEW_KEY_FILE"

    # Set secure permissions
    chmod 400 "$NEW_KEY_FILE"

    # Verify permissions
    local perms
    perms=$(stat -c "%a" "$NEW_KEY_FILE" 2>/dev/null || stat -f "%Lp" "$NEW_KEY_FILE" 2>/dev/null)
    [[ "$perms" == "400" ]] || fatal "Failed to set permissions on new key file"

    success "New key generated: $NEW_KEY_FILE"
}

# Stop service
stop_service() {
    if $SKIP_SERVICE; then
        warn "Skipping service stop (--no-service)"
        return
    fi

    info "Stopping $SERVICE_NAME service..."

    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        systemctl stop "$SERVICE_NAME"
        success "Service stopped"
    else
        warn "Service not running or not managed by systemd"
    fi
}

# Start service
start_service() {
    if $SKIP_SERVICE; then
        warn "Skipping service start (--no-service)"
        return
    fi

    info "Starting $SERVICE_NAME service..."

    if systemctl list-unit-files "$SERVICE_NAME.service" &>/dev/null; then
        systemctl start "$SERVICE_NAME"
        sleep 2
        if systemctl is-active --quiet "$SERVICE_NAME"; then
            success "Service started"
        else
            fatal "Service failed to start - check logs with: journalctl -u $SERVICE_NAME"
        fi
    else
        warn "Service not managed by systemd - start manually"
    fi
}

# Run rotation
run_rotation() {
    info "Rotating keys in database..."

    export DATABASE_PATH

    if ! "$PAYCHECK_BIN" --rotate-key \
        --old-key-file "$KEY_FILE" \
        --new-key-file "$NEW_KEY_FILE"; then
        fatal "Key rotation failed - database unchanged, old key still valid"
    fi

    success "Database keys rotated"
}

# Swap keys
swap_keys() {
    BACKUP_KEY_FILE="${KEY_FILE}.old.$(date +%Y%m%d%H%M%S)"

    info "Swapping key files..."

    # Backup old key
    cp -p "$KEY_FILE" "$BACKUP_KEY_FILE"
    chmod 400 "$BACKUP_KEY_FILE"
    success "Old key backed up to: $BACKUP_KEY_FILE"

    # Atomic swap
    mv "$NEW_KEY_FILE" "$KEY_FILE"
    chmod 400 "$KEY_FILE"
    success "New key installed: $KEY_FILE"

    # Secure delete old key backup (optional)
    info "Securely deleting old key backup..."
    if command -v shred &>/dev/null; then
        shred -u "$BACKUP_KEY_FILE"
        success "Old key securely deleted"
    else
        rm -f "$BACKUP_KEY_FILE"
        warn "Old key deleted (shred not available - used rm)"
    fi
}

# Confirmation prompt
confirm() {
    if $SKIP_CONFIRM; then
        return 0
    fi

    echo
    echo -e "${YELLOW}=== MASTER KEY ROTATION ===${NC}"
    echo
    echo "This will:"
    echo "  1. Generate a new master key"
    echo "  2. Stop the Paycheck service"
    echo "  3. Re-encrypt all project private keys and payment configs"
    echo "  4. Replace the old key with the new one"
    echo "  5. Restart the service"
    echo
    echo "Configuration:"
    echo "  Key file:     $KEY_FILE"
    echo "  Service:      $SERVICE_NAME"
    echo "  Database:     $DATABASE_PATH"
    echo "  Binary:       $(find_binary)"
    echo
    read -rp "Continue? [y/N] " response
    case "$response" in
        [yY][eE][sS]|[yY]) return 0 ;;
        *) fatal "Aborted by user" ;;
    esac
}

# Cleanup on error
cleanup() {
    if [[ -f "${NEW_KEY_FILE:-}" ]]; then
        rm -f "$NEW_KEY_FILE"
    fi
}
trap cleanup EXIT

# Main
main() {
    echo
    echo -e "${BLUE}Paycheck Master Key Rotation${NC}"
    echo -e "${BLUE}=============================${NC}"
    echo

    check_deps
    validate_current_key
    confirm

    echo
    generate_new_key
    stop_service
    run_rotation
    swap_keys
    start_service

    echo
    echo -e "${GREEN}=== ROTATION COMPLETE ===${NC}"
    echo
    echo "The master key has been rotated successfully."
    echo
    echo "New key file: $KEY_FILE"
    echo
    if ! $SKIP_SERVICE; then
        echo "The service has been restarted. Verify with:"
        echo "  systemctl status $SERVICE_NAME"
        echo "  curl http://localhost:3000/health"
    else
        echo "Remember to restart your Paycheck service."
    fi
    echo
}

main "$@"
