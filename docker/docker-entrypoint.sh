#!/bin/sh
set -e

# Fix ownership of mounted volumes if running as root
if [ "$(id -u)" = "0" ]; then
    # Data directory
    chown -R paycheck:paycheck /var/lib/paycheck

    # Master key - ensure paycheck can read it, keep strict permissions
    if [ -f /etc/paycheck/master.key ]; then
        chown paycheck:paycheck /etc/paycheck/master.key
        chmod 400 /etc/paycheck/master.key
    fi

    exec gosu paycheck "$@"
else
    exec "$@"
fi
