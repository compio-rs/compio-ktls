#!/bin/bash
set -e

echo "Checking if tls module is loaded..."
if lsmod | grep -q "^tls "; then
    echo "✓ tls module is loaded"
else
    echo "✗ tls module is not loaded"
    echo "Attempting to load tls module..."
    if sudo modprobe tls 2>/dev/null; then
        echo "✓ Successfully loaded tls module"
    else
        echo "✗ Failed to load tls module"
        echo "Your kernel may not support kTLS"
        exit 1
    fi
fi

echo ""
echo "Kernel version:"
uname -r

echo ""
echo "Checking kernel config..."
if [ -f /proc/config.gz ]; then
    if zcat /proc/config.gz | grep -q "CONFIG_TLS="; then
        echo "✓ CONFIG_TLS is set in kernel"
        zcat /proc/config.gz | grep "CONFIG_TLS="
    else
        echo "✗ CONFIG_TLS not found in kernel config"
    fi
elif [ -f /boot/config-$(uname -r) ]; then
    if grep -q "CONFIG_TLS=" /boot/config-$(uname -r); then
        echo "✓ CONFIG_TLS is set in kernel"
        grep "CONFIG_TLS=" /boot/config-$(uname -r)
    else
        echo "✗ CONFIG_TLS not found in kernel config"
    fi
else
    echo "⚠ Cannot find kernel config file"
fi

echo ""
echo "System is ready for kTLS!"
