#!/bin/bash
# Sync plugin to OPNsense dev VM and reload services.
# Usage: ./deploy-dev.sh
set -e

DEV_HOST="root@192.168.3.161"
SRC_DIR="$(cd "$(dirname "$0")" && pwd)/src"

if [ ! -d "$SRC_DIR" ]; then
    echo "src/ not found at $SRC_DIR"
    exit 1
fi

# Compile locale if msgfmt is present
if command -v msgfmt >/dev/null 2>&1; then
    for po in "$SRC_DIR"/opnsense/mvc/app/locale/*/LC_MESSAGES/*.po; do
        [ -f "$po" ] && msgfmt -o "${po%.po}.mo" "$po"
    done
fi

echo "==> rsync opnsense/* -> /usr/local/opnsense/"
rsync -az --delete \
    --include='controllers/OPNsense/Abuseipdb/***' \
    --include='models/OPNsense/Abuseipdb/***' \
    --include='views/OPNsense/Abuseipdb/***' \
    --include='widgets/Widgets/Abuseipdb/***' \
    --include='widgets/Api/Abuseipdb/***' \
    --include='scripts/OPNsense/Abuseipdb/***' \
    --include='service/conf/actions.d/actions_abuseipdb.conf' \
    --include='service/templates/OPNsense/Abuseipdb/***' \
    --include='*/' \
    --exclude='*' \
    "$SRC_DIR/opnsense/" "$DEV_HOST:/usr/local/opnsense/"

echo "==> rsync etc/rc.syshook.d -> /usr/local/etc/rc.syshook.d/"
rsync -az \
    "$SRC_DIR/etc/rc.syshook.d/start/20-abuseipdb" \
    "$DEV_HOST:/usr/local/etc/rc.syshook.d/start/"

echo "==> rsync locale .mo"
rsync -az \
    "$SRC_DIR/opnsense/mvc/app/locale/de_DE/LC_MESSAGES/de_DE.mo" \
    "$DEV_HOST:/usr/local/opnsense/mvc/app/locale/de_DE/LC_MESSAGES/" 2>/dev/null || true

echo "==> fix permissions on remote"
ssh "$DEV_HOST" "
    chmod +x /usr/local/opnsense/scripts/OPNsense/Abuseipdb/*.py 2>/dev/null || true
    chmod +x /usr/local/etc/rc.syshook.d/start/20-abuseipdb 2>/dev/null || true
"

echo "==> reload configd + webgui (no pfctl changes)"
ssh "$DEV_HOST" "
    service configd restart
    sleep 1
    configctl webgui restart
"

echo "==> smoke test: configctl abuseipdb stats"
ssh "$DEV_HOST" "configctl abuseipdb stats" 2>/dev/null || echo "(stats action not registered yet — ok if first deploy)"

echo "==> done"
