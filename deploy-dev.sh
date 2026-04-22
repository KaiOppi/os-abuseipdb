#!/bin/bash
# Sync plugin to OPNsense dev VM and reload services.
set -e

DEV_HOST="root@192.168.3.161"
SRC="$(cd "$(dirname "$0")" && pwd)/src"

# Compile .po -> .mo
if command -v msgfmt >/dev/null 2>&1; then
    for po in "$SRC"/opnsense/mvc/app/locale/*/LC_MESSAGES/*.po; do
        [ -f "$po" ] && msgfmt -o "${po%.po}.mo" "$po"
    done
fi

echo "==> syncing MVC controllers"
rsync -az --delete \
    "$SRC/opnsense/mvc/app/controllers/OPNsense/Abuseipdb/" \
    "$DEV_HOST:/usr/local/opnsense/mvc/app/controllers/OPNsense/Abuseipdb/"

echo "==> syncing MVC models"
rsync -az --delete \
    "$SRC/opnsense/mvc/app/models/OPNsense/Abuseipdb/" \
    "$DEV_HOST:/usr/local/opnsense/mvc/app/models/OPNsense/Abuseipdb/"

echo "==> syncing MVC views"
rsync -az --delete \
    "$SRC/opnsense/mvc/app/views/OPNsense/Abuseipdb/" \
    "$DEV_HOST:/usr/local/opnsense/mvc/app/views/OPNsense/Abuseipdb/"

echo "==> syncing scripts"
rsync -az --delete \
    "$SRC/opnsense/scripts/OPNsense/Abuseipdb/" \
    "$DEV_HOST:/usr/local/opnsense/scripts/OPNsense/Abuseipdb/"

echo "==> syncing configd actions"
rsync -az \
    "$SRC/opnsense/service/conf/actions.d/actions_abuseipdb.conf" \
    "$DEV_HOST:/usr/local/opnsense/service/conf/actions.d/"

echo "==> syncing locale .mo"
ssh "$DEV_HOST" "mkdir -p /usr/local/opnsense/mvc/app/locale/de_DE/LC_MESSAGES"
rsync -az \
    "$SRC/opnsense/mvc/app/locale/de_DE/LC_MESSAGES/de_DE.mo" \
    "$DEV_HOST:/usr/local/opnsense/mvc/app/locale/de_DE/LC_MESSAGES/" 2>/dev/null || true

echo "==> syncing rc hook"
rsync -az \
    "$SRC/etc/rc.syshook.d/start/20-abuseipdb" \
    "$DEV_HOST:/usr/local/etc/rc.syshook.d/start/"

echo "==> fixing permissions + reloading"
ssh "$DEV_HOST" "
    chmod +x /usr/local/opnsense/scripts/OPNsense/Abuseipdb/*.py || true
    chmod +x /usr/local/etc/rc.syshook.d/start/20-abuseipdb || true
    service configd restart
    sleep 1
    configctl webgui restart
"

echo "==> smoke test"
ssh "$DEV_HOST" "configctl abuseipdb stats" || true

echo "==> done"
