#!/bin/sh
# Build an OPNsense-compatible FreeBSD pkg from the plugin sources.
# Run on a FreeBSD host (e.g. the OPNsense dev VM) — pkg(8) must be present.
# Plain POSIX sh, no bashisms (FreeBSD /bin/sh).
set -eu

NAME=os-abuseipdb
VERSION=0.1.1
ARCH=FreeBSD:14:amd64

ROOT="$(cd "$(dirname "$0")" && pwd)"
OUT="$ROOT/dist"
STAGE="$ROOT/work/stage"

rm -rf "$ROOT/work" "$OUT"
mkdir -p "$STAGE" "$OUT"

# Compile locales (best effort, skip if msgfmt missing or no .po files)
if command -v msgfmt >/dev/null 2>&1; then
    find "$ROOT/src/opnsense/mvc/app/views/OPNsense/Abuseipdb/locale" \
         -name '*.po' 2>/dev/null | while read -r po; do
        msgfmt -o "${po%.po}.mo" "$po"
    done
fi

# Stage layout (everything under /usr/local on the target)
mkdir -p "$STAGE/usr/local/opnsense/mvc/app/controllers/OPNsense/Abuseipdb"
mkdir -p "$STAGE/usr/local/opnsense/mvc/app/models/OPNsense/Abuseipdb"
mkdir -p "$STAGE/usr/local/opnsense/mvc/app/views/OPNsense/Abuseipdb"
mkdir -p "$STAGE/usr/local/opnsense/scripts/OPNsense/Abuseipdb"
mkdir -p "$STAGE/usr/local/opnsense/service/conf/actions.d"
mkdir -p "$STAGE/usr/local/opnsense/www/js/widgets/Metadata"
mkdir -p "$STAGE/usr/local/etc/rc.syshook.d/start"

cp -R "$ROOT/src/opnsense/mvc/app/controllers/OPNsense/Abuseipdb/"* \
      "$STAGE/usr/local/opnsense/mvc/app/controllers/OPNsense/Abuseipdb/"
cp -R "$ROOT/src/opnsense/mvc/app/models/OPNsense/Abuseipdb/"* \
      "$STAGE/usr/local/opnsense/mvc/app/models/OPNsense/Abuseipdb/"
cp -R "$ROOT/src/opnsense/mvc/app/views/OPNsense/Abuseipdb/"* \
      "$STAGE/usr/local/opnsense/mvc/app/views/OPNsense/Abuseipdb/"
cp -R "$ROOT/src/opnsense/scripts/OPNsense/Abuseipdb/"* \
      "$STAGE/usr/local/opnsense/scripts/OPNsense/Abuseipdb/"
cp    "$ROOT/src/opnsense/service/conf/actions.d/actions_abuseipdb.conf" \
      "$STAGE/usr/local/opnsense/service/conf/actions.d/"
cp    "$ROOT/src/opnsense/www/js/widgets/AbuseIPDB.js" \
      "$STAGE/usr/local/opnsense/www/js/widgets/"
cp    "$ROOT/src/opnsense/www/js/widgets/Metadata/AbuseIPDB.xml" \
      "$STAGE/usr/local/opnsense/www/js/widgets/Metadata/"
cp    "$ROOT/src/etc/rc.syshook.d/start/20-abuseipdb" \
      "$STAGE/usr/local/etc/rc.syshook.d/start/"

# Perms
chmod +x "$STAGE/usr/local/opnsense/scripts/OPNsense/Abuseipdb/"*.py \
         "$STAGE/usr/local/opnsense/scripts/OPNsense/Abuseipdb/"*.sh \
         "$STAGE/usr/local/etc/rc.syshook.d/start/20-abuseipdb"
# PHP scripts shouldn't be +x (they're invoked through php)

# Manifest
cat > "$ROOT/work/+MANIFEST" <<EOF
name: $NAME
version: "$VERSION"
origin: security/$NAME
comment: "OPNsense plugin for bidirectional AbuseIPDB integration"
desc: "AbuseIPDB blacklist downloader and reporter for OPNsense. Automatic pf-table population, firewall alias + WAN block rule, log-based reporter that submits firewall hits back to AbuseIPDB, dashboard widget, daily download and 5-min reporter cron."
maintainer: info@it-service-nf.de
www: https://github.com/KaiOppi/os-abuseipdb
abi: $ARCH
arch: $ARCH
prefix: /usr/local
licenselogic: single
licenses: [BSD2CLAUSE]
categories: [security, sysutils]
deps: { py311-requests: { origin: "www/py-requests", version: "0" } }
EOF

# Post-install: make sure our scripts are executable and state dir exists
cat > "$ROOT/work/+POST_INSTALL" <<'EOF'
#!/bin/sh
mkdir -p /var/db/abuseipdb
chmod 755 /var/db/abuseipdb
chmod +x /usr/local/opnsense/scripts/OPNsense/Abuseipdb/*.py \
         /usr/local/opnsense/scripts/OPNsense/Abuseipdb/*.sh \
         /usr/local/etc/rc.syshook.d/start/20-abuseipdb 2>/dev/null || true
service configd restart 2>/dev/null || true
EOF

# Pre-deinstall: we leave alias + rule + cron in place so admins can re-enable
# without losing the block protection during upgrades.
cat > "$ROOT/work/+PRE_DEINSTALL" <<'EOF'
#!/bin/sh
: # nothing to do
EOF

# Post-deinstall: clean state dir (state.sqlite can stay for re-install continuity)
cat > "$ROOT/work/+POST_DEINSTALL" <<'EOF'
#!/bin/sh
# keep /var/db/abuseipdb so reinstall keeps history; admin can rm -rf manually
:
EOF

# Generate a plist from the staged tree — paths relative to prefix (/usr/local).
( cd "$STAGE/usr/local" && find . -type f | sed 's|^\./||' ) > "$ROOT/work/pkg-plist"

cd "$ROOT/work"
pkg create -M +MANIFEST -r "$STAGE" -p pkg-plist -o "$OUT" -f pkg

echo
echo "=== built: ==="
ls -lh "$OUT"
