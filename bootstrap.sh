#!/bin/sh
# Add the it-service-nf signed OPNsense plugin repository to this box.
# Run once, as root, in the OPNsense shell:
#
#   fetch -o - https://pkg.itsnf.de/bootstrap.sh | sh
#
# Afterwards install plugins the normal way, e.g.:
#   pkg install -y os-abuseipdb
# or via System -> Firmware -> Plugins in the GUI.
set -e

PUBKEY=/usr/local/etc/pkg/itsnf.pub
REPOCONF=/usr/local/etc/pkg/repos/itsnf.conf
BASEURL=https://pkg.itsnf.de/latest

echo "Fetching repository public key..."
fetch -q -o "$PUBKEY" "$BASEURL/itsnf.pub"

echo "Writing repository config to $REPOCONF ..."
cat > "$REPOCONF" <<EOF
itsnf: {
  url: "$BASEURL",
  signature_type: "pubkey",
  pubkey: "$PUBKEY",
  priority: 5,
  enabled: yes
}
EOF

echo "Updating package catalogues..."
pkg update

echo
echo "Done. The it-service-nf repository is now available."
echo "Install a plugin with e.g.:  pkg install -y os-abuseipdb"
