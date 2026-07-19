#!/bin/sh
# Build a signed OPNsense-compatible pkg repository from one or more plugin
# packages, so they install via `pkg install` / the OPNsense plugin manager
# instead of a bare `pkg add` (which leaves them as "unknown-repository" ->
# "falsch konfiguriert"). Run on a FreeBSD host with pkg(8) (the OPNsense dev
# VM). Plain POSIX sh, no bashisms.
#
# Signing: RSA public-key scheme. `pkg repo <dir> <rsa-privkey>` signs the
# catalog; clients verify with `signature_type: pubkey` + the matching
# public key (itsnf.pub). The private key never leaves the build host.
#
# Usage:  sh build-repo.sh [pkg-file-or-dir ...]
#   With no args it collects every *.pkg under $DEFAULT_PKG_SRC.
set -eu

REPO_BASE=/root/itsnf-pkg-repo
KEY="$REPO_BASE/keys/repo.key"
PUB="$REPO_BASE/keys/itsnf.pub"
STAGE="$REPO_BASE/repo/latest"          # served at https://pkg.itsnf.de/latest
ALL="$STAGE/All"
DEFAULT_PKG_SRC=/root/os-abuseipdb-build/dist

if [ ! -f "$KEY" ]; then
    echo "!! signing key missing: $KEY" >&2
    exit 1
fi

# Resolve the package sources: explicit args (files or dirs) or the default dist
rm -rf "$STAGE"
mkdir -p "$ALL"

collect() {
    # copy every .pkg found in the given path (file or directory) into All/
    if [ -d "$1" ]; then
        find "$1" -type f -name '*.pkg' -exec cp {} "$ALL/" \;
    elif [ -f "$1" ]; then
        cp "$1" "$ALL/"
    else
        echo "!! not found, skipped: $1" >&2
    fi
}

if [ "$#" -gt 0 ]; then
    for src in "$@"; do collect "$src"; done
else
    collect "$DEFAULT_PKG_SRC"
fi

if [ -z "$(ls -A "$ALL" 2>/dev/null)" ]; then
    echo "!! no packages collected into $ALL" >&2
    exit 1
fi

echo "=== packages in repo ==="
ls -la "$ALL"

# Build + sign the catalog (meta.conf, packagesite.pkg, data.pkg, ...).
pkg repo "$STAGE" "$KEY"

# Drop the public key next to the catalog so the bootstrap can fetch it.
cp "$PUB" "$STAGE/itsnf.pub"

echo
echo "=== repo built + signed at $STAGE ==="
ls -la "$STAGE"
echo
echo "pubkey sha256: $(sha256 -q "$PUB")"
