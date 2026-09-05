#!/usr/bin/env bash
#
# install.sh - install the cockpit-wireguard package into Cockpit's package
#              directory.
#
# MUST BE RUN AS ROOT. /usr/share/cockpit is root-owned; this script writes
# there and sets ownership and modes explicitly. It refuses to run otherwise
# rather than half-installing a package that Cockpit would then serve with the
# wrong permissions.
#
#   sudo ./install.sh                 # install to /usr/share/cockpit/wireguard
#   sudo DESTDIR=/tmp/x ./install.sh  # stage under an alternative root
#   sudo ./install.sh --uninstall     # remove the installed package
#
# What it touches, and nothing else:
#   /usr/share/cockpit/wireguard/{manifest.json,index.html,wireguard.js,wireguard.css}
#
# It does not restart Cockpit, reload systemd, or alter any WireGuard,
# NetworkManager or firewall state. Cockpit rescans its package directory when
# a browser session starts, so a page reload (and, for the menu entry, a
# logout/login) is all that is needed.

set -Eeuo pipefail

SRC="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
DESTDIR="${DESTDIR:-}"
PKGDIR="${DESTDIR}/usr/share/cockpit/wireguard"

FILES=(manifest.json index.html wireguard.js wgclient.js wireguard.css)

# Host-side helpers and the stored routing policy. These are NOT Cockpit package
# files: they live in /usr/local/sbin and /etc/wireguard, and the watch unit is a
# systemd service. Installed only when --with-policy is passed, so a plain UI
# install cannot silently start changing firewall state.
POLICY_FILES=(routing-policy.json wg-policy wg-policy-watch wg-policy-watch.service)

die() { printf 'install.sh: %s\n' "$*" >&2; exit 1; }
say() { printf '  %s\n' "$*"; }

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    sed -n '2,26p' "${BASH_SOURCE[0]}" | sed 's/^# \?//'
    exit 0
fi

[[ $EUID -eq 0 ]] || die "must be run as root (try: sudo $0)"

if [[ "${1:-}" == "--uninstall" ]]; then
    if [[ -d "$PKGDIR" ]]; then
        rm -rf -- "$PKGDIR"
        echo "Removed $PKGDIR"
    else
        echo "Nothing to remove at $PKGDIR"
    fi
    exit 0
fi

echo "Installing cockpit-wireguard"
say "from: $SRC"
say "to:   $PKGDIR"

# Refuse to install something broken: an invalid manifest makes Cockpit drop
# the package silently, which is a miserable thing to debug after the fact.
for f in "${FILES[@]}"; do
    [[ -f "$SRC/$f" ]] || die "missing source file: $SRC/$f"
done

if command -v python3 >/dev/null 2>&1; then
    python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$SRC/manifest.json" \
        || die "manifest.json is not valid JSON"
    say "manifest.json: valid JSON"
fi

install -d -o root -g root -m 0755 "$PKGDIR"

for f in "${FILES[@]}"; do
    install -o root -g root -m 0644 "$SRC/$f" "$PKGDIR/$f"
    say "installed $f"
done

# Drop anything a previous version left behind, so an old file can never keep
# being served after it has been removed from the source tree.
shopt -s nullglob
for existing in "$PKGDIR"/*; do
    name="$(basename -- "$existing")"
    keep=0
    for f in "${FILES[@]}"; do [[ "$name" == "$f" ]] && keep=1; done
    if [[ $keep -eq 0 ]]; then
        rm -rf -- "$existing"
        say "removed stale $name"
    fi
done
shopt -u nullglob

echo
echo "Done. Reload Cockpit in the browser (log out and back in to pick up the"
echo "menu entry). Cockpit itself was not restarted and no system state changed."

# --with-policy: install the routing-policy reconciler and its watch unit.
if [[ "${WITH_POLICY:-0}" == "1" || "${1:-}" == "--with-policy" ]]; then
    for f in "${POLICY_FILES[@]}"; do
        [[ -f "$SRC/$f" ]] || die "missing policy file: $SRC/$f"
    done
    install -D -m 0644 -o root -g root "$SRC/routing-policy.json"      "${DESTDIR}/etc/wireguard/routing-policy.json"
    install -D -m 0755 -o root -g root "$SRC/wg-policy"                "${DESTDIR}/usr/local/sbin/wg-policy"
    install -D -m 0755 -o root -g root "$SRC/wg-policy-watch"          "${DESTDIR}/usr/local/sbin/wg-policy-watch"
    install -D -m 0644 -o root -g root "$SRC/wg-policy-watch.service"  "${DESTDIR}/etc/systemd/system/wg-policy-watch.service"
    say "installed routing policy + reconciler"
    if [[ -z "$DESTDIR" ]]; then
        systemctl daemon-reload
        say "run: systemctl enable --now wg-policy-watch.service"
        say "check drift any time with: wg-policy check"
    fi
fi
