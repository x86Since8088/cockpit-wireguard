#!/bin/bash
# Syntax-check the plugin before installing. There is no build step for Cockpit
# plugins, so a stray paren ships straight to the browser and the panel renders
# blank with only a console error. gjs parses the file inside a never-called
# wrapper: parse errors surface, missing browser globals do not.
set -u
cd "$(dirname "$0")" || exit 1
rc=0
for f in *.js; do
    python3 -c "
import sys
src = open('$f').read()
open('/tmp/.syn-$f','w').write('function __never(cockpit, document, window){\n'+src+'\n}')
"
    if gjs /tmp/".syn-$f" 2>/tmp/.syn-err; then
        printf '  %-20s syntax OK\n' "$f"
    else
        printf '  %-20s SYNTAX ERROR\n' "$f"
        sed 's/^/      /' /tmp/.syn-err
        rc=1
    fi
    rm -f /tmp/".syn-$f" /tmp/.syn-err
done

# --- shell syntax, for the four helpers and the two scripts ------------------
for f in wg-admin wg-admin-package wg-policy wg-policy-watch install.sh deploy.sh; do
    [ -f "$f" ] || continue
    if bash -n "$f" 2>/tmp/.syn-err; then
        printf '  %-20s syntax OK\n' "$f"
    else
        printf '  %-20s SYNTAX ERROR\n' "$f"; sed 's/^/      /' /tmp/.syn-err; rc=1
    fi
    rm -f /tmp/.syn-err
done

# --- the standing greps (DEPLOY-CONTRACT.md section 4.4) ---------------------
# Each must print nothing. They are here, in the thing a developer already runs,
# rather than only in deploy.sh, because the mistake they catch is made while
# editing and should be caught then.
check_grep() {
    label=$1; shift
    out=$("$@" 2>/dev/null) || true
    if [ -n "$out" ]; then
        printf '  %-20s FAIL\n' "$label"; printf '%s\n' "$out" | sed 's/^/      /'; rc=1
    else
        printf '  %-20s clean\n' "$label"
    fi
}

HELPERS="wg-admin wg-admin-package wg-policy wg-policy-watch"
PAGEF="manifest.json index.html wireguard.js wgclient.js wireguard.css"

# 1. No shipped file ever names a source .env.
check_grep "grep 1 source/.env" grep -In -e 'source/\.env' -e '"\.env"' -e "'\.env'" -- $PAGEF $HELPERS

# 2. No helper resolves .env relative to itself. A deployed helper that could
#    look beside itself would read the dev checkout's test .env on a dev install.
check_grep "grep 2 self-relative" grep -In -e 'dirname.*\.env' -e '__file__.*\.env' -e 'BASH_SOURCE.*\.env' -- $HELPERS

# 3. Every helper that reads config reads install.conf, or reads nothing.
for h in $HELPERS; do
    grep -qI 'CFG\[' "$h" 2>/dev/null || continue
    grep -qI 'install\.conf' "$h" || { printf '  %-20s FAIL: reads a config but never install.conf\n' "$h"; rc=1; }
done

# 9. No dev root and no retired path in anything shipped. This one check would
#    have caught all thirteen occurrences in samba-ad-lab.
check_grep "grep 9 dev/retired" grep -In -e '/opt/sc/git' \
    -e '/srv/smb/share/sc/ai-orchestrator-group' \
    -- $PAGEF $HELPERS .envdefault etcdefaults/routing-policy.json systemd/wg-policy-watch.service.in

# The regression this whole exercise exists to close: every /usr/local/sbin
# helper the page names must be in install.sh's HELPERS array.
for h in $(grep -oh '/usr/local/sbin/[A-Za-z0-9_-]*' $PAGEF 2>/dev/null | sed 's#.*/##' | sort -u); do
    if grep -q "^HELPERS=(.*\b$h\b" install.sh; then
        printf '  %-20s declared in HELPERS\n' "$h"
    else
        printf '  %-20s FAIL: the page calls it, install.sh does not install it\n' "$h"; rc=1
    fi
done

exit $rc
