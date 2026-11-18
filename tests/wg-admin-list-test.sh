#!/bin/bash
# wg-admin-list-test.sh - `wg-admin list` carries each client's public key and
# never any private key or PSK. wg-admin is SOURCED (no dispatch), state dirs are
# a temp tree, `wg` is a mock. Runs as a normal user, never touches /etc/wireguard.
#     bash tests/wg-admin-list-test.sh
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
[[ $EUID -ne 0 ]] || { echo "run as a normal user"; exit 2; }
mkdir -p "$T/bin" "$T/state/clients"
cat > "$T/bin/wg" <<'SH'
#!/bin/bash
# only `show <if> peers` is used by list (peer_present)
if [[ "$1" == show && "$3" == peers ]]; then cat "$MOCKPEERS"; elif [[ "$1 $2" == "show interfaces" ]]; then echo wg0; fi
SH
chmod +x "$T/bin/wg"
export MOCKPEERS="$T/peers" PATH="$T/bin:$PATH"; : > "$MOCKPEERS"
# shellcheck disable=SC1090
source "$HERE/../wg-admin"
set +e
STATE_DIR="$T/state"; CLIENTS_DIR="$STATE_DIR/clients"; WG_IF=wg0
pass=0; fail=0
ok() { if [[ "$2" == "1" ]]; then pass=$((pass+1)); echo "  PASS  $1"; else fail=$((fail+1)); echo "  FAIL  $1"; fi; }
j() { jq -r "$2" <<<"$1"; }
PUB1="FAKEPUBKEYalice0000000000000000000000000000="
PUB2="FAKEPUBKEYbob000000000000000000000000000000="
mk() { local d="$CLIENTS_DIR/$1"; mkdir -p "$d"; echo "PRIVSECRET-$1" > "$d/privatekey"
       echo "PSKSECRET-$1" > "$d/presharedkey"; echo "$2" > "$d/publickey"; echo "$3" > "$d/ip"
       printf '[Interface]\nPrivateKey = PRIVSECRET-%s\n[Peer]\nPresharedKey = PSKSECRET-%s\n' "$1" "$1" > "$d/cfg-laptop.conf"; }
mk alice "$PUB1" 172.16.0.2; mk bob "$PUB2" 172.16.0.3
mkdir -p "$CLIENTS_DIR/nokey"; echo 172.16.0.4 > "$CLIENTS_DIR/nokey/ip"
echo "$PUB1" > "$MOCKPEERS"

out="$(verb_list)"
ok "alice carries pubkey" "$([[ "$(j "$out" '.clients[]|select(.name=="alice").pubkey')" == "$PUB1" ]] && echo 1)"
ok "bob carries pubkey" "$([[ "$(j "$out" '.clients[]|select(.name=="bob").pubkey')" == "$PUB2" ]] && echo 1)"
ok "client without a key file gets empty pubkey" "$([[ "$(j "$out" '.clients[]|select(.name=="nokey").pubkey')" == "" ]] && echo 1)"
ok "existing fields intact (name, ip, configs, enabled)" "$([[ "$(j "$out" '.clients[]|select(.name=="alice")|[.name,.ip,.configs[0],.enabled]|join(",")')" == "alice,172.16.0.2,laptop,true" && "$(j "$out" '.clients[]|select(.name=="bob").enabled')" == false ]] && echo 1)"
ok "every client has exactly the 5 expected keys" "$([[ "$(j "$out" '[.clients[]|keys|join(",")]|unique|join(";")')" == "configs,enabled,ip,name,pubkey" ]] && echo 1)"
ok "no private key or PSK in list output" "$([[ "$out" != *PRIVSECRET* && "$out" != *PSKSECRET* && "$out" != *PrivateKey* && "$out" != *PresharedKey* ]] && echo 1)"

echo; echo "TOTAL: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
