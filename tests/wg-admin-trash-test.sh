#!/bin/bash
# wg-admin-trash-test.sh - exercises the trash/undelete verbs of wg-admin
# against throwaway temp paths. NEVER touches /etc/wireguard: wg-admin is
# SOURCED (it only dispatches when executed), the state dirs are re-pointed at a
# temp tree, `wg` is a mock on PATH, and netplan_file is redefined to a temp
# file. Runs as a normal user.      bash tests/wg-admin-trash-test.sh
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
[[ $EUID -ne 0 ]] || { echo "run as a normal user"; exit 2; }
mkdir -p "$T/bin" "$T/state/clients"

# ---- mock wg: state in $T/wg.json {peers:{pub:{psk,ep,aips,ka}}} ----------------
cat > "$T/bin/wg" <<'PY'
#!/usr/bin/env python3
import json, os, sys
f = os.environ["MOCKWG"]
d = json.load(open(f)) if os.path.exists(f) else {"peers": {}}
a = sys.argv[1:]
def save(): json.dump(d, open(f, "w"))
if a[:2] == ["show", "interfaces"]: print("wg0")
elif a[0] == "show" and a[2] == "peers": print("\n".join(d["peers"]))
elif a[0] == "show" and a[2] == "allowed-ips":
    for k, p in d["peers"].items(): print(k + "\t" + p["aips"])
elif a[0] == "show" and a[2] == "latest-handshakes":
    for k in d["peers"]: print(k + "\t0")
elif a[0] == "show" and a[2] == "dump":
    print("PRIVATEKEYMUSTNEVERLEAK00000000000000000000=\tSERVERPUB\t51820\toff")
    for k, p in d["peers"].items():
        print("\t".join([k, p["psk"], p["ep"], p["aips"], "0", "0", "0", p["ka"]]))
elif a[0] == "set":
    i = 2
    while i < len(a):
        assert a[i] == "peer"; k = a[i+1]; i += 2
        if i < len(a) and a[i] == "remove":
            d["peers"].pop(k, None); i += 1; continue
        p = d["peers"].setdefault(k, {"psk": "(none)", "ep": "(none)", "aips": "(none)", "ka": "off"})
        while i < len(a) and a[i] != "peer":
            o, v = a[i], a[i+1]; i += 2
            if o == "allowed-ips": p["aips"] = v
            elif o == "endpoint": p["ep"] = v
            elif o == "persistent-keepalive": p["ka"] = v
            elif o == "preshared-key": p["psk"] = open(v).read().strip()
            else: sys.exit("bad opt " + o)
    save()
else: sys.exit("unsupported: " + " ".join(a))
PY
chmod +x "$T/bin/wg"
export MOCKWG="$T/wg.json" PATH="$T/bin:$PATH"

cat > "$T/np.yaml" <<'Y'
network:
  version: 2
  tunnels:
    wg0:
      mode: wireguard
      peers: []
Y

# ---- load wg-admin without dispatching ----------------------------------------
# shellcheck disable=SC1090
source "$HERE/../wg-admin"
set +e
STATE_DIR="$T/state"; CLIENTS_DIR="$STATE_DIR/clients"; LOCK_FILE="$STATE_DIR/.lock"
CONF_FILE="$STATE_DIR/wg-admin.conf"; TRASH_DIR="$STATE_DIR/trash"
IPAM_FILE_DEFAULT="$STATE_DIR/ipam.json"; WG_IF=wg0; TUNNEL_PREFIX=172.16.0
netplan_file() { printf '%s' "$T/np.yaml"; }
CFG_ERROR=""
export WG_ADMIN_TEST_MODE=1

pass=0; fail=0
ok() { if [[ "$2" == "1" ]]; then pass=$((pass+1)); echo "  PASS  $1"; else fail=$((fail+1)); echo "  FAIL  $1"; fi; }
j() { jq -r "$2" <<<"$1"; }
K() { printf '%s%s=' "$1" "$(printf 'A%.0s' $(seq 1 $((43 - ${#1}))))"; }   # 43 chars + '='
run() { ( "$@" ) 2>"$T/stderr"; }

mkclient() {   # name octet
    local d="$CLIENTS_DIR/$1"; mkdir -p "$d"
    printf 'priv-%s\n' "$1" > "$d/privatekey"; K "pk$1" > "$d/publickey"; echo >> "$d/publickey"
    printf '172.16.0.%s\n' "$2" > "$d/ip"; printf '[Interface]\nPrivateKey = x\n' > "$d/cfg-laptop.conf"
    python3 - "$MOCKWG" "$(K "pk$1")" "172.16.0.$2/32" <<'PY'
import json, os, sys
f, k, a = sys.argv[1:]
d = json.load(open(f)) if os.path.exists(f) else {"peers": {}}
d["peers"][k] = {"psk": "(none)", "ep": "(none)", "aips": a, "ka": "off"}
json.dump(d, open(f, "w"))
PY
}
# publickey file must hold exactly the key (verb reads with $(<file))
mkclient alice 2; mkclient bob 3; mkclient carol 4
for n in alice bob carol; do K "pk$n" > "$CLIENTS_DIR/$n/publickey"; done

echo "== single del-client"
out="$(run verb_del_client alice)"
ok "single output keeps ok/persisted/needs_apply + trash_id" "$([[ "$(j "$out" '.ok')" == true && "$(j "$out" '.trash_id')" == *-alice && "$(j "$out" 'has("persisted") and has("needs_apply")')" == true ]] && echo 1)"
ok "client dir moved, not shredded" "$([[ ! -d $CLIENTS_DIR/alice && -f $TRASH_DIR/$(j "$out" .trash_id)/client/privatekey ]] && echo 1)"
ok "trash dir 0700, meta 0600" "$([[ "$(stat -c %a "$TRASH_DIR")" == 700 && "$(stat -c %a "$TRASH_DIR/$(j "$out" .trash_id)/meta.json")" == 600 ]] && echo 1)"
ok "live peer removed" "$(grep -q "$(K pkalice)" "$MOCKWG" && echo 0 || echo 1)"
AID="$(j "$out" .trash_id)"

echo "== trash-list"
tl="$(run verb_trash_list)"
ok "retention 30, one client entry" "$([[ "$(j "$tl" .retention_days)" == 30 && "$(j "$tl" '.entries|length')" == 1 && "$(j "$tl" '.entries[0].kind')" == client && "$(j "$tl" '.entries[0].ip')" == 172.16.0.2 ]] && echo 1)"
ok "expires = deleted + 30d" "$([[ "$(j "$tl" '.entries[0].expires_at - .entries[0].deleted_at')" == 2592000 ]] && echo 1)"
ok "no key material in trash-list" "$([[ "$tl" != *priv-* && "$tl" != *PRIVATE* ]] && echo 1)"

echo "== IP held while trashed"
ok "alloc_ip skips the trashed client's .2" "$([[ "$(alloc_ip)" != 172.16.0.2 ]] && echo 1)"
ip_st="$(run verb_ipam_status)"
ok "ipam-status: .2 not free, listed as held with restorable_until" "$([[ "$(j "$ip_st" '[.free[]|select(.=="172.16.0.2")]|length')" == 0 && "$(j "$ip_st" '.held[0].ip')" == 172.16.0.2 && "$(j "$ip_st" '.held[0].note')" == "held (deleted, restorable until "* && "$(j "$ip_st" '.held[0].restorable_until')" == "$(j "$tl" '.entries[0].expires_at')" ]] && echo 1)"

echo "== multi del-client (one netplan rewrite)"
python3 - "$T/np.yaml" "$(K pkbob)" "$(K pkcarol)" <<'PY'
import sys, yaml
f = sys.argv[1]; d = yaml.safe_load(open(f))
d["network"]["tunnels"]["wg0"]["peers"] = [{"keys": {"public": k}, "allowed-ips": ["172.16.0.9/32"]} for k in sys.argv[2:]]
yaml.safe_dump(d, open(f, "w"))
PY
rm -f "$T/np.yaml.wg-admin.bak"
out="$(run verb_del_client bob carol ghost bad_name_ok bob)"
ok "multi results shape/counts" "$([[ "$(j "$out" '.results|length')" == 5 && "$(j "$out" .deleted)" == 2 && "$(j "$out" .failed)" == 1 ]] && echo 1)"
ok "missing name is ok+note, duplicate fails" "$([[ "$(j "$out" '.results[2].ok')" == true && "$(j "$out" '.results[2].note')" == "no such client" && "$(j "$out" '.results[4].error')" == "duplicate name" ]] && echo 1)"
ok "both peers gone from netplan in one rewrite" "$([[ "$(python3 -c "import yaml;print(len(yaml.safe_load(open('$T/np.yaml'))['network']['tunnels']['wg0'].get('peers') or []))")" == 0 ]] && echo 1)"
( run verb_del_client 'bad name' ) >/dev/null 2>&1; ok "invalid name rejected up front" "$([[ $? -ne 0 ]] && echo 1)"
tl="$(run verb_trash_list)"; ok "three client entries" "$([[ "$(j "$tl" '.entries|length')" == 3 ]] && echo 1)"
BID="$(j "$tl" '.entries[]|select(.name=="bob").id')"; CID="$(j "$tl" '.entries[]|select(.name=="carol").id')"

echo "== restore (client)"
out="$(run verb_restore "$AID")"
ok "restore ok, dir back, peer re-added, entry gone" "$([[ "$(j "$out" .restored)" == 1 && -f $CLIENTS_DIR/alice/privatekey && ! -d $TRASH_DIR/$AID ]] && grep -q "$(K pkalice)" "$MOCKWG" && echo 1)"
mkclient bob 3     # name reused
out="$(run verb_restore "$BID")"
ok "restore fails cleanly when the name was reused" "$([[ "$(j "$out" '.results[0].ok')" == false && "$(j "$out" '.results[0].error')" == *"exists now"* && -d $TRASH_DIR/$BID ]] && echo 1)"
rm -rf "$CLIENTS_DIR/bob"; mkclient dave 4
python3 - "$MOCKWG" "$(K pkcarol)" <<'PY'
import json,sys; f=sys.argv[1]; d=json.load(open(f)); d["peers"].pop(sys.argv[2],None); json.dump(d,open(f,"w"))
PY
out="$(run verb_restore "$CID")"
ok "restore fails cleanly when the IP was reused" "$([[ "$(j "$out" '.results[0].error')" == *"in use by something else"* && -d $TRASH_DIR/$CID ]] && echo 1)"
rm -rf "$CLIENTS_DIR/dave"

echo "== peer-remove / restore"
P1="$(K peerone)"; P2="$(K peertwo)"; P3="$(K peerthree)"
python3 - "$MOCKWG" "$P1" "$P2" "$P3" <<'PY'
import json,sys; f=sys.argv[1]; d=json.load(open(f))
d["peers"][sys.argv[2]]={"psk":"PSKSECRETVALUE000000000000000000000000000=","ep":"1.2.3.4:51820","aips":"10.9.0.1/32,10.9.1.0/24","ka":"25"}
d["peers"][sys.argv[3]]={"psk":"(none)","ep":"(none)","aips":"10.9.0.2/32","ka":"off"}
d["peers"][sys.argv[4]]={"psk":"(none)","ep":"(none)","aips":"10.9.0.3/32","ka":"off"}
json.dump(d,open(f,"w"))
PY
out="$(run verb_peer_remove wg0 "$P1" "$P2" "$(K nothere)")"
ok "results + counts" "$([[ "$(j "$out" .removed)" == 2 && "$(j "$out" .failed)" == 1 && "$(j "$out" '.results[2].ok')" == false ]] && echo 1)"
ok "PSK / private key never printed" "$([[ "$out" != *PSKSECRET* && "$out" != *PRIVATEKEY* && "$(cat "$T/stderr")" != *PSKSECRET* ]] && echo 1)"
ok "peers gone live, third untouched" "$( ! grep -q "$P1" "$MOCKWG" && grep -q "$P3" "$MOCKWG" && echo 1)"
PID1="$(j "$out" '.results[0].trash_id')"
ok "PSK in 0600 file inside entry; interface private key not stored anywhere" "$([[ "$(stat -c %a "$TRASH_DIR/$PID1/psk")" == 600 ]] && ! grep -rq PRIVATEKEYMUSTNEVERLEAK "$TRASH_DIR" && echo 1)"
tl="$(run verb_trash_list)"
ok "peer entry metadata, has_psk true, no psk text" "$([[ "$(j "$tl" ".entries[]|select(.id==\"$PID1\")|.has_psk")" == true && "$(j "$tl" ".entries[]|select(.id==\"$PID1\")|.allowed_ips|length")" == 2 && "$tl" != *PSKSECRET* ]] && echo 1)"
out="$(run verb_restore "$PID1")"
ok "peer restored with allowed-ips, endpoint, keepalive, PSK" "$([[ "$(j "$out" .restored)" == 1 ]] && python3 - "$MOCKWG" "$P1" <<'PY' && echo 1
import json,sys; p=json.load(open(sys.argv[1]))["peers"][sys.argv[2]]
sys.exit(0 if (p["aips"]=="10.9.0.1/32,10.9.1.0/24" and p["ep"]=="1.2.3.4:51820" and p["ka"]=="25" and p["psk"].startswith("PSKSECRET")) else 1)
PY
)"
( run verb_peer_remove wg9 "$P3" ) >/dev/null 2>&1; ok "unknown interface rejected" "$([[ $? -ne 0 ]] && echo 1)"
( run verb_peer_remove wg0 "bad;key" ) >/dev/null 2>&1; ok "bad key rejected" "$([[ $? -ne 0 ]] && echo 1)"

echo "== expiry with a faked clock"
rm -rf "$TRASH_DIR"; mkclient erin 5
out="$(run verb_del_client erin)"; EID="$(j "$out" .trash_id)"
now="$(date +%s)"
export WG_ADMIN_NOW=$((now + 29*86400)); run verb_trash_list >/dev/null
ok "still there at day 29" "$([[ -d $TRASH_DIR/$EID ]] && echo 1)"
export WG_ADMIN_NOW=$((now + 31*86400)); run verb_trash_list >/dev/null
ok "purged opportunistically at day 31" "$([[ ! -d $TRASH_DIR/$EID ]] && echo 1)"
unset WG_ADMIN_NOW
mkclient fred 6; out="$(run verb_del_client fred)"; FID="$(j "$out" .trash_id)"
export WG_ADMIN_NOW=$((now + 40*86400)); out="$(run verb_trash_purge --expired)"
ok "trash-purge --expired empties it; IP released" "$([[ ! -d $TRASH_DIR/$FID && "$(j "$out" .purged)" == 0 ]] && echo 1)"
unset WG_ADMIN_NOW
printf 'TRASH_DAYS=7\n' > "$CONF_FILE"; mkclient gina 7; out="$(run verb_del_client gina)"
tl="$(run verb_trash_list)"
ok "TRASH_DAYS from wg-admin.conf honoured" "$([[ "$(j "$tl" .retention_days)" == 7 && "$(j "$tl" '.entries[0].expires_at - .entries[0].deleted_at')" == 604800 ]] && echo 1)"
rm -f "$CONF_FILE"
WG_ADMIN_NOW=1 ; export WG_ADMIN_NOW
ok "clock override ignored without test mode" "$([[ "$(WG_ADMIN_TEST_MODE=0 now_epoch)" != 1 ]] && echo 1)"
unset WG_ADMIN_NOW

echo "== trash-purge"
GID="$(j "$tl" '.entries[0].id')"
out="$(run verb_trash_purge "$GID")"; ok "purge by id" "$([[ "$(j "$out" .purged)" == 1 && ! -d $TRASH_DIR/$GID ]] && echo 1)"
out="$(run verb_trash_purge "$GID")"; ok "purge of a gone id reports ok:false" "$([[ "$(j "$out" '.results[0].ok')" == false ]] && echo 1)"
( run verb_trash_purge '../etc' ) >/dev/null 2>&1; ok "path-ish id rejected" "$([[ $? -ne 0 ]] && echo 1)"
mkclient hal 8; run verb_del_client hal >/dev/null
out="$(run verb_trash_purge --all)"; ok "--all purges everything" "$([[ "$(j "$out" .purged)" -ge 1 && "$(j "$(run verb_trash_list)" '.entries|length')" == 0 ]] && echo 1)"

echo; echo "TOTAL: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
