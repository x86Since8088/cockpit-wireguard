# wg-admin contract

The Cockpit plugin never runs raw commands. It calls ONE root helper,
`/usr/local/sbin/wg-admin`, with a narrow verb interface, always via
`cockpit.spawn(..., { superuser: "require" })`. Every verb prints JSON on stdout
and nothing else; diagnostics go to stderr. Exit 0 = success.

## Why this tool exists

WireGuard client setup "rarely results in anything other than lost communication"
because `AllowedIPs` means two different things on the two ends, and hand-editing
gets it backwards:

| Where | Meaning | Correct value |
|---|---|---|
| **Client** `[Peer] AllowedIPs` | what the client **routes into** the tunnel | every destination subnet the user wants to reach |
| **Server** `[Peer] AllowedIPs` | cryptokey routing: which source addresses this peer may **use**, and where the server sends replies | the client's `/32` **only** (plus subnets that client itself gateways) |

Putting the destination list on the server side is the single most common cause of
"the tunnel connects and nothing works": it makes the server route those subnets
*to the client*, and two peers claiming overlapping ranges silently fight — last
match wins. `wg-admin` derives both sides from one selection so they cannot
disagree.

Four more failure modes the generator handles automatically:

- **No `PersistentKeepalive`** behind NAT: the mapping expires (~2 min) and the
  tunnel goes one-way until the client sends again. Default `25`.
- **`net.ipv4.ip_forward=0`**: the tunnel is up, the server just will not forward.
- **No masquerade** for the tunnel source range: packets reach the target subnet
  and the replies have nowhere to go back to.
- **MTU too large**: handshake succeeds, ping succeeds, TCP hangs on the first
  large frame. Default `1420`.

## Destination catalogue (this host, EDT1)

| id | CIDR | description |
|---|---|---|
| `tunnel` | 172.16.0.0/24 | the WireGuard tunnel itself; always included except in `full` |
| `lan` | 192.168.2.0/24 | the physical LAN behind bridge0 |
| `static-edt` | 172.15.4.0/24 | podman static network (br-static-edt) |
| `lab` | 172.16.4.0/24 | lab network, static addressing, services via edy-proxy-go |
| `edy-lab` | 172.20.10.0/24 | libvirt edy-lab VM network; **hosts the headscale control plane** at 172.20.10.1:8085 |
| `elt-static` | 172.16.2.0/25 | reached through the ELT peer, not this host |
| `full` | 0.0.0.0/0 | default route through the tunnel |

## Presets

- `tunnel-only` → `tunnel`
- `lab`         → `tunnel`, `lab`, `static-edt`
- `lan`         → `tunnel`, `lan`
- `full`        → `full`

A client may hold MULTIPLE named configs. `lab` and `lan` are deliberately
separate profiles so one client can carry both and pick per session, which is
what "access 192.168.2.0/24 via a second config" means.

## Verbs

```
wg-admin catalogue                         -> { networks:[...], presets:{...} }
wg-admin list                              -> { clients:[ {name, ip, configs:[...], enabled} ] }
wg-admin new-client NAME [--ip A.B.C.D]    -> { name, ip, pubkey }
wg-admin add-config NAME CFG --routes a,b  -> { name, config, allowed_ips, path }
wg-admin get-config NAME CFG [--qr]        -> { conf: "<text>", qr: "<utf8 art>" }
wg-admin del-config NAME CFG               -> { ok:true }
wg-admin del-client NAME                   -> { ok:true }
wg-admin routing-status                    -> { ip_forward, rules:[{dest,iface,present}] }
wg-admin routing-set DEST on|off           -> { ok:true, changed:bool }
```

`--routes` takes catalogue ids, comma separated. The helper resolves ids to CIDRs
so the UI never hardcodes a subnet.

## Non-negotiables

- Private keys are generated with `wg genkey` under `umask 077` and stored
  `0600 root:root` in `/etc/wireguard/clients/NAME/`. They are emitted to the
  plugin only inside `get-config`, never logged, never echoed to a job log.
- The server peer entry is written with the client `/32` only.
- Every mutation is idempotent and re-runnable.

---

# Contract v2 — schema-driven UI, IPAM, client packages

## Design rule

The UI renders NOTHING it invented. Every form, control, validation rule and
recommendation is derived from `wg-admin schema` at load time. Adding a field to
the backend adds it to the UI with zero JS changes. This mirrors the pattern
already proven in cockpit-adlab.

## New verb: `schema`

```
wg-admin schema -> {
  version: 2,
  groups: [ { id, title, order, fields: [FIELD] } ],
  recommendations: [ RECO ]
}

FIELD = {
  id: "mtu",
  label: "MTU",
  control: "number" | "text" | "toggle" | "select" | "radio" | "cidr-set"
         | "readonly" | "password-reveal",
  default: <value>,           # effective default, resolved from config
  min/max: numbers            # control=number only
  options: [{value,label}]    # control=select/radio only
  pattern: "regex"            # control=text/cidr validation, JS-compatible
  placeholder: "…",
  help: "one-line plain-English explanation",
  breaks_when_wrong: "what fails if this is set badly",   # rendered as hint
  unit: "bytes"|"seconds"|null
}

RECO = {
  id: "needs-nat",
  when: { field: "routes", contains_any: ["lan","full"] },   # declarative, no JS eval
  level: "warn" | "info",
  text: "Routing to the LAN needs masquerade for 172.16.0.0/24 → bridge0. It is <state>.",
  check: "routing-status:lan"    # live check the UI runs to fill <state>
}
```

`when` supports: `contains_any`, `equals`, `not_equals`, `gt`, `lt`, `truthy`.
The UI implements ONLY these six operators; anything fancier belongs server-side.
NAT/gateway recommendations MUST be schema-driven: selecting `lan`/`full`/`lab`
surfaces whether the matching masquerade and ip_forward are live, with a one-click
fix that calls `routing-set`.

## New verbs: IPAM

```
wg-admin ipam-status                     -> { pool, reserved:[R], observed:[O], free:[ip], lru:[O] }
wg-admin ipam-reserve IP --name N [--mac M] [--pubkey K]  -> { ok, reservation:R }
wg-admin ipam-release IP                 -> { ok }
wg-admin ipam-scan [--net tunnel|lab|static-edt]          -> { scanned, alive:[{ip,mac,rtt_ms}], free:[ip] }

R = { ip, name, mac, pubkey, created, last_seen }
O = { ip, mac, pubkey, first_seen, last_seen, source: "arp"|"ping"|"wg"|"lease" }
```

- `ipam-scan` ping-sweeps the subnet (parallel, ≤2s/host budget), then reads the
  neighbor table for MACs. An IP is FREE only if it is (a) not reserved, (b) not
  alive to ping, (c) not in the neighbor table, and (d) not a wg peer tunnel IP.
- Identity: on L2 networks the MAC is the identity. The wg tunnel is L3 — peers
  have NO MAC; the public key is the identity and is recorded in the mac-shaped
  slot's `pubkey` field instead. The schema labels the column "MAC / WG key".
- Usage tracking: every scan upserts observed rows keyed by identity, updating
  `last_seen`. Persisted in /etc/wireguard/ipam.json (0600 root:root).
- Exhaustion: when `free` is empty, allocation returns the LEAST RECENTLY SEEN
  observed IP with `{ reused: true, warning: "..." }` and the UI MUST render the
  warning prominently. Never silently reuse.
- new-client allocation consults ipam: reserved and observed IPs are skipped.

## New verb: `client-package`

```
wg-admin client-package NAME CFG --os windows|linux|pfsense|opnsense|freebsd
  -> { os, files: [ {name, mode, content} ], instructions: "...", undo_note: "..." }
```

Emits a COMPLETE self-contained bundle per OS:

- Every bundle contains: the .conf; an install script that downloads/installs
  WireGuard idempotently for that OS; an `up` path; a `down` path; and UNDO data.
- UNDO CONTRACT: before changing any route/gateway/interface setting the scripts
  record the prior state to an undo file (JSON lines: {action, prev}). The down
  script replays the undo file in reverse: routes added are deleted, settings
  changed are restored, then the undo file is removed. Down must be safe to run
  twice (idempotent) and must not remove routes it did not add.
- linux: wg-quick with PostUp/PreDown hooks writing/consuming the undo file;
  detect systemd vs not; apt/dnf/pacman detection for install.
- windows: PowerShell — winget or official MSI download, service-based tunnel
  install, route recording via Get-NetRoute before/after, undo on uninstall.
- freebsd: pkg install wireguard-tools; rc.conf wg_enable handling; route(8)
  add/delete with undo; explicit note that /etc/rc.conf edits are backed up.
- pfsense / opnsense: DO NOT edit config.xml blindly. Emit the exact GUI/API
  steps plus a shell script (both are FreeBSD) that validates the tunnel from
  the CLI without persisting outside the WG interface; where the platform's own
  config system owns routing (it does), the script only VERIFIES and prints what
  the GUI must own — with the reasoning stated in `instructions`.
- All scripts must survive `sh -n` / PowerShell parse validation at generation
  time. The generator refuses to emit a bundle that fails its own linter.

## UI obligations (wgclient.js)

- Render controls STRICTLY from schema `control` types; no hand-built forms for
  schema-covered fields. Control style mapping: toggle→checkbox row with state
  pill; number→spinner with min/max; cidr-set→the destination toggle grid;
  select→native select; password-reveal→masked with reveal click.
- Recommendations panel re-evaluates on every field change (the six operators),
  and resolves each `check:` against live `routing-status`.
- IPAM panel: reservation table (IP, name, MAC/WG key, last seen), scan button
  with progress, free-IP picker in the client form, LRU-reuse warning banner.
- Script blocks: per-OS tabs, monospace, one-click copy, download as file.
