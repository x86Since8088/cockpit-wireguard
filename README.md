# cockpit-wireguard

A read-only Cockpit page showing the live state of both WireGuard instances on
this host: the NetworkManager-managed host tunnel `wg0`, and the containerised
`wg-easy` server.

Plain HTML, vanilla JS and CSS. **No build step, no npm, no node, no framework,
no vendored assets, no CDN.** The only script it loads besides its own is
Cockpit's `../base1/cockpit.js`.

---

## What it shows

**Summary tiles** — interface count, peer count, and the numbers that matter:
peers with a recent handshake, stale peers, peers that have never connected,
plus aggregate rx/tx.

**Host tunnels** — every interface `wg show` reports, with public key, listen
port, addresses, MTU, link state, and the NetworkManager connection that owns
it (`con-wg0`, generated from `/etc/netplan/90-NM-36e49541-*.yaml`).

**Containerised wg-easy** — container state from `podman ps`, image, the LAN
address it holds via macvlan (`192.168.2.250`), and its tunnel `wg0`
(`10.8.0.1/24`) read with `podman exec wg-easy wg show`. Peers are created and
revoked in wg-easy's own admin UI, which is linked from the card header
(`http://192.168.2.250:51821`); this page only reads.

**Per peer** — public key (truncated, full value on hover, click to expand),
endpoint, allowed-ips, last handshake as a relative time, rx/tx in IEC units,
persistent-keepalive, and whether a pre-shared key is configured.

Peer health is the headline signal, and it is carried by the row itself rather
than a badge you have to hunt for:

| state | meaning | appearance |
|---|---|---|
| `connected` | handshake within 3 minutes | green left rule, normal background |
| `stale` | handshake older than 3 minutes | amber left rule, amber row |
| `never` | no handshake has ever completed | red left rule, red row |

Peers sort worst-first, so anything wrong is at the top of the table.

**Routing & NAT** — `net.ipv4.ip_forward`, the state of `wg-lan-nat.service`,
and the `FORWARD` / `POSTROUTING` rules it installs, filtered to those naming a
WireGuard interface or one of the routed subnets (`172.16.0.0/24`,
`172.16.2.0/25`, `10.8.0.0/24`, `wg-shim`, `br-static-edt` for
`172.15.4.0/24`). The rule count is shown as "N of M total" so it is obvious
that filtering happened.

**Services** — `systemctl` state for `wg-quick@wg0`, `NetworkManager`,
`wg-easy`, `wg-lan-network` and `wg-lan-nat`, plus the WireGuard-carrying
NetworkManager connections.

The page refreshes every 5 seconds. Handshake ages tick every second in place,
without rebuilding the table, so an expanded key stays expanded. Polling pauses
while the tab is hidden and can be switched off entirely.

---

## Safety properties

**It never changes anything.** There is no button, no form and no code path in
this package that writes state. Every command it runs is a read: `wg show`,
`ip addr`, `podman ps`, `podman exec … wg show`, `systemctl show`, `nmcli
connection show`, `iptables -S`, `cat /proc/sys/net/ipv4/ip_forward`, `id -u`.
Nothing runs on load except those reads. The host's WireGuard is production;
this page is a window, not a control panel.

**It never displays a private or pre-shared key.** `wg show <if> dump` puts the
interface private key in the first field of the interface line — the second
field of `wg show all dump`, which prefixes the interface name — and each
peer's pre-shared key in its own field. Both are stripped by `awk` **on the
host**, so the secrets never cross the Cockpit channel at all:

```sh
o=$(wg show all dump) || exit $?
printf '%s\n' "$o" | awk -F'\t' 'BEGIN{OFS="\t"} \
    NF==5{$2="(hidden)"} NF==9 && $3!="(none)"{$3="(set)"} {print}'
```

The command substitution is what makes the exit status survive; a bare pipeline
would report `awk`'s success and silently swallow `Operation not permitted`.
The parser in `wireguard.js` additionally never reads those field indices, so
changing the `awk` program cannot quietly leak them into the DOM. Only the
*presence* of a pre-shared key is shown, as yes/no.

**It degrades instead of failing.** Every command runs with
`{ superuser: "try", err: "message" }`. With administrative access off, the
page still shows interface names, addresses, MTU, link state, NetworkManager
connections, systemd unit states and `ip_forward`, and each panel that needs
root says so and why — rather than rendering blank.

---

## Install

`install.sh` **must run as root**; `/usr/share/cockpit` is root-owned. It
refuses to run otherwise rather than half-installing a package Cockpit would
serve with the wrong permissions.

```sh
sudo ./install.sh                  # -> /usr/share/cockpit/wireguard
sudo DESTDIR=/tmp/stage ./install.sh   # stage under another root
sudo ./install.sh --uninstall      # remove it again
```

It validates `manifest.json` as JSON before copying, installs the four files
`root:root` mode `0644` into a `0755` directory, and deletes anything a
previous version left behind. It is idempotent. It does **not** restart
Cockpit, reload systemd, or touch WireGuard, NetworkManager or the firewall.

Reload the browser afterwards. The **Networking → WireGuard** menu entry
appears on the next login, because Cockpit reads package manifests when a
session starts.

Confirm Cockpit picked it up:

```sh
cockpit-bridge --packages | grep wireguard
# wireguard    WireGuard    /usr/share/cockpit/wireguard
```

---

## Files

| file | purpose |
|---|---|
| `manifest.json` | Cockpit package manifest: menu label, order 45, keywords, docs links |
| `index.html` | page skeleton — no inline script, no inline styles |
| `wireguard.js` | all logic: probes, parsers, rendering, theming |
| `wireguard.css` | self-contained stylesheet, light and dark |
| `install.sh` | root installer |

---

## Limitations

**Read-only, by design.** Peers cannot be added, removed or edited here. Use
wg-easy's admin UI for container peers, and netplan/NetworkManager for `wg0`.

**Most of the useful data requires root.** The kernel restricts `wg show` to
root, `wg-easy` is a *rootful* container so an unprivileged `podman` cannot see
it, and `iptables -S` needs root. Without Cockpit's administrative access the
page is a thin shell of itself. This is a property of the underlying tools, not
something the plugin can work around.

**"Stale" is a heuristic, not a fault.** WireGuard only rekeys when there is
traffic, so a perfectly healthy peer with an idle tunnel will show as stale
after 3 minutes. Read amber as "not currently passing traffic", not "broken".
Red (`never`) is the stronger signal. Adjust `STALE_SECS` at the top of
`wireguard.js` if 180 seconds is wrong for your traffic pattern.

**Unprivileged `podman exec` reports "no such container", not a permission
error.** Rootless podman honestly reports that `wg-easy` is absent from *its*
store. The page therefore runs `id -u` alongside the other probes and treats a
container miss as a privilege problem when it is not running as root. If you
ever run a *rootless* container also named `wg-easy`, that inference would be
wrong.

**Host-specific values are hardcoded** as constants at the top of
`wireguard.js` — `EASY_CONTAINER`, `EASY_UI`, `NM_CONNECTION`, `UNITS`, and the
subnet regex in `isWgRule()`. They match this host. Edit them for another.

**Polling cost.** Each 5-second tick spawns 6 short-lived processes, plus 4
more every 25 seconds. Small, but not free. Polling stops when the tab is
hidden and when auto-refresh is unchecked.

**Menu entry needs a re-login.** A browser reload picks up changed files but
not a changed manifest.

**`conditions` hides the package if `/usr/bin/wg` is missing.** That is
intentional, but it means an uninstalled `wireguard-tools` makes the plugin
vanish rather than show an error.

**IPv6.** Whatever `wg show` and `ip -j addr` report is displayed, but this
host's setup is IPv4-only (`DISABLE_IPV6=true` for wg-easy, `ipv6.method=
disabled` for `con-wg0`), so the IPv6 paths are untested here.

---

## Development notes

There is no `node` on this host and none is wanted. Two things still work:

**Syntax-check** with `gjs` (SpiderMonkey), which is installed:

```sh
gjs -c 'const s = imports.byteArray.toString(
    imports.gi.GLib.file_get_contents("wireguard.js")[1]);
  new Function(s); print("syntax OK");'
```

**Test the parsers** by capturing real command output to fixture files and
running the parser functions under `gjs`. The parsers (`parseWgDump`,
`parseIpJson`, `parseUnits`, `parseNmcli`, `parseNat`, `parsePs`) are pure
string-in/object-out functions with no DOM dependency, specifically so they can
be exercised this way.

**Check it in the browser** by loading the page with a shim `base1/cockpit.js`
that implements `cockpit.spawn()` over a small local HTTP endpoint, so the real
`index.html`/`wireguard.js`/`wireguard.css` can be loaded and their console read
without a Cockpit login.
