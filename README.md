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

## Install and deploy

There are **two** processes and they are not the same thing.

| | `install.sh` | `deploy.sh` / `deploy.ps1` / `deploy.bat` |
|---|---|---|
| What it is | An in-place install **by symlink**, from wherever it is run | The real deployment: a copy, then config, then `install.sh` |
| Moves bytes? | **No.** It links; it never copies the payload | Yes. It is the only thing that copies |
| Where it runs from | The payload — dev checkout *or* install path | The dev checkout |
| Owns `.env`? | No. Reads it, refuses without it | Yes. Seeds it from `.envdefault`, **missing-only** |
| Owns units? | Renders and places. Never enables or starts | Enables and starts, behind `--with-policy` |

The one idea: **the script is the same; only where it is run from differs.**

### Deploy (the normal case)

```sh
sudo ./deploy.sh                      # -> /opt/cockpit-wireguard
sudo ./deploy.sh --install-to /srv/x  # somewhere else
sudo ./deploy.sh --with-policy        # ...and enable the routing reconciler
sudo ./deploy.sh --verify             # standing checks only, change nothing
sudo ./deploy.sh --uninstall          # remove links and units, keep the tree
sudo ./deploy.sh --remove             # remove the deployed tree too
```

That produces:

```
/opt/cockpit-wireguard/payload -> payload-1.1.0/      bin/wg-admin, index.html, ...
/opt/cockpit-wireguard/.env                           your settings   0644 root:root
/etc/cockpit-wireguard/install.conf                   what install.sh did
/usr/share/cockpit/wireguard/*        -> payload/*    per-file symlinks
/usr/local/sbin/{wg-admin,wg-admin-package,wg-policy,wg-policy-watch} -> payload/bin/*
/etc/systemd/system/wg-policy-watch.service           rendered from systemd/*.in
```

**Unmount the share and all of that keeps working.** That is the acceptance
test, and `install.sh` asserts it after every deployed install: no symlink and
no unit may resolve into the dev tree.

### Dev install (live editing)

Run the *same* `install.sh` from the checkout. The Cockpit page becomes symlinks
into the checkout, so editing `wgclient.js` changes what the browser loads on the
next reload.

```sh
cp .envdefault .env         # TESTS ONLY, gitignored - see below
sudo ./install.sh
sudo ./install.sh --with-units    # only if you really want the unit rendered
sudo ./install.sh --uninstall
```

A dev install deliberately breaks when the share is unmounted — it *is* the
share. It also refuses to render a systemd unit without `--with-units`, because
two `wg-policy-watch` daemons reconciling one firewall against two policy files
is a confusing outage nobody should be able to cause by running an installer.

### Which install is this host running?

```sh
for d in /usr/share/cockpit/*/; do
    n=${d%/}; n=${n##*/}
    t=$(readlink -f "$d/index.html" 2>/dev/null) || continue
    case $t in
      */ai-orchestrator-storage/*) k="DEV  (share)";;
      /opt/*)                                    k="prod (/opt)";;
      "")                                        k="?? no index.html";;
      *)                                         k="OTHER";;
    esac
    printf '%-12s %s  %s\n' "$n" "$k" "$t"
done
```

> The snippet matches on `*/ai-orchestrator-storage/*` rather than the full
> share path, and this table says "retired checkout path" rather than spelling
> one. That is not squeamishness: `README.md` ships to the install path, and
> check 9 greps every shipped file for the dev root and for the retired
> `/opt/sc/...` prefix. The check is deliberately blunt - it cannot tell prose
> from a hardcoded path, and an exemption list for "files where it is only
> documentation" is a list that grows until the check means nothing. Rewording
> two lines is the cheaper half of that trade, and the wildcard match is better
> documentation anyway: it works wherever the share is mounted.


Or read `/etc/cockpit-wireguard/install.conf`, which records `INSTALL_KIND`,
`INSTALL_PATH`, `PAYLOAD`, `ENV_FILE` and `UNITDIR`.

Neither script ever restarts `cockpit.socket`. Reload the browser; the
**Networking → WireGuard** menu entry appears on the next login, because Cockpit
reads package manifests when a session starts.

```sh
cockpit-bridge --packages | grep wireguard
# wireguard    WireGuard    /usr/share/cockpit/wireguard
```

---

## Configuration: `.envdefault` → `[install path]/.env`

`.envdefault` is committed and fully commented. `deploy.sh` copies it to
`[install path]/.env` **only when that file does not exist** — an operator's
settings are never clobbered. When a new version adds a key, the deploy *says
so*, and `install.sh`'s pre-flight refuses if a required key is missing.

**A `.env` in this checkout is TESTS ONLY and is gitignored.** A deployed helper
cannot read it, and not by discipline: every helper resolves its configuration
as `$WG_ADMIN_ENV` (non-root only, owner-checked) → `ENV_FILE=` from
`/etc/cockpit-wireguard/install.conf` → **fail, naming install.conf**. There is
no "look beside me" step, because that step would land in the checkout on a dev
install.

A deployed `.env` carries **locations and settings, never secrets**. `deploy.sh`
refuses to write a key whose name looks like a credential and whose value is not
a path to one. WireGuard private keys live under `WG_STATE_DIR` at 0600.

---

## The helpers, and why each one ships

| helper | shipped? | why |
|---|---|---|
| `wg-admin` | **yes** | `wgclient.js` pins `/usr/local/sbin/wg-admin` in one constant and calls it for every client operation. Until this version the installer never mentioned it, so a fresh clone installed a UI with no backend. |
| `wg-admin-package` | **yes** | `wg-admin`'s `client-package` verb `exec`s it and dies "wg-admin-package not installed" without it. The page calls `client-package`, so it is a hard runtime dependency even though the page never names it. |
| `wg-policy` | **yes** | The routing reconciler. Run by an operator (`wg-policy check`) and by the watch unit. |
| `wg-policy-watch` | **yes** | `ExecStart` of `wg-policy-watch.service`. |

Not shipped, and deliberately: `check.sh`, `tests/`, `docs/`,
`schema-fixture.json`, `.git/`, any `.env`. `windows-client/` ships to a Windows
machine via `deploy.ps1`, not to this server.

**The completeness gate.** `install.sh` carries one declaration (`PAGE`,
`HELPERS`, `LIBS`, `UNITS`, `SEEDS`, `REQUIRED_ENV`) that `deploy.sh` *sources*
rather than restates — two lists that can disagree is the failure being designed
out. Nine pre-flight checks refuse before anything is written; check 3 greps the
shipped page files for `/usr/local/sbin/<x>` literals and refuses any hit that
`HELPERS` does not install. That is the check that catches the `wg-admin` bug,
and it is why each helper path must be **one top-of-file literal constant**: a
path assembled at runtime is invisible to it.

---

## Conformance

Against `cockpit-secrets/source/docs/DEPLOY-CONTRACT.md`, checked 2026-09-07:

| | |
|---|---|
| Deploys to `/opt/<project>`, payload versioned, `.env` a sibling | yes |
| `install.sh` resolves itself with `readlink -f`; links, never copies | yes |
| Per-file symlinks into a real `/usr/share/cockpit/wireguard` directory | yes |
| Refuses a `/usr/local/sbin` entry it does not own | yes |
| Writes `/etc/cockpit-wireguard/install.conf` | yes |
| Renders units; never enables, starts or stops them | yes |
| Never touches `cockpit.socket` | yes |
| No `rm -r` outside `remove_old_payload`'s three assertions | yes |
| `--uninstall` removes only declared entries and names the data it kept | yes |
| `.envdefault` in the §4.1 grammar; helpers resolve `.env` via `install.conf` | yes |
| All nine pre-flight checks and the post-install assertion present | yes |
| No retired checkout path and no dev-root literal in any shipped file | yes |

---

## Files

| file | purpose |
|---|---|
| `manifest.json` | Cockpit package manifest: menu label, order 45, keywords, docs links |
| `index.html` | page skeleton — no inline script, no inline styles |
| `wireguard.js` | monitoring page: probes, parsers, rendering, theming |
| `wgclient.js` | the client-management UI; speaks only to `wg-admin` |
| `wireguard.css` | self-contained stylesheet, light and dark |
| `wg-admin` | the only root entry point for the page; one verb per call, JSON out |
| `wg-admin-package` | per-OS client bundles; reached through `wg-admin client-package` |
| `wg-policy` | reconciles volatile forward/NAT rules against the stored policy |
| `wg-policy-watch` | runs `wg-policy` on a poll; `ExecStart` of the unit |
| `install.sh` | the symlink installer — the same script for dev and deployed |
| `deploy.sh` | the Linux deployment: copy a subset, seed `.env`, run `install.sh` |
| `deploy.ps1` / `deploy.bat` | deploys `windows-client/` to a Windows machine |
| `.envdefault` | the committed seed for `[install path]/.env` |
| `etcdefaults/routing-policy.json` | seed for the file `WG_POLICY_FILE` names, missing-only |
| `systemd/*.in` | unit templates; at-sign tokens substituted at install time |
| `check.sh` | syntax check plus the standing greps — run it before installing |

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
