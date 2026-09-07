# WireGuard client setup on EDT1

> "WireGuard client setup rarely results in anything other than lost communication."

That is not bad luck. WireGuard has one field, `AllowedIPs`, that means two
*different* things depending on which side of the tunnel it appears on, and every
tutorial shows both without distinguishing them. This page explains the trap; the
Cockpit panel exists so you never have to think about it again.

## The one thing that goes wrong

```
CLIENT config                          SERVER config
[Peer]                                 [Peer]
  PublicKey = <server>                   PublicKey = <client>
  AllowedIPs = 192.168.2.0/24  <-- (A)   AllowedIPs = 172.16.0.7/32  <-- (B)
```

- **(A) on the client is a routing table.** "Send traffic for these destinations
  into the tunnel." This is where your destination subnets go.
- **(B) on the server is an access-control list *and* a reverse routing table.**
  "Packets claiming these source addresses are allowed from this peer, and replies
  for these addresses go back to it." This must be the client's own address.

Put your destination list in (B) — the intuitive-looking mistake — and you have told
the server to route 192.168.2.0/24 *toward the client*. The handshake still
succeeds, `wg show` still looks healthy, and nothing works. Add a second client the
same way and they silently fight over the range: WireGuard picks the most recent
match, so one client works and the other dies at random.

**The panel derives both sides from one selection**, so they cannot disagree.

## The other four killers

| Symptom | Cause | Handled by |
|---|---|---|
| Works, then dies after ~2 minutes idle | no `PersistentKeepalive`; the NAT mapping expired | default `25` |
| Handshake fine, cannot reach any subnet | `net.ipv4.ip_forward=0` | Routing toggle |
| Reaches the subnet, no replies come back | no masquerade for the tunnel source range | Routing toggle |
| Ping works, SSH/HTTP hangs | MTU too high; large frames dropped | default `1420` |

Each of these produces a *healthy-looking* tunnel, which is why they eat so much
time. `wg show` reporting a recent handshake tells you the crypto works. It tells
you nothing about routing.

## Why two configs instead of one

One client profile cannot be "sometimes routed, sometimes not" — the routes are
baked into the file. So EDT1 issues **named configs per client**:

- **`lab`** → tunnel + `172.16.4.0/24` (lab) + `172.15.4.0/24` (static-edt).
  Reaches the lab and container networks. Leaves your local LAN alone.
- **`lan`** → tunnel + `192.168.2.0/24`. Reaches the physical LAN behind EDT1.

Keeping them separate is deliberate, and not only for tidiness: if you are sitting
on a home network that is *also* `192.168.2.0/24`, the `lan` profile will capture
your own subnet and cut you off from your local router and printer. Load `lab` in
that situation and `lan` only when you are on a different network. Both files can
live in the client at once — WireGuard clients on every platform let you pick which
tunnel to activate.

A `full` profile (`0.0.0.0/0`) is offered but routes *everything*, including your
default route and DNS, through EDT1. Use it for untrusted Wi-Fi, not day to day.

## Destination catalogue

| id | CIDR | what it is |
|---|---|---|
| `tunnel` | 172.16.0.0/24 | the tunnel itself; always present except in `full` |
| `lan` | 192.168.2.0/24 | physical LAN behind bridge0 |
| `static-edt` | 172.15.4.0/24 | podman static network (br-static-edt) |
| `lab` | 172.16.4.0/24 | lab network, static addressing, services via edy-proxy-go |
| `edy-lab` | 172.20.10.0/24 | libvirt VM network; headscale's login server lives here |
| `elt-static` | 172.16.2.0/25 | lives behind the ELT peer, not this host |
| `full` | 0.0.0.0/0 | default route through the tunnel |

## Checking a client that "connected but does nothing"

Ask in this order — each step assumes the previous passed:

1. `wg show` on the client: is there a **recent handshake**? No → endpoint, port
   forward, or firewall. The rest of this list is irrelevant until this passes.
2. Ping the server's tunnel address (`172.16.0.1`). Fails → `AllowedIPs` on the
   client does not include the tunnel subnet, or a key mismatch.
3. Ping something in the target subnet. Fails → server-side forwarding or the
   server's peer `AllowedIPs` is wrong (see the trap above).
4. Ping works but TCP hangs → MTU. Drop the client to 1380 and retest.
5. Works for two minutes then stops → `PersistentKeepalive`.

## If the client will also use headscale/tailscale

headscale's login server is bound to `172.20.10.1:8085` on the libvirt `virbr-edy`
bridge. Verified reachable from other routed networks on this host (a container on
`static-edt` gets HTTP 200 from `/health`), because the `FORWARD` policy is `ACCEPT`
and nothing blocks that path.

So a WireGuard client **can** complete a headscale join over the tunnel — but only if
its `AllowedIPs` include `172.20.10.0/24`. Enable the `edy-lab` destination for any
client that needs to enrol. Without it the tunnel comes up, headscale is simply
unreachable, and `tailscale up` times out against the login server with no
indication that routing is the reason.

Note this address is RFC1918: it is reachable *through* the tunnel, never from the
open internet. A client must therefore bring up WireGuard before it can enrol in
headscale.
