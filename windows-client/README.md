# edt1 WireGuard client — Windows (ELT3)

Two profiles, the hook script they call, and the one registry value Windows
requires before it will run hooks at all.

| File | What it is |
|---|---|
| `edt1-full.conf` | Full tunnel — **all** traffic via edt1, internet egressing `192.168.2.254` |
| `edt1-split.conf` | Split tunnel — only edt1's networks, local internet untouched |
| `wg-hooks.ps1` | The PreUp/PostUp/PreDown/PostDown implementation |

## Install

1. Copy `wg-hooks.ps1` to `C:\Program Files\edt1-wg\wg-hooks.ps1`.
2. **Enable hook execution.** WireGuard for Windows silently ignores
   `PreUp`/`PostUp`/`PreDown`/`PostDown` unless this is set — the tunnel still
   connects, the hooks just never run, with no warning:

   ```powershell
   New-Item -Path 'HKLM:\SOFTWARE\WireGuard' -Force | Out-Null
   Set-ItemProperty -Path 'HKLM:\SOFTWARE\WireGuard' -Name 'DangerousScriptExecution' -Value 1 -Type DWord
   ```

   The name is Microsoft's, not a warning about this script: it means *any*
   tunnel config can now run commands as SYSTEM. Only enable it if you control
   every `.conf` you import.
3. Put your client private key in the `[Interface] PrivateKey` line.
4. Import the `.conf` in the WireGuard app and activate.

Restart the WireGuard service after the registry change, or the running service
keeps the old setting.

## Which profile

Use **full** if you want what the routing goal specifies: everything, including
internet, leaves through edt1's gateway at `192.168.2.254`. Use **split** if you
only want edt1 access.

Two traps worth knowing before choosing split:

- **`192.168.2.0/24` collision.** That is edt1's LAN. If the network you connect
  *from* is also `192.168.2.x` — very common on home routers and hotspots — that
  entry captures your own default gateway and local connectivity dies. Remove it
  and reach edt1 by tunnel address instead.
- **DNS.** `edt1-split.conf` deliberately has no `DNS =` line. A resolver only
  reachable through the tunnel becomes the resolver for *everything* once the
  tunnel is up, so a degraded tunnel stops all name resolution and looks exactly
  like "the internet is down". The full profile sets `DNS = 172.16.4.1` because
  there all traffic is going through the tunnel anyway.

## What the hooks actually do

They deliberately **do not manage the tunnel's routes**. WireGuard installs
those from `AllowedIPs` and removes them on disconnect; competing with it leaves
a half-torn-down tunnel that blackholes traffic. Instead:

- **PreUp** — snapshots the pre-tunnel default route, DNS and forwarding state
  into an undo journal at `%TEMP%\edt1-wg\undo.jsonl`, before anything changes.
- **PostUp** — verifies the tunnel actually *carries traffic* (pings
  `172.16.0.1` through it) rather than trusting the "Active" label, then enables
  IPv4 forwarding so containers on this laptop can use the tunnel.
- **PreDown** — marks that teardown began, so an interrupted PostDown is
  distinguishable from one that never ran.
- **PostDown** — replays the journal in reverse and consumes it. Idempotent:
  running it twice, or after a crash, converges to the same state.

Logs and the journal land in `%TEMP%\edt1-wg\`.

## The ELT3 container subnet

`172.16.2.0/25` is the container network on this laptop. edt1 already routes it:
the peer's `AllowedIPs` includes it, and edt1 masquerades that range onto every
destination network, so containers here reach edt1's subnets and the internet
through the tunnel exactly as the host does.

For that to work this machine must forward IPv4 — which is what `PostUp` sets
up. If hooks are disabled, enable it yourself:

```powershell
Set-NetIPInterface -InterfaceAlias '<tunnel name>' -AddressFamily IPv4 -Forwarding Enabled
```

## Verifying

From the client, once connected:

```powershell
Test-NetConnection 172.16.0.1 -InformationLevel Quiet   # the tunnel itself
Test-NetConnection 192.168.2.254 -InformationLevel Quiet # edt1's LAN gateway
Test-NetConnection 172.30.10.12 -Port 443                # the reverse proxy
```

On the full profile, confirm your egress is edt1's and not the local link:

```powershell
(Invoke-RestMethod https://api.ipify.org?format=json).ip   # expect 45.19.59.138
```

Every destination below is verified reachable from a tunnelled client:
`192.168.2.0/24`, `172.16.4.0/24`, `172.15.4.0/24`, `172.20.10.0/24`,
`172.30.10.0/24`, `10.90.0.0/24`, `10.88.0.0/16`, `192.168.122.0/24`, and the
internet via `192.168.2.254`.

The edt1 side keeps itself honest: `wg-policy-watch` reconciles the forwarding
and NAT rules against the stored policy every 10 seconds, so a client connecting
after podman or libvirt restarted still finds working routes.
