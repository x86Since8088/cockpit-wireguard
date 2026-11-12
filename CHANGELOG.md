# Changelog

## 1.2.0

- Host peer table: toolbar above the table (Add peer, Set port, status chips
  All/Connected/Stale/Never connected with counts, text filter on key / endpoint /
  allowed IP, "Select all shown", per-row checkboxes, "Remove selected (N)").
  Selection is keyed by public key and survives the 5 s repaint; filters persist
  in localStorage. Selecting while filtered selects only the rows shown.
- Bulk remove opens the confirm modal with the count, the first 10 keys, the exact
  command(s), and "Also delete matching wg-admin clients (persistent)" (default on
  when a peer's /32 matches a client). One `wg-admin` call per 100 peers; the
  Clients list refreshes through the shared mutation queue.
- Clients section: the same toolbar, filter (All/Enabled/Disabled/No configs),
  select-all-shown and "Delete selected (N)", using one multi-name `del-client`.
- `wg-admin del-client` accepts several names (one lock, one netplan rewrite,
  per-name JSON results; single-name output unchanged apart from `trash_id`).
- 30-day undelete: deletes move data to `/etc/wireguard/trash` instead of shredding;
  new verbs `peer-remove`, `trash-list`, `restore`, `trash-purge`; trashed client
  IPs stay reserved (`ipam-status` `held`); "Recently deleted" panels with bulk
  Restore / Delete permanently; optional `wg-trash-purge.timer` (not auto-enabled).
- Host peer removal now goes through `wg-admin peer-remove` (snapshot first, still
  runtime-only).

## 1.1.4

- Work around a Cockpit 360 bridge file-descriptor leak: every non-pty `cockpit.spawn` left 1-2 pipe fds open in the privileged bridge, which hit its 1024-fd limit after a few minutes of polling and then failed every command with `internal-error`. All spawns now use `pty: true` (measured: 0 fds leaked), with stderr and exit status carried back as marker lines so error classification is unchanged.
- The host dashboard poll is one combined spawn instead of six (slow poll: one instead of four).
- New guard test `tests/unit/no-leaky-spawn-test.js` fails on any spawn without `pty: true`.

## 1.1.3 - 2026-11-12

Fixes the dashboard errors seen after deleting many peers/clients rapidly.

- `wireguard.js`: a forced `poll(true)` (issued after "Remove peer" etc.) was
  silently dropped while the 5s auto-poll was in flight, so the pre-removal
  snapshot repainted removed peers. A forced poll arriving mid-flight now sets
  a pending flag and exactly one trailing forced poll runs afterwards; the
  superseded snapshot is not painted, and collect results carry a poll
  generation so only the newest is applied.
- `wgclient.js`: all mutations (del-client, del-config, new-client, add-config,
  routing-set, ipam-*) share one client-side queue, so at most one wg-admin
  mutation is in flight (no more N concurrent privileged spawns timing out on
  wg-admin's flock). Queued rows show "Queued..."/"Deleting..."; the per-key
  double-click guard is kept.
- `refresh()` is single-flight with trailing coalescing and a generation
  counter: a stale `list` can no longer repaint deleted clients, and one
  refresh runs after the queue drains instead of one per mutation.
- A burst reports one aggregated notice ("Deleted 7 clients", or which changes
  failed) instead of last-writer-wins. Deleted clients/configs disappear from
  the list immediately on success.
- Transient faults (wg-admin lock timeout, Cockpit terminated/timeout/
  disconnected/internal-error) no longer raise the blocking gate; only genuine
  privilege / missing-helper faults do. Transient faults show as notices.
- Tests: new section 9 in `tests/unit/wgclient-render-test.js` and
  `tests/unit/wireguard-poll-test.js`.

## 1.1.2 - 2026-09-18

The client-config QR code is now a real scannable bitmap instead of terminal
text art, so a phone camera can read it straight off the page.

- `wg-admin get-config … --qr` returns `qr` as a `data:image/png;base64,…` URL.
  It runs `qrencode -t PNG -o - -s 6 -m 2` and base64-encodes the bytes; the
  pipeline forces `pipefail` on inside its own subshell so `qrencode`'s exit is
  what fails the step, not `base64`'s (which stays 0 on empty input). The `--qr`
  flag and the `qr` field name are unchanged; only the value's shape changed.
- `wgclient.js` renders the QR with `<img class="wgc-qr" src="<data url>">`
  instead of a `<pre>` of text art. The `--qr` fetch flow and the Show/Hide QR
  button are untouched.
- `wireguard.css` restyles `.wgc-qr` for an image: a centered white-padded block
  with a sensible max width and `image-rendering: pixelated` so the modules stay
  crisp when the bitmap is scaled.
- CONTRACT.md and the headless render test track the new shape; the test now
  asserts the viewer paints an `<img>` whose `src` is the helper's PNG data URL.

## 1.1.1 - 2026-09-07

Install classification is now decided by LAYOUT, not by a development-root path
prefix, and this plugin was deployed to its real install path on edt1.

- `install.sh` decides dev vs deployed by asking whether its own directory is
  what a sibling `payload` symlink resolves to. The old test compared `$SRC`
  against a hardcoded development root and got a checkout sitting ANYWHERE ELSE
  wrong: such a checkout classified itself `deployed`, so it skipped the
  group-writable warning, wrote INSTALL_KIND=deployed for a host that was not
  self-sustaining, and dropped "the checkout is not touched" from
  `--uninstall`. Reproduced before the change and confirmed fixed after.
- Because that literal is gone, pre-flight check 9 now scans `install.sh`
  itself. The carve-out that exempted it is removed. Both of the check's own
  patterns are split so the scanner cannot match itself; the string it searches
  for is unchanged, so nothing is weakened.
- `owned_by_us` recognises a dev link by `$SRC` rather than by "anywhere
  under the development root", which is tighter: it no longer adopts a link
  belonging to a different checkout of the same project.
- The uninstall notice and the dev warning ask the LINK TARGET's layout, so
  they stay correct when the deployed installer tears down links a dev install
  made.
- The self-sustaining assertion is stated positively: every link must resolve
  INSIDE the install path, rather than merely "not into the development share".
  That needs no path literal and is strictly stronger - a link into any other
  foreign tree fails it too. Unit paths must be inside the install path or on an
  FHS system prefix, so `ExecStart=/bin/sh -c ...` stays legal.
- wg-admin, wg-admin-package, wg-policy and wg-policy-watch are installed by the
  installer that declares them; deployed and verified on edt1.
A recursive grep of the deployed tree for the development root or the retired
checkout path now returns nothing at all.
