/*
 * wireguard-bulk-test.js - headless tests of wireguard.js's pure helpers:
 * combined-probe build/parse (run through a REAL /bin/sh), and the host-peer
 * bulk-select / filter / command-builder logic.
 *
 *     gjs tests/unit/wireguard-bulk-test.js
 */
"use strict";
const GLib = imports.gi.GLib;
const System = imports.system;

const HERE = GLib.path_get_dirname(System.programInvocationName);
const SRC = new TextDecoder().decode(
    GLib.file_get_contents(GLib.canonicalize_filename(HERE + "/../../wireguard.js", null))[1]);

let passes = 0, fails = 0;
function ok(c, l) { if (c) { passes++; print("  PASS  " + l); } else { fails++; print("  FAIL  " + l); } }
function section(t) { print("\n== " + t); }

function node(tag) {
    const n = {
        tag, children: [], attrs: {}, listeners: {}, style: {}, className: "", value: "",
        checked: false, disabled: false, parentNode: null, _t: "",
        classList: { add() {}, remove() {}, toggle() {}, contains() { return false; } },
        setAttribute(k, v) { this.attrs[k] = String(v); },
        getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; },
        appendChild(c) { this.children.push(c); c.parentNode = this; return c; },
        removeChild(c) { const i = this.children.indexOf(c); if (i >= 0) this.children.splice(i, 1); return c; },
        insertBefore(c) { this.children.push(c); return c; },
        addEventListener(t, f) { (this.listeners[t] = this.listeners[t] || []).push(f); },
        removeEventListener() {}, querySelector() { return null; },
        focus() {}, remove() {}
    };
    Object.defineProperty(n, "firstChild", { get() { return this.children[0] || null; } });
    Object.defineProperty(n, "textContent", {
        get() { return this._t + this.children.map(c => c.textContent).join(""); },
        set(v) { this.children = []; this._t = String(v); }
    });
    return n;
}
const byId = {};
globalThis.document = {
    readyState: "complete", hidden: false, documentElement: node("html"),
    createElement: node, createTextNode(t) { const n = node("#text"); n._t = String(t); return n; },
    getElementById(id) { return byId[id] || (byId[id] = node("div")); },
    addEventListener() {}, removeEventListener() {}, body: node("body")
};
globalThis.addEventListener = function () {};
globalThis.setInterval = function () { return 1; };
globalThis.clearInterval = function () {};
const store = {};
globalThis.localStorage = { getItem(k) { return k in store ? store[k] : null; },
                            setItem(k, v) { store[k] = String(v); } };
try { globalThis.window.matchMedia = undefined; } catch (e) {}
/* The page under test boots against a fake host: one wg0 with five peers. */
const NOW = Math.floor(Date.now() / 1000);
const key = n => ("PEER" + n + "A".repeat(43)).slice(0, 43) + "=";
let peers = [
    { k: key(1), hs: 0,        ip: "172.16.0.11/32" },       /* never */
    { k: key(2), hs: 0,        ip: "172.16.0.12/32" },       /* never */
    { k: key(3), hs: 0,        ip: "172.16.0.13/32" },       /* never */
    { k: key(4), hs: NOW - 900, ip: "172.16.0.14/32" },      /* stale */
    { k: key(5), hs: NOW - 10,  ip: "172.16.0.15/32", ep: "203.0.113.5:51820" }   /* connected */
];
const spawns = [];
function dumpText() {
    return ["wg0\t(hidden)\tIFACEPUB=\t51820\toff"].concat(peers.map(p =>
        ["wg0", p.k, "(none)", p.ep || "(none)", p.ip, p.hs, 100, 200, "off"].join("\t"))).join("\n") + "\n";
}
globalThis.cockpit = {
    spawn(argv, opts) {
        spawns.push({ argv: argv.slice(), opts });
        const script = argv[2] || "";
        if (argv[3] === "sh") {                       /* wg-admin / argv runner */
            const verb = argv[5];
            const out = JSON.stringify({ results: argv.slice(7).map(k => ({ key: k, ok: true })) });
            if (verb === "peer-remove") {
                const gone = argv.slice(7);
                peers = peers.filter(p => gone.indexOf(p.k) < 0);
            }
            return Promise.resolve(out + "\r\n\r\n@@RC@@0\r\n");
        }
        let o = "";
        const re = /@@S:(\w+)@@/g; let m;
        while ((m = re.exec(script))) {
            const body = m[1] === "hostDump" ? dumpText() : m[1] === "privilege" ? "0\n" : "";
            o += "@@S:" + m[1] + "@@\r\n" + body.replace(/\n/g, "\r\n") + "\r\n@@E:" + m[1] + ":0@@\r\n";
        }
        return Promise.resolve(o);
    }
};

(0, eval)(SRC);
const C = globalThis.WGPeers.compute;

function sh(script) {
    const [, out] = GLib.spawn_sync(null, ["/bin/sh", "-c", script], null, 0, null);
    return new TextDecoder().decode(out);
}

section("combined probe: one script, sections fail independently");
{
    const secs = [
        ["a", "echo hello; echo world"],
        ["b", "echo 'wg: Operation not permitted' >&2; exit 1"],
        ["c", "printf 'no newline'"],
        ["d", "echo oops >&2; exit 3"],
        ["e", "true"]
    ];
    const script = C.buildSections(secs);
    ok(script.indexOf("@@S:a@@") >= 0 && script.split("\n").length >= 5, "builds one script covering all sections");
    /* a pty would turn \n into \r\n; emulate that to prove the parser copes */
    const raw = sh(script).replace(/\n/g, "\r\n");
    const r = C.parseSections(raw, secs);
    ok(r.a.ok && r.a.data === "hello\nworld\n", "section a: ok, data intact (" + JSON.stringify(r.a.data) + ")");
    ok(!r.b.ok && r.b.denied && /not permitted/.test(r.b.error), "section b fails alone and is classed as a permission error");
    ok(r.c.ok && r.c.data === "no newline", "section c: output without trailing newline kept exactly");
    ok(!r.d.ok && !r.d.denied && r.d.error === "oops", "section d: non-permission failure carries its message");
    ok(r.e.ok && r.e.data === "", "section e: empty ok output");
    const trunc = C.parseSections(raw.slice(0, raw.indexOf("@@S:c@@")), secs);
    ok(trunc.a.ok && !trunc.c.ok && !trunc.d.ok, "a truncated reply keeps finished sections and fails the rest");
}

section("parseRc");
{
    const r = C.parseRc("some\r\nout\r\n\r\n@@RC@@4\r\n");
    ok(r.rc === 4 && r.out === "some\nout\n", "rc and merged output recovered from a pty-style reply");
    ok(C.parseRc("nothing").rc === null, "missing marker -> rc null");
}

/* ---- pure helpers ------------------------------------------------------ */
const mk = (k, hs, ip, ep) => ({ publicKey: k, handshake: hs, allowedIps: [ip], endpoint: ep || null });
const P = peers.map(p => mk(p.k, p.hs, p.ip, p.ep));

section("filter counts / filtering");
{
    const c = C.filterCounts(P);
    ok(c.all === 5 && c.never === 3 && c.stale === 1 && c.ok === 1, "counts: " + JSON.stringify(c));
    ok(C.filterPeers(P, { status: "never", text: "" }).length === 3, "status filter never -> 3");
    ok(C.filterPeers(P, { status: "all", text: "203.0.113" }).length === 1, "text filter matches endpoint substring");
    ok(C.filterPeers(P, { status: "all", text: "172.16.0.12" }).length === 1, "text filter matches allowed IP");
    ok(C.filterPeers(P, { status: "all", text: key(3).slice(0, 8).toLowerCase() }).length === 1, "text filter matches key, case-insensitive");
    ok(C.filterPeers(P, { status: "stale", text: "172.16.0.11" }).length === 0, "status and text combine with AND");
}

section("selection helpers");
{
    const sel = Object.create(null);
    const shown = C.filterPeers(P, { status: "never", text: "" });
    C.setAllShown(sel, shown, true);
    ok(C.selectedKeys(sel).length === 3 && !sel[key(4)] && !sel[key(5)], "select all shown selects only the filtered rows");
    C.setAllShown(sel, shown.slice(0, 1), false);
    ok(C.selectedKeys(sel).length === 2, "deselect-all-shown only touches the rows given");
    C.pruneSelection(sel, P.filter(p => p.publicKey !== key(2)));
    ok(C.selectedKeys(sel).length === 1 && sel[key(3)], "keys that disappear are dropped from the selection");
}

section("bulk command builder");
{
    const many = []; for (let i = 0; i < 250; i++) many.push(mk("K" + i, 0, "10.0.0." + (i % 250) + "/32"));
    const cmds = C.buildBulkCommands("wg0", many, [], false);
    ok(cmds.length === 3 && cmds[0].length === 3 + 100 && cmds[2].length === 3 + 50, "250 peers -> chunks of 100/100/50");
    ok(cmds[0].slice(0, 3).join(" ") === "/usr/local/sbin/wg-admin peer-remove wg0", "exact argv prefix");
    ok(cmds[0][3] === "K0" && cmds[1][3] === "K100", "keys in order, no loss between chunks");
    const one = C.buildBulkCommands("wg0", [mk("KA=", 0, "172.16.0.5/32"), mk("KB=", 0, "172.16.0.6/32")], [], false);
    ok(JSON.stringify(one) === JSON.stringify([["/usr/local/sbin/wg-admin", "peer-remove", "wg0", "KA=", "KB="]]), "single exact argv");
}

section("batch del-client mapping by IP");
{
    const cl = [{ name: "alice", ip: "172.16.0.11" }, { name: "bob", ip: "172.16.0.12" }, { name: "carol", ip: "172.16.0.99" }];
    const sel = P.slice(0, 3);                              /* .11 .12 .13 */
    const m = C.matchClients(sel, cl);
    ok(m.matched.length === 2 && m.unmatched.length === 1 && m.unmatched[0] === key(3), "matches by the peer's /32, leaves the rest");
    const on = C.buildBulkCommands("wg0", sel, cl, true);
    ok(JSON.stringify(on) === JSON.stringify([
        ["/usr/local/sbin/wg-admin", "del-client", "alice", "bob"],
        ["/usr/local/sbin/wg-admin", "peer-remove", "wg0", key(3)]]),
       "option ON: persistent del-client for matched, runtime peer-remove for unmatched");
    const off = C.buildBulkCommands("wg0", sel, cl, false);
    ok(off.length === 1 && off[0][1] === "peer-remove" && off[0].length === 3 + 3, "option OFF: everything via peer-remove");
    const notslash32 = C.matchClients([mk("KX=", 0, "172.16.0.11/24")], cl);
    ok(notslash32.matched.length === 0, "a /24 allowed-ip is not mistaken for the client's /32");
    const schema = C.bulkRemoveSchema("wg0", sel, cl);
    ok(schema.fields.length === 1 && schema.fields[0].value === true, "modal offers the clients option, default ON when any match");
    ok(C.bulkRemoveSchema("wg0", sel, []).fields.length === 0, "no option when no peer matches a client");
    const keys12 = []; for (let i = 0; i < 25; i++) keys12.push(mk("K" + i, 0, "10.9.0." + i + "/32"));
    ok(/and 15 more/.test(C.bulkRemoveSchema("wg0", keys12, []).extra[1].textContent), "modal lists ~10 keys then 'and N more'");
}

/* ---- the real page: filter, select, repaint, remove ------------------- */
function walk(n, f, out) { out = out || []; if (f(n)) out.push(n); (n.children || []).forEach(c => walk(c, f, out)); return out; }
function text(n) { return n.textContent; }
const host = () => byId["wg-host-body"];
const delay = ms => new Promise(r => GLib.timeout_add(GLib.PRIORITY_DEFAULT, ms, () => { r(); return GLib.SOURCE_REMOVE; }));
const rowBoxes = () => walk(host(), n => n.tag === "input" && n.className === "wg-rowcheck" &&
                                     !(n.attrs["data-wg-focus"]));
const btn = (root, re) => walk(root, n => n.tag === "button" && re.test(text(n)))[0];

async function page() {
    await delay(100);
    section("page: toolbar above the table, filter chips with counts");
    const toolbar = walk(host(), n => n.className === "wg-toolbar")[0];
    const table = walk(host(), n => n.tag === "table")[0];
    const card = walk(host(), n => n.className === "wg-card")[0];
    ok(!!toolbar && card.children.indexOf(toolbar) < card.children.indexOf(walk(card, n => n.className === "wg-table-wrap")[0]),
       "toolbar precedes the peer table in the card");
    ok(!!btn(toolbar, /^Add peer$/) && !!btn(toolbar, /^Set port$/), "Add peer / Set port live in the toolbar");
    ok(walk(toolbar, n => n.tag === "button" && /^Never connected \(3\)$/.test(text(n))).length === 1, "chip 'Never connected (3)'");
    ok(!!btn(toolbar, /^All \(5\)$/) && !!btn(toolbar, /^Stale \(1\)$/) && !!btn(toolbar, /^Connected \(1\)$/), "chips All/Stale/Connected with counts");
    ok(walk(table, n => n.tag === "tr").length === 1 + 5, "unfiltered: 5 rows");

    btn(toolbar, /^Never connected/).listeners.click[0]();
    ok(walk(host(), n => n.tag === "tr").length === 1 + 3, "never-connected filter: 3 rows");
    ok(/"status":"never"/.test(store["wg:peerfilter:wg0"] || ""), "filter persisted to localStorage");

    section("page: select all shown, survive the 5 s repaint");
    const selAll = walk(host(), n => n.attrs && n.attrs["data-wg-focus"] === "selall:wg0")[0];
    selAll.checked = true; selAll.listeners.change[0]();
    ok(rowBoxes().filter(b => b.checked).length === 3, "all three shown rows ticked");
    ok(!!btn(host(), /^Remove selected \(3\)$/), "button reads Remove selected (3)");
    byId["wg-refresh"].listeners.click[0]();                 /* forced poll + repaint */
    await delay(150);
    ok(rowBoxes().filter(b => b.checked).length === 3 && !!btn(host(), /^Remove selected \(3\)$/),
       "selection survives a poll repaint");
    peers = peers.filter(p => p.k !== key(2));               /* a selected peer vanishes upstream */
    byId["wg-refresh"].listeners.click[0]();
    await delay(150);
    ok(!!btn(host(), /^Remove selected \(2\)$/), "a peer that disappears is dropped from the selection");

    section("page: bulk remove runs ONE spawn");
    btn(host(), /^Remove selected/).listeners.click[0]();
    const modal = byId["wg-modal-root"];
    ok(/Remove 2 peers from wg0/.test(text(modal)), "confirm modal shows the count");
    const pre = walk(modal, n => n.tag === "pre").map(text).join("\n");
    ok(pre.indexOf("/usr/local/sbin/wg-admin peer-remove wg0 " + key(1) + " " + key(3)) >= 0, "modal previews the exact command");
    ok(/Recently deleted for 30 days/.test(text(modal)), "modal says the peers go to Recently deleted for 30 days");
    const before = spawns.filter(s => s.argv[3] === "sh").length;
    btn(modal, /^Remove 2 peers$/).listeners.click[0]();
    await delay(300);
    const adm = spawns.filter(s => s.argv[3] === "sh");
    ok(adm.length === before + 1, "exactly one privileged spawn for the whole batch");
    ok(JSON.stringify(adm[adm.length - 1].argv.slice(4)) ===
       JSON.stringify(["/usr/local/sbin/wg-admin", "peer-remove", "wg0", key(1), key(3)]), "argv is exactly peer-remove wg0 K1 K3");
    ok(adm[adm.length - 1].opts.pty === true && adm[adm.length - 1].opts.err === "out", "spawn uses pty:true err:out");
    ok(!!btn(host(), /^Remove selected \(0\)$/), "selection is empty after the batch (Remove selected (0))");
    ok(spawns.filter(s => (s.argv[2] || "").indexOf("@@S:hostDump@@") >= 0).length >= 3, "a forced poll followed");
}

print("\nTOTAL: " + passes + " passed, " + fails + " failed");
let exitStatus = 0;
const loop = GLib.MainLoop.new(null, false);
page().then(() => {
    print("\nPAGE TOTAL: " + passes + " passed, " + fails + " failed");
    exitStatus = fails ? 1 : 0; loop.quit();
}, e => { logError(e, "harness crashed"); exitStatus = 2; loop.quit(); });
loop.run();
System.exit(exitStatus);
