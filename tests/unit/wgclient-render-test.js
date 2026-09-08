/*
 * wgclient-render-test.js - headless render harness for the REAL shipped
 * wgclient.js at the repo root, run under gjs (no browser, no cockpit).
 *
 *     gjs tests/unit/wgclient-render-test.js
 *
 * A minimal DOM shim plus a fake cockpit.spawn drive the full UI:
 *   - `wg-admin schema` answers with schema-fixture.json, the
 *     contract-exact sample schema (test-only: the live UI always calls
 *     the real verb);
 *   - every other verb answers with contract-shaped canned JSON.
 *
 * What is asserted:
 *   1. every schema control type renders as the right element with the
 *      right attributes (and ip_forward, cidr-less, is NOT a route toggle)
 *   2. all six `when` operators fire; non-listed operators are rejected
 *   3. the recommendations panel reacts to a destination toggle flip,
 *      resolves <state> from routing-status, and its "Enable now" button
 *      calls routing-set and re-checks
 *   4. the IPAM panel renders (incl. the exact "MAC / WG key" column),
 *      the scan flow shows progress + summary, and reused:true from
 *      new-client renders the prominent warning banner
 *   5. the package panel renders five OS tabs, instructions above files,
 *      the undo callout, and masks the private key until revealed
 *   6. a Cockpit problem code is attributed to Cockpit, never to wg-admin
 */
"use strict";

const GLib = imports.gi.GLib;
const System = imports.system;

/* ------------------------------------------------------------------ *
 * Locate the shipped sources relative to this script
 * ------------------------------------------------------------------ */

const HERE = GLib.path_get_dirname(System.programInvocationName);
const SRC_DIR = GLib.canonicalize_filename(HERE + "/../..", null);

function readFile(path) {
    const [ok, bytes] = GLib.file_get_contents(path);
    if (!ok) throw new Error("cannot read " + path);
    return new TextDecoder().decode(bytes);
}

const WGCLIENT_SRC = readFile(SRC_DIR + "/wgclient.js");
const FIXTURE_TEXT = readFile(SRC_DIR + "/schema-fixture.json");
JSON.parse(FIXTURE_TEXT);   /* the fixture itself must be valid JSON */

/* ------------------------------------------------------------------ *
 * Assertion bookkeeping
 * ------------------------------------------------------------------ */

let passes = 0, fails = 0;
const failures = [];

function ok(cond, label) {
    if (cond) { passes++; print("  PASS  " + label); }
    else      { fails++; failures.push(label); print("  FAIL  " + label); }
}

function section(t) { print("\n== " + t + " =="); }

/* ------------------------------------------------------------------ *
 * DOM shim - just enough for wgclient.js
 * ------------------------------------------------------------------ */

function makeText(t) {
    const n = { children: [], parentNode: null, isText: true, _text: String(t) };
    Object.defineProperty(n, "textContent", {
        get() { return this._text; },
        set(v) { this._text = String(v); }
    });
    return n;
}

function makeNode(tag) {
    const node = {
        tag: String(tag).toLowerCase(),
        children: [],
        parentNode: null,
        attrs: {},
        listeners: {},
        _text: "",
        className: "",
        value: "",
        checked: false,
        disabled: false,
        style: {},
        setAttribute(k, v) {
            this.attrs[k] = String(v);
            if (k === "value") this.value = String(v);
        },
        getAttribute(k) { return (k in this.attrs) ? this.attrs[k] : null; },
        appendChild(c) {
            if (c.parentNode) c.parentNode.removeChild(c);
            c.parentNode = this;
            this.children.push(c);
            return c;
        },
        removeChild(c) {
            const i = this.children.indexOf(c);
            if (i >= 0) this.children.splice(i, 1);
            c.parentNode = null;
            return c;
        },
        insertBefore(n, ref) {
            if (n.parentNode) n.parentNode.removeChild(n);
            const i = ref ? this.children.indexOf(ref) : -1;
            if (i < 0) this.children.push(n);
            else this.children.splice(i, 0, n);
            n.parentNode = this;
            return n;
        },
        addEventListener(t, fn) {
            (this.listeners[t] = this.listeners[t] || []).push(fn);
        },
        removeEventListener() {},
        click() { fire(this, "click"); },
        select() {}
    };
    Object.defineProperty(node, "firstChild", {
        get() { return this.children.length ? this.children[0] : null; }
    });
    Object.defineProperty(node, "textContent", {
        get() {
            let s = this._text;
            this.children.forEach(c => { s += c.textContent; });
            return s;
        },
        set(v) { this.children = []; this._text = String(v); }
    });
    return node;
}

function fire(node, type, extra) {
    const ls = (node.listeners && node.listeners[type]) ? node.listeners[type].slice() : [];
    const ev = Object.assign({ type, target: node, preventDefault() {} }, extra || {});
    ls.forEach(fn => fn(ev));
}

/* tree helpers */
function all(root, pred, out) {
    out = out || [];
    if (pred(root)) out.push(root);
    (root.children || []).forEach(c => all(c, pred, out));
    return out;
}
function flat(root, out) {
    out = out || [];
    out.push(root);
    (root.children || []).forEach(c => flat(c, out));
    return out;
}
function hasClass(n, c) {
    return typeof n.className === "string" &&
           (" " + n.className + " ").indexOf(" " + c + " ") >= 0;
}
function byClass(root, c) { return all(root, n => hasClass(n, c)); }
function byTag(root, t) { return all(root, n => n.tag === t); }
function inputsOfType(root, t) {
    return all(root, n => n.tag === "input" && n.getAttribute &&
                          n.getAttribute("type") === t);
}
function buttonExact(root, label) {
    return all(root, n => n.tag === "button" && n.textContent === label);
}
function buttonContaining(root, label) {
    return all(root, n => n.tag === "button" && n.textContent.indexOf(label) >= 0);
}
function textOf(n) { return n ? String(n.textContent) : ""; }

/* ------------------------------------------------------------------ *
 * Globals the shipped file expects (window === globalThis)
 * ------------------------------------------------------------------ */

/* gjs already exposes `window` as a read-only alias of globalThis, which is
   exactly what the shipped file expects; only define it if absent. */
if (typeof globalThis.window === "undefined") {
    try { globalThis.window = globalThis; } catch (e) { /* alias exists */ }
}
if (globalThis.window !== globalThis)
    throw new Error("window is not globalThis; the shim cannot work here");
globalThis.document = {
    createElement: makeNode,
    createTextNode: makeText,
    body: makeNode("body"),
    getElementById() { return null; },
    execCommand() { return false; }
};
globalThis.__blobs = [];
globalThis.Blob = function (parts) {
    this.content = parts.map(String).join("");
    globalThis.__blobs.push(this);
};
globalThis.URL = {
    createObjectURL() { return "blob:test"; },
    revokeObjectURL() {}
};

/* ------------------------------------------------------------------ *
 * Fake cockpit - contract-shaped canned replies, mutable routing state
 * ------------------------------------------------------------------ */

const calls = [];
const superuserViolations = [];

const fakeState = {
    ipForward: true,
    lanPresent: false
};

const CATALOGUE = {
    networks: [
        { id: "tunnel",     cidr: "172.16.0.0/24", description: "the WireGuard tunnel itself" },
        { id: "lan",        cidr: "192.168.2.0/24", description: "the physical LAN behind bridge0" },
        { id: "lab",        cidr: "172.16.4.0/24", description: "lab network" },
        { id: "static-edt", cidr: "172.15.4.0/24", description: "podman static network" },
        { id: "full",       cidr: "0.0.0.0/0",     description: "default route through the tunnel" },
        { id: "ip_forward", cidr: "",              description: "routing-set control id, not a destination" }
    ],
    presets: {
        "tunnel-only": ["tunnel"],
        "lab": ["tunnel", "lab", "static-edt"],
        "lan": ["tunnel", "lan"],
        "full": ["full"]
    }
};

const IPAM_STATUS = {
    pool: "172.16.0.0/24",
    reserved: [
        { ip: "172.16.0.10", name: "printer", mac: "aa:bb:cc:dd:ee:ff", pubkey: "",
          created: "2026-08-01T10:00:00Z", last_seen: "2026-08-30T09:00:00Z" },
        { ip: "172.16.0.7", name: "laptop", mac: "",
          pubkey: "LaptopPubkey00000000000000000000000000000A0=",
          created: "2026-08-02T10:00:00Z", last_seen: "2026-09-01T07:30:00Z" }
    ],
    observed: [
        { ip: "172.16.0.31", mac: "11:22:33:44:55:66", pubkey: "",
          first_seen: "2026-08-10T00:00:00Z", last_seen: "2026-08-29T00:00:00Z",
          source: "arp" }
    ],
    free: ["172.16.0.50", "172.16.0.51"],
    lru: []
};

const CONF_TEXT = "[Interface]\nPrivateKey = SUPERSECRETFIXTUREKEY0000000000000000000000=\n" +
                  "Address = 172.16.0.7/32\nMTU = 1420\n" +
                  "[Peer]\nAllowedIPs = 172.16.0.0/24\n";

function packageFor(os, name, cfg) {
    return {
        os: os,
        files: [
            { name: name + "-" + cfg + ".conf", mode: "0600", content: CONF_TEXT },
            { name: (os === "windows") ? "install.ps1" : "install.sh", mode: "0755",
              content: "#!/bin/sh\necho install for " + os + "\n" }
        ],
        instructions: "1. Install WireGuard for " + os + ".\n" +
                      "2. Copy every file of this bundle into one folder.\n" +
                      "3. Run the install script with administrative rights.",
        undo_note: "The down script replays the undo file in reverse; run it " +
                   "before uninstalling so recorded routes are restored."
    };
}

function fakeReply(argv) {
    const verb = argv[1];
    switch (verb) {
    case "catalogue": return CATALOGUE;
    case "list":
        return { clients: [
            { name: "laptop", ip: "172.16.0.7", enabled: true,
              configs: [{ name: "lab",
                          allowed_ips: ["172.16.0.0/24", "172.16.4.0/24"] }] }
        ] };
    case "routing-status":
        return { ip_forward: fakeState.ipForward, rules: [
            { dest: "lan",        iface: "bridge0",       present: fakeState.lanPresent },
            { dest: "lab",        iface: "br-lab",        present: true },
            { dest: "static-edt", iface: "br-static-edt", present: true },
            { dest: "full",       iface: "eno1",          present: false }
        ] };
    case "routing-set":
        if (argv[2] === "lan") fakeState.lanPresent = (argv[3] === "on");
        if (argv[2] === "ip_forward") fakeState.ipForward = (argv[3] === "on");
        return { ok: true, changed: true };
    case "schema": return JSON.parse(FIXTURE_TEXT);
    case "ipam-status": return IPAM_STATUS;
    case "ipam-scan":
        return { scanned: "172.16.4.0/24",
                 alive: [ { ip: "172.16.4.1", mac: "aa:aa:aa:aa:aa:01", rtt_ms: 0.4 },
                          { ip: "172.16.4.2", mac: "aa:aa:aa:aa:aa:02", rtt_ms: 1.2 },
                          { ip: "172.16.4.7", mac: "aa:aa:aa:aa:aa:07", rtt_ms: 9.1 } ],
                 free: ["172.16.4.9", "172.16.4.10"] };
    case "new-client":
        return { name: argv[2], ip: "172.16.0.9", pubkey: "NewClientPub=",
                 reused: true,
                 warning: "The tunnel pool has no free address; reusing the least " +
                          "recently seen 172.16.0.9 (last seen 2026-07-01)." };
    case "get-config": return { conf: CONF_TEXT, qr: "QRART" };
    case "client-package": return packageFor(argv[5], argv[2], argv[3]);
    case "ipam-reserve": case "ipam-release":
    case "add-config": case "del-config": case "del-client":
        return { ok: true };
    default:
        return null;
    }
}

function goodCockpit() {
    return {
        spawn(argv, opts) {
            calls.push(argv.slice());
            if (!opts || opts.superuser !== "require")
                superuserViolations.push(argv.join(" "));
            const data = fakeReply(argv);
            if (data === null)
                return Promise.reject({ problem: "", exit_status: 2,
                                        message: "unknown verb " + argv[1] });
            return Promise.resolve(JSON.stringify(data));
        }
    };
}

function deniedCockpit() {
    return {
        spawn(argv, opts) {
            calls.push(argv.slice());
            if (!opts || opts.superuser !== "require")
                superuserViolations.push(argv.join(" "));
            return Promise.reject({ problem: "access-denied", message: "" });
        }
    };
}

/* async settle: give the promise chains a few main-loop turns */
function tick() {
    return new Promise(resolve => {
        GLib.idle_add(GLib.PRIORITY_LOW, () => { resolve(); return GLib.SOURCE_REMOVE; });
    });
}
async function flush(n) {
    for (let i = 0; i < (n || 8); i++) await tick();
}

function loadWGClient() {
    delete globalThis.WGClient;
    (0, eval)(WGCLIENT_SRC);
    return globalThis.WGClient;
}

function callsSince(mark, verb) {
    return calls.slice(mark).filter(a => a[1] === verb);
}

/* ------------------------------------------------------------------ *
 * The tests
 * ------------------------------------------------------------------ */

async function main() {

    /* ============================================================== */
    section("1. schema fixture renders every control type");

    globalThis.cockpit = goodCockpit();
    let WGClient = loadWGClient();
    ok(!!WGClient && typeof WGClient.render === "function",
       "shipped file loads and exports WGClient.render");

    const container = makeNode("div");
    WGClient.render(container, { heading: false });
    await flush();

    ok(superuserViolations.length === 0,
       "every cockpit.spawn used superuser:\"require\" so far");
    ok(["catalogue", "list", "routing-status", "schema", "ipam-status"].every(
           v => calls.some(a => a[1] === v)),
       "load calls all five read verbs (catalogue, list, routing-status, schema, ipam-status)");

    const manage = buttonExact(container, "Manage")[0];
    ok(!!manage, "client card for “laptop” offers a Manage button");
    fire(manage, "click");

    const builder = byClass(container, "wgc-builder")[0];
    ok(!!builder, "opening Manage renders the builder panel");

    /* number */
    const numbers = inputsOfType(builder, "number");
    ok(numbers.length === 2, "two control=number fields render as <input type=number> (mtu, keepalive)");
    const mtuIn = numbers.filter(n => n.getAttribute("min") === "1280")[0];
    ok(!!mtuIn && mtuIn.getAttribute("max") === "1500" && mtuIn.value === "1420",
       "mtu input carries min=1280 max=1500 and the schema default 1420");
    const mtuRow = byClass(builder, "wgc-srow-number")
        .filter(r => inputsOfType(r, "number").indexOf(mtuIn) >= 0)[0];
    ok(!!mtuRow && textOf(mtuRow).indexOf("bytes") >= 0,
       "mtu row shows the unit suffix “bytes”");
    ok(textOf(mtuRow).indexOf("Packet size on the tunnel interface.") >= 0,
       "help text renders under the mtu control");

    /* text + pattern */
    const dnsIn = all(builder, n => n.tag === "input" &&
                      n.getAttribute("placeholder") === "172.16.0.1")[0];
    ok(!!dnsIn && dnsIn.getAttribute("type") === "text",
       "control=text (dns) renders as a text input with its placeholder");

    /* select */
    const sels = byTag(builder, "select");
    ok(sels.length === 1, "control=select renders exactly one native <select>");
    ok(sels.length && byTag(sels[0], "option").length === 3 && sels[0].value === "auto",
       "select has the 3 schema options and the default value “auto”");

    /* radio */
    const radios = inputsOfType(builder, "radio");
    ok(radios.length === 3, "control=radio renders a 3-option radio group");
    ok(radios.filter(r => r.checked).length === 1 &&
       radios.filter(r => r.checked)[0].getAttribute("value") === "none",
       "exactly the default radio option (“none”) is checked");
    ok(radios.every(r => r.getAttribute("name") === radios[0].getAttribute("name")),
       "all radio inputs share one group name");

    /* cidr-set: catalogue-fed toggle grid, cidr-less ids filtered */
    const grid = byClass(builder, "wgc-toggles")[0];
    ok(!!grid, "control=cidr-set renders the destination toggle grid");
    const gridBoxes = inputsOfType(grid, "checkbox");
    ok(gridBoxes.length === 5,
       "grid has 5 route toggles (tunnel, lan, lab, static-edt, full)");
    ok(byClass(grid, "wgc-toggle-id").every(n => textOf(n) !== "ip_forward"),
       "ip_forward (cidr \"\") is NOT rendered as a route toggle");
    const idOf = box => textOf(byClass(box.parentNode, "wgc-toggle-id")[0]);
    const tunnelBox = gridBoxes.filter(b => idOf(b) === "tunnel")[0];
    ok(!!tunnelBox && tunnelBox.checked,
       "the schema default routes [\"tunnel\"] pre-checks the tunnel toggle");

    /* toggle (ip_forward, live) */
    const togRow = byClass(builder, "wgc-srow-toggle")
        .filter(r => textOf(r).indexOf("IPv4 forwarding") >= 0)[0];
    ok(!!togRow, "ip_forward appears in the routing group as a toggle field");
    ok(inputsOfType(togRow, "checkbox").length === 1 &&
       inputsOfType(togRow, "checkbox")[0].checked,
       "ip_forward toggle is a checkbox reflecting live routing-status (on)");
    ok(all(togRow, n => hasClass(n, "pill") && n.textContent === "on").length === 1,
       "ip_forward toggle row carries an “on” state pill");
    ok(all(togRow, n => hasClass(n, "pill") && n.textContent === "live").length === 1,
       "ip_forward toggle is marked live (backed by routing-set, applies immediately)");

    /* readonly */
    const roRow = byClass(builder, "wgc-srow-readonly")[0];
    ok(!!roRow && textOf(roRow).indexOf("FIXTUREServerPubkey") >= 0,
       "control=readonly renders label + value row (server public key visible)");

    /* password-reveal */
    const secretVal = "FIXTUREPresharedKeySECRET0000000000000000000=";
    const secRow = byClass(builder, "wgc-srow-password-reveal")[0];
    ok(!!secRow, "control=password-reveal renders its row");
    ok(textOf(builder).indexOf(secretVal) < 0 && textOf(secRow).indexOf("•") >= 0,
       "password-reveal value is masked: the secret is NOT in the DOM text");
    const revealBtn = buttonExact(secRow, "Reveal")[0];
    ok(!!revealBtn, "password-reveal offers a Reveal button");
    fire(revealBtn, "click");
    ok(textOf(secRow).indexOf(secretVal) >= 0, "clicking Reveal shows the value");
    fire(revealBtn, "click");
    ok(textOf(secRow).indexOf(secretVal) < 0, "clicking again masks it back");

    /* text pattern validation on input, using breaks_when_wrong */
    dnsIn.value = "not-an-ip";
    fire(dnsIn, "input");
    let dnsRow = byClass(builder, "wgc-srow-text")
        .filter(r => inputsOfType(r, "text").indexOf(dnsIn) >= 0)[0];
    ok(textOf(byClass(dnsRow, "wgc-srow-err")[0])
           .indexOf("wg-quick fail to bring the interface up") >= 0,
       "invalid text shows a red hint carrying breaks_when_wrong");
    dnsIn.value = "172.16.0.1";
    fire(dnsIn, "input");
    ok(textOf(byClass(dnsRow, "wgc-srow-err")[0]) === "",
       "a valid value clears the hint");

    /* number range validation, using breaks_when_wrong */
    mtuIn.value = "9000";
    fire(mtuIn, "input");
    ok(textOf(byClass(mtuRow, "wgc-srow-err")[0]).indexOf("Maximum is 1500") >= 0 &&
       textOf(byClass(mtuRow, "wgc-srow-err")[0]).indexOf("TCP hangs") >= 0,
       "out-of-range number shows min/max hint + breaks_when_wrong");
    mtuIn.value = "1420";
    fire(mtuIn, "input");
    ok(textOf(byClass(mtuRow, "wgc-srow-err")[0]) === "",
       "back in range clears the hint");
    await flush();

    /* ============================================================== */
    section("2. the six `when` operators - and only those six");

    const C = WGClient.compute;
    const get = vals => (id => vals[id]);

    ok(C.evalWhen({ field: "routes", contains_any: ["lan", "full"] },
                  get({ routes: ["tunnel", "lan"] })).fire === true &&
       C.evalWhen({ field: "routes", contains_any: ["lan", "full"] },
                  get({ routes: ["tunnel"] })).fire === false,
       "contains_any fires on intersection, not otherwise");
    ok(C.evalWhen({ field: "keepalive", equals: 0 }, get({ keepalive: "0" })).fire === true &&
       C.evalWhen({ field: "keepalive", equals: 0 }, get({ keepalive: "25" })).fire === false,
       "equals fires (numeric coercion: \"0\" equals 0)");
    ok(C.evalWhen({ field: "dns_mode", not_equals: "none" }, get({ dns_mode: "tunnel" })).fire === true &&
       C.evalWhen({ field: "dns_mode", not_equals: "none" }, get({ dns_mode: "none" })).fire === false,
       "not_equals fires on difference");
    ok(C.evalWhen({ field: "mtu", gt: 1420 }, get({ mtu: "1500" })).fire === true &&
       C.evalWhen({ field: "mtu", gt: 1420 }, get({ mtu: "1420" })).fire === false,
       "gt fires strictly above");
    ok(C.evalWhen({ field: "mtu", lt: 1320 }, get({ mtu: "1280" })).fire === true &&
       C.evalWhen({ field: "mtu", lt: 1320 }, get({ mtu: "1320" })).fire === false,
       "lt fires strictly below");
    ok(C.evalWhen({ field: "ip_forward", truthy: true }, get({ ip_forward: true })).fire === true &&
       C.evalWhen({ field: "ip_forward", truthy: true }, get({ ip_forward: false })).fire === false &&
       C.evalWhen({ field: "ip_forward", truthy: false }, get({ ip_forward: false })).fire === true,
       "truthy compares the field's truthiness against the operand");

    const rej = C.evalWhen({ field: "mtu", matches: "^14" }, get({ mtu: "1420" }));
    ok(rej.ok === false && rej.fire === false && rej.reason.indexOf("matches") >= 0,
       "a non-listed operator (matches) is rejected by name, never evaluated");
    ok(C.evalWhen({ field: "mtu", gt: 1, lt: 2 }, get({ mtu: "1.5" })).ok === false,
       "two operators in one `when` are rejected");
    ok(C.evalWhen({ field: "mtu" }, get({ mtu: "1420" })).ok === false,
       "`when` with no operator is rejected");

    const firing = C.recoFiring(
        [{ id: "a", when: { field: "x", truthy: true }, level: "info", text: "t", check: "" },
         { id: "b", when: { field: "x", regex: "y" }, level: "info", text: "t", check: "" }],
        get({ x: 1 }));
    ok(firing.firing.length === 1 && firing.firing[0].id === "a" &&
       firing.rejected.length === 1 && firing.rejected[0].reco.id === "b",
       "recoFiring separates firing recommendations from rejected ones");

    /* ============================================================== */
    section("3. recommendations react to a toggle flip, resolve live state, fix on click");

    let recoBox = byClass(builder, "wgc-reco-wrap")[0];
    ok(!!recoBox, "builder renders the recommendations box");
    ok(textOf(recoBox).indexOf("Forwarding is enabled host-wide") >= 0,
       "truthy reco (forward-on) fires with routes=[tunnel] already");
    ok(textOf(recoBox).indexOf("masquerade") < 0,
       "needs-nat-lan does NOT fire while lan is unselected");

    const lanBox = gridBoxes.filter(b => idOf(b) === "lan")[0];
    ok(!!lanBox, "grid has the lan toggle");
    const markFlip = calls.length;
    lanBox.checked = true;
    fire(lanBox, "change");

    ok(textOf(recoBox).indexOf("Routing to the LAN needs masquerade") >= 0,
       "flipping the lan toggle makes needs-nat-lan fire immediately");
    ok(textOf(recoBox).indexOf("It is NOT active.") >= 0,
       "check routing-status:lan resolves <state> to “NOT active” (rule absent)");
    ok(textOf(recoBox).indexOf("needs net.ipv4.ip_forward. It is ACTIVE.") >= 0,
       "check routing-status:ip_forward resolves <state> to “ACTIVE”");
    await flush();
    ok(callsSince(markFlip, "routing-status").length >= 1,
       "the field change re-reads routing-status live");

    const enableBtn = buttonExact(recoBox, "Enable now")[0];
    ok(!!enableBtn, "warn-level reco with a NOT-active check offers “Enable now”");
    const markFix = calls.length;
    fire(enableBtn, "click");
    await flush();
    ok(calls.slice(markFix).some(a => a[1] === "routing-set" && a[2] === "lan" && a[3] === "on"),
       "Enable now calls `routing-set lan on`");
    ok(callsSince(markFix, "routing-status").length >= 1,
       "…then re-checks routing-status");
    recoBox = byClass(builder, "wgc-reco-wrap")[0];
    ok(textOf(recoBox).indexOf("Routing to the LAN needs masquerade") >= 0 &&
       textOf(recoBox).indexOf("It is NOT active.") < 0 &&
       buttonExact(recoBox, "Enable now").length === 0,
       "after the fix the reco shows ACTIVE and the button is gone");

    /* ============================================================== */
    section("4. IPAM panel: table, scan flow, free-IP picker, reuse banner");

    let ipamCard = byClass(container, "wgc-ipam")[0];
    ok(!!ipamCard, "the IPAM card renders");
    const ths = byTag(ipamCard, "th").map(textOf);
    ok(ths.indexOf("IP") >= 0 && ths.indexOf("Name") >= 0 &&
       ths.indexOf("MAC / WG key") >= 0 && ths.indexOf("Last seen") >= 0,
       "reservation table columns are IP, Name, “MAC / WG key” (exact), Last seen");
    ok(textOf(ipamCard).indexOf("aa:bb:cc:dd:ee:ff") >= 0,
       "an L2 reservation shows its MAC in the identity column");
    ok(textOf(ipamCard).indexOf("LaptopPubkey") >= 0,
       "a tunnel reservation (no MAC) shows its WG public key instead");
    ok(textOf(ipamCard).indexOf("2 reserved · 1 observed · 2 free") >= 0,
       "the summary line reports reserved/observed/free counts");

    /* scan: per-net select, in-progress state, result summary */
    const scanSel = byClass(ipamCard, "wgc-scan")[0] &&
                    byTag(byClass(ipamCard, "wgc-scan")[0], "select")[0];
    ok(!!scanSel && byTag(scanSel, "option").map(textOf).join(",") ===
                    "tunnel,lab,static-edt",
       "scan offers exactly the contract nets tunnel/lab/static-edt");
    scanSel.value = "lab";
    fire(scanSel, "change");
    const markScan = calls.length;
    fire(buttonExact(ipamCard, "Scan")[0], "click");

    ipamCard = byClass(container, "wgc-ipam")[0];       /* repainted */
    const busyBtn = buttonContaining(ipamCard, "Scanning")[0];
    ok(!!busyBtn && busyBtn.disabled,
       "while the scan runs the button reads “Scanning…” and is disabled");
    await flush();
    ok(calls.slice(markScan).some(a => a[1] === "ipam-scan" && a[2] === "--net" && a[3] === "lab"),
       "Scan calls `ipam-scan --net lab` (the selected net)");
    ipamCard = byClass(container, "wgc-ipam")[0];
    ok(textOf(ipamCard).indexOf("3 alive, 2 free") >= 0,
       "the result summary reports N alive, M free");
    ok(callsSince(markScan, "ipam-status").length >= 1,
       "a finished scan re-reads ipam-status (last-seen data changed)");

    /* new-client form: free-IP picker + the mandatory reuse banner */
    fire(buttonExact(container, "Create client")[0], "click");
    const form = byClass(container, "wgc-form-card")[0];
    ok(!!form, "Create client opens the form");
    const nameIn = all(form, n => n.tag === "input" &&
                       n.getAttribute("placeholder") === "laptop")[0];
    const ipPicker = byTag(form, "select")[0];
    const opts = byTag(ipPicker, "option");
    ok(opts.length === 3 && textOf(opts[0]) === "(auto)" && opts[0].value === "" &&
       textOf(opts[1]) === "172.16.0.50" && textOf(opts[2]) === "172.16.0.51",
       "the IP picker offers “(auto)” plus the ipam-status free list");
    ok(ipPicker.value === "", "the picker defaults to (auto)");

    nameIn.value = "phone";
    const markNew = calls.length;
    fire(buttonExact(form, "Create")[0], "click");
    await flush();
    const newCalls = calls.slice(markNew).filter(a => a[1] === "new-client");
    ok(newCalls.length === 1 && newCalls[0][2] === "phone" &&
       newCalls[0].indexOf("--ip") < 0,
       "(auto) sends `new-client phone` with no --ip flag");
    const banner = byClass(container, "wgc-banner-warn")[0];
    ok(!!banner, "reused:true renders the prominent .wgc-banner-warn banner (not a toast)");
    ok(textOf(banner).indexOf("reusing the least recently seen 172.16.0.9") >= 0,
       "the banner carries the backend's warning text");
    ok(textOf(banner).indexOf("REUSED") >= 0 && buttonExact(banner, "Dismiss").length === 1,
       "the banner is explicit and sticky until dismissed");

    /* ============================================================== */
    section("5. client packages: five OS tabs, steps above files, masked key");

    const markPkg = calls.length;
    fire(buttonExact(container, "Package")[0], "click");
    await flush();

    let pkg = byClass(container, "wgc-pkg")[0];
    ok(!!pkg, "the package panel renders under the config row");
    const tabLabels = byClass(pkg, "wgc-tab").map(textOf);
    ok(tabLabels.join("|") === "Windows|Linux|pfSense|OPNsense|FreeBSD",
       "five OS tabs render: Windows / Linux / pfSense / OPNsense / FreeBSD");
    ok(calls.slice(markPkg).some(a => a[1] === "client-package" && a[2] === "laptop" &&
                                      a[3] === "lab" && a[4] === "--os" && a[5] === "windows"),
       "opening the panel calls `client-package laptop lab --os windows`");

    const steps = byClass(pkg, "wgc-pkg-steps")[0];
    ok(!!steps && byTag(steps, "li").length === 3,
       "instructions render as 3 numbered steps");
    ok(textOf(byTag(steps, "li")[0]) === "Install WireGuard for windows.",
       "the generator's own “1.” numbering is stripped from each step");
    const order = flat(pkg);
    const firstFile = byClass(pkg, "wgc-file")[0];
    ok(order.indexOf(steps) >= 0 && order.indexOf(firstFile) >= 0 &&
       order.indexOf(steps) < order.indexOf(firstFile),
       "instructions render ABOVE the files");
    ok(textOf(byClass(pkg, "wgc-undo-note")[0]).indexOf("replays the undo file in reverse") >= 0,
       "undo_note renders as a highlighted callout");

    const files = byClass(pkg, "wgc-file");
    ok(files.length === 2 &&
       textOf(byClass(files[0], "wgc-file-name")[0]) === "laptop-lab.conf" &&
       textOf(byClass(files[0], "wgc-file-mode")[0]) === "mode 0600" &&
       textOf(byClass(files[1], "wgc-file-mode")[0]) === "mode 0755",
       "each bundle file is a titled block with its mode note");
    ok(textOf(pkg).indexOf("SUPERSECRETFIXTUREKEY") < 0 &&
       textOf(byClass(files[0], "wgc-file-body")[0]).indexOf("•") >= 0,
       "the .conf private key is masked until revealed");
    ok(buttonExact(files[0], "Copy").length === 1 &&
       buttonExact(files[0], "Download").length === 1,
       "each file offers copy-to-clipboard and a download");

    fire(buttonExact(files[0], "Reveal private key")[0], "click");
    pkg = byClass(container, "wgc-pkg")[0];
    ok(textOf(pkg).indexOf("SUPERSECRETFIXTUREKEY") >= 0,
       "Reveal shows the key in the .conf block");

    /* download goes through Blob, never a data: URI */
    globalThis.__blobs.length = 0;
    const files2 = byClass(pkg, "wgc-file");
    fire(buttonExact(files2[1], "Download")[0], "click");
    ok(globalThis.__blobs.length === 1 &&
       globalThis.__blobs[0].content.indexOf("echo install for windows") >= 0,
       "Download builds a Blob with the exact file content (no data: URI path)");

    const markLinux = calls.length;
    fire(buttonExact(pkg, "Linux")[0], "click");
    await flush();
    ok(calls.slice(markLinux).some(a => a[1] === "client-package" && a[5] === "linux"),
       "switching tab calls `client-package … --os linux`");
    pkg = byClass(container, "wgc-pkg")[0];
    ok(byClass(pkg, "wgc-file").length === 2 &&
       textOf(pkg).indexOf("Install WireGuard for linux.") >= 0,
       "the Linux bundle renders its own steps and files");

    /* ============================================================== */
    section("6. error attribution: a Cockpit problem code is never wg-admin's");

    const cls = WGClient.compute.classify;
    ok(cls({ problem: "terminated" }).blame === "cockpit",
       "classify: problem code “terminated” blames Cockpit");
    ok(cls({ problem: "access-denied" }).blame === "cockpit",
       "classify: “access-denied” blames Cockpit");
    ok(cls({ problem: "not-found" }).blame === "cockpit",
       "classify: “not-found” (helper missing) is a Cockpit report, not backend output");
    ok(cls({ problem: "", exit_status: 4, message: "boom" }).blame === "backend" &&
       cls({ problem: "", exit_status: 4, message: "boom" }).detail === "boom",
       "classify: empty problem + exit_status blames wg-admin and quotes its stderr");

    globalThis.cockpit = deniedCockpit();
    WGClient = loadWGClient();                 /* fresh closure state */
    const container2 = makeNode("div");
    WGClient.render(container2, { heading: false });
    await flush();

    const gate = byClass(container2, "wg-alert")[0];
    ok(!!gate && textOf(gate).indexOf("Administrative access is required") >= 0,
       "an access-denied load renders the privilege gate panel");
    ok(textOf(gate).indexOf("Source: Cockpit") >= 0,
       "the panel names Cockpit as the source");
    ok(textOf(gate).indexOf("privilege escalation declining, not wg-admin") >= 0 &&
       textOf(gate).indexOf("exited") < 0,
       "the panel explicitly says wg-admin never ran - the code is not backend output");

    /* ============================================================== */
    section("7. hygiene");

    ok(superuserViolations.length === 0,
       "all " + calls.length + " spawns used superuser:\"require\"");
    ok(WGCLIENT_SRC.indexOf("console.") < 0,
       "the shipped file contains no console.* calls at all (secrets can never leak there)");
    ok(WGCLIENT_SRC.indexOf("data:") < 0 || WGCLIENT_SRC.indexOf("createObjectURL") >= 0,
       "downloads use Blob + object URL");

    const fixtureSchema = WGClient.compute.normaliseSchema(JSON.parse(FIXTURE_TEXT));
    ok(fixtureSchema.ok && fixtureSchema.version === 2 &&
       fixtureSchema.groups.length === 2 && fixtureSchema.recommendations.length === 7,
       "the fixture normalises: version 2, 2 groups, 7 recommendations");
    const controls = [];
    fixtureSchema.groups.forEach(g => g.fields.forEach(f => controls.push(f.control)));
    ok(["number", "text", "toggle", "select", "radio", "cidr-set", "readonly",
        "password-reveal"].every(c => controls.indexOf(c) >= 0),
       "the fixture exercises all eight documented control types");
}

/* ------------------------------------------------------------------ *
 * Run under a main loop so promise chains and idle sources settle
 * ------------------------------------------------------------------ */

let exitStatus = 0;
const loop = GLib.MainLoop.new(null, false);
main().then(() => {
    print("\n---------------------------------------------");
    print("TOTAL: " + passes + " passed, " + fails + " failed");
    if (fails) {
        print("Failed assertions:");
        failures.forEach(f => print("  - " + f));
        exitStatus = 1;
    }
    loop.quit();
}, e => {
    logError(e, "harness crashed");
    exitStatus = 2;
    loop.quit();
});
loop.run();
System.exit(exitStatus);
