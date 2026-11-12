/*
 * wireguard-poll-test.js - headless test of the host-peer page's poll():
 * a FORCED poll issued while one is in flight (the post-"Remove peer" repaint)
 * must not be dropped; it is coalesced into exactly one trailing poll.
 *
 *     gjs tests/unit/wireguard-poll-test.js
 */
"use strict";
const GLib = imports.gi.GLib;
const System = imports.system;

const HERE = GLib.path_get_dirname(System.programInvocationName);
const SRC = new TextDecoder().decode(
    GLib.file_get_contents(GLib.canonicalize_filename(HERE + "/../../wireguard.js", null))[1]);

let passes = 0, fails = 0;
function ok(c, l) { if (c) { passes++; print("  PASS  " + l); } else { fails++; print("  FAIL  " + l); } }

function node(tag) {
    const n = {
        tag, children: [], attrs: {}, listeners: {}, style: {}, className: "", value: "",
        checked: true, disabled: false, parentNode: null, _t: "",
        classList: { add() {}, remove() {}, toggle() {}, contains() { return false; } },
        setAttribute(k, v) { this.attrs[k] = String(v); },
        getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; },
        appendChild(c) { this.children.push(c); c.parentNode = this; return c; },
        removeChild(c) { const i = this.children.indexOf(c); if (i >= 0) this.children.splice(i, 1); return c; },
        insertBefore(c) { this.children.push(c); return c; },
        addEventListener(t, f) { (this.listeners[t] = this.listeners[t] || []).push(f); },
        removeEventListener() {}, querySelector() { return null; },
        focus() {}, remove() {}, showModal() {}, close() {}
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
    readyState: "complete", hidden: false,
    documentElement: node("html"),
    createElement: node, createTextNode(t) { const n = node("#text"); n._t = String(t); return n; },
    getElementById(id) { return byId[id] || (byId[id] = node("div")); },
    addEventListener() {}, body: node("body")
};
globalThis.addEventListener = function () {};
globalThis.setInterval = function () { return 1; };
globalThis.clearInterval = function () {};
try { globalThis.window.matchMedia = undefined; } catch (e) {}

function delay(ms) {
    return new Promise(r => GLib.timeout_add(GLib.PRIORITY_DEFAULT, ms, () => { r(); return GLib.SOURCE_REMOVE; }));
}

let polls = 0;           /* each poll starts with the `id -u` privilege probe */
let snapshotGen = 0;     /* bumped when the "peer removal" lands */
globalThis.cockpit = {
    spawn(argv) {
        const script = argv[2] || "";
        if (script === "id -u") polls++;
        return delay(60).then(() => script === "id -u" ? "0\n" : "");
    }
};

async function main() {
    (0, eval)(SRC);                       /* boots: poll(true) #1 now in flight */
    await delay(10);
    ok(polls === 1, "boot starts exactly one poll");
    /* the operator removed a peer; the modal calls poll(true) while the 5s
       auto-poll / boot poll is still running */
    byId["wg-refresh"].listeners.click[0]();
    byId["wg-refresh"].listeners.click[0]();     /* and again: must still coalesce */
    await delay(600);
    ok(polls === 2,
       "forced polls issued mid-flight coalesce into exactly one trailing poll (polls=" + polls + ")");
    await delay(200);
    ok(polls === 2, "no further polls run once idle");
}

let exitStatus = 0;
const loop = GLib.MainLoop.new(null, false);
main().then(() => {
    print("\nTOTAL: " + passes + " passed, " + fails + " failed");
    if (fails) exitStatus = 1;
    loop.quit();
}, e => { logError(e, "harness crashed"); exitStatus = 2; loop.quit(); });
loop.run();
System.exit(exitStatus);
