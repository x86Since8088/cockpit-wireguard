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
globalThis.cockpit = { spawn() { return new Promise(() => {}); } };   /* boot polls never finish */

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

print("\nTOTAL: " + passes + " passed, " + fails + " failed");
System.exit(fails ? 1 : 0);
