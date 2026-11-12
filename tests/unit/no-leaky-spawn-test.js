/*
 * no-leaky-spawn-test.js - guard against the Cockpit 360 bridge fd leak.
 *
 * cockpit-bridge 360 never closes the pipe fds of a non-pty stream channel:
 * err:"message" (the DEFAULT when `err` is omitted) leaks 2 fds per spawn,
 * err:"out"/"ignore" leak 1, only pty:true leaks none (measured, see the
 * comment above shellWrap() in wireguard.js). Every cockpit.spawn in the
 * shipped JS must therefore pass { pty: true, err: "out" } (or "ignore").
 *
 *     gjs tests/unit/no-leaky-spawn-test.js [dir-with-shipped-js]
 */
"use strict";
const GLib = imports.gi.GLib;
const System = imports.system;

const HERE = GLib.path_get_dirname(System.programInvocationName);
const DIR = ARGV[0] || GLib.canonicalize_filename(HERE + "/../..", null);

let passes = 0, fails = 0;
function ok(c, l) { if (c) { passes++; print("  PASS  " + l); } else { fails++; print("  FAIL  " + l); } }

function read(p) { return new TextDecoder().decode(GLib.file_get_contents(p)[1]); }

/* Blank out comments (keeping newlines so line numbers survive) and leave
   string/template literals intact. */
function stripComments(src) {
    let out = "", q = null;
    for (let i = 0; i < src.length; i++) {
        const c = src[i], n = src[i + 1];
        if (q) {
            out += c;
            if (c === "\\") { out += src[++i] || ""; }
            else if (c === q) q = null;
            continue;
        }
        if (c === "/" && n === "/") { while (i < src.length && src[i] !== "\n") i++; out += "\n"; continue; }
        if (c === "/" && n === "*") {
            const e = src.indexOf("*/", i + 2);
            const body = src.slice(i, e < 0 ? src.length : e + 2);
            out += body.replace(/[^\n]/g, " ");
            i += body.length - 1;
            continue;
        }
        if (c === '"' || c === "'" || c === "`") q = c;
        out += c;
    }
    return out;
}

/* Text of the argument list of every `cockpit.spawn(` call (balanced parens,
   string-aware so a ")" inside a shell script is harmless). */
function spawnCalls(rawSrc) {
    const src = stripComments(rawSrc);
    const out = [];
    const re = /cockpit\.spawn\s*\(/g;
    let m;
    while ((m = re.exec(src))) {
        let i = re.lastIndex, depth = 1, q = null;
        const start = i;
        for (; i < src.length && depth > 0; i++) {
            const c = src[i];
            if (q) { if (c === "\\") i++; else if (c === q) q = null; continue; }
            if (c === '"' || c === "'" || c === "`") { q = c; continue; }
            if (c === "(") depth++; else if (c === ")") depth--;
        }
        out.push({ text: src.slice(start, i - 1),
                   line: src.slice(0, m.index).split("\n").length });
    }
    return out;
}

let total = 0;
for (const f of ["wireguard.js", "wgclient.js"]) {
    const src = read(DIR + "/" + f);
    const calls = spawnCalls(src);
    for (const c of calls) {
        total++;
        const where = f + ":" + c.line;
        const msg = /err\s*:\s*["']message["']/.test(c.text);
        const hasErr = /err\s*:\s*["'](out|ignore)["']/.test(c.text);
        const pty = /pty\s*:\s*true/.test(c.text);
        ok(!msg, where + " cockpit.spawn does not use err:\"message\"");
        ok(hasErr, where + " cockpit.spawn sets err explicitly (omitting it means \"message\")");
        ok(pty, where + " cockpit.spawn uses pty:true (the only non-leaking mode)");
    }
}
ok(total >= 3, "found the shipped cockpit.spawn calls (" + total + ")");

print("\nTOTAL: " + passes + " passed, " + fails + " failed");
System.exit(fails ? 1 : 0);
