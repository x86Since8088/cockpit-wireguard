/*
 * wgclient.js - WireGuard client management for cockpit-wireguard.
 *
 * Standalone by design: this file defines exactly one global, window.WGClient,
 * and touches nothing else. wireguard.js, index.html and manifest.json are
 * unaware of it beyond one call site.
 *
 *     WGClient.render(container, opts)   build the whole Clients section
 *     WGClient.refresh()                 re-read state and repaint
 *
 * It speaks only to /usr/local/sbin/wg-admin, one verb per call, exactly as
 * docs/CONTRACT.md describes: JSON on stdout, diagnostics on stderr, exit 0 on
 * success. It never runs a raw command, never invents a subnet (every CIDR on
 * screen comes from `wg-admin catalogue`) and never generates or stores a key.
 *
 * CONTRACT v2 - schema-driven UI
 * ------------------------------
 * The config-builder form renders NOTHING this file invented. Every control,
 * validation rule and recommendation comes from `wg-admin schema` at load
 * time (renderField() below maps the eight documented control types to DOM).
 * The recommendation engine implements EXACTLY the six declarative `when`
 * operators the contract allows - contains_any, equals, not_equals, gt, lt,
 * truthy - and rejects anything else by name rather than guessing. Each
 * firing recommendation with a `check:` is resolved against live
 * `routing-status`, and a warn-level recommendation whose check is NOT
 * active offers a one-click fix that calls `routing-set`.
 *
 * v2 also adds the IPAM panel (reservations, scan, free-IP picker, the
 * mandatory LRU-reuse warning banner) and per-client per-config install
 * bundles via `client-package` with five OS tabs.
 *
 * ERROR ATTRIBUTION - read this before changing anything below
 * -----------------------------------------------------------
 * Every call is cockpit.spawn(argv, { superuser: "require", err: "message" }).
 * That rejection has two entirely different shapes and conflating them has
 * already cost this project hours:
 *
 *   err.problem is a non-empty string
 *       COCKPIT could not run the helper at all - the channel, the session or
 *       the privilege escalation failed. wg-admin produced no output, may not
 *       even have been executed, and must NEVER be named as the source.
 *       Codes seen here: internal-error, access-denied, authentication-failed,
 *       cancelled, terminated, not-found, protocol-error, disconnected...
 *
 *   err.problem is empty and err.exit_status is set
 *       The helper RAN and exited non-zero. err.message is wg-admin's stderr
 *       and is the only case where the backend may be blamed.
 *
 * classify() below is the single place that decision is made; faultPanel()
 * renders it with the attribution spelled out in plain English.
 *
 * SECRETS
 * -------
 * `get-config` and the .conf inside every `client-package` bundle carry a
 * private key. It is never written to the console, never placed in a URL,
 * never put in a data: URI (downloads are Blob + object URL), and is masked
 * in the <pre> until the operator clicks Reveal. Malformed replies are
 * reported by length only, never by echoing the bytes back into the page.
 */

(function () {
    "use strict";

    /* ------------------------------------------------------------------ *
     * Configuration
     * ------------------------------------------------------------------ */

    var WG_ADMIN = "/usr/local/sbin/wg-admin";

    /*
     * routing-status returns ip_forward alongside rules[].dest, and routing-set
     * takes a single DEST. The sysctl is therefore addressed by the same name
     * the status object uses for it.
     */
    var IP_FORWARD_DEST = "ip_forward";

    var NAME_RE  = /^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$/;
    var MAC_RE   = /^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$/;
    var WGKEY_RE = /^[A-Za-z0-9+/]{43}=$/;

    /* The --net domain is fixed by the contract's verb signature:
       `ipam-scan [--net tunnel|lab|static-edt]`. */
    var IPAM_SCAN_NETS = ["tunnel", "lab", "static-edt"];

    /* The --os domain, likewise fixed by the client-package signature. */
    var PACKAGE_OSES = [
        ["windows",  "Windows"],
        ["linux",    "Linux"],
        ["pfsense",  "pfSense"],
        ["opnsense", "OPNsense"],
        ["freebsd",  "FreeBSD"]
    ];

    /* The eight control types the contract documents. Anything else renders
       read-only with an honest "newer than this page" note. */
    var CONTROL_TYPES = {
        toggle: 1, number: 1, text: 1, select: 1, radio: 1,
        "cidr-set": 1, readonly: 1, "password-reveal": 1
    };

    /* ------------------------------------------------------------------ *
     * DOM helpers - same shape as wireguard.js so the two files read alike
     * ------------------------------------------------------------------ */

    function el(tag, opts) {
        var node = document.createElement(tag);
        opts = opts || {};
        if (opts.cls) node.className = opts.cls;
        if (opts.text !== undefined && opts.text !== null) node.textContent = String(opts.text);
        if (opts.title) node.setAttribute("title", opts.title);
        if (opts.attrs)
            Object.keys(opts.attrs).forEach(function (k) { node.setAttribute(k, opts.attrs[k]); });
        for (var i = 2; i < arguments.length; i++) {
            var c = arguments[i];
            if (c === null || c === undefined || c === false) continue;
            node.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
        }
        return node;
    }

    function clear(node) { while (node && node.firstChild) node.removeChild(node.firstChild); }

    function pill(text, cls) {
        return el("span", { cls: "pill" + (cls ? " " + cls : ""), text: text });
    }

    function button(label, cls, onClick, title) {
        var b = el("button", { cls: "wg-btn" + (cls ? " " + cls : ""), text: label,
                               attrs: { type: "button" } });
        if (title) b.setAttribute("title", title);
        if (onClick) b.addEventListener("click", onClick);
        return b;
    }

    function textInput(value, placeholder, size) {
        var attrs = { type: "text", spellcheck: "false", autocomplete: "off" };
        if (placeholder) attrs.placeholder = placeholder;
        if (size) attrs.size = String(size);
        var n = el("input", { cls: "wgc-input", attrs: attrs });
        n.value = (value === undefined || value === null) ? "" : String(value);
        return n;
    }

    /* Mark a hand-built row as the realization of a schema field, so tests and
     * tooling can find schema ids uniformly whether a row came from the schema
     * renderer or from a bespoke form. */
    function stamp(node, schemaId) {
        node.setAttribute("data-field", schemaId);
        return node;
    }

    function field(labelText, inputNode, hintText) {
        return el("div", { cls: "wgc-field" },
                  el("label", { cls: "wgc-field-label" },
                     el("span", { text: labelText }), inputNode),
                  hintText ? el("div", { cls: "wg-hint", text: hintText }) : null);
    }

    /* ------------------------------------------------------------------ *
     * Pure helpers
     *
     * Everything from here to "Backend" is free of DOM and cockpit, so it can
     * be exercised head-less (see WGClient.compute at the bottom). This is
     * where the AllowedIPs asymmetry and the recommendation operators are
     * decided, so it is the part that most needs to be testable without a
     * browser.
     * ------------------------------------------------------------------ */

    function truthy(v) {
        if (v === true) return true;
        if (v === false || v === null || v === undefined) return false;
        var s = String(v).trim().toLowerCase();
        return s === "1" || s === "true" || s === "yes" || s === "on";
    }

    function firstOf(obj, keys) {
        for (var i = 0; i < keys.length; i++) {
            var v = obj[keys[i]];
            if (v !== undefined && v !== null && String(v) !== "") return String(v);
        }
        return "";
    }

    /* 0.0.0.0/0 (or ::/0) is "everything" - it captures the client default route. */
    function isDefaultRoute(cidr) {
        var s = String(cidr || "").trim();
        return s === "0.0.0.0/0" || s === "::/0";
    }

    function ipv4ToInt(ip) {
        var m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(String(ip || "").trim());
        if (!m) return null;
        var n = 0;
        for (var i = 1; i <= 4; i++) {
            var o = Number(m[i]);
            if (!isFinite(o) || o < 0 || o > 255) return null;
            n = (n * 256) + o;
        }
        return n;
    }

    function validIpv4(ip) { return ipv4ToInt(ip) !== null; }

    /* Strip any prefix length and re-attach /32: the server side is one host. */
    function host32(ip) {
        var bare = String(ip || "").trim().split("/")[0];
        return validIpv4(bare) ? bare + "/32" : "";
    }

    function cidrContains(cidr, ip) {
        var parts = String(cidr || "").trim().split("/");
        var base = ipv4ToInt(parts[0]);
        var addr = ipv4ToInt(String(ip || "").split("/")[0]);
        var bits = (parts.length > 1) ? Number(parts[1]) : 32;
        if (base === null || addr === null || !isFinite(bits) || bits < 0 || bits > 32)
            return false;
        if (bits === 0) return true;
        var size = Math.pow(2, 32 - bits);
        var start = base - (base % size);
        return addr >= start && addr < start + size;
    }

    /*
     * `wg-admin catalogue` -> { networks:[...], presets:{...} }. The exact key
     * names inside each network are read defensively: CONTRACT.md documents the
     * columns (id, CIDR, description) rather than the JSON spelling, and a
     * catalogue we cannot read is worse than one we read three ways.
     */
    function normaliseCatalogue(raw) {
        var cat = { networks: [], byId: Object.create(null), presets: Object.create(null),
                    presetOrder: [], ok: false };
        if (!raw || typeof raw !== "object") return cat;

        var list = raw.networks || raw.destinations || raw.catalogue || [];
        if (!(list instanceof Array)) list = [];

        list.forEach(function (n) {
            if (!n) return;
            var id, cidr, desc;
            if (typeof n === "string") { id = n; cidr = ""; desc = ""; }
            else {
                id   = firstOf(n, ["id", "name", "key"]);
                cidr = firstOf(n, ["cidr", "network", "subnet", "range", "prefix"]);
                desc = firstOf(n, ["description", "desc", "label", "text"]);
            }
            if (!id || cat.byId[id]) return;
            var rec = { id: id, cidr: cidr, description: desc,
                        full: isDefaultRoute(cidr) };
            cat.networks.push(rec);
            cat.byId[id] = rec;
        });

        var pres = raw.presets || {};
        if (pres && typeof pres === "object") {
            Object.keys(pres).forEach(function (name) {
                var v = pres[name];
                var ids = null;
                if (v instanceof Array) ids = v;
                else if (v && typeof v === "object") ids = v.routes || v.networks || v.ids;
                else if (typeof v === "string") ids = v.split(",");
                if (!(ids instanceof Array)) return;
                cat.presets[name] = ids.map(function (x) { return String(x).trim(); })
                                       .filter(function (x) { return !!x; });
                cat.presetOrder.push(name);
            });
        }

        cat.ok = cat.networks.length > 0;
        return cat;
    }

    function presetIds(cat, name) {
        var ids = cat && cat.presets ? cat.presets[name] : null;
        return (ids instanceof Array) ? ids.slice() : [];
    }

    /*
     * Turn a set of catalogue ids into the client's AllowedIPs.
     *
     * Rules, both taken from CONTRACT.md rather than invented here:
     *   - output follows catalogue order, deduplicated
     *   - a default-route entry (0.0.0.0/0) subsumes everything else, so it is
     *     emitted alone. Keeping the others would make the preview disagree
     *     with what the helper writes for preset `full`, and a preview that
     *     lies about the generated config is the whole failure this UI exists
     *     to prevent.
     */
    function computeSelection(cat, ids) {
        var wanted = Object.create(null), unknown = [];
        (ids || []).forEach(function (raw) {
            var id = String(raw === null || raw === undefined ? "" : raw).trim();
            if (!id || wanted[id]) return;
            wanted[id] = true;
            if (!cat.byId[id]) unknown.push(id);
        });

        var ordered = cat.networks.filter(function (n) { return wanted[n.id]; });
        var fullNets = ordered.filter(function (n) { return n.full; });
        var dropped = [];
        var chosen = ordered;

        if (fullNets.length) {
            chosen = [fullNets[0]];
            dropped = ordered.filter(function (n) { return n !== fullNets[0]; })
                             .map(function (n) { return n.id; });
        }

        return {
            ids:      chosen.map(function (n) { return n.id; }),
            networks: chosen,
            cidrs:    chosen.map(function (n) { return n.cidr; })
                            .filter(function (c) { return !!c; }),
            unknown:  unknown,
            dropped:  dropped,
            full:     fullNets.length > 0,
            routesArg: chosen.map(function (n) { return n.id; }).join(",")
        };
    }

    /* The server side is, always and only, this client's /32. */
    function serverAllowedIps(clientIp) {
        var h = host32(clientIp);
        return h ? [h] : [];
    }

    /* The network the client's own address lives in - i.e. the tunnel itself. */
    function tunnelNetwork(cat, clientIp) {
        if (!clientIp) return null;
        var hit = null;
        cat.networks.forEach(function (n) {
            if (n.full || !n.cidr) return;
            if (cidrContains(n.cidr, clientIp) && !hit) hit = n;
        });
        return hit;
    }

    /*
     * The model behind the live explanation panel: both sides plus every
     * warning worth raising before the config is written.
     */
    function explain(cat, ids, clientIp) {
        var sel = computeSelection(cat, ids);
        var warnings = [];
        var tunnel = tunnelNetwork(cat, clientIp);

        if (!sel.ids.length)
            warnings.push({ level: "bad", text:
                "Nothing is selected, so the client would route nothing into the tunnel. " +
                "The handshake would succeed and no traffic would ever use it." });

        if (sel.full)
            warnings.push({ level: "warn", text:
                "0.0.0.0/0 becomes the client's DEFAULT ROUTE: every packet it sends, " +
                "including DNS and traffic to its own local network, goes through this " +
                "host. If the tunnel drops the client loses connectivity until the " +
                "config is switched off, and any other selection is redundant so it is " +
                "not written." });

        if (sel.dropped.length)
            warnings.push({ level: "info", text:
                "Covered by 0.0.0.0/0 and therefore not listed separately: " +
                sel.dropped.join(", ") + "." });

        if (!sel.full && sel.ids.length && tunnel && sel.ids.indexOf(tunnel.id) < 0)
            warnings.push({ level: "warn", text:
                "The client's own address " + String(clientIp) + " lives in " +
                tunnel.cidr + " (" + tunnel.id + ") but that destination is not " +
                "selected, so the client cannot reach the server's tunnel address or " +
                "any other peer. Add it unless you know why you are leaving it out." });

        if (sel.unknown.length)
            warnings.push({ level: "bad", text:
                "Not in the catalogue and will be ignored: " + sel.unknown.join(", ") + "." });

        if (!serverAllowedIps(clientIp).length && clientIp)
            warnings.push({ level: "bad", text:
                "The client address \"" + String(clientIp) + "\" is not a plain IPv4 " +
                "address, so the server-side /32 cannot be shown." });

        return {
            selection: sel,
            client: sel.networks.slice(),
            server: serverAllowedIps(clientIp),
            tunnel: tunnel,
            warnings: warnings
        };
    }

    /* Mask both secrets a .conf can carry. Applied to the DISPLAYED copy only. */
    var MASK = "•".repeat ? "•".repeat(24) : "------------------------";

    function maskConf(text) {
        return String(text === undefined || text === null ? "" : text)
            .replace(/^([ \t]*(?:PrivateKey|PresharedKey)[ \t]*=[ \t]*)(\S+)/gmi,
                     function (m, lead) { return lead + MASK; });
    }

    function safeFileName(clientName, configName) {
        var base = String(clientName || "wg") + "-" + String(configName || "conf");
        base = base.replace(/[^A-Za-z0-9_=+.-]/g, "-").replace(/^-+/, "");
        if (!base) base = "wireguard";
        return base.slice(0, 32) + ".conf";
    }

    /* Bundle file names come from the helper; keep the name (the OS scripts
       reference each other by it) but never allow a path component through. */
    function safeBundleName(name) {
        var s = String(name || "").replace(/[\/\\]/g, "_").replace(/[^A-Za-z0-9._+=-]/g, "_");
        if (!s || s === "." || s === "..") s = "bundle-file";
        return s.slice(0, 64);
    }

    /* ------------------------------------------------------------------ *
     * Pure helpers - Contract v2 schema
     * ------------------------------------------------------------------ */

    function normaliseSchema(raw) {
        var s = { version: 0, groups: [], recommendations: [], ok: false };
        if (!raw || typeof raw !== "object") return s;

        s.version = Number(raw.version) || 0;

        var groups = (raw.groups instanceof Array) ? raw.groups : [];
        groups.forEach(function (g) {
            if (!g || typeof g !== "object") return;
            var fields = (g.fields instanceof Array) ? g.fields : [];
            s.groups.push({
                id: String(g.id || ""),
                title: String(g.title || g.id || ""),
                order: Number(g.order) || 0,
                fields: fields.filter(function (f) { return f && f.id; })
                              .map(function (f) {
                    var control = String(f.control || "");
                    return {
                        id: String(f.id),
                        label: String(f.label || f.id),
                        control: control,
                        known: !!CONTROL_TYPES[control],
                        "default": (f["default"] === undefined) ? null : f["default"],
                        min: (f.min === undefined || f.min === null || !isFinite(Number(f.min)))
                                ? null : Number(f.min),
                        max: (f.max === undefined || f.max === null || !isFinite(Number(f.max)))
                                ? null : Number(f.max),
                        options: (f.options instanceof Array)
                            ? f.options.filter(function (o) { return o && o.value !== undefined; })
                                       .map(function (o) {
                                  return { value: String(o.value),
                                           label: String(o.label !== undefined ? o.label : o.value) };
                              })
                            : [],
                        pattern: f.pattern ? String(f.pattern) : "",
                        placeholder: f.placeholder ? String(f.placeholder) : "",
                        help: f.help ? String(f.help) : "",
                        breaks_when_wrong: f.breaks_when_wrong ? String(f.breaks_when_wrong) : "",
                        unit: f.unit ? String(f.unit) : ""
                    };
                })
            });
        });
        s.groups.sort(function (a, b) { return a.order - b.order; });

        var recos = (raw.recommendations instanceof Array) ? raw.recommendations : [];
        s.recommendations = recos
            .filter(function (r) { return r && r.id && r.when && typeof r.when === "object"; })
            .map(function (r) {
                return {
                    id: String(r.id),
                    when: r.when,
                    level: (r.level === "warn") ? "warn" : "info",
                    text: String(r.text || ""),
                    check: r.check ? String(r.check) : ""
                };
            });

        s.ok = s.version === 2 && s.groups.length > 0;
        return s;
    }

    function eachField(schema, fn) {
        (schema.groups || []).forEach(function (g) {
            (g.fields || []).forEach(fn);
        });
    }

    function fieldIndex(schema) {
        var map = Object.create(null);
        eachField(schema, function (f) { map[f.id] = f; });
        return map;
    }

    /*
     * The six `when` operators - the contract allows EXACTLY these, so this
     * table is the whole vocabulary. Anything else is rejected by name; a
     * silently mis-evaluated recommendation is worse than a refused one.
     */
    function looseEq(v, arg) {
        var a = Number(v), b = Number(arg);
        if (String(v).trim() !== "" && String(arg).trim() !== "" && isFinite(a) && isFinite(b))
            return a === b;
        return String(v) === String(arg);
    }

    var WHEN_OPS = {
        contains_any: function (v, arg) {
            var list = (arg instanceof Array) ? arg : [arg];
            if (v instanceof Array) {
                for (var i = 0; i < list.length; i++)
                    if (v.indexOf(list[i]) >= 0) return true;
                return false;
            }
            return list.indexOf(v) >= 0;
        },
        equals:     function (v, arg) { return looseEq(v, arg); },
        not_equals: function (v, arg) { return !looseEq(v, arg); },
        gt: function (v, arg) {
            var a = Number(v), b = Number(arg);
            return isFinite(a) && isFinite(b) && a > b;
        },
        lt: function (v, arg) {
            var a = Number(v), b = Number(arg);
            return isFinite(a) && isFinite(b) && a < b;
        },
        truthy: function (v, arg) {
            return truthy(v) === ((arg === undefined) ? true : truthy(arg));
        }
    };

    function evalWhen(when, getValue) {
        if (!when || typeof when !== "object" || !when.field)
            return { ok: false, fire: false, reason: "no field named in `when`" };
        var ops = [];
        Object.keys(when).forEach(function (k) { if (k !== "field") ops.push(k); });
        if (ops.length === 0)
            return { ok: false, fire: false, reason: "no operator in `when`" };
        if (ops.length > 1)
            return { ok: false, fire: false,
                     reason: "more than one operator: " + ops.join(", ") };
        var op = ops[0];
        if (!Object.prototype.hasOwnProperty.call(WHEN_OPS, op))
            return { ok: false, fire: false,
                     reason: "operator “" + op + "” is not one of the six the contract allows" };
        return { ok: true, op: op,
                 fire: !!WHEN_OPS[op](getValue(when.field), when[op]) };
    }

    function recoFiring(recos, getValue) {
        var out = { firing: [], rejected: [] };
        (recos || []).forEach(function (r) {
            var res = evalWhen(r.when, getValue);
            if (!res.ok) out.rejected.push({ reco: r, reason: res.reason });
            else if (res.fire) out.firing.push(r);
        });
        return out;
    }

    /* check: "routing-status:lan" -> "lan". Only routing-status checks exist
       in the contract; anything else returns null and is reported as such. */
    function checkTarget(check) {
        var s = String(check || "");
        var i = s.indexOf(":");
        if (i <= 0) return null;
        var verb = s.slice(0, i), target = s.slice(i + 1);
        if (verb !== "routing-status" || !target) return null;
        return target;
    }

    function resolveCheckState(routing, target) {
        if (!routing) return { known: false, active: false };
        if (target === IP_FORWARD_DEST)
            return routing.ipForwardKnown
                ? { known: true, active: routing.ipForward }
                : { known: false, active: false };
        for (var i = 0; i < routing.rules.length; i++)
            if (routing.rules[i].dest === target)
                return { known: true, active: routing.rules[i].present };
        return { known: false, active: false };
    }

    function stateWord(st) {
        return st.known ? (st.active ? "ACTIVE" : "NOT active") : "unknown";
    }

    function interpolateState(text, word) {
        return String(text || "").split("<state>").join(word);
    }

    /* "Different from the schema default" decides whether add-config gets a
       --<field> flag at all: defaults are the backend's business. */
    function valueDiffers(fld, cur) {
        var def = fld["default"];
        if (fld.control === "toggle") return truthy(cur) !== truthy(def);
        var s = String(cur === null || cur === undefined ? "" : cur).trim();
        var d = String(def === null || def === undefined ? "" : def).trim();
        if (s === "") return false;          /* empty means "use the default" */
        var a = Number(s), b = Number(d);
        if (d !== "" && isFinite(a) && isFinite(b)) return a !== b;
        return s !== d;
    }

    function encodeFlagValue(fld, cur) {
        if (fld.control === "toggle") return truthy(cur) ? "on" : "off";
        return String(cur).trim();
    }

    /* client-package `instructions` is one string; every non-empty line is a
       step, with any numbering the generator already added stripped so the
       rendered <ol> does not read "1. 1. Install...". */
    function splitInstructions(text) {
        var steps = [];
        String(text || "").split(/\r?\n/).forEach(function (line) {
            var s = line.trim();
            if (!s) return;
            s = s.replace(/^(?:\d+[.)]\s*|[-*]\s+)/, "");
            if (s) steps.push(s);
        });
        return steps;
    }

    /* ------------------------------------------------------------------ *
     * Pure helpers - Contract v2 IPAM and packages
     * ------------------------------------------------------------------ */

    function normaliseIpam(raw) {
        raw = raw || {};
        function rows(list) {
            return ((list instanceof Array) ? list : []).map(function (r) {
                r = r || {};
                return {
                    ip: firstOf(r, ["ip"]),
                    name: firstOf(r, ["name"]),
                    mac: firstOf(r, ["mac"]),
                    pubkey: firstOf(r, ["pubkey"]),
                    created: firstOf(r, ["created"]),
                    first_seen: firstOf(r, ["first_seen"]),
                    last_seen: firstOf(r, ["last_seen"]),
                    source: firstOf(r, ["source"])
                };
            }).filter(function (r) { return !!r.ip; });
        }
        return {
            pool: firstOf(raw, ["pool"]),
            reserved: rows(raw.reserved),
            observed: rows(raw.observed),
            free: ((raw.free instanceof Array) ? raw.free : []).map(function (ip) {
                return String(ip);
            }),
            lru: rows(raw.lru)
        };
    }

    function normalisePackage(raw) {
        raw = raw || {};
        return {
            os: firstOf(raw, ["os"]),
            files: ((raw.files instanceof Array) ? raw.files : []).map(function (f) {
                f = f || {};
                return {
                    name: firstOf(f, ["name"]),
                    mode: firstOf(f, ["mode"]),
                    content: String(f.content === undefined || f.content === null
                                        ? "" : f.content)
                };
            }).filter(function (f) { return !!f.name; }),
            instructions: String(raw.instructions || ""),
            undo_note: String(raw.undo_note || "")
        };
    }

    /* ------------------------------------------------------------------ *
     * Fault classification - see the header comment. This function is the
     * only thing allowed to decide who to blame.
     * ------------------------------------------------------------------ */

    /* Cockpit could not escalate: the operator is not an administrator here,
       declined the prompt, or the session cannot authenticate. */
    var DENY_PROBLEMS = { "access-denied": 1, "authentication-failed": 1,
                          "not-authorized": 1, "cancelled": 1 };

    var COCKPIT_PROBLEM_TEXT = {
        "internal-error":
            "Cockpit's bridge hit an internal error while opening the channel.",
        "terminated":
            "Cockpit terminated the channel before the helper finished.",
        "protocol-error":
            "Cockpit's bridge and the browser disagreed on the channel protocol.",
        "disconnected":
            "The Cockpit session dropped while the request was in flight.",
        "timeout":
            "Cockpit gave up waiting for the channel to open.",
        "no-cockpit":
            "No Cockpit bridge is running on the target host."
    };

    function classify(err) {
        var problem = (err && err.problem) ? String(err.problem) : "";
        var status  = (err && err.exit_status !== undefined && err.exit_status !== null)
                        ? Number(err.exit_status) : null;
        var message = String((err && err.message) || "").trim();

        if (problem === "not-found")
            return {
                source: "missing", problem: problem, blame: "cockpit",
                title: "The wg-admin helper is not installed",
                detail: "Cockpit reported “not-found” for " + WG_ADMIN +
                        ", which means the file is missing or not executable. " +
                        "Nothing ran, so there is no backend output to show.",
                retry: true
            };

        if (DENY_PROBLEMS[problem])
            return {
                source: "denied", problem: problem, blame: "cockpit",
                title: (problem === "cancelled")
                    ? "Administrative access was cancelled"
                    : "Administrative access is required",
                detail: "Cockpit reported “" + problem + "” when asked to run " +
                        "the helper as root. This is Cockpit's privilege escalation " +
                        "declining, not wg-admin: the helper was never started and " +
                        "produced no output.",
                retry: true
            };

        if (problem)
            return {
                source: "cockpit", problem: problem, blame: "cockpit",
                title: "Cockpit could not run the helper",
                detail: (COCKPIT_PROBLEM_TEXT[problem] ||
                         "Cockpit reported the channel problem “" + problem + "”.") +
                        " This is a Cockpit channel failure, not output from wg-admin — " +
                        "the helper may not have been started at all, and nothing it " +
                        "prints could reach this page.",
                retry: true
            };

        if (status !== null && status !== 0)
            return {
                source: "backend", problem: "", blame: "backend", status: status,
                title: "wg-admin exited " + status,
                detail: message || "The helper exited non-zero and printed nothing on stderr.",
                retry: false
            };

        return {
            source: "unknown", problem: "", blame: "unknown",
            title: "The request failed",
            detail: message || "No problem code and no exit status were reported, " +
                               "so it is not possible to say whether Cockpit or the " +
                               "helper failed.",
            retry: true
        };
    }

    function malformedFault(byteLength) {
        return {
            source: "malformed", problem: "", blame: "backend",
            title: "The helper's reply was not the JSON the contract describes",
            /* Deliberately no echo of the payload: get-config and
               client-package replies carry a private key and a malformed one
               is exactly when it would leak. */
            detail: "wg-admin exited 0 but stdout (" + byteLength + " bytes) did not " +
                    "parse as a JSON object. The bytes are not shown here because " +
                    "some replies contain a private key.",
            retry: true
        };
    }

    function isBlockingFault(fault) {
        return !!fault && (fault.source === "denied" || fault.source === "cockpit" ||
                           fault.source === "missing");
    }

    /* ------------------------------------------------------------------ *
     * Backend
     * ------------------------------------------------------------------ */

    function callAdmin(args) {
        var argv = [state.binary].concat(args);

        if (!window.cockpit || typeof cockpit.spawn !== "function")
            return Promise.resolve({ ok: false, fault: {
                source: "cockpit", problem: "no-cockpit", blame: "cockpit",
                title: "cockpit.js is not loaded",
                detail: "This page has no Cockpit API object, so no command can be run. " +
                        "That is a page loading problem, not a wg-admin problem.",
                retry: true } });

        return cockpit.spawn(argv, { superuser: "require", err: "message" })
            .then(function (out) {
                var text = String(out === undefined || out === null ? "" : out).trim();
                var data;
                try { data = JSON.parse(text || "null"); }
                catch (e) { return { ok: false, fault: malformedFault(text.length) }; }
                if (!data || typeof data !== "object")
                    return { ok: false, fault: malformedFault(text.length) };
                return { ok: true, data: data };
            }, function (err) {
                return { ok: false, fault: classify(err) };
            });
    }

    /* ------------------------------------------------------------------ *
     * State
     * ------------------------------------------------------------------ */

    var state = {
        binary:   WG_ADMIN,
        loading:  false,
        loaded:   false,
        gate:     null,     /* blocking fault: nothing usable without root     */
        cat:      normaliseCatalogue(null),
        catFault: null,
        clients:  [],
        listFault: null,
        routing:  null,
        routingFault: null,
        schema:   normaliseSchema(null),
        schemaFault: null,
        ipam:     normaliseIpam(null),
        ipamFault: null,
        notice:   null,     /* {cls, title, text} from the last mutation       */
        reusedBanner: null  /* the mandatory LRU-reuse warning; sticky until
                               dismissed - never a toast                       */
    };

    /* UI state survives repaints, the way expandedKeys does in wireguard.js. */
    var ui = {
        open:     Object.create(null),   /* client name -> true                */
        builder:  Object.create(null),   /* client name -> builder model       */
        viewer:   Object.create(null),   /* "name\0cfg"  -> viewer model       */
        pkg:      Object.create(null),   /* "name\0cfg"  -> package model      */
        confirm:  Object.create(null),   /* action key   -> armed              */
        busy:     Object.create(null),   /* action key   -> in flight          */
        creating: false,
        ipamScan: { net: IPAM_SCAN_NETS[0], busy: false, result: null, fault: null }
    };

    var dom = null;          /* set by render()                               */
    var options = {};
    var permission = null;   /* cockpit.permission({admin:true}), lazily made  */
    var recoSeq = 0;         /* stale-response guard for live reco checks      */

    function vkey(name, cfg) { return name + "\u0000" + cfg; }

    function builderFor(client) {
        var b = ui.builder[client.name];
        if (!b) {
            b = { open: false, config: "",
                  ids: Object.create(null),      /* cidr-set selection         */
                  nodes: Object.create(null),    /* cidr-set checkbox nodes    */
                  values: Object.create(null),   /* schema field values        */
                  invalid: Object.create(null),  /* schema field validity      */
                  seeded: false,
                  explainBox: null, recoBox: null, error: null };
            ui.builder[client.name] = b;
        }
        return b;
    }

    function selectedIds(b) {
        return Object.keys(b.ids).filter(function (id) { return b.ids[id]; });
    }

    /* Seed the builder from schema defaults exactly once; a repaint must not
       wipe what the operator typed. */
    function seedBuilder(b, schema, cat) {
        if (b.seeded || !schema.ok) return;
        b.seeded = true;
        eachField(schema, function (f) {
            if (f.control === "cidr-set") {
                var def = (f["default"] instanceof Array) ? f["default"] : [];
                def.forEach(function (id) { if (cat.byId[id]) b.ids[id] = true; });
            } else if (!(f.id in b.values)) {
                b.values[f.id] = (f["default"] === null || f["default"] === undefined)
                                    ? "" : f["default"];
            }
        });
    }

    /*
     * A toggle field is a LIVE host switch (not an add-config flag) when the
     * backend itself addresses it: routing-status reports it, or the
     * catalogue carries it as a cidr-less control id for routing-set. Both
     * tests read backend data - nothing here decides by field name.
     */
    function liveRoutingId(id) {
        if (state.routing) {
            if (id === IP_FORWARD_DEST && state.routing.ipForwardKnown) return true;
            for (var i = 0; i < state.routing.rules.length; i++)
                if (state.routing.rules[i].dest === id) return true;
        }
        var n = state.cat.byId[id];
        if (n && !n.cidr) return true;
        return false;
    }

    function liveToggleState(fld) {
        var st = resolveCheckState(state.routing, fld.id);
        return st.known ? st.active : truthy(fld["default"]);
    }

    /* What the recommendation engine sees for a field id. */
    function fieldValueGetter(client, b) {
        var idx = fieldIndex(state.schema);
        return function (id) {
            var f = idx[id];
            if (f && f.control === "cidr-set") return selectedIds(b);
            if (f && f.control === "toggle" && liveRoutingId(id)) return liveToggleState(f);
            if (f && (id in b.values)) {
                var v = b.values[id];
                if (f.control === "number" && String(v).trim() === "") return f["default"];
                return v;
            }
            return f ? f["default"] : undefined;
        };
    }

    /* ------------------------------------------------------------------ *
     * Loading
     * ------------------------------------------------------------------ */

    function refresh() {
        if (!dom) return Promise.resolve();
        state.loading = true;
        paintStatus();

        return Promise.all([
            callAdmin(["catalogue"]),
            callAdmin(["list"]),
            callAdmin(["routing-status"]),
            callAdmin(["schema"]),
            callAdmin(["ipam-status"])
        ]).then(function (res) {
            var c = res[0], l = res[1], r = res[2], s = res[3], ip = res[4];

            state.catFault     = c.ok  ? null : c.fault;
            state.listFault    = l.ok  ? null : l.fault;
            state.routingFault = r.ok  ? null : r.fault;
            state.schemaFault  = s.ok  ? null : s.fault;
            state.ipamFault    = ip.ok ? null : ip.fault;

            if (c.ok)  state.cat     = normaliseCatalogue(c.data);
            if (l.ok)  state.clients = normaliseClients(l.data);
            if (r.ok)  state.routing = normaliseRouting(r.data);
            if (s.ok)  state.schema  = normaliseSchema(s.data);
            if (ip.ok) state.ipam    = normaliseIpam(ip.data);

            /* One blocking fault gates the whole section; it is the same
               escalation failing five times, so report it once. */
            state.gate = [c.fault, l.fault, r.fault, s.fault, ip.fault]
                             .filter(isBlockingFault)[0] || null;

            state.loading = false;
            state.loaded = true;
            paint();
        });
    }

    function normaliseClients(raw) {
        var list = (raw && raw.clients instanceof Array) ? raw.clients : [];
        return list.map(function (c) {
            c = c || {};
            var configs = c.configs;
            if (!(configs instanceof Array)) configs = [];
            return {
                name: firstOf(c, ["name", "client", "id"]),
                ip: firstOf(c, ["ip", "address", "tunnel_ip"]),
                enabled: (c.enabled === undefined) ? true : truthy(c.enabled),
                configs: configs.map(function (cf) {
                    if (typeof cf === "string") return { name: cf, allowed: "" };
                    cf = cf || {};
                    return {
                        name: firstOf(cf, ["name", "config", "id"]),
                        allowed: (cf.allowed_ips instanceof Array)
                                    ? cf.allowed_ips.join(", ")
                                    : firstOf(cf, ["allowed_ips", "allowed"])
                    };
                }).filter(function (cf) { return !!cf.name; })
            };
        }).filter(function (c) { return !!c.name; });
    }

    function normaliseRouting(raw) {
        raw = raw || {};
        var rules = (raw.rules instanceof Array) ? raw.rules : [];
        return {
            ipForward: truthy(raw.ip_forward),
            ipForwardKnown: raw.ip_forward !== undefined && raw.ip_forward !== null,
            rules: rules.map(function (r) {
                r = r || {};
                return {
                    dest: firstOf(r, ["dest", "destination", "id"]),
                    iface: firstOf(r, ["iface", "interface", "dev"]),
                    present: truthy(r.present)
                };
            }).filter(function (r) { return !!r.dest; })
        };
    }

    /*
     * Mutations. Every verb is idempotent per the contract, so a failed call
     * can simply be repeated. `key` guards against a double click firing the
     * same change twice.
     */
    function mutate(key, args, describe) {
        if (ui.busy[key]) return Promise.resolve();
        ui.busy[key] = true;
        state.notice = null;
        paint();

        return callAdmin(args).then(function (res) {
            delete ui.busy[key];
            if (res.ok) {
                state.notice = { cls: "ok", title: describe.ok, text: describe.detail || "" };
                return refresh();
            }
            state.notice = { cls: "bad", title: describe.fail, fault: res.fault };
            if (isBlockingFault(res.fault)) state.gate = res.fault;
            paint();
        });
    }

    /* ------------------------------------------------------------------ *
     * Rendering - shell
     * ------------------------------------------------------------------ */

    function render(container, opts) {
        if (!container) return;
        options = opts || {};
        state.binary = options.binary ? String(options.binary) : WG_ADMIN;

        clear(container);

        var root = el("div", { cls: "wgc" });

        /*
         * The header row always exists - it carries the status text and the
         * Refresh button. `heading:false` only drops the <h2>, for a caller
         * that has already put "Clients" in its own <section> heading.
         */
        var statusNode = el("span", { cls: "wg-subtle wgc-status" });
        var refreshBtn = button("Refresh", "", function () { refresh(); });
        var headRow = el("div", { cls: "wgc-head" },
            (options.heading === false)
                ? null
                : el("h2", { cls: "wgc-title", text: options.title || "Clients" }),
            statusNode,
            el("span", { cls: "wgc-head-spacer" }),
            refreshBtn);
        root.appendChild(headRow);

        var banner  = el("div", { cls: "wgc-banner" });
        var body    = el("div", { cls: "wgc-body" });
        var ipam    = el("div", { cls: "wgc-ipam-wrap" });
        var routing = el("div", { cls: "wgc-routing-wrap" });

        root.appendChild(banner);
        root.appendChild(body);
        root.appendChild(ipam);
        root.appendChild(routing);
        container.appendChild(root);

        dom = {
            container: container,
            root: root,
            status: statusNode,
            refreshBtn: refreshBtn,
            banner: banner,
            body: body,
            ipam: ipam,
            routing: routing
        };

        watchPermission();
        paint();
        if (options.autoload === false) return;
        refresh();
    }

    /*
     * When the operator turns "Administrative access" on in the Cockpit header
     * the gate should clear itself rather than sit there until someone presses
     * Refresh. cockpit.permission is optional, so every use is guarded.
     */
    function watchPermission() {
        if (permission || !window.cockpit || typeof cockpit.permission !== "function")
            return;
        try {
            permission = cockpit.permission({ admin: true });
            permission.addEventListener("changed", function () {
                if (permission.allowed && state.gate) refresh();
                else paintStatus();
            });
        } catch (e) {
            permission = null;              /* older Cockpit: not fatal */
        }
    }

    function adminAllowed() {
        try { return permission ? permission.allowed : null; }
        catch (e) { return null; }
    }

    function paintStatus() {
        if (!dom) return;
        if (dom.refreshBtn) dom.refreshBtn.disabled = !!state.loading;
        if (!dom.status) return;
        dom.status.textContent =
              state.loading ? "Loading…"
            : state.gate    ? "unavailable"     /* a count of 0 would read as fact */
            : state.loaded  ? (state.clients.length +
                                  (state.clients.length === 1 ? " client" : " clients"))
            : "";
    }

    function paint() {
        if (!dom) return;
        paintStatus();
        paintBanner();
        paintBody();
        paintIpam();
        paintRouting();
    }

    /* ------------------------------------------------------------------ *
     * Rendering - faults and notices
     * ------------------------------------------------------------------ */

    /*
     * The one place a fault turns into prose. Note that the attribution line is
     * derived from fault.blame, not from the message text: a Cockpit channel
     * code must never be presented as something wg-admin said.
     */
    function faultPanel(fault, retryLabel) {
        var cls = (fault.source === "denied") ? "warn" : "bad";
        var box = el("div", { cls: "wg-alert " + cls });

        box.appendChild(el("h3", { text: fault.title }));
        box.appendChild(el("div", { cls: "wgc-fault-detail", text: fault.detail }));

        if (fault.blame === "cockpit") {
            box.appendChild(el("div", { cls: "wg-hint",
                text: "Source: Cockpit" + (fault.problem ? " (problem “" + fault.problem +
                      "”)" : "") + ". This message is Cockpit's, not wg-admin's — " +
                      "the helper's own errors always arrive with an exit status instead." }));
        } else if (fault.blame === "backend") {
            box.appendChild(el("div", { cls: "wg-hint",
                text: "Source: " + state.binary + " on stderr" +
                      (fault.status !== undefined ? " (exit " + fault.status + ")" : "") + "." }));
        }

        if (fault.source === "denied") {
            var howto = el("ul");
            [ "Switch “Administrative access” on in the Cockpit header bar, " +
              "then press " + (retryLabel || "Retry") + ".",
              "That requires an account Cockpit accepts for sudo/polkit on this host." ]
                .forEach(function (t) { howto.appendChild(el("li", { text: t })); });
            box.appendChild(howto);
            var allowed = adminAllowed();
            if (allowed === false)
                box.appendChild(el("div", { cls: "wg-hint",
                    text: "Cockpit currently reports this session as unprivileged." }));
        }

        if (fault.source === "missing")
            box.appendChild(el("div", { cls: "wg-hint mono", text: state.binary }));

        if (fault.retry !== false)
            box.appendChild(el("div", { cls: "wgc-actions" },
                button(retryLabel || "Retry", "", function () { refresh(); })));

        return box;
    }

    function paintBanner() {
        clear(dom.banner);

        if (state.gate) {
            dom.banner.appendChild(faultPanel(state.gate, "Try again"));
            return;
        }

        /*
         * The LRU-reuse warning the contract demands be rendered prominently:
         * a sticky banner with its own style, dismissed only deliberately -
         * never a toast, never folded into the ordinary notice line.
         */
        if (state.reusedBanner) {
            var warnEl = el("div", { cls: "wgc-banner-warn" },
                el("h3", { text: state.reusedBanner.title }),
                el("div", { cls: "wgc-banner-warn-text", text: state.reusedBanner.text }),
                el("div", { cls: "wg-hint", text:
                    "The pool had no free address, so the least-recently-seen one was " +
                    "handed out again. If its previous holder comes back the two will " +
                    "conflict — release a reservation or retire the old device." }),
                el("div", { cls: "wgc-actions" },
                    button("Dismiss", "", function () {
                        state.reusedBanner = null; paintBanner();
                    })));
            warnEl.setAttribute("data-lru-warning", "");
            dom.banner.appendChild(warnEl);
        }

        if (state.notice) {
            var n = state.notice;
            if (n.fault) {
                /* Say which action failed as well as why: the fault panel only
                   knows about the channel or the exit status, not the intent. */
                var box = faultPanel(n.fault, "Reload state");
                box.insertBefore(el("div", { cls: "wg-subtle", text: n.title }),
                                 box.firstChild);
                dom.banner.appendChild(box);
            } else {
                var a = el("div", { cls: "wg-alert " + (n.cls === "ok" ? "" : n.cls) });
                a.appendChild(el("h3", { text: n.title }));
                if (n.text) a.appendChild(el("div", { cls: "wg-subtle", text: n.text }));
                dom.banner.appendChild(a);
            }
        }

        /* Non-blocking faults: one verb failed, the rest of the page is fine.
           ipam-status faults render inside the IPAM card instead, next to
           the data they concern. */
        [[state.catFault, "catalogue"],
         [state.listFault, "list"],
         [state.routingFault, "routing-status"],
         [state.schemaFault, "schema"]].forEach(function (pair) {
            var f = pair[0];
            if (!f || isBlockingFault(f) || f === state.gate) return;
            var box = faultPanel(f, "Retry");
            box.insertBefore(el("div", { cls: "wg-subtle", text: "wg-admin " + pair[1] }),
                             box.firstChild);
            dom.banner.appendChild(box);
        });
    }

    /* ------------------------------------------------------------------ *
     * Rendering - client list
     * ------------------------------------------------------------------ */

    function paintBody() {
        clear(dom.body);

        if (state.gate) return;             /* the banner already explains why */

        if (!state.loaded && state.loading) {
            dom.body.appendChild(el("div", { cls: "wg-empty", text: "Reading client list…" }));
            return;
        }

        if (ui.creating) dom.body.appendChild(createForm());

        if (!state.clients.length) {
            if (!ui.creating) dom.body.appendChild(emptyState());
            return;
        }

        var actionsRow = el("div", { cls: "wgc-actions" });
        if (!ui.creating)
            actionsRow.appendChild(button("Create client", "primary", function () {
                ui.creating = true; paintBody();
            }));
        dom.body.appendChild(actionsRow);

        state.clients.slice().sort(function (a, b) {
            return a.name < b.name ? -1 : (a.name > b.name ? 1 : 0);
        }).forEach(function (c) { dom.body.appendChild(clientCard(c)); });
    }

    function emptyState() {
        var box = el("div", { cls: "wg-card wgc-empty-card" },
            el("div", { cls: "wg-card-body" },
                el("h3", { cls: "wgc-empty-title", text: "No clients yet" }),
                el("p", { cls: "wg-subtle", text:
                    "Nothing is configured on this host yet. Create a client to get a " +
                    "key pair and a tunnel address; you can then build one or more named " +
                    "configs for it — for example a “lab” profile and a " +
                    "“lan” profile the same device can switch between." }),
                el("div", { cls: "wgc-actions" },
                    button("Create the first client", "primary", function () {
                        ui.creating = true; paintBody();
                    }))));
        return box;
    }

    /*
     * new-client. The IP is picked from the ipam-status free list rather than
     * typed: reserved, observed and peer addresses are already excluded by
     * the backend, so the picker cannot offer a colliding address. "(auto)"
     * hands the choice to wg-admin entirely.
     */
    function createForm() {
        var nameIn = textInput("", "laptop", 20);

        var ipSel = el("select", { cls: "wgc-input wgc-select" });
        ipSel.setAttribute("data-free-ip", "");
        ipSel.appendChild(el("option", { attrs: { value: "" }, text: "(auto)" }));
        (state.ipam.free || []).forEach(function (ip) {
            ipSel.appendChild(el("option", { attrs: { value: ip }, text: ip }));
        });
        ipSel.value = "";

        var ipHint = state.ipamFault
            ? "The free-address list could not be read (ipam-status failed), so only " +
              "“(auto)” is offered; wg-admin still allocates safely on the host."
            : "“(auto)” lets wg-admin allocate. The list is the free addresses " +
              "ipam-status reports — reserved, observed and peer addresses excluded.";

        var errBox = el("div", { cls: "wgc-form-error" });

        function submit() {
            var name = nameIn.value.trim();
            clear(errBox);

            if (!NAME_RE.test(name)) {
                errBox.appendChild(el("div", { cls: "wg-inline-err", text:
                    "Name must start with a letter or digit and use only letters, " +
                    "digits, dot, dash or underscore (max 32 characters)." }));
                return;
            }
            createClient(name, String(ipSel.value || ""));
        }

        var card = el("div", { cls: "wg-card wgc-form-card" },
            el("div", { cls: "wg-card-head" },
                el("span", { cls: "name", text: "New client" })),
            el("div", { cls: "wg-card-body" },
                el("div", { cls: "wgc-form-row" },
                    stamp(field("Name", nameIn, "Used for the directory under /etc/wireguard/clients."), "name"),
                    stamp(field("Tunnel IP", ipSel, ipHint), "ip")),
                errBox,
                el("div", { cls: "wgc-actions" },
                    button("Create", "primary", submit),
                    button("Cancel", "", function () { ui.creating = false; paintBody(); }))));

        nameIn.addEventListener("keydown", function (ev) {
            if (ev.key === "Enter") { ev.preventDefault(); submit(); }
        });
        return card;
    }

    /*
     * Not routed through mutate(): the reply must be inspected for the
     * contract's exhaustion signal. `reused:true` means the pool was empty
     * and the least-recently-seen address was handed out again - that gets
     * the sticky warning banner, never a quiet success line.
     */
    function createClient(name, ip) {
        var key = "new/" + name;
        if (ui.busy[key]) return Promise.resolve();
        ui.busy[key] = true;
        state.notice = null;
        paint();

        var args = ["new-client", name];
        if (ip) args = args.concat(["--ip", ip]);

        return callAdmin(args).then(function (res) {
            delete ui.busy[key];
            if (!res.ok) {
                state.notice = { cls: "bad",
                                 title: "Could not create client “" + name + "”",
                                 fault: res.fault };
                if (isBlockingFault(res.fault)) state.gate = res.fault;
                paint();
                return;
            }

            ui.creating = false;
            if (truthy(res.data.reused)) {
                state.reusedBanner = {
                    title: "Address REUSED for “" + name + "”" +
                           (res.data.ip ? " — " + String(res.data.ip) : ""),
                    text: String(res.data.warning ||
                        ("The pool has no free address; the least recently seen one " +
                         "was reused for this client."))
                };
            }
            state.notice = { cls: "ok",
                             title: "Client “" + name + "” created",
                             text: "A key pair was generated on the host. Build a config " +
                                   "for it below to get a .conf file." };
            return refresh();
        });
    }

    function clientCard(client) {
        var open = !!ui.open[client.name];

        var head = el("div", { cls: "wg-card-head" });
        head.appendChild(el("span", { cls: "name", text: client.name }));
        head.appendChild(el("span", { cls: "mono wgc-ip", text: client.ip || "—",
            title: "tunnel address" }));
        head.appendChild(pill(client.enabled ? "enabled" : "disabled",
                              client.enabled ? "ok" : "warn"));
        head.appendChild(pill(client.configs.length +
            (client.configs.length === 1 ? " config" : " configs"),
            client.configs.length ? "" : "warn"));

        var toggle = button(open ? "Hide" : "Manage", "", function () {
            ui.open[client.name] = !open;
            paintBody();
        });
        toggle.className += " wgc-head-btn";
        head.appendChild(toggle);

        var card = el("div", { cls: "wg-card wgc-client" }, head);
        var body = el("div", { cls: "wg-card-body" });

        if (!client.configs.length) {
            body.appendChild(el("div", { cls: "wg-empty", text:
                "No configs yet — this client has keys and an address but nothing " +
                "to hand to the device." }));
        } else {
            body.appendChild(configTable(client));
        }

        if (open) {
            body.appendChild(builderPanel(client));
            body.appendChild(dangerRow(client));
        }

        card.appendChild(body);
        return card;
    }

    function configTable(client) {
        /*
         * `list` may return configs as bare names or as objects carrying
         * allowed_ips. Show the column only when there is something in it -
         * a column of em-dashes reads as missing data rather than as a
         * field the contract does not promise.
         */
        var showRoutes = client.configs.some(function (cf) { return !!cf.allowed; });
        var span = showRoutes ? "3" : "2";

        var hrow = el("tr");
        ["Config", showRoutes ? "Client AllowedIPs" : null, ""]
            .forEach(function (h) {
                if (h !== null) hrow.appendChild(el("th", { text: h }));
            });
        var table = el("table", { cls: "wg-table" }, el("thead", {}, hrow));
        var tbody = el("tbody");

        client.configs.forEach(function (cf) {
            var key = vkey(client.name, cf.name);
            var v = ui.viewer[key];
            var pk = ui.pkg[key];
            var tr = el("tr");

            tr.appendChild(el("td", { cls: "mono nowrap", text: cf.name }));
            if (showRoutes)
                tr.appendChild(el("td", { cls: "mono", text: cf.allowed || "—",
                    title: cf.allowed ? "what this client routes into the tunnel" : "" }));

            var acts = el("td", { cls: "nowrap wgc-row-actions" });
            acts.appendChild(button(v && v.open ? "Hide config" : "Show config", "", function () {
                openViewer(client, cf.name);
            }));
            acts.appendChild(button(pk && pk.open ? "Hide package" : "Package", "", function () {
                togglePkg(client, cf.name);
            }, "Self-contained install bundle per OS, generated by wg-admin client-package."));

            var ckey = "delcfg/" + key;
            if (ui.confirm[ckey]) {
                acts.appendChild(button("Confirm delete", "danger", function () {
                    delete ui.confirm[ckey];
                    mutate(ckey, ["del-config", client.name, cf.name], {
                        ok: "Config “" + cf.name + "” removed from " + client.name,
                        fail: "Could not remove config “" + cf.name + "”"
                    });
                }));
                acts.appendChild(button("Keep", "", function () {
                    delete ui.confirm[ckey]; paintBody();
                }));
            } else {
                acts.appendChild(button("Delete", "", function () {
                    ui.confirm[ckey] = true; paintBody();
                }));
            }
            tr.appendChild(acts);
            tbody.appendChild(tr);

            if (v && v.open) {
                var vr = el("tr", { cls: "wgc-viewer-row" });
                var td = el("td", { attrs: { colspan: span } });
                td.appendChild(viewerPanel(client, cf.name, v));
                vr.appendChild(td);
                tbody.appendChild(vr);
            }

            if (pk && pk.open) {
                var pr = el("tr", { cls: "wgc-viewer-row" });
                var ptd = el("td", { attrs: { colspan: span } });
                ptd.appendChild(pkgPanel(client, cf.name, pk));
                pr.appendChild(ptd);
                tbody.appendChild(pr);
            }
        });

        table.appendChild(tbody);
        return el("div", { cls: "wg-table-wrap" }, table);
    }

    function dangerRow(client) {
        var ckey = "delclient/" + client.name;
        var row = el("div", { cls: "wgc-actions wgc-danger" });
        if (ui.confirm[ckey]) {
            row.appendChild(el("span", { cls: "wg-subtle", text:
                "Delete " + client.name + ", its keys and all " + client.configs.length +
                " config(s)? The device's current .conf stops working immediately." }));
            row.appendChild(button("Confirm delete client", "danger", function () {
                delete ui.confirm[ckey];
                mutate(ckey, ["del-client", client.name], {
                    ok: "Client “" + client.name + "” deleted",
                    fail: "Could not delete client “" + client.name + "”"
                });
            }));
            row.appendChild(button("Cancel", "", function () {
                delete ui.confirm[ckey]; paintBody();
            }));
        } else {
            row.appendChild(button("Delete client…", "", function () {
                ui.confirm[ckey] = true; paintBody();
            }));
        }
        return row;
    }

    /* ------------------------------------------------------------------ *
     * Rendering - the schema-driven config builder
     *
     * Contract v2 design rule: the UI renders NOTHING it invented. The only
     * non-schema input below is the config NAME, because that is a verb
     * argument (add-config NAME CFG), not a config field.
     * ------------------------------------------------------------------ */

    function builderPanel(client) {
        var b = builderFor(client);
        var panel = el("div", { cls: "wgc-builder" });
        panel.appendChild(el("h3", { cls: "wgc-sub", text: "Build a config for " + client.name }));

        if (!state.schema.ok) {
            if (state.schemaFault) {
                panel.appendChild(el("div", { cls: "wg-empty", text:
                    "wg-admin schema failed — see the banner above. Every control in " +
                    "this form is derived from the schema, so there is nothing to " +
                    "render without it." }));
            } else if (state.schema.version && state.schema.version !== 2) {
                panel.appendChild(el("div", { cls: "wg-alert warn" },
                    el("h3", { text: "Schema version mismatch" }),
                    el("div", { text:
                        "wg-admin publishes schema version " + state.schema.version +
                        " and this page implements version 2. Rendering a schema it " +
                        "does not understand could mislabel a control, so nothing is " +
                        "rendered instead." })));
            } else {
                panel.appendChild(el("div", { cls: "wg-empty", text:
                    "The form schema has not been read yet, so there is no form: " +
                    "every control on this page comes from `wg-admin schema` and " +
                    "none are invented here." }));
            }
            return panel;
        }

        seedBuilder(b, state.schema, state.cat);

        var nameIn = textInput(b.config, "lab", 16);
        nameIn.addEventListener("input", function () { b.config = nameIn.value; });
        panel.appendChild(el("div", { cls: "wgc-form-row" },
            stamp(field("Config name", nameIn,
                  "A client may hold several: e.g. “lab” and “lan”, " +
                  "switched per session on the device."), "config")));

        var ctx = {
            client: client,
            b: b,
            onChange: function () { paintRecos(client, b, true); }
        };

        state.schema.groups.forEach(function (g) {
            var sec = el("div", { cls: "wgc-sgroup" });
            if (g.title) sec.appendChild(el("h4", { cls: "wgc-sgroup-title", text: g.title }));
            g.fields.forEach(function (f) {
                /* name and ip are CLIENT-level: realized in the Create-client
                 * form, fixed for the life of the client, and not add-config
                 * flags. Rendering them here seeded an empty name that failed
                 * its own pattern and blocked every config creation - and a
                 * filled one would emit --name, which add-config rejects. */
                if (f.id === "name" || f.id === "ip") return;
                sec.appendChild(renderField(f, ctx));
            });
            panel.appendChild(sec);
        });

        b.recoBox = el("div", { cls: "wgc-reco-wrap" });
        panel.appendChild(b.recoBox);
        paintRecos(client, b, false);

        var errBox = el("div", { cls: "wgc-form-error" });
        panel.appendChild(errBox);
        panel.appendChild(el("div", { cls: "wgc-actions" },
            button("Create config", "primary", function () {
                submitConfig(client, b, errBox);
            }),
            button("Reset to defaults", "", function () {
                b.config = "";
                b.ids = Object.create(null);
                b.values = Object.create(null);
                b.invalid = Object.create(null);
                b.seeded = false;
                paintBody();
            })));

        return panel;
    }

    /*
     * renderField - the single place a schema `control` becomes DOM.
     *
     *   toggle          checkbox row + on/off state pill (live host switches
     *                   apply immediately via routing-set)
     *   number          <input type=number> with min/max + unit suffix
     *   text            input with pattern validation on every keystroke
     *   select          native <select>
     *   radio           radio group
     *   cidr-set        the destination toggle grid (catalogue-fed; cidr-less
     *                   control ids are filtered out) + the AllowedIPs
     *                   explanation panel
     *   readonly        label + value row
     *   password-reveal masked value with a Reveal click
     *   anything else   honest read-only "newer than this page" row
     */
    function renderField(f, ctx) {
        var b = ctx.b;
        var row = el("div", { cls: "wgc-srow wgc-srow-" +
                                   f.control.replace(/[^a-z0-9-]/gi, "") });
        /* Stable hook for tests and tooling: the schema id travels on the row,
         * so "which DOM node renders schema field X" never depends on label
         * text or ordering. */
        row.setAttribute("data-field", String(f.id));
        var labelCell = el("div", { cls: "wgc-srow-label" }, el("span", { text: f.label }));
        var ctl = el("div", { cls: "wgc-srow-ctl" });
        var side = el("div", { cls: "wgc-srow-side" });
        var below = el("div", { cls: "wgc-srow-below" });

        var errNode = el("div", { cls: "wgc-srow-err" });
        function setErr(msg) {
            clear(errNode);
            b.invalid[f.id] = !!msg;
            if (msg) errNode.appendChild(el("div", { cls: "wg-inline-err", text: msg }));
        }

        var cur = (f.id in b.values) ? b.values[f.id] : f["default"];

        if (!f.known)                            renderUnknown(f, ctl, side, cur);
        else if (f.control === "toggle")          renderToggle(f, ctx, ctl, side, cur);
        else if (f.control === "number")          renderNumber(f, ctx, ctl, cur, setErr);
        else if (f.control === "text")            renderText(f, ctx, ctl, cur, setErr);
        else if (f.control === "select")          renderSelect(f, ctx, ctl, cur);
        else if (f.control === "radio")           renderRadio(f, ctx, ctl, cur);
        else if (f.control === "cidr-set")        renderCidrSet(f, ctx, ctl);
        else if (f.control === "readonly")        renderReadonly(f, ctl, side, cur);
        else if (f.control === "password-reveal") renderSecret(f, ctl, side, cur);

        if (f.help) below.appendChild(el("div", { cls: "wg-hint", text: f.help }));
        below.appendChild(errNode);

        row.appendChild(el("div", { cls: "wgc-srow-main" }, labelCell, ctl, side));
        row.appendChild(below);
        return row;
    }

    function renderUnknown(f, ctl, side, cur) {
        ctl.appendChild(el("span", { cls: "wg-subtle", text:
            "The schema uses control type “" + f.control + "”, which is newer than " +
            "this page. The value is shown read-only." }));
        if (cur !== null && cur !== undefined && String(cur) !== "")
            side.appendChild(el("span", { cls: "mono", text: String(cur) }));
    }

    function renderToggle(f, ctx, ctl, side, cur) {
        var b = ctx.b;
        var live = liveRoutingId(f.id);
        var on = live ? liveToggleState(f) : truthy(cur);

        var input = el("input", { attrs: { type: "checkbox" } });
        input.checked = on;

        var statePill = pill(on ? "on" : "off", on ? "ok" : "");

        if (live) {
            /* The backend addresses this id via routing-set, so the toggle is
               a live host switch: it applies immediately, and its state comes
               from routing-status rather than from the form. */
            var key = "routing/" + f.id;
            input.disabled = !!ui.busy[key];
            input.addEventListener("change", function () {
                var want = input.checked ? "on" : "off";
                input.disabled = true;
                mutate(key, ["routing-set", f.id, want], {
                    ok: f.label + " turned " + want,
                    fail: "Could not turn " + f.label + " " + want
                });
            });
            side.appendChild(statePill);
            side.appendChild(pill("live", "", null));
            ctl.appendChild(el("label", { cls: "wgc-toggle-row",
                title: "Applies immediately: wg-admin routing-set " + f.id + " on|off" },
                input,
                el("span", { cls: "wg-subtle", text: "host-wide, applies immediately" })));
        } else {
            input.addEventListener("change", function () {
                b.values[f.id] = !!input.checked;
                statePill.textContent = input.checked ? "on" : "off";
                statePill.className = "pill" + (input.checked ? " ok" : "");
                ctx.onChange(f);
            });
            side.appendChild(statePill);
            ctl.appendChild(el("label", { cls: "wgc-toggle-row" }, input,
                el("span", { cls: "wg-subtle", text: "written into this config" })));
        }
    }

    function withBreak(f, msg) {
        return f.breaks_when_wrong ? msg + " " + f.breaks_when_wrong : msg;
    }

    function numberProblem(f, v) {
        var s = String(v === null || v === undefined ? "" : v).trim();
        if (s === "") return "";             /* empty falls back to the default */
        var n = Number(s);
        if (!isFinite(n))
            return withBreak(f, "“" + s + "” is not a number.");
        if (f.min !== null && n < f.min)
            return withBreak(f, "Minimum is " + f.min + (f.unit ? " " + f.unit : "") + ".");
        if (f.max !== null && n > f.max)
            return withBreak(f, "Maximum is " + f.max + (f.unit ? " " + f.unit : "") + ".");
        return "";
    }

    function renderNumber(f, ctx, ctl, cur, setErr) {
        var input = el("input", { cls: "wgc-input wgc-num",
                                  attrs: { type: "number", spellcheck: "false" } });
        if (f.min !== null) input.setAttribute("min", String(f.min));
        if (f.max !== null) input.setAttribute("max", String(f.max));
        if (f.placeholder) input.setAttribute("placeholder", f.placeholder);
        input.value = (cur === null || cur === undefined) ? "" : String(cur);

        input.addEventListener("input", function () {
            ctx.b.values[f.id] = input.value;
            setErr(numberProblem(f, input.value));
            ctx.onChange(f);
        });

        ctl.appendChild(input);
        if (f.unit) ctl.appendChild(el("span", { cls: "wgc-unit wg-subtle", text: f.unit }));
        setErr(numberProblem(f, input.value));
    }

    function renderText(f, ctx, ctl, cur, setErr) {
        var input = textInput(cur, f.placeholder, null);
        var re = null;
        if (f.pattern) {
            try { re = new RegExp("^(?:" + f.pattern + ")$"); }
            catch (e) { re = null; }         /* an unusable pattern must not
                                                take the whole form down      */
        }

        function check() {
            if (re && !re.test(input.value))
                setErr(withBreak(f, "Does not match the required format" +
                       (f.placeholder ? " (e.g. " + f.placeholder + ")" : "") + "."));
            else
                setErr("");
        }

        input.addEventListener("input", function () {
            ctx.b.values[f.id] = input.value;
            check();
            ctx.onChange(f);
        });

        ctl.appendChild(input);
        check();
    }

    function renderSelect(f, ctx, ctl, cur) {
        var sel = el("select", { cls: "wgc-input wgc-select" });
        f.options.forEach(function (o) {
            sel.appendChild(el("option", { attrs: { value: o.value }, text: o.label }));
        });
        sel.value = String(cur === null || cur === undefined ? "" : cur);
        sel.addEventListener("change", function () {
            ctx.b.values[f.id] = sel.value;
            ctx.onChange(f);
        });
        ctl.appendChild(sel);
    }

    function renderRadio(f, ctx, ctl, cur) {
        var wrap = el("div", { cls: "wgc-radio" });
        var groupName = "wgcr-" + ctx.client.name + "-" + f.id;
        f.options.forEach(function (o) {
            var input = el("input", { attrs: { type: "radio", name: groupName,
                                               value: o.value } });
            input.checked = String(cur) === o.value;
            input.addEventListener("change", function () {
                if (!input.checked) return;
                ctx.b.values[f.id] = o.value;
                ctx.onChange(f);
            });
            wrap.appendChild(el("label", { cls: "wgc-radio-opt" }, input,
                el("span", { text: o.label })));
        });
        ctl.appendChild(wrap);
    }

    function renderReadonly(f, ctl, side, cur) {
        ctl.appendChild(el("span", { cls: "mono wgc-ro-value",
            text: (cur === null || cur === undefined || String(cur) === "")
                    ? "—" : String(cur) }));
        if (f.unit) ctl.appendChild(el("span", { cls: "wgc-unit wg-subtle", text: f.unit }));
        side.appendChild(pill("read-only", ""));
    }

    function renderSecret(f, ctl, side, cur) {
        var value = (cur === null || cur === undefined) ? "" : String(cur);
        if (!value) {
            ctl.appendChild(el("span", { cls: "wg-subtle", text: "(not set)" }));
            return;
        }
        var revealed = false;
        var span = el("span", { cls: "mono wgc-secret", text: MASK });
        var btn = button("Reveal", "", function () {
            revealed = !revealed;
            span.textContent = revealed ? value : MASK;
            btn.textContent = revealed ? "Hide" : "Reveal";
        }, "Shown only on this screen; never written to the console or a URL.");
        ctl.appendChild(span);
        ctl.appendChild(btn);
        side.appendChild(pill("secret", "warn"));
    }

    function renderCidrSet(f, ctx, ctl) {
        var b = ctx.b, cat = state.cat, client = ctx.client;

        if (!cat.ok) {
            ctl.appendChild(el("div", { cls: "wg-empty", text:
                "The destination catalogue could not be read, so there is nothing " +
                "to choose from. Subnets are never hardcoded in this page." }));
            return;
        }

        /* --- presets (catalogue data, not invented here) ---------------- */
        if (cat.presetOrder.length) {
            var presetRow = el("div", { cls: "wgc-presets" });
            presetRow.appendChild(el("span", { cls: "wg-subtle", text: "Presets:" }));
            cat.presetOrder.forEach(function (p) {
                presetRow.appendChild(button(p, "wgc-preset", function () {
                    b.ids = Object.create(null);
                    presetIds(cat, p).forEach(function (id) { b.ids[id] = true; });
                    syncToggles(b);
                    paintExplain(client, b);
                    ctx.onChange(f);
                }, "Sets the toggles to: " + presetIds(cat, p).join(", ")));
            });
            ctl.appendChild(presetRow);
            ctl.appendChild(el("div", { cls: "wg-hint", text:
                "A preset only sets the toggles below — nothing is written until " +
                "you press Create config." }));
        }

        /* --- destination toggles ---------------------------------------- */
        var toggles = el("div", { cls: "wgc-toggles" });
        b.nodes = Object.create(null);

        cat.networks.forEach(function (n) {
            /*
             * The catalogue doubles as the address space for routing-set, so it
             * carries non-routable control ids (ip_forward) alongside real
             * destinations. Those have no cidr and must never appear as a route
             * toggle: ticking one would write an id the generator rejects. They
             * surface instead as schema fields (the routing group's toggles).
             */
            if (!n.cidr) return;

            var input = el("input", { attrs: { type: "checkbox" } });
            input.setAttribute("data-net", n.id);
            input.value = n.id;
            input.checked = !!b.ids[n.id];
            b.nodes[n.id] = input;

            input.addEventListener("change", function () {
                b.ids[n.id] = input.checked;
                /*
                 * 0.0.0.0/0 and a specific subnet are not a meaningful pair:
                 * the default route already covers it. Keep the toggles honest
                 * so what is on screen is what gets written.
                 */
                if (input.checked && n.full)
                    cat.networks.forEach(function (o) { if (o !== n) b.ids[o.id] = false; });
                else if (input.checked)
                    cat.networks.forEach(function (o) { if (o.full) b.ids[o.id] = false; });
                syncToggles(b);
                paintExplain(client, b);
                ctx.onChange(f);
            });

            var lab = el("label", { cls: "wgc-toggle" + (n.full ? " wgc-toggle-full" : "") },
                input,
                el("span", { cls: "wgc-toggle-id", text: n.id }),
                el("span", { cls: "mono wgc-toggle-cidr", text: n.cidr || "—" }),
                el("span", { cls: "wg-subtle wgc-toggle-desc", text: n.description || "" }));
            toggles.appendChild(lab);
        });
        ctl.appendChild(toggles);

        /* --- live explanation ------------------------------------------- */
        b.explainBox = el("div", { cls: "wgc-explain-wrap" });
        ctl.appendChild(b.explainBox);
        paintExplain(client, b);
    }

    function syncToggles(b) {
        Object.keys(b.nodes).forEach(function (id) {
            b.nodes[id].checked = !!b.ids[id];
        });
    }

    /*
     * The centrepiece. Rebuilt on every toggle, and only this node is rebuilt,
     * so the checkbox that has focus keeps it.
     */
    function paintExplain(client, b) {
        if (!b.explainBox) return;
        clear(b.explainBox);

        var model = explain(state.cat, selectedIds(b), client.ip);

        var left = el("div", { cls: "wgc-explain-col" },
            el("h4", { text: "The client routes this INTO the tunnel" }),
            el("div", { cls: "wg-subtle", text:
                "[Peer] AllowedIPs in the .conf you hand to the device — the list " +
                "of destinations it will send through wg0 instead of its normal route." }));

        if (!model.client.length) {
            left.appendChild(el("div", { cls: "wg-empty", text: "nothing selected" }));
        } else {
            var ul = el("ul", { cls: "wgc-cidrs" });
            model.client.forEach(function (n) {
                ul.appendChild(el("li", {},
                    el("span", { cls: "mono wgc-cidr", text: n.cidr || "—" }),
                    el("span", { cls: "wg-subtle", text: " " + n.id +
                        (n.description ? " — " + n.description : "") })));
            });
            left.appendChild(ul);
        }

        var right = el("div", { cls: "wgc-explain-col" },
            el("h4", { text: "The server ACCEPTS only this from the peer" }),
            el("div", { cls: "wg-subtle", text:
                "[Peer] AllowedIPs in this host's wg0 config — cryptokey routing: " +
                "the only source address this peer may use, and where replies are sent." }));

        var rul = el("ul", { cls: "wgc-cidrs" });
        if (model.server.length)
            rul.appendChild(el("li", {},
                el("span", { cls: "mono wgc-cidr", text: model.server[0] }),
                el("span", { cls: "wg-subtle", text: " " + client.name + " and nothing else" })));
        else
            rul.appendChild(el("li", {}, el("span", { cls: "wg-subtle", text:
                "unknown — this client has no usable tunnel address" })));
        right.appendChild(rul);
        right.appendChild(el("div", { cls: "wg-hint", text:
            "It does not change when you move the toggles, and it must not: the " +
            "selection above is the client's business only." }));

        b.explainBox.appendChild(el("div", { cls: "wgc-explain" }, left, right));

        b.explainBox.appendChild(el("p", { cls: "wg-hint wgc-asym", text:
            "Same field name, two different jobs. Copying the destination list onto " +
            "the server side is the classic mistake: it tells this host to route those " +
            "subnets TO the client, and when two peers claim overlapping ranges the last " +
            "match silently wins — the tunnel comes up and nothing works. " +
            "wg-admin derives both columns from the one selection so they cannot " +
            "disagree." }));

        model.warnings.forEach(function (w) {
            var cls = (w.level === "bad") ? "bad" : (w.level === "warn" ? "warn" : "");
            b.explainBox.appendChild(el("div", { cls: "wg-alert wgc-inline-alert " + cls },
                el("div", { text: w.text })));
        });
    }

    /* ------------------------------------------------------------------ *
     * Rendering - the recommendation engine
     *
     * Re-evaluated on EVERY field change (ctx.onChange), using only the six
     * contract operators. Firing recommendations with a `check:` resolve it
     * against routing-status; warn-level ones whose check is NOT active get
     * the one-click routing-set fix.
     * ------------------------------------------------------------------ */

    function paintRecos(client, b, fresh) {
        if (!b.recoBox) return;
        clear(b.recoBox);
        if (!state.schema.ok) return;

        var res = recoFiring(state.schema.recommendations, fieldValueGetter(client, b));
        if (!res.firing.length && !res.rejected.length) return;

        var box = el("div", { cls: "wgc-recos" });
        box.appendChild(el("h4", { cls: "wgc-sgroup-title", text: "Recommendations" }));

        var anyCheck = false;
        res.firing.forEach(function (r) {
            var node = el("div", { cls: "wg-alert wgc-inline-alert wgc-reco" +
                                       (r.level === "warn" ? " warn" : "") });
            var target = checkTarget(r.check);

            if (r.check && !target) {
                node.appendChild(el("div", { text: interpolateState(r.text, "unknown") }));
                node.appendChild(el("div", { cls: "wg-hint", text:
                    "The schema's check “" + r.check + "” is not a routing-status " +
                    "check this page understands, so the live state cannot be shown." }));
            } else if (target) {
                anyCheck = true;
                var st = resolveCheckState(state.routing, target);
                node.appendChild(el("div", { text: interpolateState(r.text, stateWord(st)) }));
                if (!st.known)
                    node.appendChild(el("div", { cls: "wg-hint", text:
                        "routing-status reports no entry named “" + target + "”." }));
                if (st.known && !st.active && r.level === "warn")
                    node.appendChild(el("div", { cls: "wgc-actions" },
                        button("Enable now", "primary", function () {
                            enableRouting(client, b, target);
                        }, "Runs wg-admin routing-set " + target + " on, then re-checks.")));
            } else {
                node.appendChild(el("div", { text: r.text }));
            }
            box.appendChild(node);
        });

        /* A rejected operator is reported, never guessed at. */
        res.rejected.forEach(function (rej) {
            box.appendChild(el("div", { cls: "wg-alert wgc-inline-alert" },
                el("div", { text:
                    "Recommendation “" + rej.reco.id + "” was not evaluated: " +
                    rej.reason + ". This page implements exactly contains_any, " +
                    "equals, not_equals, gt, lt and truthy." })));
        });

        b.recoBox.appendChild(box);

        /* Live resolution: re-read routing-status so <state> is current, then
           repaint only this box (the field keeping focus must not rebuild). */
        if (fresh && anyCheck) freshenRecoState(client, b);
    }

    function freshenRecoState(client, b) {
        var seq = ++recoSeq;
        callAdmin(["routing-status"]).then(function (res) {
            if (seq !== recoSeq) return;               /* superseded */
            if (res.ok) {
                state.routing = normaliseRouting(res.data);
                state.routingFault = null;
            }
            paintRecos(client, b, false);
        });
    }

    function enableRouting(client, b, target) {
        var key = "recofix/" + target;
        if (ui.busy[key]) return;
        ui.busy[key] = true;
        callAdmin(["routing-set", target, "on"]).then(function (res) {
            delete ui.busy[key];
            if (!res.ok) {
                state.notice = { cls: "bad",
                                 title: "Could not enable “" + target + "”",
                                 fault: res.fault };
                if (isBlockingFault(res.fault)) state.gate = res.fault;
                paint();
                return;
            }
            /* Re-check, then repaint the pieces that show routing state. */
            callAdmin(["routing-status"]).then(function (r2) {
                if (r2.ok) {
                    state.routing = normaliseRouting(r2.data);
                    state.routingFault = null;
                }
                paintRecos(client, b, false);
                paintRouting();
            });
        });
    }

    /* ------------------------------------------------------------------ *
     * Rendering - config viewer (private key handling lives here)
     * ------------------------------------------------------------------ */

    function openViewer(client, cfg) {
        var key = vkey(client.name, cfg);
        var v = ui.viewer[key];

        if (v && v.open) { v.open = false; paintBody(); return; }

        v = ui.viewer[key] = { open: true, loading: true, conf: "", qr: "",
                               qrWanted: false, reveal: false, fault: null,
                               copied: "" };
        paintBody();
        loadConfig(client, cfg, false);
    }

    function loadConfig(client, cfg, wantQr) {
        var key = vkey(client.name, cfg);
        var v = ui.viewer[key];
        if (!v) return;
        v.loading = true;
        paintBody();

        var args = ["get-config", client.name, cfg];
        if (wantQr) args.push("--qr");

        callAdmin(args).then(function (res) {
            var cur = ui.viewer[key];
            if (!cur) return;
            cur.loading = false;
            if (res.ok) {
                cur.fault = null;
                cur.conf = String(res.data.conf || "");
                if (wantQr) cur.qr = String(res.data.qr || "");
                /* Optional, additive: if the reply flags the Endpoint as a
                   placeholder, say so. Absent field -> no claim either way. */
                cur.placeholder = (res.data.endpoint_placeholder !== undefined) &&
                                  truthy(res.data.endpoint_placeholder);
            } else {
                cur.fault = res.fault;
                if (isBlockingFault(res.fault)) state.gate = res.fault;
            }
            paint();
        });
    }

    function viewerPanel(client, cfg, v) {
        var box = el("div", { cls: "wgc-viewer" });

        box.appendChild(el("div", { cls: "wgc-secret-note" },
            el("strong", { text: "Contains a private key. " }),
            el("span", { text:
                "It is masked below until you click Reveal, and it is never written to " +
                "the browser console or into a link. Treat the copy and the download " +
                "as you would a password." })));

        if (v.loading) {
            box.appendChild(el("div", { cls: "wg-empty", text: "Reading configuration…" }));
            return box;
        }

        if (v.fault) {
            box.appendChild(faultPanel(v.fault, "Try again"));
            return box;
        }

        if (v.placeholder)
            box.appendChild(el("div", { cls: "wg-alert warn wgc-inline-alert" },
                el("div", { text:
                    "The Endpoint line in this config is a placeholder. Replace it with " +
                    "the address and port clients actually reach this host on before " +
                    "handing the file over, or the tunnel will never handshake." })));

        var pre = el("pre", { cls: "wg-rules wgc-conf",
                              text: v.reveal ? v.conf : maskConf(v.conf) });
        box.appendChild(pre);

        var acts = el("div", { cls: "wgc-actions" });

        acts.appendChild(button(v.reveal ? "Hide private key" : "Reveal private key", "", function () {
            v.reveal = !v.reveal;
            pre.textContent = v.reveal ? v.conf : maskConf(v.conf);
            paintBody();
        }));

        var copyBtn = button(v.copied || "Copy to clipboard", "", function () {
            copyText(v.conf).then(function (ok) {
                v.copied = ok ? "Copied" : "Copy failed — select and copy manually";
                copyBtn.textContent = v.copied;
                window.setTimeout(function () {
                    v.copied = "";
                    if (copyBtn.parentNode) copyBtn.textContent = "Copy to clipboard";
                }, 2500);
            });
        }, "Puts the whole configuration, private key included, on the clipboard.");
        acts.appendChild(copyBtn);

        acts.appendChild(button("Download .conf", "", function () {
            downloadText(safeFileName(client.name, cfg), v.conf);
        }, "Saves " + safeFileName(client.name, cfg)));

        acts.appendChild(button(v.qrWanted ? "Hide QR" : "Show QR", "", function () {
            v.qrWanted = !v.qrWanted;
            if (v.qrWanted && !v.qr) loadConfig(client, cfg, true);
            else paintBody();
        }, "For the phone app: scan instead of transferring a file."));

        box.appendChild(acts);

        if (v.qrWanted) {
            if (v.qr) {
                box.appendChild(el("pre", { cls: "wgc-qr", text: v.qr }));
                box.appendChild(el("div", { cls: "wg-hint", text:
                    "The code encodes the entire configuration, private key included. " +
                    "Do not photograph it, screen-share it, or leave it on screen." }));
            } else {
                box.appendChild(el("div", { cls: "wg-empty", text:
                    "The helper returned no qr field for this config." }));
            }
        }

        return box;
    }

    /* ------------------------------------------------------------------ *
     * Rendering - client packages (per-client per-config OS bundles)
     * ------------------------------------------------------------------ */

    function osLabel(os) {
        for (var i = 0; i < PACKAGE_OSES.length; i++)
            if (PACKAGE_OSES[i][0] === os) return PACKAGE_OSES[i][1];
        return os;
    }

    function togglePkg(client, cfg) {
        var key = vkey(client.name, cfg);
        var p = ui.pkg[key];
        if (p && p.open) { p.open = false; paintBody(); return; }
        if (!p)
            p = ui.pkg[key] = { open: true, os: PACKAGE_OSES[0][0],
                                perOs: Object.create(null) };
        p.open = true;
        paintBody();
        ensurePackage(client, cfg, p.os);
    }

    function ensurePackage(client, cfg, os) {
        var key = vkey(client.name, cfg);
        var p = ui.pkg[key];
        if (!p) return;
        var slot = p.perOs[os];
        if (slot && (slot.loading || slot.data)) return;   /* cached or in flight */

        p.perOs[os] = { loading: true, data: null, fault: null,
                        reveal: Object.create(null) };
        paintBody();

        callAdmin(["client-package", client.name, cfg, "--os", os]).then(function (res) {
            var cur = ui.pkg[key];
            if (!cur) return;
            var s = cur.perOs[os];
            if (!s) return;
            s.loading = false;
            if (res.ok) {
                s.data = normalisePackage(res.data);
            } else {
                s.fault = res.fault;
                if (isBlockingFault(res.fault)) state.gate = res.fault;
            }
            paint();
        });
    }

    function pkgPanel(client, cfg, p) {
        var box = el("div", { cls: "wgc-pkg" });

        box.appendChild(el("div", { cls: "wgc-secret-note" },
            el("strong", { text: "The configuration file in this bundle contains a private key. " }),
            el("span", { text:
                "It stays masked until you click its Reveal button. Treat copies and " +
                "downloads as you would a password." })));

        /* --- OS tabs ----------------------------------------------------- */
        var tabs = el("div", { cls: "wgc-tabs", attrs: { role: "tablist" } });
        PACKAGE_OSES.forEach(function (pair) {
            var os = pair[0], label = pair[1];
            tabs.appendChild(button(label,
                "wgc-tab" + (p.os === os ? " active" : ""),
                function () {
                    p.os = os;
                    paintBody();
                    ensurePackage(client, cfg, os);
                },
                "wg-admin client-package " + client.name + " " + cfg + " --os " + os));
        });
        box.appendChild(tabs);

        var slot = p.perOs[p.os];
        if (!slot || slot.loading) {
            box.appendChild(el("div", { cls: "wg-empty",
                text: "Generating the " + osLabel(p.os) + " bundle…" }));
            return box;
        }

        if (slot.fault) {
            var fp = faultPanel(slot.fault, "Reload state");
            fp.insertBefore(el("div", { cls: "wg-subtle",
                text: "wg-admin client-package " + client.name + " " + cfg +
                      " --os " + p.os }), fp.firstChild);
            box.appendChild(fp);
            box.appendChild(el("div", { cls: "wgc-actions" },
                button("Regenerate", "", function () {
                    delete p.perOs[p.os];
                    paintBody();
                    ensurePackage(client, cfg, p.os);
                })));
            return box;
        }

        var d = slot.data;

        /* --- instructions render ABOVE the files ------------------------- */
        if (d.instructions) {
            box.appendChild(el("h4", { cls: "wgc-pkg-h",
                text: "Install steps — " + osLabel(p.os) }));
            var ol = el("ol", { cls: "wgc-pkg-steps" });
            splitInstructions(d.instructions).forEach(function (s) {
                ol.appendChild(el("li", { text: s }));
            });
            box.appendChild(ol);
        }

        if (d.undo_note)
            box.appendChild(el("div", { cls: "wgc-undo-note" },
                el("strong", { text: "Undo: " }),
                el("span", { text: d.undo_note })));

        if (!d.files.length)
            box.appendChild(el("div", { cls: "wg-empty",
                text: "The bundle contained no files." }));

        d.files.forEach(function (f, idx) {
            box.appendChild(pkgFile(slot, f, idx));
        });

        return box;
    }

    function pkgFile(slot, f, idx) {
        /* If masking changes the content, the file holds a key: same handling
           as get-config - masked until an explicit Reveal. */
        var secret = maskConf(f.content) !== f.content;
        var revealed = !!slot.reveal[idx];

        var head = el("div", { cls: "wgc-file-head" },
            el("span", { cls: "mono wgc-file-name", text: f.name }),
            f.mode ? el("span", { cls: "wgc-file-mode mono", text: "mode " + f.mode }) : null,
            secret ? pill("private key", "warn") : null);

        var pre = el("pre", { cls: "wg-rules wgc-file-body",
            text: (secret && !revealed) ? maskConf(f.content) : f.content });
        if (secret) pre.setAttribute("data-conf", "");

        var acts = el("div", { cls: "wgc-actions" });

        if (secret)
            acts.appendChild(button(revealed ? "Hide private key" : "Reveal private key",
                "", function () {
                    slot.reveal[idx] = !revealed;
                    paintBody();
                }));

        var copyBtn = button("Copy", "", function () {
            copyText(f.content).then(function (ok) {
                copyBtn.textContent = ok ? "Copied" : "Copy failed — select and copy manually";
                window.setTimeout(function () {
                    if (copyBtn.parentNode) copyBtn.textContent = "Copy";
                }, 2500);
            });
        }, "Copies the full file content" + (secret ? ", private key included." : "."));
        acts.appendChild(copyBtn);

        acts.appendChild(button("Download", "", function () {
            downloadText(safeBundleName(f.name), f.content);
        }, "Saves " + safeBundleName(f.name) +
           (f.mode ? ". Set mode " + f.mode + " after saving — a browser download cannot carry it."
                   : "")));

        return el("div", { cls: "wgc-file" }, head, pre, acts);
    }

    /*
     * Clipboard. navigator.clipboard needs a secure context; Cockpit is served
     * over TLS in the normal case but not always, hence the textarea fallback.
     * Neither path logs the text.
     */
    function copyText(text) {
        try {
            if (window.navigator && navigator.clipboard && navigator.clipboard.writeText)
                return navigator.clipboard.writeText(text)
                    .then(function () { return true; }, function () { return legacyCopy(text); });
        } catch (e) { /* fall through */ }
        return Promise.resolve(legacyCopy(text));
    }

    function legacyCopy(text) {
        try {
            var ta = el("textarea", { cls: "wgc-offscreen" });
            ta.value = text;
            document.body.appendChild(ta);
            ta.select();
            var ok = document.execCommand("copy");
            document.body.removeChild(ta);
            return !!ok;
        } catch (e) {
            return false;
        }
    }

    /*
     * Blob + object URL, revoked immediately. Deliberately NOT a data: URI:
     * that would put the private key into a URL, where it can end up in the
     * status bar, in history, or in a screenshot.
     */
    function downloadText(filename, text) {
        try {
            var blob = new window.Blob([text], { type: "application/octet-stream" });
            var url = window.URL.createObjectURL(blob);
            var a = el("a", { attrs: { href: url, download: filename } });
            a.style.display = "none";
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.setTimeout(function () { window.URL.revokeObjectURL(url); }, 30000);
            return true;
        } catch (e) {
            return false;
        }
    }

    /* ------------------------------------------------------------------ *
     * Rendering - IPAM panel
     * ------------------------------------------------------------------ */

    function paintIpam() {
        if (!dom || !dom.ipam) return;
        clear(dom.ipam);
        if (state.gate) return;
        if (!state.loaded) return;

        var head = el("div", { cls: "wg-card-head" },
            el("span", { cls: "name", text: "IP address management" }),
            state.ipam.pool
                ? el("span", { cls: "mono wg-subtle", text: state.ipam.pool })
                : null);

        var body = el("div", { cls: "wg-card-body" });

        if (state.ipamFault) {
            var fp = faultPanel(state.ipamFault, "Retry");
            fp.insertBefore(el("div", { cls: "wg-subtle", text: "wg-admin ipam-status" }),
                            fp.firstChild);
            body.appendChild(fp);
            dom.ipam.appendChild(el("div", { cls: "wg-card wgc-ipam" }, head, body));
            return;
        }

        body.appendChild(el("div", { cls: "wg-subtle wgc-ipam-summary", text:
            state.ipam.reserved.length + " reserved · " +
            state.ipam.observed.length + " observed · " +
            state.ipam.free.length + " free" }));

        /* --- reservations ----------------------------------------------- */
        var hrow = el("tr");
        /* "MAC / WG key" is the contract's own column label: the tunnel is
           L3, its peers have no MAC, so the public key is the identity. */
        ["IP", "Name", "MAC / WG key", "Last seen", ""].forEach(function (h) {
            hrow.appendChild(el("th", { text: h }));
        });
        var table = el("table", { cls: "wg-table" }, el("thead", {}, hrow));
        var tbody = el("tbody");

        if (!state.ipam.reserved.length) {
            var tr0 = el("tr");
            tr0.appendChild(el("td", { attrs: { colspan: "5" }, cls: "wg-empty", text:
                "No reservations. Reserving pins an address to a device so " +
                "allocation never hands it out." }));
            tbody.appendChild(tr0);
        }

        state.ipam.reserved.forEach(function (r) {
            var tr = el("tr");
            tr.appendChild(el("td", { cls: "mono nowrap", text: r.ip }));
            tr.appendChild(el("td", { text: r.name || "—" }));
            tr.appendChild(el("td", { cls: "mono wgc-ident",
                text: r.mac || r.pubkey || "—",
                title: r.mac ? "MAC address (L2 identity)"
                     : (r.pubkey ? "WireGuard public key — tunnel peers have no MAC" : "") }));
            tr.appendChild(el("td", { cls: "nowrap", text: r.last_seen || "never" }));

            var acts = el("td", { cls: "nowrap wgc-row-actions" });
            var ckey = "ipamrel/" + r.ip;
            if (ui.confirm[ckey]) {
                acts.appendChild(button("Confirm release", "danger", function () {
                    delete ui.confirm[ckey];
                    mutate(ckey, ["ipam-release", r.ip], {
                        ok: "Reservation for " + r.ip + " released",
                        fail: "Could not release " + r.ip
                    });
                }));
                acts.appendChild(button("Keep", "", function () {
                    delete ui.confirm[ckey]; paintIpam();
                }));
            } else {
                acts.appendChild(button("Release", "", function () {
                    ui.confirm[ckey] = true; paintIpam();
                }));
            }
            tr.appendChild(acts);
            tbody.appendChild(tr);
        });

        table.appendChild(tbody);
        body.appendChild(el("div", { cls: "wg-table-wrap" }, table));

        body.appendChild(reserveForm());
        body.appendChild(scanRow());

        dom.ipam.appendChild(el("div", { cls: "wg-card wgc-ipam" }, head, body));
    }

    function reserveForm() {
        var ipIn = textInput("", "172.16.0.20", 16);
        var nameIn = textInput("", "printer", 16);
        var idIn = textInput("", "MAC or WireGuard public key", 30);
        var errBox = el("div", { cls: "wgc-form-error" });

        function submit() {
            clear(errBox);
            var ip = ipIn.value.trim(), name = nameIn.value.trim(),
                idv = idIn.value.trim();

            if (!validIpv4(ip)) {
                errBox.appendChild(el("div", { cls: "wg-inline-err", text:
                    "“" + ip + "” is not an IPv4 address." }));
                return;
            }
            if (!name) {
                errBox.appendChild(el("div", { cls: "wg-inline-err", text:
                    "Give the reservation a name — an anonymous pin is a mystery " +
                    "in a month." }));
                return;
            }

            var args = ["ipam-reserve", ip, "--name", name];
            if (idv) {
                if (MAC_RE.test(idv)) args = args.concat(["--mac", idv]);
                else if (WGKEY_RE.test(idv)) args = args.concat(["--pubkey", idv]);
                else {
                    errBox.appendChild(el("div", { cls: "wg-inline-err", text:
                        "Identity must be a MAC (aa:bb:cc:dd:ee:ff) or a " +
                        "44-character WireGuard public key. Tunnel peers have no " +
                        "MAC — use the key." }));
                    return;
                }
            }

            mutate("ipamres/" + ip, args, {
                ok: "Reserved " + ip + " for " + name,
                fail: "Could not reserve " + ip
            });
        }

        var det = el("details", { cls: "wgc-adv" });
        det.appendChild(el("summary", { text: "Reserve an address" }));
        det.appendChild(el("div", { cls: "wgc-adv-body" },
            el("div", { cls: "wgc-form-row" },
                field("IP", ipIn, "Must lie in the managed pool."),
                field("Name", nameIn, "Who or what the address belongs to."),
                field("Identity (optional)", idIn,
                      "MAC for L2 networks; the WireGuard public key for tunnel " +
                      "peers, which have no MAC.")),
            errBox,
            el("div", { cls: "wgc-actions" },
                button("Reserve", "primary", submit))));
        return det;
    }

    function scanRow() {
        var sel = el("select", { cls: "wgc-input wgc-select" });
        IPAM_SCAN_NETS.forEach(function (n) {
            sel.appendChild(el("option", { attrs: { value: n }, text: n }));
        });
        sel.value = ui.ipamScan.net;
        sel.disabled = !!ui.ipamScan.busy;
        sel.addEventListener("change", function () { ui.ipamScan.net = sel.value; });

        var btn = button(ui.ipamScan.busy ? "Scanning…" : "Scan", "primary",
            function () { runScan(); },
            "Ping-sweeps the subnet in parallel (≤2 s per host), then reads the " +
            "neighbour table for MACs. Updates last-seen tracking.");
        btn.disabled = !!ui.ipamScan.busy;

        var status = el("span", { cls: "wg-subtle wgc-scan-status" });
        if (ui.ipamScan.busy)
            status.textContent = "Scanning " + ui.ipamScan.net + "…";
        else if (ui.ipamScan.result)
            status.textContent = "Scanned " +
                (ui.ipamScan.result.scanned || ui.ipamScan.result.net) + ": " +
                ui.ipamScan.result.alive + " alive, " +
                ui.ipamScan.result.free + " free.";

        var row = el("div", { cls: "wgc-scan" },
            el("span", { cls: "wg-subtle", text: "Scan a network:" }),
            sel, btn, status);

        if (!ui.ipamScan.fault) return row;

        var fp = faultPanel(ui.ipamScan.fault, "Reload state");
        fp.insertBefore(el("div", { cls: "wg-subtle",
            text: "wg-admin ipam-scan --net " + ui.ipamScan.net }), fp.firstChild);
        return el("div", {}, row, fp);
    }

    function runScan() {
        if (ui.ipamScan.busy) return;
        ui.ipamScan.busy = true;
        ui.ipamScan.result = null;
        ui.ipamScan.fault = null;
        paintIpam();

        var net = ui.ipamScan.net || IPAM_SCAN_NETS[0];
        callAdmin(["ipam-scan", "--net", net]).then(function (res) {
            ui.ipamScan.busy = false;
            if (!res.ok) {
                ui.ipamScan.fault = res.fault;
                if (isBlockingFault(res.fault)) { state.gate = res.fault; paint(); return; }
                paintIpam();
                return;
            }
            ui.ipamScan.result = {
                net: net,
                scanned: firstOf(res.data, ["scanned"]),
                alive: (res.data.alive instanceof Array) ? res.data.alive.length : 0,
                free: (res.data.free instanceof Array) ? res.data.free.length : 0
            };
            paintIpam();
            /* A scan upserts observed rows and last_seen on the host, so the
               table is stale the moment the scan returns: re-read it. */
            callAdmin(["ipam-status"]).then(function (r2) {
                if (r2.ok) { state.ipam = normaliseIpam(r2.data); state.ipamFault = null; }
                paintIpam();
            });
        });
    }

    /* ------------------------------------------------------------------ *
     * Rendering - routing controls
     * ------------------------------------------------------------------ */

    var IP_FORWARD_WHY =
        "Off: the tunnel still comes up and the handshake still succeeds, but this " +
        "host refuses to pass packets through it — clients reach wg0 and nothing " +
        "behind it.";

    function masqueradeWhy(dest) {
        var n = state.cat.byId[dest];
        var where = n && n.cidr ? n.cidr : dest;
        return "Off: packets reach " + where + " still carrying the client's tunnel " +
               "address as their source, and the replies have no route back — " +
               "connections hang instead of failing cleanly.";
    }

    function paintRouting() {
        clear(dom.routing);
        if (state.gate) return;

        var head = el("div", { cls: "wg-card-head" },
            el("span", { cls: "name", text: "Routing & NAT" }));

        var body = el("div", { cls: "wg-card-body" });
        body.appendChild(el("p", { cls: "wg-hint", text:
            "Three quarters of “the tunnel connects and nothing works” is one " +
            "of these two switches being off. Changes apply immediately." }));

        if (!state.routing) {
            body.appendChild(el("div", { cls: "wg-empty", text:
                state.routingFault ? "Routing state could not be read."
                                   : "Routing state not read yet." }));
            dom.routing.appendChild(el("div", { cls: "wg-card wgc-routing" }, head, body));
            return;
        }

        var list = el("div", { cls: "wgc-switches" });

        /*
         * routing-status REPORTS ip_forward, but routing-set takes a catalogue
         * DEST - so unless the catalogue itself offers "ip_forward" as an id,
         * the documented interface has no verb that can change the sysctl and a
         * toggle here would be a button that always fails. Show it as state
         * instead, and say why. If the contract later makes it addressable this
         * becomes a live toggle with no code change.
         */
        list.appendChild(switchRow({
            key: "routing/" + IP_FORWARD_DEST,
            label: "IPv4 forwarding",
            sub: "net.ipv4.ip_forward",
            on: state.routing.ipForward,
            why: IP_FORWARD_WHY,
            dest: IP_FORWARD_DEST,
            readOnly: !state.cat.byId[IP_FORWARD_DEST],
            readOnlyWhy:
                "Reported here but not settable from this page: routing-set takes a " +
                "catalogue destination and rejects “" + IP_FORWARD_DEST + "”. " +
                "Change it on the host (sysctl net.ipv4.ip_forward=1, persisted under " +
                "/etc/sysctl.d) and press Refresh."
        }));

        if (!state.routing.rules.length) {
            list.appendChild(el("div", { cls: "wg-empty", text:
                "The helper reported no masquerade rules for any catalogue destination." }));
        } else {
            state.routing.rules.forEach(function (r) {
                var n = state.cat.byId[r.dest];
                list.appendChild(switchRow({
                    key: "routing/" + r.dest,
                    label: "Masquerade to " + r.dest,
                    sub: (n && n.cidr ? n.cidr : "") +
                         (r.iface ? (n && n.cidr ? " via " : "via ") + r.iface : ""),
                    on: r.present,
                    why: masqueradeWhy(r.dest),
                    dest: r.dest
                }));
            });
        }

        body.appendChild(list);
        dom.routing.appendChild(el("div", { cls: "wg-card wgc-routing" }, head, body));
    }

    function switchRow(spec) {
        var input = el("input", { attrs: { type: "checkbox" } });
        input.checked = !!spec.on;
        input.disabled = !!ui.busy[spec.key] || !!spec.readOnly;

        if (!spec.readOnly)
            input.addEventListener("change", function () {
                var want = input.checked ? "on" : "off";
                input.disabled = true;
                mutate(spec.key, ["routing-set", spec.dest, want], {
                    ok: spec.label + " turned " + want,
                    fail: "Could not turn " + spec.label.toLowerCase() + " " + want
                });
            });

        var row = el("div", { cls: "wgc-switch" + (spec.on ? " on" : "") +
                                   (spec.readOnly ? " ro" : "") },
            el("label", { cls: "wgc-switch-label" },
               input,
               el("span", { cls: "wgc-switch-name", text: spec.label }),
               spec.sub ? el("span", { cls: "mono wg-subtle", text: spec.sub }) : null,
               spec.readOnly ? pill(spec.on ? "on" : "off", spec.on ? "ok" : "bad") : null,
               spec.readOnly ? pill("read-only", "warn") : null),
            el("div", { cls: "wg-hint wgc-switch-why", text: spec.why }));

        if (spec.readOnly && spec.readOnlyWhy)
            row.appendChild(el("div", { cls: "wg-hint wgc-switch-ro", text: spec.readOnlyWhy }));

        return row;
    }

    /* ------------------------------------------------------------------ *
     * Submitting the schema-built config
     * ------------------------------------------------------------------ */

    function submitConfig(client, b, errBox) {
        clear(errBox);
        var cfg = String(b.config || "").trim();
        var sel = computeSelection(state.cat, selectedIds(b));

        if (!NAME_RE.test(cfg)) {
            errBox.appendChild(el("div", { cls: "wg-inline-err", text:
                "Give the config a name (letters, digits, dot, dash, underscore)." }));
            return;
        }
        if (!sel.ids.length) {
            errBox.appendChild(el("div", { cls: "wg-inline-err", text:
                "Select at least one destination — a config that routes " +
                "nothing into the tunnel is never what you want." }));
            return;
        }
        var badIds = Object.keys(b.invalid).filter(function (id) { return b.invalid[id]; });
        if (badIds.length) {
            errBox.appendChild(el("div", { cls: "wg-inline-err", text:
                "Fix the highlighted field(s) first: " + badIds.join(", ") + "." }));
            return;
        }

        /*
         * Contract v2 flag mapping: the cidr-set selection is always --routes;
         * every other EDITED schema field travels as --<id> <value>. A field
         * left at its schema default sends nothing - defaults are resolved by
         * the backend, which is what `default: effective default, resolved
         * from config` means. readonly, password-reveal and live routing
         * toggles are display/host state, never flags.
         */
        var args = ["add-config", client.name, cfg, "--routes", sel.routesArg];
        eachField(state.schema, function (f) {
            if (!f.known) return;
            if (f.control === "cidr-set" || f.control === "readonly" ||
                f.control === "password-reveal") return;
            if (f.control === "toggle" && liveRoutingId(f.id)) return;
            if (!(f.id in b.values)) return;
            if (!valueDiffers(f, b.values[f.id])) return;
            args.push("--" + f.id, encodeFlagValue(f, b.values[f.id]));
        });

        mutate("addcfg/" + client.name + "/" + cfg, args, {
            ok: "Config “" + cfg + "” added to " + client.name,
            detail: "Client AllowedIPs: " + sel.cidrs.join(", ") +
                    " · server peer entry: " + serverAllowedIps(client.ip).join(", "),
            fail: "Could not add config “" + cfg + "”"
        }).then(function () { b.config = ""; });
    }

    /* ------------------------------------------------------------------ *
     * Public surface - exactly one global.
     *
     * `compute` is the pure core, exported so the AllowedIPs logic, the
     * schema normaliser and the six-operator recommendation engine can be
     * run head-less under gjs without a browser. It has no DOM or cockpit
     * dependency; nothing in the UI reaches back through it.
     * ------------------------------------------------------------------ */

    window.WGClient = {
        render: render,
        refresh: refresh,

        compute: {
            normaliseCatalogue: normaliseCatalogue,
            normaliseClients: normaliseClients,
            normaliseRouting: normaliseRouting,
            normaliseSchema: normaliseSchema,
            normaliseIpam: normaliseIpam,
            normalisePackage: normalisePackage,
            computeSelection: computeSelection,
            serverAllowedIps: serverAllowedIps,
            tunnelNetwork: tunnelNetwork,
            presetIds: presetIds,
            explain: explain,
            classify: classify,
            maskConf: maskConf,
            safeFileName: safeFileName,
            safeBundleName: safeBundleName,
            cidrContains: cidrContains,
            validIpv4: validIpv4,
            host32: host32,
            evalWhen: evalWhen,
            recoFiring: recoFiring,
            checkTarget: checkTarget,
            resolveCheckState: resolveCheckState,
            stateWord: stateWord,
            interpolateState: interpolateState,
            splitInstructions: splitInstructions,
            valueDiffers: valueDiffers,
            encodeFlagValue: encodeFlagValue
        }
    };
})();
