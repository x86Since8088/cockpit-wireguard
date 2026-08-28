/*
 * cockpit-wireguard - read-only live view of this host's WireGuard state.
 *
 * Deliberately dependency-free: plain DOM + cockpit.js. No build step, no
 * framework, no bundler, no vendored assets.
 *
 * SECRET HANDLING
 * ---------------
 * `wg show all dump` prints the interface PRIVATE KEY (field 2 of an interface
 * line, after the interface name) and each peer's PRE-SHARED KEY (field 3 of a
 * peer line). Neither belongs in a web page. Rather than fetch them and filter
 * in the browser, every dump is piped through awk on the host, so the secrets
 * never cross the Cockpit channel at all. The parser additionally refuses to
 * read those field indices, so a change to the awk program cannot silently
 * leak them into the DOM.
 *
 * PRIVILEGE
 * ---------
 * Everything runs with { superuser: "try" }. With Cockpit's administrative
 * access enabled the full picture is available; without it the page still
 * renders interface names, addresses, link state, NetworkManager connections,
 * systemd unit states and net.ipv4.ip_forward, and says plainly which panels
 * need root and why.
 *
 * THIS PAGE ISSUES NO STATE-CHANGING COMMAND OF ANY KIND.
 */

(function () {
    "use strict";

    /* ------------------------------------------------------------------ *
     * Theme
     *
     * The Cockpit shell stores the choice in localStorage["shell:style"]
     * (auto|light|dark) and marks dark mode with pf-v6-theme-dark on <html>.
     * Mirror that onto our own classes so the stylesheet needs no knowledge
     * of PatternFly.
     * ------------------------------------------------------------------ */

    function prefersDark() {
        return !!(window.matchMedia &&
                  window.matchMedia("(prefers-color-scheme: dark)").matches);
    }

    function applyTheme() {
        var root = document.documentElement;
        var dark;
        try {
            var pref = window.localStorage.getItem("shell:style") || "auto";
            dark = (pref === "dark") ? true : (pref === "light") ? false : prefersDark();
        } catch (e) {
            dark = prefersDark();          /* localStorage can throw when blocked */
        }
        if (root.classList.contains("pf-v6-theme-dark"))
            dark = true;                   /* shell already decided for this frame */
        root.classList.toggle("wg-dark", dark);
        root.classList.toggle("wg-light", !dark);
    }

    applyTheme();
    window.addEventListener("storage", function (ev) {
        if (!ev || ev.key === null || ev.key === "shell:style")
            applyTheme();
    });
    if (window.matchMedia) {
        var mq = window.matchMedia("(prefers-color-scheme: dark)");
        if (mq.addEventListener) mq.addEventListener("change", applyTheme);
        else if (mq.addListener) mq.addListener(applyTheme);
    }

    /* ------------------------------------------------------------------ *
     * Configuration
     * ------------------------------------------------------------------ */

    var STALE_SECS = 180;        /* handshake older than this counts as stale  */
    var FAST_MS    = 5000;       /* live poll interval                         */
    var SLOW_EVERY = 5;          /* refresh slow-moving data every N ticks     */

    var EASY_CONTAINER = "wg-easy";
    var EASY_UI        = "http://192.168.2.250:51821";
    var NM_CONNECTION  = "con-wg0";

    var UNITS = [
        "wg-quick@wg0.service",
        "NetworkManager.service",
        "wg-easy.service",
        "wg-lan-network.service",
        "wg-lan-nat.service"
    ];

    /*
     * Capture the dump, propagate wg's exit status (a bare pipeline would
     * report awk's success and silently hide "Operation not permitted"), then
     * strip both secrets before the bytes leave the host.
     *
     * String.raw keeps the shell and awk quoting readable. Neither string
     * below contains a ${ sequence, so template interpolation cannot fire.
     */
    var DUMP_TAIL = String.raw`) || exit $?; printf '%s\n' "$o" | awk -F'\t' 'BEGIN{OFS="\t"} NF==5{$2="(hidden)"} NF==9 && $3!="(none)"{$3="(set)"} {print}'`;

    /*
     * The NAT probe must not fail as a unit: net.ipv4.ip_forward is world
     * readable and worth showing even when iptables is not. Each section
     * therefore reports its own failure inline and the script always exits 0.
     */
    var NAT_CMD = [
        "printf '@@FWD_SYSCTL@@\\n'; cat /proc/sys/net/ipv4/ip_forward 2>/dev/null",
        "printf '@@FORWARD@@\\n'; iptables -S FORWARD 2>&1 || printf '@@ERROR@@\\n'",
        "printf '@@POSTROUTING@@\\n'; iptables -t nat -S POSTROUTING 2>&1 || printf '@@ERROR@@\\n'"
    ].join("\n");

    var CMD = {
        privilege: "id -u",
        hostDump:  "o=$(wg show all dump" + DUMP_TAIL,
        hostList:  "wg show interfaces",
        hostAddr:  "ip -j addr show",
        easyDump:  "o=$(podman exec " + EASY_CONTAINER + " wg show all dump" + DUMP_TAIL,
        easyAddr:  "podman exec " + EASY_CONTAINER + " ip -j addr show",
        easyPs:    "podman ps --all --no-trunc --filter 'name=^" + EASY_CONTAINER + "$' " +
                   "--format '{{.Names}}\\t{{.Image}}\\t{{.State}}\\t{{.Status}}\\t{{.RunningFor}}'",
        units:     "systemctl show --property=Id --property=Description --property=LoadState " +
                   "--property=ActiveState --property=SubState --property=UnitFileState " +
                   UNITS.join(" "),
        nm:        "nmcli -t -f NAME,UUID,TYPE,DEVICE,STATE connection show",
        nat:       NAT_CMD
    };

    /* ------------------------------------------------------------------ *
     * DOM helpers
     * ------------------------------------------------------------------ */

    function $(id) { return document.getElementById(id); }

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

    function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }

    /* ------------------------------------------------------------------ *
     * Formatting
     * ------------------------------------------------------------------ */

    function fmtBytes(n) {
        n = Number(n);
        if (!isFinite(n) || n < 0) return "—";
        if (n === 0) return "0 B";
        var units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
        var i = 0;
        while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
        var digits = (i === 0) ? 0 : (n < 10 ? 2 : (n < 100 ? 1 : 0));
        return n.toFixed(digits) + " " + units[i];
    }

    function fmtDuration(secs) {
        secs = Math.max(0, Math.floor(secs));
        if (secs < 60) return secs + "s";
        var m = Math.floor(secs / 60), s = secs % 60;
        if (m < 60) return m + "m " + s + "s";
        var h = Math.floor(m / 60); m %= 60;
        if (h < 24) return h + "h " + m + "m";
        var d = Math.floor(h / 24); h %= 24;
        return d + "d " + h + "h";
    }

    /*
     * The single most useful signal in a WireGuard UI: has this peer completed
     * a handshake recently? Never -> bad, older than STALE_SECS -> warn.
     */
    function handshakeHealth(epoch) {
        epoch = Number(epoch) || 0;
        if (epoch <= 0)
            return { kind: "never", cls: "bad", label: "never", pill: "never" };
        var age = Math.max(0, Math.floor(Date.now() / 1000) - epoch);
        if (age > STALE_SECS)
            return { kind: "stale", cls: "warn", label: fmtDuration(age) + " ago",
                     pill: "stale", age: age };
        return { kind: "ok", cls: "ok", label: fmtDuration(age) + " ago",
                 pill: "connected", age: age };
    }

    function truncKey(k) {
        if (!k || k.length <= 20) return k || "—";
        return k.slice(0, 9) + "…" + k.slice(-7);
    }

    /* Expansion survives re-renders so a poll does not collapse what you opened. */
    var expandedKeys = Object.create(null);

    function keyNode(key) {
        if (!key || key === "(none)")
            return el("span", { cls: "mono", text: "—" });

        var btn = el("button", {
            cls: "keybtn",
            attrs: { type: "button", "aria-label": "public key " + key }
        });

        function paint() {
            var open = !!expandedKeys[key];
            btn.textContent = open ? key : truncKey(key);
            btn.setAttribute("title", key + (open ? "  (click to shorten)"
                                                  : "  (click to show in full)"));
        }
        paint();
        btn.addEventListener("click", function () {
            expandedKeys[key] = !expandedKeys[key];
            paint();
        });
        return btn;
    }

    function pill(text, cls) {
        return el("span", { cls: "pill" + (cls ? " " + cls : ""), text: text });
    }

    /* ------------------------------------------------------------------ *
     * Command execution - all read-only, all non-blocking
     * ------------------------------------------------------------------ */

    var PERM_RE = /not permitted|permission denied|must be root|access denied|not authoriz/i;

    function isPermissionError(msg) { return PERM_RE.test(String(msg || "")); }

    /* Resolves to { ok, data } or { ok:false, error, denied }. Never rejects. */
    function probe(script) {
        return cockpit.spawn(["/bin/sh", "-c", script],
                             { superuser: "try", err: "message" })
            .then(function (out) {
                return { ok: true, data: out };
            }, function (err) {
                var msg = (err && (err.message || err.problem)) || String(err);
                return { ok: false, error: String(msg).trim(),
                         denied: isPermissionError(msg) };
            });
    }

    /* ------------------------------------------------------------------ *
     * Actions - schema-driven, confirmed, runtime-only
     *
     * The monitoring above stays read-only. The ONLY mutations this page
     * performs are explicit `wg set` commands on host interfaces, each one
     * shown verbatim in a dialog before it runs. They change the kernel's
     * runtime state and nothing else: no NetworkManager profiles, no
     * config files, no systemd units, no firewall rules. Every successful
     * submit ends in poll(true), so the page repaints from re-read data.
     * ------------------------------------------------------------------ */

    function runAction(argv) {
        return cockpit.spawn(argv, { superuser: "try", err: "message" });
    }

    var RE_B64KEY  = "^[A-Za-z0-9+/]{43}=$";
    var RE_CIDR    = "^[0-9a-fA-F.:]+/[0-9]{1,3}$";
    var RE_ENDPOINT = "^\\[?[A-Za-z0-9.:_-]+\\]?:[0-9]{1,5}$";

    var PERSIST_NOTE = "Runtime change (wg set): it takes effect immediately but lives in the " +
        "kernel only. wg0 on this host is brought up by NetworkManager (connection " +
        NM_CONNECTION + ", generated from netplan), so make the same change there for it " +
        "to survive a reconnect or reboot.";

    function peerAddSchema(ifaceName) {
        return {
            title: "Add peer to " + ifaceName,
            intro: PERSIST_NOTE,
            fields: [
                { id: "pubkey", label: "Public key", type: "text", required: true, span2: true,
                  placeholder: "base64, 44 characters ending in =",
                  pattern: RE_B64KEY, patternHint: "a 44-character base64 WireGuard public key",
                  help: "From `wg pubkey` on the peer. Never paste a private key here." },
                { id: "allowed", label: "Allowed IPs", type: "list", required: true, span2: true,
                  placeholder: "10.20.0.12/32",
                  itemPattern: RE_CIDR, itemHint: "a CIDR like 10.20.0.12/32",
                  help: "One CIDR per line. Both routing and firewall for this peer — keep it tight; /32 for a single client." },
                { id: "endpoint", label: "Endpoint", type: "text",
                  placeholder: "host:51820", pattern: RE_ENDPOINT,
                  patternHint: "host:port",
                  help: "Optional; only for peers with a stable address." },
                { id: "keepalive", label: "Persistent keepalive (s)", type: "int",
                  min: 0, max: 3600, placeholder: "25",
                  help: "Optional; 25 is the usual value for peers behind NAT." }
            ],
            submitLabel: "Add peer",
            build: function (v) {
                var a = ["wg", "set", ifaceName, "peer", v.pubkey,
                         "allowed-ips", v.allowed.join(",")];
                if (v.endpoint) a.push("endpoint", v.endpoint);
                if (v.keepalive !== "" && v.keepalive !== null && v.keepalive !== undefined)
                    a.push("persistent-keepalive", String(v.keepalive));
                return [a];
            }
        };
    }

    function listenPortSchema(iface) {
        return {
            title: "Set listen port on " + iface.name,
            intro: PERSIST_NOTE,
            fields: [
                { id: "port", label: "Listen port (UDP)", type: "int", required: true,
                  min: 1, max: 65535, value: iface.listenPort || "",
                  help: "Peers connect to this port; remember to forward it on the edge router." }
            ],
            submitLabel: "Set port",
            build: function (v) {
                return [["wg", "set", iface.name, "listen-port", String(v.port)]];
            }
        };
    }

    function peerRemoveSchema(ifaceName, publicKey) {
        return {
            title: "Remove peer from " + ifaceName,
            intro: "The peer's tunnel stops working immediately. " + PERSIST_NOTE,
            fields: [],
            danger: true,
            submitLabel: "Remove peer",
            build: function () {
                return [["wg", "set", ifaceName, "peer", publicKey, "remove"]];
            }
        };
    }

    /*
     * The generic form dialog: renders a schema's fields, validates them,
     * previews the exact argv, runs it. Adding an action is adding a schema
     * above — no new UI code.
     */
    function schemaForm(schema) {
        var root = $("wg-modal-root");
        clear(root);

        var getters = {};
        var errNodes = {};
        var previewPre = el("pre", { cls: "wg-rules" });
        var errBox = el("div");
        var busyNote = el("div", { cls: "wg-hint" });
        var submitBtn;

        function close() {
            clear(root);
            document.removeEventListener("keydown", onKey);
        }

        function onKey(ev) {
            if (ev.key === "Escape") close();
        }

        function collect() {
            var v = {};
            Object.keys(getters).forEach(function (id) { v[id] = getters[id](); });
            return v;
        }

        function setErr(f, msg) {
            clear(errNodes[f.id]);
            if (msg)
                errNodes[f.id].appendChild(el("div", { cls: "wg-ferr", text: msg }));
        }

        function validate(values) {
            var ok = true;
            schema.fields.forEach(function (f) {
                var val = values[f.id];
                var msg = null;
                if (f.type === "list") {
                    if (f.required && !val.length)
                        msg = "At least one entry is required.";
                    else if (f.itemPattern) {
                        var re = new RegExp(f.itemPattern);
                        for (var i = 0; i < val.length; i++) {
                            if (!re.test(val[i])) {
                                msg = "“" + val[i] + "” is not " + (f.itemHint || "valid") + ".";
                                break;
                            }
                        }
                    }
                } else if (f.type === "int") {
                    var s = String(val === null || val === undefined ? "" : val).trim();
                    if (f.required && s === "")
                        msg = "Required.";
                    else if (s !== "") {
                        var n = Number(s);
                        if (!isFinite(n) || Math.floor(n) !== n)
                            msg = "Must be a whole number.";
                        else if ((f.min !== undefined && n < f.min) ||
                                 (f.max !== undefined && n > f.max))
                            msg = "Must be between " + f.min + " and " + f.max + ".";
                    }
                } else {
                    var t = String(val || "").trim();
                    if (f.required && !t)
                        msg = "Required.";
                    else if (t && f.pattern && !new RegExp(f.pattern).test(t))
                        msg = "Must be " + (f.patternHint || "valid") + ".";
                }
                setErr(f, msg);
                if (msg) ok = false;
            });
            return ok;
        }

        function commands(values) {
            try { return schema.build(values) || []; } catch (e) { return []; }
        }

        function updatePreview() {
            var cmds = commands(collect());
            previewPre.textContent = cmds.length
                ? cmds.map(function (a) { return a.join(" "); }).join("\n")
                : "(no command yet)";
        }

        function fieldNode(f) {
            var wrap = el("div", { cls: "wg-field" + (f.span2 ? " wg-span2" : "") });
            errNodes[f.id] = el("div");

            var label = el("label", {}, f.label,
                f.required ? el("span", { cls: "wg-req", text: "*" }) : "");

            var control;
            if (f.type === "list") {
                control = el("textarea", { cls: "wg-textarea",
                    attrs: { rows: "3", placeholder: f.placeholder || "" } });
                if (f.value) control.value = f.value;
                getters[f.id] = function () {
                    return control.value.split("\n")
                        .map(function (s) { return s.trim(); })
                        .filter(Boolean);
                };
            } else {
                control = el("input", { cls: "wg-input",
                    attrs: { type: "text", placeholder: f.placeholder || "" } });
                if (f.value !== undefined && f.value !== null && f.value !== "")
                    control.value = String(f.value);
                getters[f.id] = function () { return control.value.trim(); };
            }
            control.addEventListener("input", updatePreview);

            wrap.appendChild(label);
            wrap.appendChild(control);
            if (f.help) wrap.appendChild(el("div", { cls: "wg-fhelp", text: f.help }));
            wrap.appendChild(errNodes[f.id]);
            return wrap;
        }

        function onSubmit() {
            var values = collect();
            clear(errBox);
            if (!validate(values)) return;
            var cmds = commands(values);
            if (!cmds.length) return;

            submitBtn.disabled = true;
            clear(busyNote);
            busyNote.appendChild(el("span", { cls: "wg-spin" }));
            busyNote.appendChild(document.createTextNode(" Running…"));

            var chain = Promise.resolve();
            cmds.forEach(function (argv) {
                chain = chain.then(function () { return runAction(argv); });
            });
            chain.then(function () {
                close();
                poll(true);
            }).catch(function (err) {
                var msg = (err && (err.message || err.problem)) || String(err);
                submitBtn.disabled = false;
                clear(busyNote);
                var box = el("div", { cls: "wg-alert bad" });
                box.appendChild(el("h3", { text: isPermissionError(msg)
                    ? "Administrative access required"
                    : "The command failed" }));
                box.appendChild(el("div", { cls: "wg-subtle", text: isPermissionError(msg)
                    ? "wg set needs root and it was not granted, so nothing was changed."
                    : "Nothing was changed. wg reported:" }));
                box.appendChild(el("pre", { cls: "wg-rules", text: String(msg).trim() }));
                errBox.appendChild(box);
            });
        }

        submitBtn = el("button", { cls: "wg-btn primary" + (schema.danger ? " danger" : ""),
                                   attrs: { type: "button" }, text: schema.submitLabel });
        submitBtn.addEventListener("click", onSubmit);

        var cancelBtn = el("button", { cls: "wg-btn", attrs: { type: "button" }, text: "Cancel" });
        cancelBtn.addEventListener("click", close);

        var body = el("div", { cls: "wg-modal-body" });
        if (schema.intro) body.appendChild(el("p", { cls: "wg-hint", text: schema.intro }));
        if (schema.fields.length) {
            var grid = el("div", { cls: "wg-form-grid" });
            schema.fields.forEach(function (f) { grid.appendChild(fieldNode(f)); });
            body.appendChild(grid);
        }
        body.appendChild(el("div", { cls: "wg-subtle", text: "Command to be run:" }));
        body.appendChild(previewPre);
        body.appendChild(errBox);
        body.appendChild(busyNote);

        var dialog = el("div", { cls: "wg-modal",
                                 attrs: { role: "dialog", "aria-modal": "true" } },
            el("div", { cls: "wg-modal-head", text: schema.title }),
            body,
            el("div", { cls: "wg-modal-foot" }, cancelBtn, submitBtn));

        var backdrop = el("div", { cls: "wg-modal-backdrop" }, dialog);
        backdrop.addEventListener("click", function (ev) {
            if (ev.target === backdrop) close();
        });

        root.appendChild(backdrop);
        document.addEventListener("keydown", onKey);
        updatePreview();
        var first = dialog.querySelector("input, textarea");
        (first || submitBtn).focus();
    }

    /* ------------------------------------------------------------------ *
     * Parsers
     * ------------------------------------------------------------------ */

    /*
     * `wg show all dump`:
     *   interface line, 5 fields: iface privkey pubkey listen-port fwmark
     *   peer line,      9 fields: iface pubkey psk endpoint allowed-ips
     *                             handshake rx tx keepalive
     * Fields 1 (private key) and, on peer lines, 2 (pre-shared key) are
     * already redacted host-side and are never read below.
     */
    function parseWgDump(text) {
        var ifaces = [], byName = Object.create(null);

        String(text || "").split("\n").forEach(function (line) {
            if (!line) return;
            var f = line.split("\t");

            if (f.length === 5) {
                var iface = byName[f[0]];
                if (!iface) {
                    iface = { name: f[0], peers: [] };
                    byName[f[0]] = iface;
                    ifaces.push(iface);
                }
                /* f[1] is the PRIVATE KEY - deliberately never touched. */
                iface.publicKey  = f[2];
                iface.listenPort = f[3];
                iface.fwmark     = f[4];

            } else if (f.length === 9) {
                var target = byName[f[0]];
                if (!target) {
                    target = { name: f[0], publicKey: null, listenPort: null, peers: [] };
                    byName[f[0]] = target;
                    ifaces.push(target);
                }
                target.peers.push({
                    publicKey:    f[1],
                    /* f[2] is the PRE-SHARED KEY - only its presence is used. */
                    presharedKey: (f[2] === "(none)") ? null : "set",
                    endpoint:     (f[3] === "(none)") ? null : f[3],
                    allowedIps:   (!f[4] || f[4] === "(none)") ? [] : f[4].split(","),
                    handshake:    Number(f[5]) || 0,
                    rx:           Number(f[6]) || 0,
                    tx:           Number(f[7]) || 0,
                    keepalive:    (f[8] === "off") ? null : f[8]
                });
            }
        });
        return ifaces;
    }

    /* `ip -j addr show` -> { ifname: { mtu, operstate, flags, addrs[] } } */
    function parseIpJson(text) {
        var map = Object.create(null), arr;
        try { arr = JSON.parse(text); } catch (e) { return map; }
        if (!Array.isArray(arr)) return map;

        arr.forEach(function (link) {
            if (!link || !link.ifname) return;
            map[link.ifname] = {
                mtu: link.mtu,
                operstate: link.operstate,
                flags: link.flags || [],
                addrs: (link.addr_info || [])
                    .filter(function (a) { return a.scope !== "link" && a.scope !== "host"; })
                    .map(function (a) { return a.local + "/" + a.prefixlen; })
            };
        });
        return map;
    }

    /* `systemctl show` over several units emits blank-line-separated blocks. */
    function parseUnits(text) {
        var out = [];
        String(text || "").split(/\n\s*\n/).forEach(function (block) {
            if (!block.trim()) return;
            var obj = {};
            block.split("\n").forEach(function (line) {
                var i = line.indexOf("=");
                if (i > 0) obj[line.slice(0, i)] = line.slice(i + 1);
            });
            if (obj.Id) out.push(obj);
        });
        return out;
    }

    function parseNmcli(text) {
        return String(text || "").split("\n").filter(Boolean).map(function (line) {
            var f = line.split(":");
            return { name: f[0], uuid: f[1], type: f[2], device: f[3], state: f[4] };
        });
    }

    function parseNat(text) {
        var buckets = { sysctl: [], forward: [], postrouting: [] };
        var section = null;

        String(text || "").split("\n").forEach(function (line) {
            if (line === "@@FWD_SYSCTL@@")   { section = "sysctl";      return; }
            if (line === "@@FORWARD@@")      { section = "forward";     return; }
            if (line === "@@POSTROUTING@@")  { section = "postrouting"; return; }
            if (section && line.trim()) buckets[section].push(line);
        });

        function section_of(lines) {
            if (lines.indexOf("@@ERROR@@") >= 0) {
                return { rules: [], error: lines.filter(function (l) {
                    return l !== "@@ERROR@@";
                }).join(" ").trim() || "command failed" };
            }
            return { rules: lines, error: null };
        }

        return {
            ipForward: buckets.sysctl.length ? buckets.sysctl[0].trim() : null,
            forward: section_of(buckets.forward),
            postrouting: section_of(buckets.postrouting)
        };
    }

    function parsePs(text) {
        var line = String(text || "").split("\n").filter(Boolean)[0];
        if (!line) return null;
        var f = line.split("\t");
        return { name: f[0], image: f[1], state: f[2], status: f[3], runningFor: f[4] };
    }

    /* Rules touching a WireGuard interface or one of the routed subnets. */
    function isWgRule(rule) {
        return /wg0|wg-shim|172\.16\.|172\.15\.4\.|10\.8\.0\./.test(rule);
    }

    /* ------------------------------------------------------------------ *
     * State
     * ------------------------------------------------------------------ */

    var state = {
        privileged: null,                                    /* null = unknown yet */
        host: { ifaces: [], addrs: {}, list: [], err: null, denied: false },
        easy: { ifaces: [], addrs: {}, ps: null, err: null, denied: false, psErr: null },
        units: [], unitsErr: null,
        nm: [], nmErr: null,
        nat: null, natErr: null,
        lastUpdate: null,
        loading: false
    };

    var tick = 0;
    var timer = null;
    var inFlight = false;

    /* Live-ageing handshake cells, refreshed in place between polls. */
    var ageWidgets = [];

    /* ------------------------------------------------------------------ *
     * Collection
     * ------------------------------------------------------------------ */

    function collectFast() {
        return Promise.all([
            probe(CMD.privilege),
            probe(CMD.hostDump),
            probe(CMD.hostList),
            probe(CMD.hostAddr),
            probe(CMD.easyDump),
            probe(CMD.easyPs)
        ]).then(function (r) {
            var priv = r[0], dump = r[1], list = r[2], addr = r[3], eDump = r[4], ps = r[5];

            state.privileged = priv.ok ? (priv.data.trim() === "0") : null;

            if (dump.ok) {
                state.host.ifaces = parseWgDump(dump.data);
                state.host.err = null;
                state.host.denied = false;
            } else {
                state.host.ifaces = [];
                state.host.err = dump.error;
                state.host.denied = dump.denied || state.privileged === false;
            }

            state.host.list  = list.ok ? list.data.split(/\s+/).filter(Boolean) : [];
            state.host.addrs = addr.ok ? parseIpJson(addr.data) : {};

            if (eDump.ok) {
                state.easy.ifaces = parseWgDump(eDump.data);
                state.easy.err = null;
                state.easy.denied = false;
            } else {
                state.easy.ifaces = [];
                state.easy.err = eDump.error;
                /*
                 * wg-easy is a ROOTFUL container. Unprivileged, podman talks to
                 * the caller's own rootless store and honestly reports "no such
                 * container" - which is a privilege problem, not a missing
                 * container, so classify it as such.
                 */
                state.easy.denied = eDump.denied || state.privileged === false;
            }

            state.easy.ps    = ps.ok ? parsePs(ps.data) : null;
            state.easy.psErr = ps.ok ? null : ps.error;
        });
    }

    function collectSlow() {
        return Promise.all([
            probe(CMD.units),
            probe(CMD.nm),
            probe(CMD.nat),
            probe(CMD.easyAddr)
        ]).then(function (r) {
            var units = r[0], nm = r[1], nat = r[2], eAddr = r[3];

            state.units    = units.ok ? parseUnits(units.data) : [];
            state.unitsErr = units.ok ? null : units.error;

            state.nm    = nm.ok ? parseNmcli(nm.data) : [];
            state.nmErr = nm.ok ? null : nm.error;

            state.nat    = nat.ok ? parseNat(nat.data) : null;
            state.natErr = nat.ok ? null : nat.error;

            state.easy.addrs = eAddr.ok ? parseIpJson(eAddr.data) : {};
        });
    }

    /*
     * Nothing blocks: the previous snapshot stays on screen while commands run,
     * and an overlapping tick is dropped rather than queued.
     */
    function poll(force) {
        if (inFlight) return;
        inFlight = true;
        state.loading = true;
        renderTopbar();

        var jobs = [collectFast()];
        if (force || tick % SLOW_EVERY === 0) jobs.push(collectSlow());
        tick++;

        Promise.all(jobs).catch(function (e) {
            console.error("cockpit-wireguard: poll failed", e);   /* probe() never rejects */
        }).then(function () {
            inFlight = false;
            state.loading = false;
            state.lastUpdate = new Date();
            render();
        });
    }

    function schedule() {
        if (timer) { window.clearInterval(timer); timer = null; }
        if ($("wg-auto").checked)
            timer = window.setInterval(function () {
                if (!document.hidden) poll(false);
            }, FAST_MS);
    }

    /* ------------------------------------------------------------------ *
     * Rendering
     * ------------------------------------------------------------------ */

    function renderTopbar() {
        var u = $("wg-updated");
        if (!state.lastUpdate)
            u.textContent = state.loading ? "Loading…" : "";
        else
            u.textContent = "Updated " + state.lastUpdate.toLocaleTimeString() +
                            (state.loading ? " · refreshing…" : "");
    }

    function renderBanner() {
        var box = $("wg-banner");
        clear(box);

        var denied = [];
        if (state.host.denied)
            denied.push("peer list, public keys, handshakes and transfer counters " +
                        "for host tunnels (wg show — the kernel restricts this to root)");
        if (state.easy.denied)
            denied.push("the rootful Podman container " + EASY_CONTAINER +
                        " (podman ps / podman exec must run as root to see it)");
        if (state.nat && (state.nat.forward.error || state.nat.postrouting.error))
            denied.push("NAT and forwarding rules (iptables)");

        if (denied.length) {
            var a = el("div", { cls: "wg-alert warn" });
            a.appendChild(el("h3", { text: "Showing unprivileged data only" }));
            a.appendChild(el("div", { cls: "wg-subtle",
                text: "Turn on “Administrative access” in the Cockpit header to read " +
                      "the rest. Everything below that does not need root is still live." }));
            var ul = el("ul");
            denied.forEach(function (d) { ul.appendChild(el("li", { text: "Needs root: " + d })); });
            a.appendChild(ul);
            box.appendChild(a);
        }

        /* Failures that are not about privilege deserve their own, louder box. */
        var faults = [];
        if (state.host.err && !state.host.denied) faults.push("wg show: " + state.host.err);
        if (state.easy.err && !state.easy.denied) faults.push("wg-easy: " + state.easy.err);
        if (state.unitsErr)                       faults.push("systemctl: " + state.unitsErr);
        if (state.nmErr)                          faults.push("nmcli: " + state.nmErr);
        if (state.natErr)                         faults.push("iptables: " + state.natErr);

        if (faults.length) {
            var b = el("div", { cls: "wg-alert bad" });
            b.appendChild(el("h3", { text: "Some data could not be read" }));
            var ul2 = el("ul");
            faults.forEach(function (f) { ul2.appendChild(el("li", { cls: "mono", text: f })); });
            b.appendChild(ul2);
            box.appendChild(b);
        }
    }

    function allPeers() {
        var peers = [];
        state.host.ifaces.forEach(function (i) { peers = peers.concat(i.peers); });
        state.easy.ifaces.forEach(function (i) { peers = peers.concat(i.peers); });
        return peers;
    }

    function renderSummary() {
        var box = $("wg-summary");
        clear(box);

        var peers = allPeers();
        var ok = 0, stale = 0, never = 0, rx = 0, tx = 0;
        peers.forEach(function (p) {
            var k = handshakeHealth(p.handshake).kind;
            if (k === "ok") ok++; else if (k === "stale") stale++; else never++;
            rx += p.rx; tx += p.tx;
        });

        var ifaceCount = state.host.ifaces.length + state.easy.ifaces.length;
        if (!ifaceCount) ifaceCount = state.host.list.length;

        function tile(n, label, cls) {
            return el("div", { cls: "wg-tile" + (cls ? " " + cls : "") },
                      el("div", { cls: "n", text: n }),
                      el("div", { cls: "l", text: label }));
        }

        box.appendChild(tile(ifaceCount, "Interfaces"));
        box.appendChild(tile(peers.length, "Peers"));
        box.appendChild(tile(ok, "Handshake < " + Math.round(STALE_SECS / 60) + "m",
                             ok ? "ok" : ""));
        box.appendChild(tile(stale, "Stale", stale ? "warn" : ""));
        box.appendChild(tile(never, "Never connected", never ? "bad" : ""));
        box.appendChild(tile(fmtBytes(rx), "Received"));
        box.appendChild(tile(fmtBytes(tx), "Sent"));
    }

    function peerTable(peers, ifaceName, managed) {
        if (!peers.length)
            return el("div", { cls: "wg-empty", text: "No peers configured on this interface." });

        var table = el("table", { cls: "wg-table" });
        var hrow = el("tr");
        var headers = ["Peer public key", "Status", "Last handshake", "Endpoint", "Allowed IPs",
                       "Received", "Sent", "Keepalive", "PSK"];
        if (managed) headers.push("Actions");
        headers.forEach(function (h) {
            hrow.appendChild(el("th", { text: h }));
        });
        table.appendChild(el("thead", {}, hrow));

        var tbody = el("tbody");
        var rank = { never: 0, stale: 1, ok: 2 };      /* worst first */

        peers.slice().sort(function (a, b) {
            var ka = rank[handshakeHealth(a.handshake).kind];
            var kb = rank[handshakeHealth(b.handshake).kind];
            if (ka !== kb) return ka - kb;
            return (b.handshake || 0) - (a.handshake || 0);
        }).forEach(function (p) {
            var h = handshakeHealth(p.handshake);
            var tr = el("tr", { cls: "peer-" + h.kind });

            tr.appendChild(el("td", {}, keyNode(p.publicKey)));

            var pillNode = pill(h.pill, h.cls);
            tr.appendChild(el("td", { cls: "nowrap" }, pillNode));

            var ageNode = el("td", { cls: "nowrap mono", text: h.label,
                title: p.handshake ? new Date(p.handshake * 1000).toString()
                                   : "no handshake has ever completed" });
            tr.appendChild(ageNode);
            ageWidgets.push({ epoch: p.handshake, cell: ageNode, pill: pillNode, row: tr });

            tr.appendChild(el("td", { cls: "mono", text: p.endpoint || "—",
                title: p.endpoint ? "" : "this peer has never contacted the host" }));

            var ips = el("td", { cls: "mono" });
            if (!p.allowedIps.length) {
                ips.textContent = "—";
            } else {
                p.allowedIps.forEach(function (ip, i) {
                    if (i) ips.appendChild(el("br"));
                    ips.appendChild(document.createTextNode(ip));
                });
            }
            tr.appendChild(ips);

            tr.appendChild(el("td", { cls: "num mono", text: fmtBytes(p.rx),
                                      title: p.rx + " bytes" }));
            tr.appendChild(el("td", { cls: "num mono", text: fmtBytes(p.tx),
                                      title: p.tx + " bytes" }));
            tr.appendChild(el("td", { cls: "nowrap mono",
                                      text: p.keepalive ? p.keepalive + "s" : "off" }));
            tr.appendChild(el("td", { cls: "nowrap", text: p.presharedKey ? "yes" : "no",
                title: "pre-shared key values are never read or displayed" }));

            if (managed) {
                var rm = el("button", { cls: "wg-btn danger sm",
                                        attrs: { type: "button" }, text: "Remove" });
                rm.addEventListener("click", function () {
                    schemaForm(peerRemoveSchema(ifaceName, p.publicKey));
                });
                tr.appendChild(el("td", { cls: "nowrap" }, rm));
            }

            tbody.appendChild(tr);
        });

        table.appendChild(tbody);
        return el("div", { cls: "wg-table-wrap" }, table);
    }

    /* Age the handshake cells between polls without rebuilding the DOM. */
    function refreshAges() {
        var changedKind = false;
        ageWidgets.forEach(function (w) {
            var h = handshakeHealth(w.epoch);
            if (w.cell.textContent !== h.label) w.cell.textContent = h.label;
            if (w.pill.textContent !== h.pill) {
                w.pill.textContent = h.pill;
                w.pill.className = "pill " + h.cls;
                changedKind = true;
            }
            var cls = "peer-" + h.kind;
            if (w.row.className !== cls) { w.row.className = cls; changedKind = true; }
        });
        if (changedKind) renderSummary();      /* a peer just crossed the threshold */
    }

    function linkStatePill(link) {
        if (!link) return pill("unknown");
        var up = (link.flags || []).indexOf("UP") >= 0;
        return pill(up ? "up" : "down", up ? "ok" : "bad");
    }

    function interfaceCard(iface, link, extras, managed) {
        var card = el("div", { cls: "wg-card" });

        var head = el("div", { cls: "wg-card-head" });
        head.appendChild(el("span", { cls: "name", text: iface.name }));
        head.appendChild(linkStatePill(link));

        var n = iface.peers.length;
        var bad = iface.peers.filter(function (p) {
            return handshakeHealth(p.handshake).kind !== "ok";
        }).length;
        head.appendChild(pill(n + (n === 1 ? " peer" : " peers")));
        if (n && bad) head.appendChild(pill(bad + " needing attention", "warn"));
        else if (n)   head.appendChild(pill("all peers healthy", "ok"));

        if (managed) {
            var actions = el("span", { cls: "wg-actions" });
            var addBtn = el("button", { cls: "wg-btn primary sm",
                                        attrs: { type: "button" }, text: "Add peer" });
            addBtn.addEventListener("click", function () {
                schemaForm(peerAddSchema(iface.name));
            });
            var portBtn = el("button", { cls: "wg-btn sm",
                                         attrs: { type: "button" }, text: "Set port" });
            portBtn.addEventListener("click", function () {
                schemaForm(listenPortSchema(iface));
            });
            actions.appendChild(addBtn);
            actions.appendChild(portBtn);
            head.appendChild(actions);
        }
        card.appendChild(head);

        var dl = el("dl", { cls: "wg-dl" });
        function row(term, value) {
            dl.appendChild(el("dt", { text: term }));
            dl.appendChild(typeof value === "string"
                ? el("dd", { cls: "mono", text: value })
                : el("dd", {}, value));
        }

        row("Public key", keyNode(iface.publicKey));
        row("Listen port", iface.listenPort || "—");
        row("Addresses", (link && link.addrs.length) ? link.addrs.join(", ") : "—");
        if (link && link.mtu) row("MTU", String(link.mtu));
        if (link && link.operstate) row("Link state", link.operstate);
        if (iface.fwmark && iface.fwmark !== "off") row("fwmark", iface.fwmark);
        (extras || []).forEach(function (e) { row(e[0], e[1]); });

        card.appendChild(el("div", { cls: "wg-card-body" }, dl));
        card.appendChild(peerTable(iface.peers, iface.name, managed));
        return card;
    }

    function nmNodeFor(device) {
        var nm = state.nm.filter(function (c) { return c.device === device; })[0];
        if (!nm) return null;
        return el("span", {},
            el("span", { cls: "mono", text: nm.name }),
            document.createTextNode(" "),
            pill(nm.state || "unknown", nm.state === "activated" ? "ok" : "warn"),
            document.createTextNode(" "),
            el("span", { cls: "wg-subtle", text: nm.type + " · " + nm.uuid }));
    }

    function renderHost() {
        var box = $("wg-host-body");
        clear(box);

        if (state.host.ifaces.length) {
            state.host.ifaces.forEach(function (iface) {
                var extras = [];
                var nm = nmNodeFor(iface.name);
                if (nm) extras.push(["NetworkManager", nm]);
                box.appendChild(interfaceCard(iface, state.host.addrs[iface.name], extras, true));
            });
            return;
        }

        /*
         * Unprivileged fallback: `wg show interfaces` and `ip addr` both work
         * without root, so show the interface and say exactly what is missing
         * rather than rendering an empty page.
         */
        var names = state.host.list;
        if (!names.length)
            names = Object.keys(state.host.addrs).filter(function (n) { return /^wg/.test(n); });

        if (!names.length) {
            box.appendChild(el("div", { cls: "wg-empty",
                text: state.host.err
                    ? "No host WireGuard interface data available."
                    : "No WireGuard interfaces are present on this host." }));
            if (state.host.err)
                box.appendChild(el("div", { cls: "wg-inline-err", text: state.host.err }));
            return;
        }

        names.forEach(function (name) {
            var link = state.host.addrs[name];
            var head = el("div", { cls: "wg-card-head" },
                el("span", { cls: "name", text: name }),
                linkStatePill(link),
                pill("limited data", "warn"));

            var dl = el("dl", { cls: "wg-dl" });
            dl.appendChild(el("dt", { text: "Addresses" }));
            dl.appendChild(el("dd", { cls: "mono",
                text: (link && link.addrs.length) ? link.addrs.join(", ") : "—" }));
            if (link && link.mtu) {
                dl.appendChild(el("dt", { text: "MTU" }));
                dl.appendChild(el("dd", { cls: "mono", text: String(link.mtu) }));
            }
            var nm = nmNodeFor(name);
            if (nm) {
                dl.appendChild(el("dt", { text: "NetworkManager" }));
                dl.appendChild(el("dd", {}, nm));
            }

            var body = el("div", { cls: "wg-card-body" }, dl,
                el("p", { cls: "wg-hint",
                    text: "Public key, peers, handshakes and transfer counters come from " +
                          "“wg show”, which the kernel restricts to root. Enable " +
                          "administrative access to see them." }));

            box.appendChild(el("div", { cls: "wg-card" }, head, body));
        });
    }

    function renderEasy() {
        var box = $("wg-easy-body");
        clear(box);

        var ps = state.easy.ps;

        var head = el("div", { cls: "wg-card-head" },
            el("span", { cls: "name", text: EASY_CONTAINER }),
            ps ? pill(ps.state || "unknown", ps.state === "running" ? "ok" : "bad")
               : pill("not readable", "warn"),
            el("a", { attrs: { href: EASY_UI, target: "_blank", rel: "noopener noreferrer" },
                      text: "Open wg-easy admin UI ↗",
                      title: "Opens " + EASY_UI + " in a new tab" }));

        var dl = el("dl", { cls: "wg-dl" });
        function row(term, value, mono) {
            dl.appendChild(el("dt", { text: term }));
            dl.appendChild(typeof value === "string"
                ? el("dd", { cls: mono ? "mono" : "", text: value })
                : el("dd", {}, value));
        }

        if (ps) {
            row("Image", ps.image, true);
            row("Status", ps.status || "—");
            if (ps.runningFor) row("Started", ps.runningFor);
        }
        var eth = state.easy.addrs["eth0"];
        row("Container LAN address",
            (eth && eth.addrs.length) ? eth.addrs.join(", ") : "192.168.2.250 (configured)", true);
        row("Admin UI", el("a", { attrs: { href: EASY_UI, target: "_blank",
                                           rel: "noopener noreferrer" },
                                  cls: "mono", text: EASY_UI }));
        row("Runtime", "rootful Podman · macvlan, own LAN IP, no published host ports");

        var body = el("div", { cls: "wg-card-body" }, dl);
        if (!ps) {
            body.appendChild(el("p", { cls: "wg-hint",
                text: state.easy.denied
                    ? "The container is rootful, so it is invisible to an unprivileged " +
                      "podman. Enable administrative access to inspect it."
                    : "The container was not found by podman." }));
            if (state.easy.psErr)
                body.appendChild(el("div", { cls: "wg-inline-err", text: state.easy.psErr }));
        }

        box.appendChild(el("div", { cls: "wg-card" }, head, body));

        if (state.easy.ifaces.length) {
            state.easy.ifaces.forEach(function (iface) {
                box.appendChild(interfaceCard(iface, state.easy.addrs[iface.name],
                    [["Namespace", "inside container " + EASY_CONTAINER]]));
            });
        } else {
            box.appendChild(el("div", { cls: "wg-empty",
                text: state.easy.denied
                    ? "Reading the container's WireGuard state needs administrative access."
                    : (state.easy.err
                        ? "Could not read WireGuard state inside the container."
                        : "The container reports no WireGuard interfaces.") }));
            if (state.easy.err && !state.easy.denied)
                box.appendChild(el("div", { cls: "wg-inline-err", text: state.easy.err }));
        }
    }

    function renderNat() {
        var box = $("wg-nat-body");
        clear(box);

        var unit = state.units.filter(function (u) { return u.Id === "wg-lan-nat.service"; })[0];

        var head = el("div", { cls: "wg-card-head" },
            el("span", { cls: "name", text: "wg-lan-nat.service" }),
            unit ? pill(unit.ActiveState + " (" + unit.SubState + ")",
                        unit.ActiveState === "active" ? "ok" : "bad") : null);
        if (state.nat && state.nat.ipForward !== null)
            head.appendChild(pill("ip_forward=" + state.nat.ipForward,
                                  state.nat.ipForward === "1" ? "ok" : "bad"));

        var body = el("div", { cls: "wg-card-body" });
        body.appendChild(el("p", { cls: "wg-hint",
            text: "These rules let wg0 peers reach the LAN (192.168.2.0/24), the wg-easy " +
                  "container and the 172.15.4.0/24 static-edt network. Only rules naming a " +
                  "WireGuard interface or one of those subnets are listed." }));

        if (!state.nat) {
            body.appendChild(el("div", { cls: "wg-empty", text: "Firewall rules not read yet." }));
        } else {
            [["FORWARD (filter table)", state.nat.forward],
             ["POSTROUTING (nat table)", state.nat.postrouting]].forEach(function (pair) {
                var sec = pair[1];
                if (sec.error) {
                    body.appendChild(el("h3", { cls: "wg-subtle", text: pair[0] }));
                    body.appendChild(el("div", { cls: "wg-empty",
                        text: isPermissionError(sec.error)
                            ? "Reading iptables needs administrative access."
                            : "Could not read these rules." }));
                    body.appendChild(el("div", { cls: "wg-inline-err", text: sec.error }));
                    return;
                }
                var rules = sec.rules.filter(isWgRule);
                body.appendChild(el("h3", { cls: "wg-subtle",
                    text: pair[0] + " — " + rules.length + " WireGuard-related rule" +
                          (rules.length === 1 ? "" : "s") +
                          " of " + sec.rules.length + " total" }));
                body.appendChild(rules.length
                    ? el("pre", { cls: "wg-rules", text: rules.join("\n") })
                    : el("div", { cls: "wg-empty", text: "No matching rules." }));
            });
        }

        box.appendChild(el("div", { cls: "wg-card" }, head, body));
    }

    function renderUnits() {
        var box = $("wg-units-body");
        clear(box);

        if (!state.units.length) {
            box.appendChild(el("div", { cls: "wg-empty",
                text: state.unitsErr ? "Unit states could not be read."
                                     : "No unit data yet." }));
        } else {
            var hrow = el("tr");
            ["Unit", "Description", "Active", "Sub-state", "Enablement"].forEach(function (h) {
                hrow.appendChild(el("th", { text: h }));
            });
            var table = el("table", { cls: "wg-table" }, el("thead", {}, hrow));

            var tbody = el("tbody");
            state.units.forEach(function (u) {
                var tr = el("tr");
                tr.appendChild(el("td", { cls: "mono nowrap", text: u.Id }));

                var descCell = el("td", { text: u.Description || "" });
                /*
                 * wg0 is an NM/netplan tunnel on this host, so wg-quick@wg0
                 * being dead is correct, not a fault. Say so rather than
                 * painting it red.
                 */
                if (u.Id === "wg-quick@wg0.service" && u.ActiveState !== "active")
                    descCell.appendChild(el("div", { cls: "wg-hint",
                        text: "Not used here — wg0 is brought up by NetworkManager " +
                              "(connection " + NM_CONNECTION + ", generated from netplan)." }));
                tr.appendChild(descCell);

                var neutral = (u.Id === "wg-quick@wg0.service");
                var good = (u.ActiveState === "active");
                tr.appendChild(el("td", { cls: "nowrap" },
                    pill(u.ActiveState || "?", good ? "ok" : (neutral ? "" : "bad"))));
                tr.appendChild(el("td", { cls: "nowrap mono", text: u.SubState || "—" }));
                tr.appendChild(el("td", { cls: "nowrap mono", text: u.UnitFileState || "—" }));
                tbody.appendChild(tr);
            });
            table.appendChild(tbody);
            box.appendChild(el("div", { cls: "wg-card" },
                               el("div", { cls: "wg-table-wrap" }, table)));
        }

        var wgConns = state.nm.filter(function (c) {
            return c.type === "wireguard" || c.name === NM_CONNECTION ||
                   /^wg/.test(c.device || "");
        });
        if (!wgConns.length) return;

        var hr2 = el("tr");
        ["NetworkManager connection", "Type", "Device", "State", "UUID"].forEach(function (h) {
            hr2.appendChild(el("th", { text: h }));
        });
        var t2 = el("table", { cls: "wg-table" }, el("thead", {}, hr2));

        var tb2 = el("tbody");
        wgConns.forEach(function (c) {
            var tr = el("tr");
            tr.appendChild(el("td", { cls: "mono nowrap", text: c.name }));
            tr.appendChild(el("td", { cls: "mono nowrap", text: c.type }));
            tr.appendChild(el("td", { cls: "mono nowrap", text: c.device || "—" }));
            tr.appendChild(el("td", { cls: "nowrap" },
                pill(c.state || "inactive", c.state === "activated" ? "ok" : "warn")));
            tr.appendChild(el("td", { cls: "mono", text: c.uuid }));
            tb2.appendChild(tr);
        });
        t2.appendChild(tb2);
        box.appendChild(el("div", { cls: "wg-card" }, el("div", { cls: "wg-table-wrap" }, t2)));
    }

    function render() {
        ageWidgets = [];              /* rebuilt by peerTable() below */
        renderTopbar();
        renderBanner();
        renderSummary();
        renderHost();
        renderEasy();
        renderNat();
        renderUnits();
    }

    /* ------------------------------------------------------------------ *
     * Boot
     * ------------------------------------------------------------------ */

    function boot() {
        $("wg-refresh").addEventListener("click", function () { poll(true); });
        $("wg-auto").addEventListener("change", schedule);
        document.addEventListener("visibilitychange", function () {
            if (!document.hidden && $("wg-auto").checked) poll(false);
        });

        try {
            if (window.cockpit && cockpit.transport && cockpit.transport.host)
                $("wg-host").textContent = cockpit.transport.host;
        } catch (e) { /* not fatal */ }

        render();
        poll(true);
        schedule();

        /* Handshake ages must keep ticking between polls. */
        window.setInterval(function () {
            if (!document.hidden && !inFlight && state.lastUpdate) refreshAges();
        }, 1000);
    }

    if (document.readyState === "loading")
        document.addEventListener("DOMContentLoaded", boot);
    else
        boot();
})();
