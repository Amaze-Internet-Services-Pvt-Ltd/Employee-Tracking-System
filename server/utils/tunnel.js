/**
 * The office tunnel: chosen sites, reached from this server, only while the
 * person is signed in.
 *
 * WHAT THE OWNER ASKED FOR. WHMCS (portal.99rdp.com/admin/*) should open only
 * through "the VPN": while somebody is signed in to Amaze Connect, their
 * browser reaches that site through this server, so the site sees this
 * server's IP. The web-protection rules allow /admin/* for that one IP and
 * refuse it for everyone else. Every other site goes direct, as before.
 *
 * WHY NOT WIREGUARD. A WireGuard tunnel needs administrator rights on every
 * laptop: a driver, a system service, an elevated installer. These are the
 * employees' own machines and the installer is deliberately per-user with no
 * admin prompt. WireGuard also routes by IP, not by name, and the site sits
 * behind DDoS-Guard's shared, changing addresses. What the owner described is
 * routing by URL, which is what this does:
 *
 *   browser ──(proxy config served by the app)──► Amaze Connect, 127.0.0.1
 *           ──TLS, through nginx, to /api/vpn/tunnel──► this server
 *           ──TCP──► portal.99rdp.com:443
 *
 * The browser's own TLS runs inside, end to end with the site, so this server
 * never sees the page — only which host was asked for.
 *
 * THE SESSION IS THE KEY. A tunnel is opened with the session token, checked
 * the way verifyToken checks it (the current token, not suspended) and, in
 * addition, only while the app is heard from — the heartbeat that already
 * runs every few seconds. Sign out, force logout, suspend, a password reset,
 * a role change, or a laptop that goes quiet: the open tunnels are closed and
 * new ones refused. That is the "session ends → access revoked" half of the
 * owner's diagram, and it needs no separate key to issue or revoke.
 *
 * NOT AN OPEN PROXY. Only the hostnames a super admin has listed, only port
 * 443, and never an address inside this server's own networks — otherwise a
 * listed name pointed at 127.0.0.1 would reach the database.
 */
const dns = require("dns").promises;
const net = require("net");
const jwt = require("jsonwebtoken");

const TUNNEL_PATH = "/api/vpn/tunnel";
const DOMAINS_KEY = "tunnel_domains";
const ALIVE_MINUTES = 2;          // the same window login uses
const SWEEP_MS = 15 * 1000;
const IDLE_MS = 30 * 60 * 1000;
const MAX_PER_PERSON = 64;        // a browser opens a handful; this is a ceiling
const MAX_DOMAINS = 50;

// A hostname, optionally "*." for every subdomain. No IP literals: the list is
// about names, and an address would make this a way to reach anything.
const NAME_RE = /^(\*\.)?(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;

// Addresses never reachable through the tunnel.
const PRIVATE = new net.BlockList();
for (const [addr, bits, type] of [
    ["0.0.0.0", 8, "ipv4"], ["10.0.0.0", 8, "ipv4"], ["100.64.0.0", 10, "ipv4"],
    ["127.0.0.0", 8, "ipv4"], ["169.254.0.0", 16, "ipv4"], ["172.16.0.0", 12, "ipv4"],
    ["192.168.0.0", 16, "ipv4"], ["224.0.0.0", 3, "ipv4"],
    ["::", 128, "ipv6"], ["::1", 128, "ipv6"], ["fc00::", 7, "ipv6"],
    ["fe80::", 10, "ipv6"],
]) PRIVATE.addSubnet(addr, bits, type);
// NOT "::ffff:0:0/96" here: BlockList matches plain IPv4 addresses against an
// IPv4-mapped IPv6 rule, so that one line blocked every IPv4 site there is.
// Mapped addresses are unwrapped and checked as IPv4 below instead.

// For the test suite only — set in-process, never from the environment, so no
// configuration mistake on the server can turn the loopback guard off.
const testing = { resolve: null, upstreamPort: null };

function isPrivateAddress(ip) {
    const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(String(ip));
    if (mapped) ip = mapped[1];
    const family = net.isIP(ip);
    if (!family) return true;
    return PRIVATE.check(ip, family === 6 ? "ipv6" : "ipv4");
}

/** Lower-cased, trailing dot dropped, or null if it is not a valid entry. */
function normaliseDomain(value) {
    const name = String(value || "").trim().toLowerCase().replace(/\.$/, "");
    return NAME_RE.test(name) ? name : null;
}

/** Does `host` fall under one of the listed entries? */
function hostAllowed(host, domains) {
    const h = normaliseDomain(host);
    if (!h || h.startsWith("*.")) return false;
    return domains.some((d) =>
        d.startsWith("*.") ? h.endsWith(d.slice(1)) : h === d);
}

// ── the list ────────────────────────────────────────────────────────────
let cache = { at: 0, domains: [] };

async function getDomains(pool, { fresh = false } = {}) {
    if (!fresh && Date.now() - cache.at < 15000) return cache.domains;
    const row = await pool.query(
        `SELECT value FROM app_settings WHERE key = $1`, [DOMAINS_KEY]);
    let domains = [];
    try {
        const parsed = JSON.parse(row.rows[0]?.value || "[]");
        if (Array.isArray(parsed)) {
            domains = [...new Set(parsed.map(normaliseDomain).filter(Boolean))];
        }
    } catch (_) {
        domains = [];
    }
    cache = { at: Date.now(), domains };
    return domains;
}

function forgetDomains() { cache = { at: 0, domains: [] }; }

// ── the session ─────────────────────────────────────────────────────────
/**
 * The employee this token belongs to, if it may hold a tunnel right now;
 * otherwise { error, status }.
 */
async function sessionFor(pool, token) {
    let decoded;
    try {
        decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (_) {
        return { status: 401, error: "Session expired. Sign in to Amaze Connect again." };
    }
    const held = await pool.query(
        `SELECT s.token, e.suspended,
                (s.last_seen > NOW() - INTERVAL '${ALIVE_MINUTES} minutes') AS alive
           FROM active_sessions s
           JOIN employees e ON e.employee_id = s.employee_id
          WHERE s.employee_id = $1`,
        [decoded.employee_id]
    );
    const row = held.rows[0];
    if (!row || !row.token || row.token !== token) {
        return { status: 401, error: "Signed out. Sign in to Amaze Connect again." };
    }
    if (row.suspended) return { status: 403, error: "This account is suspended." };
    if (row.alive !== true) {
        return { status: 401, error: "Amaze Connect has not been heard from. Reopen it." };
    }
    return { employeeId: decoded.employee_id };
}

// ── open tunnels ────────────────────────────────────────────────────────
// employee_id -> Set of { client, upstream, token }
const open = new Map();

function track(employeeId, entry) {
    if (!open.has(employeeId)) open.set(employeeId, new Set());
    open.get(employeeId).add(entry);
}

function untrack(employeeId, entry) {
    const set = open.get(employeeId);
    if (!set) return;
    set.delete(entry);
    if (set.size === 0) open.delete(employeeId);
}

function openCount(employeeId) { return open.get(employeeId)?.size || 0; }

/** Close every tunnel this person holds. Called when a session ends. */
function closeFor(employeeId) {
    const set = open.get(String(employeeId));
    if (!set) return 0;
    const n = set.size;
    for (const entry of [...set]) {
        entry.client.destroy();
        entry.upstream?.destroy();
    }
    open.delete(String(employeeId));
    return n;
}

/**
 * Re-check every open tunnel. Catches what no code path announces: a laptop
 * that went to sleep, lost its network, or crashed. Its heartbeat stops, the
 * session stops being alive, and its tunnels go with it.
 */
async function sweep(pool) {
    for (const [employeeId, set] of [...open.entries()]) {
        const tokens = new Set([...set].map((e) => e.token));
        for (const token of tokens) {
            let ok = false;
            try { ok = !(await sessionFor(pool, token)).error; } catch (_) { ok = true; }
            if (ok) continue;
            for (const entry of [...set]) {
                if (entry.token !== token) continue;
                entry.client.destroy();
                entry.upstream?.destroy();
                untrack(employeeId, entry);
            }
        }
    }
}

// ── the upgrade itself ──────────────────────────────────────────────────
function refuse(socket, status, message) {
    const body = JSON.stringify({ success: false, message });
    const reason = { 400: "Bad Request", 401: "Unauthorized", 403: "Forbidden",
                     429: "Too Many Requests", 502: "Bad Gateway" }[status] || "Error";
    try {
        socket.end(`HTTP/1.1 ${status} ${reason}\r\n`
            + "Content-Type: application/json\r\n"
            + `Content-Length: ${Buffer.byteLength(body)}\r\n`
            + "Connection: close\r\n\r\n" + body);
    } catch (_) {
        socket.destroy();
    }
}

async function handleUpgrade(pool, req, socket, head) {
    socket.on("error", () => {});
    const url = new URL(req.url, "http://localhost");
    const auth = String(req.headers.authorization || "");
    const token = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";
    if (!token) return refuse(socket, 401, "No token provided");

    const session = await sessionFor(pool, token);
    if (session.error) return refuse(socket, session.status, session.error);
    const { employeeId } = session;

    const host = normaliseDomain(url.searchParams.get("host"));
    const port = Number(url.searchParams.get("port") || 443);
    if (!host || port !== 443) return refuse(socket, 400, "Only listed sites, on port 443.");

    const domains = await getDomains(pool);
    if (!hostAllowed(host, domains)) {
        return refuse(socket, 403, `${host} is not on the tunnel list.`);
    }
    if (openCount(employeeId) >= MAX_PER_PERSON) {
        return refuse(socket, 429, "Too many open connections.");
    }

    let address;
    try {
        if (testing.resolve) {
            address = await testing.resolve(host);
        } else {
            const found = await dns.lookup(host, { all: true, verbatim: true });
            address = found.map((a) => a.address).find((a) => !isPrivateAddress(a));
        }
    } catch (_) {
        address = null;
    }
    if (!address) return refuse(socket, 502, `${host} could not be reached.`);

    const upstream = net.connect({ host: address, port: testing.upstreamPort || port });
    const entry = { client: socket, upstream, token };
    track(employeeId, entry);

    const finish = () => {
        socket.destroy();
        upstream.destroy();
        untrack(employeeId, entry);
    };
    upstream.on("error", finish);
    upstream.on("close", finish);
    socket.on("close", finish);
    socket.setTimeout(IDLE_MS, finish);
    upstream.setTimeout(IDLE_MS, finish);

    upstream.once("connect", () => {
        socket.write("HTTP/1.1 101 Switching Protocols\r\n"
            + "Upgrade: ets-tunnel\r\nConnection: Upgrade\r\n\r\n");
        if (head && head.length) upstream.write(head);
        socket.pipe(upstream);
        upstream.pipe(socket);
    });
}

/** Wire the tunnel onto the HTTP server and start the sweep. */
function attach(server, pool) {
    server.on("upgrade", (req, socket, head) => {
        if (!String(req.url || "").startsWith(TUNNEL_PATH)) {
            socket.destroy();
            return;
        }
        handleUpgrade(pool, req, socket, head).catch((err) => {
            console.error("[TUNNEL]", err.message);
            refuse(socket, 502, "Tunnel error");
        });
    });
    const timer = setInterval(() => {
        sweep(pool).catch((err) => console.error("[TUNNEL SWEEP]", err.message));
    }, SWEEP_MS);
    timer.unref();
    return timer;
}

module.exports = {
    attach, closeFor, getDomains, forgetDomains, normaliseDomain, hostAllowed,
    isPrivateAddress, sweep, openCount, DOMAINS_KEY, MAX_DOMAINS, TUNNEL_PATH,
    _testing: testing,
};
