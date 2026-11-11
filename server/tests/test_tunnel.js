/**
 * The office tunnel — WHMCS reached through this server, only while signed in.
 *
 * Exercised end to end against a real server and a real database: a client
 * opens the upgrade exactly as Amaze Connect does, bytes go through to a stand-
 * in for the site and come back, and then every way a session ends is checked
 * to close the tunnel that was already open — not merely to refuse the next.
 *
 * Run:  node server/tests/test_tunnel.js
 */
const { execFileSync } = require("child_process");
const net = require("net");
const path = require("path");
const { migrate } = require("./_migrate");

const DB = `ets_tunnel_${process.pid}`;
const PORT = 8000 + ((process.pid + 557) % 1000);
const BASE = `http://127.0.0.1:${PORT}/api`;

let failures = 0;
function check(label, ok, detail = "") {
    if (!ok) failures += 1;
    console.log(`  ${ok ? "PASS" : "FAIL"}  ${label}${ok || !detail ? "" : `  — ${detail}`}`);
}

function psql(db, sql) {
    return execFileSync("psql", ["-d", db, "-v", "ON_ERROR_STOP=1", "-tAc", sql],
        { encoding: "utf8" }).trim();
}

async function api(method, route, { token, body } = {}) {
    const response = await fetch(`${BASE}${route}`, {
        method,
        headers: {
            "Content-Type": "application/json",
            ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        ...(body ? { body: JSON.stringify(body) } : {}),
    });
    let payload = {};
    try { payload = await response.json(); } catch (_) {}
    return { status: response.status, body: payload };
}

const login = (u, p) => api("POST", "/auth/login", { body: { username: u, password: p } });
const wait = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * Open a tunnel the way the app does. Resolves with
 * { status, socket, body } — socket only when it switched protocols.
 */
function openTunnel(token, host) {
    return new Promise((resolve) => {
        const socket = net.connect(PORT, "127.0.0.1");
        let buf = Buffer.alloc(0);
        socket.on("error", () => resolve({ status: 0 }));
        socket.on("connect", () => {
            socket.write(`GET /api/vpn/tunnel?host=${encodeURIComponent(host)}&port=443 HTTP/1.1\r\n`
                + `Host: 127.0.0.1\r\nUpgrade: ets-tunnel\r\nConnection: Upgrade\r\n`
                + (token ? `Authorization: Bearer ${token}\r\n` : "") + "\r\n");
        });
        const onData = (chunk) => {
            buf = Buffer.concat([buf, chunk]);
            const end = buf.indexOf("\r\n\r\n");
            if (end < 0) return;
            socket.removeListener("data", onData);
            const status = Number(buf.slice(0, end).toString().split(" ")[1]);
            const rest = buf.slice(end + 4).toString();
            resolve({ status, socket: status === 101 ? socket : null, body: rest });
        };
        socket.on("data", onData);
    });
}

/** Send a line through and read the echo back. */
function roundTrip(socket, text) {
    return new Promise((resolve) => {
        const timer = setTimeout(() => resolve(null), 2000);
        socket.once("data", (d) => { clearTimeout(timer); resolve(d.toString()); });
        socket.write(text);
    });
}

function closed(socket, ms = 3000) {
    return new Promise((resolve) => {
        if (socket.destroyed) return resolve(true);
        const timer = setTimeout(() => resolve(false), ms);
        socket.once("close", () => { clearTimeout(timer); resolve(true); });
    });
}

async function main() {
    const root = path.resolve(__dirname, "..", "..");
    console.log(`Office tunnel (${DB})\n`);

    // The stand-in for portal.99rdp.com: echoes what it is sent.
    const site = net.createServer((s) => s.on("data", (d) => s.write(`echo:${d}`)));
    await new Promise((r) => site.listen(0, "127.0.0.1", r));

    try {
        migrate(DB);

        const bcrypt = require(path.join(root, "server", "node_modules", "bcryptjs"));
        const hash = await bcrypt.hash("SuperSecret123", 10);
        psql(DB, `INSERT INTO employees
                     (employee_id, username, password, role, full_name, designation) VALUES
            ('SA001','superadmin','${hash}','super_admin','Owner','Founder'),
            ('A001','admin1','${hash}','admin','Priya Nair','Operations'),
            ('E001','emp1','${hash}','employee','Rajesh Kumar','Support'),
            ('E002','emp2','${hash}','employee','Second Person','Support')`);

        check("the migration seeds the site the owner named",
            psql(DB, `SELECT value FROM app_settings WHERE key='tunnel_domains'`)
                === '["portal.99rdp.com"]');

        process.env.DB_HOST = process.env.PGHOST || "127.0.0.1";
        process.env.DB_PORT = process.env.PGPORT || "5432";
        process.env.DB_NAME = DB;
        process.env.DB_USER = process.env.PGUSER || process.env.USER;
        process.env.DB_PASSWORD = process.env.PGPASSWORD || "unused-locally";
        process.env.JWT_SECRET = "test-secret-not-used-in-production";
        process.env.PORT = String(PORT);
        process.env.ENCRYPTION_KEY = "0".repeat(64);

        const { server, pool } = require(path.join(root, "server", "server.js"));
        await new Promise((r) => (server.listening ? r() : server.once("listening", r)));
        const tunnel = require(path.join(root, "server", "utils", "tunnel.js"));
        tunnel._testing.resolve = async () => "127.0.0.1";
        tunnel._testing.upstreamPort = site.address().port;

        // ── the guards, on their own ────────────────────────────────────
        const list = ["portal.99rdp.com", "*.example.org"];
        check("a listed host is allowed", tunnel.hostAllowed("portal.99rdp.com", list));
        check("case and a trailing dot do not matter",
            tunnel.hostAllowed("PORTAL.99rdp.com.", list));
        check("a lookalike is not", !tunnel.hostAllowed("portal.99rdp.com.evil.net", list));
        check("nor the parent domain", !tunnel.hostAllowed("99rdp.com", list));
        check("a wildcard covers subdomains", tunnel.hostAllowed("a.b.example.org", list));
        check("but not the bare domain", !tunnel.hostAllowed("example.org", list));
        for (const ip of ["127.0.0.1", "10.1.2.3", "192.168.0.5", "172.20.0.1",
                          "169.254.169.254", "::1", "::ffff:127.0.0.1", "fd00::1"]) {
            check(`${ip} is never reachable through the tunnel`,
                tunnel.isPrivateAddress(ip));
        }
        check("a public address is", !tunnel.isPrivateAddress("185.178.208.1"));

        // ── the list is the super admin's ───────────────────────────────
        const sa = (await login("superadmin", "SuperSecret123")).body.token;
        const admin = (await login("admin1", "SuperSecret123")).body.token;

        let res = await api("GET", "/admin/tunnel-domains", { token: admin });
        check("an admin cannot read the site list", res.status === 403, `status ${res.status}`);
        res = await api("POST", "/admin/tunnel-domains",
            { token: admin, body: { domains: ["evil.net"] } });
        check("nor change it", res.status === 403, `status ${res.status}`);

        res = await api("POST", "/admin/tunnel-domains", { token: sa,
            body: { domains: ["https://Portal.99rdp.com/admin/*", "portal.99rdp.com",
                              "billing.example.org"] } });
        check("the super admin saves a list pasted from the address bar",
            res.status === 200, JSON.stringify(res.body));
        check("kept as host names only, once each",
            JSON.stringify(res.body.domains) === '["portal.99rdp.com","billing.example.org"]',
            JSON.stringify(res.body.domains));
        check("and it is in the database, not only in the reply",
            psql(DB, `SELECT value FROM app_settings WHERE key='tunnel_domains'`)
                === '["portal.99rdp.com","billing.example.org"]');
        check("who changed it is recorded",
            psql(DB, `SELECT updated_by FROM app_settings WHERE key='tunnel_domains'`) === "SA001");

        for (const bad of ["10.0.0.1", "localhost", "not a host", "*.", "a".repeat(300) + ".com"]) {
            res = await api("POST", "/admin/tunnel-domains",
                { token: sa, body: { domains: [bad] } });
            check(`"${bad.slice(0, 20)}" is refused`, res.status === 400, `status ${res.status}`);
        }
        check("a refused save changes nothing",
            psql(DB, `SELECT value FROM app_settings WHERE key='tunnel_domains'`)
                === '["portal.99rdp.com","billing.example.org"]');

        // ── an employee's app ───────────────────────────────────────────
        let emp = (await login("emp1", "SuperSecret123")).body.token;
        res = await api("GET", "/vpn/config", { token: emp });
        check("a signed-in employee's app gets the list",
            res.status === 200 && res.body.domains?.includes("portal.99rdp.com"),
            JSON.stringify(res.body));
        res = await api("GET", "/vpn/config");
        check("nobody else does", res.status === 401, `status ${res.status}`);

        let t = await openTunnel(null, "portal.99rdp.com");
        check("no token, no tunnel", t.status === 401, `status ${t.status}`);
        t = await openTunnel("garbage", "portal.99rdp.com");
        check("a made-up token, no tunnel", t.status === 401, `status ${t.status}`);
        t = await openTunnel(emp, "www.google.com");
        check("an unlisted site is refused", t.status === 403, `status ${t.status}`);
        check("with a reason", /not on the tunnel list/.test(t.body), t.body);

        t = await openTunnel(emp, "portal.99rdp.com");
        check("a listed site opens", t.status === 101, `status ${t.status} ${t.body}`);
        check("and bytes go through to the site and back",
            (await roundTrip(t.socket, "hello")) === "echo:hello");

        // ── every way a session ends closes the open tunnel ─────────────
        await api("POST", "/auth/logout", { token: emp });
        check("signing out closes the tunnel already open", await closed(t.socket));
        t = await openTunnel(emp, "portal.99rdp.com");
        check("and the old token cannot open another", t.status === 401, `status ${t.status}`);

        emp = (await login("emp1", "SuperSecret123")).body.token;
        t = await openTunnel(emp, "portal.99rdp.com");
        check("signed in again, it opens again", t.status === 101, `status ${t.status}`);
        res = await api("POST", "/admin/force-logout",
            { token: admin, body: { employee_id: "E001" } });
        check("an admin force-logs them out", res.status === 200, JSON.stringify(res.body));
        check("force logout closes the tunnel", await closed(t.socket));

        emp = (await login("emp1", "SuperSecret123")).body.token;
        t = await openTunnel(emp, "portal.99rdp.com");
        res = await api("POST", "/admin/employees/E001/suspend",
            { token: admin, body: { suspended: true } });
        check("suspending closes the tunnel", res.status === 200 && await closed(t.socket),
            `status ${res.status}`);
        await api("POST", "/admin/employees/E001/suspend",
            { token: admin, body: { suspended: false } });

        // A laptop that goes quiet: nothing calls logout. The heartbeat stops,
        // and the sweep is what notices.
        let emp2 = (await login("emp2", "SuperSecret123")).body.token;
        t = await openTunnel(emp2, "portal.99rdp.com");
        check("a second employee opens one", t.status === 101, `status ${t.status}`);
        psql(DB, `UPDATE active_sessions SET last_seen = NOW() - INTERVAL '5 minutes'
                   WHERE employee_id = 'E002'`);
        await tunnel.sweep(pool);
        check("a laptop not heard from for minutes loses its tunnel", await closed(t.socket));
        t = await openTunnel(emp2, "portal.99rdp.com");
        check("and cannot open a new one", t.status === 401, `status ${t.status}`);
        check("saying why", /not been heard from/.test(t.body), t.body);

        // Removing a site from the list stops new connections to it.
        await api("POST", "/admin/tunnel-domains", { token: sa, body: { domains: [] } });
        emp2 = (await login("emp2", "SuperSecret123")).body.token;
        t = await openTunnel(emp2, "portal.99rdp.com");
        check("a site taken off the list is refused at once", t.status === 403,
            `status ${t.status}`);

        server.close();
        await pool.end();
    } finally {
        site.close();
        try {
            execFileSync("dropdb", ["--if-exists", DB]);
        } catch (_) {}
    }

    console.log(`\n${failures === 0 ? "ALL PASS" : `${failures} FAILURE(S)`}`);
    process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
    console.error(err);
    try { execFileSync("dropdb", ["--if-exists", DB]); } catch (_) {}
    process.exit(1);
});
