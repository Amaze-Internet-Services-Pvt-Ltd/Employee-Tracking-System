"""
The office tunnel, on the employee's side.

Driven the way a browser drives it: the PAC file is fetched over HTTP from the
local proxy, a CONNECT is sent through it, bytes go through to a stand-in for
the office server and come back. Then signing out has to close what was open
and turn the PAC to all-DIRECT.

The system proxy setting is replaced by a recorder — this test must never
change the proxy configuration of the machine running it.

Run:  python3 tests/test_tunnel_manager.py
"""

import os
import socket
import sys
import tempfile
import threading
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("ETS_DATA_DIR", tempfile.mkdtemp(prefix="ets_test_"))
os.environ.setdefault("API_BASE_URL", "http://127.0.0.1:9/api")
os.environ["ETS_TUNNEL"] = "0"

from client.application.managers import tunnel_manager as tm  # noqa: E402

failures = 0


def check(label, ok, detail=""):
    global failures
    if not ok:
        failures += 1
    print(f"  {'PASS' if ok else 'FAIL'}  {label}" + ("" if ok or not detail else f"  — {detail}"))
    sys.stdout.flush()


class FakeOfficeServer:
    """Answers /api/vpn/tunnel like the real server, then echoes."""

    def __init__(self):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self.requests = []
        self.valid_token = "good-token"
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = conn.recv(4096)
            if not chunk:
                return
            buf += chunk
        head = buf.split(b"\r\n\r\n")[0].decode()
        self.requests.append(head)
        if f"Bearer {self.valid_token}" not in head:
            body = b'{"success":false,"message":"Signed out. Sign in to Amaze Connect again."}'
            conn.sendall(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: "
                         + str(len(body)).encode() + b"\r\n\r\n" + body)
            conn.close()
            return
        conn.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: ets-tunnel\r\n"
                     b"Connection: Upgrade\r\n\r\n")
        try:
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                conn.sendall(b"echo:" + data)
        except OSError:
            pass
        conn.close()


class DirectSite:
    """Stands in for the site reached straight from the laptop."""

    def __init__(self):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    @staticmethod
    def _serve(conn):
        try:
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                conn.sendall(b"direct:" + data)
        except OSError:
            pass
        conn.close()


class RecordingProxySetting:
    def __init__(self):
        self.installed = []
        self.restored = 0

    def install(self, url):
        self.installed.append(url)
        return True

    def restore(self):
        self.restored += 1


def connect_through(port, target):
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    s.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = s.recv(4096)
        if not chunk:
            break
        buf += chunk
    head, _, rest = buf.partition(b"\r\n\r\n")
    status = int(head.split(b" ")[1]) if b" " in head else 0
    return s, status, rest.decode(errors="replace")


def main():
    print("Office tunnel — client side\n")

    # ── the rules, on their own ─────────────────────────────────────────
    d = ["portal.99rdp.com", "*.example.org"]
    check("a listed host matches", tm.host_listed("Portal.99rdp.com.", d))
    check("a lookalike does not", not tm.host_listed("portal.99rdp.com.evil.net", d))
    check("a wildcard covers subdomains", tm.host_listed("a.example.org", d))
    check("but not the bare domain", not tm.host_listed("example.org", d))

    check("the app is off when told so, whatever the build", not tm.enabled())
    os.environ.pop("ETS_TUNNEL")
    check("and off from source by default — tests never touch the proxy setting",
          not tm.enabled())
    os.environ["ETS_TUNNEL"] = "0"

    # ── the proxy, as a browser uses it ─────────────────────────────────
    office = FakeOfficeServer()
    setting = RecordingProxySetting()
    token = {"value": "good-token"}
    mgr = tm.TunnelManager(
        token_source=lambda: token["value"],
        system_proxy=setting,
        base_url=f"http://127.0.0.1:{office.port}/api",
        fetch_domains=lambda: ["portal.99rdp.com"],
    )
    direct = DirectSite()
    mgr.open_direct = lambda host, port: socket.create_connection(("127.0.0.1", direct.port))
    mgr.start()
    check("the local proxy is listening on a fixed port",
          mgr.port in tm.PREFERRED_PORTS, str(mgr.port))
    check("the system is pointed at our PAC",
          setting.installed == [f"http://127.0.0.1:{mgr.port}/ets.pac"], str(setting.installed))

    pac = urllib.request.urlopen(f"http://127.0.0.1:{mgr.port}/ets.pac", timeout=5).read().decode()
    check("the PAC sends WHMCS to the proxy",
          '"portal.99rdp.com"' in pac and f"PROXY 127.0.0.1:{mgr.port}" in pac)
    check("and everything else direct", 'return "DIRECT"' in pac)

    s, status, _ = connect_through(mgr.port, "portal.99rdp.com:443")
    check("CONNECT to WHMCS is established", status == 200, str(status))
    s.sendall(b"hello")
    check("bytes go through the office server and back", s.recv(100) == b"echo:hello")
    asked = office.requests[-1]
    check("the server was asked for that host, on 443, with the session token",
          "host=portal.99rdp.com&port=443" in asked and "Bearer good-token" in asked
          and "Upgrade: ets-tunnel" in asked, asked)

    s2, status, body = connect_through(mgr.port, "www.google.com:443")
    check("an unlisted site is refused by the proxy", status == 403, str(status))
    check("and never reaches the server",
          not any("google" in r for r in office.requests))
    s2.close()

    s3, status, _ = connect_through(mgr.port, "portal.99rdp.com:22")
    check("only port 443", status == 403, str(status))
    s3.close()

    raw = socket.create_connection(("127.0.0.1", mgr.port), timeout=5)
    raw.sendall(b"GET http://portal.99rdp.com/admin/ HTTP/1.1\r\nHost: portal.99rdp.com\r\n\r\n")
    reply = raw.recv(1000).decode()
    check("http:// WHMCS is sent to https://",
          reply.startswith("HTTP/1.1 301") and "Location: https://portal.99rdp.com/admin/" in reply,
          reply[:80])
    raw.close()

    # The server refusing (session ended there first): the site still opens,
    # from the laptop's own IP — the client area must never break.
    token["value"] = "stale-token"
    s4, status, body = connect_through(mgr.port, "portal.99rdp.com:443")
    s4.sendall(b"hi")
    check("a token the server refuses goes direct instead of failing",
          status == 200 and s4.recv(100) == b"direct:hi", f"{status} {body}")
    s4.close()
    token["value"] = "good-token"

    # ── signing out ─────────────────────────────────────────────────────
    mgr.stop_session()
    s.settimeout(3)
    try:
        gone = s.recv(100) == b""
    except (ConnectionResetError, OSError):
        gone = True
    check("signing out closes the WHMCS connection already open", gone)
    s.close()

    before = len(office.requests)
    s5, status, _ = connect_through(mgr.port, "portal.99rdp.com:443")
    s5.sendall(b"client area")
    check("signed out, the portal still opens — direct, for the client area",
          status == 200 and s5.recv(100) == b"direct:client area", str(status))
    check("and not through the office server", len(office.requests) == before)
    s5.close()
    pac = urllib.request.urlopen(f"http://127.0.0.1:{mgr.port}/ets.pac", timeout=5).read().decode()
    check("the PAC now sends every site direct", "portal.99rdp.com" not in pac)

    mgr.start()
    s6, status, _ = connect_through(mgr.port, "portal.99rdp.com:443")
    s6.sendall(b"x")
    check("signing in again sends it through the office server again",
          status == 200 and s6.recv(100) == b"echo:x", str(status))
    s6.close()

    # ── a list that cannot be fetched does not drop what was there ──────
    def broken():
        raise ConnectionError("network down")
    mgr._fetch_domains = broken
    mgr.refresh_domains()
    check("a failed refresh keeps the last list", mgr.domains == ["portal.99rdp.com"])

    # ── quitting ────────────────────────────────────────────────────────
    port = mgr.port
    mgr.shutdown()
    check("quitting puts the proxy setting back", setting.restored == 1)
    time.sleep(0.2)
    try:
        socket.create_connection(("127.0.0.1", port), timeout=1).close()
        stopped = False
    except OSError:
        stopped = True
    check("and the local proxy stops answering — browsers fall back to direct", stopped)

    # ── the PAC file itself is valid JavaScript with the right answers ──
    pac = tm.build_pac(["portal.99rdp.com", "*.example.org"], 47821)
    check("PAC wildcard rule is written as a suffix", '".example.org"' in pac)
    # The proxy gone (app crashed or killed) must not take the site down.
    check("every PROXY answer falls back to DIRECT",
          pac.count("PROXY 127.0.0.1:47821; DIRECT") == 2
          and "PROXY 127.0.0.1:47821\";" not in pac, pac)

    # ── a setting left behind by a killed app is not "the previous one" ─
    # Seen on a real Mac: an instance killed before it could restore left
    # our PAC address set (switched off). The next launch recorded nothing
    # to go back to, so quitting left the setting on. networksetup is faked
    # here — this must never touch the machine running the test.
    class FakeMac(tm.SystemProxy):
        current = {"Wi-Fi": ("http://127.0.0.1:47821/ets.pac", False)}

        @staticmethod
        def _mac_services():
            return ["Wi-Fi"]

        @staticmethod
        def _mac_current(svc):
            return FakeMac.current[svc]

        def _mac_run(self, commands):
            FakeMac.current["Wi-Fi"] = ("http://127.0.0.1:47821/ets.pac", True)
            return True

    ran = []
    real_run = tm.subprocess.run
    tm.subprocess.run = lambda cmd, **kw: ran.append(cmd)
    try:
        fake = FakeMac(os.path.join(os.environ["ETS_DATA_DIR"], "fake_state.json"))
        fake._mac_install("http://127.0.0.1:47821/ets.pac")
        fake._mac_restore()
    finally:
        tm.subprocess.run = real_run
    check("a leftover of our own PAC is put back as OFF on quit",
          ran == [["networksetup", "-setautoproxystate", "Wi-Fi", "off"]], str(ran))

    print(f"\n{'ALL PASS' if failures == 0 else f'{failures} FAILURE(S)'}")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
