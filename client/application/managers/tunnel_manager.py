"""
The office tunnel, on the employee's side.

WHAT IT DOES. While somebody is signed in, the sites a super admin has listed
(WHMCS: portal.99rdp.com) open through the office server, so the site sees
the server's IP. The web-protection rules allow /admin/* for that IP alone, so
the same URL from anywhere else is refused. Every other site goes direct.

HOW, WITHOUT ADMINISTRATOR RIGHTS. The installer is per-user and these are
people's own laptops, so a VPN driver is not an option. Instead:

  1. A tiny proxy runs inside this app on 127.0.0.1.
  2. The system's "automatic proxy configuration" points at a PAC file that
     proxy serves. The PAC sends ONLY the listed sites to it; everything else
     is "DIRECT" — browsing, video calls, downloads are untouched.
  3. For a listed site the browser asks the proxy to CONNECT. The proxy opens
     TLS to our own server, upgrades /api/vpn/tunnel with the session token,
     and joins the two. The browser's TLS runs inside, end to end with the
     site: neither this app nor the server can read the page.

SIGNED OUT MEANS THE PERSON'S OWN IP, NOT A BLOCKED SITE. The listed host is
also the customers' client area; only /admin/* is staff-only, and HTTPS hides
the path from any proxy. So the app decides only WHICH IP the site sees, and
the web-protection rule decides what that IP may open. Signed out, the PAC
turns every site DIRECT, a browser still holding the old PAC is carried
direct by the proxy, and the server has already closed the session's tunnels.
The client area keeps working and /admin is refused. A crashed app is covered
too: the PAC address stops answering, browsers fall back to direct, and the
server stops hearing the heartbeat within two minutes.

OFF OUTSIDE THE REAL APP. Running this from the test suite would rewrite the
proxy settings of whatever machine runs the tests. It is on in a built app,
and from source only with ETS_TUNNEL=1. ETS_TUNNEL=0 turns it off anywhere.
"""

from __future__ import annotations

import json
import os
import socket
import socketserver
import ssl
import subprocess
import sys
import threading
import time
from urllib.parse import quote, urlsplit

from client.core import http as _http
from client.core.config import API_BASE_URL, DATA_DIR

PREFERRED_PORTS = (47821, 47822, 47823, 47824, 47825)
REFRESH_SECONDS = 300
HEAD_LIMIT = 16 * 1024
STATE_FILE = os.path.join(DATA_DIR, "tunnel_proxy_state.json")


def _log(message: str) -> None:
    try:
        from client.services.logger_service import LoggerService
        LoggerService.log(f"TUNNEL: {message}")
    except Exception:
        pass


def enabled() -> bool:
    flag = os.getenv("ETS_TUNNEL")
    if flag is not None:
        return flag.strip() == "1"
    return bool(getattr(sys, "frozen", False))


# ── which hosts ─────────────────────────────────────────────────────────────
def normalise(host: str) -> str:
    return str(host or "").strip().lower().rstrip(".")


def host_listed(host: str, domains) -> bool:
    h = normalise(host)
    if not h:
        return False
    for d in domains:
        if d.startswith("*."):
            if h.endswith(d[1:]):
                return True
        elif h == d:
            return True
    return False


def build_pac(domains, port: int) -> str:
    """The browser's routing rules. Only listed hosts go to the proxy.

    "PROXY ...; DIRECT", never "PROXY ..." alone. A browser keeps the PAC it
    last read, and with the proxy gone — the app crashed, quit without
    restoring the setting, or was killed — a bare PROXY line left the listed
    site unreachable: ERR_PROXY_CONNECTION_FAILED, client area and all, seen
    on a real Mac. With DIRECT after it the browser falls back to the
    person's own IP, which is exactly "app not connected".
    """
    exact = [d for d in domains if not d.startswith("*.")]
    suffix = [d[1:] for d in domains if d.startswith("*.")]   # ".example.org"
    return (
        "// Amaze Connect: listed sites through the office server, the rest direct.\n"
        "function FindProxyForURL(url, host) {\n"
        "  host = host.toLowerCase();\n"
        f"  var exact = {json.dumps(exact)};\n"
        f"  var suffix = {json.dumps(suffix)};\n"
        "  for (var i = 0; i < exact.length; i++)\n"
        f"    if (host == exact[i]) return \"PROXY 127.0.0.1:{port}; DIRECT\";\n"
        "  for (var j = 0; j < suffix.length; j++)\n"
        "    if (host.length > suffix[j].length &&\n"
        "        host.substring(host.length - suffix[j].length) == suffix[j])\n"
        f"      return \"PROXY 127.0.0.1:{port}; DIRECT\";\n"
        "  return \"DIRECT\";\n"
        "}\n"
    )


# ── the connection to our server ────────────────────────────────────────────
def _ssl_context() -> ssl.SSLContext:
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        return ssl.create_default_context()


def open_upstream(host: str, port: int, token: str, base_url: str = None):
    """
    Open the tunnel on the server. Returns (socket, leftover_bytes) once the
    server has switched protocols, or raises with the server's reason.
    """
    base = urlsplit(base_url or API_BASE_URL)
    secure = base.scheme == "https"
    server_host = base.hostname
    server_port = base.port or (443 if secure else 80)
    path = (base.path.rstrip("/") or "/api") + "/vpn/tunnel"

    raw = socket.create_connection((server_host, server_port), timeout=15)
    sock = _ssl_context().wrap_socket(raw, server_hostname=server_host) if secure else raw
    sock.sendall((
        f"GET {path}?host={quote(host)}&port={port} HTTP/1.1\r\n"
        f"Host: {server_host}\r\n"
        "Upgrade: ets-tunnel\r\nConnection: Upgrade\r\n"
        f"Authorization: Bearer {token}\r\n\r\n"
    ).encode())

    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
        if len(buf) > HEAD_LIMIT:
            break
    head, _, rest = buf.partition(b"\r\n\r\n")
    status_line = head.split(b"\r\n", 1)[0].decode("latin-1", "replace")
    parts = status_line.split(" ")
    status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
    if status != 101:
        reason = ""
        try:
            reason = json.loads(rest.decode("utf-8", "replace")).get("message", "")
        except Exception:
            pass
        sock.close()
        raise ConnectionError(reason or f"server answered {status or 'nothing'}")
    sock.settimeout(None)
    return sock, rest


def _pipe(src, dst):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        for s in (src, dst):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


# ── the local proxy ─────────────────────────────────────────────────────────
class _Handler(socketserver.BaseRequestHandler):
    def handle(self):
        mgr: TunnelManager = self.server.manager
        client = self.request
        client.settimeout(30)
        buf = b""
        try:
            while b"\r\n\r\n" not in buf and len(buf) < HEAD_LIMIT:
                chunk = client.recv(4096)
                if not chunk:
                    return
                buf += chunk
        except OSError:
            return
        head, _, early = buf.partition(b"\r\n\r\n")
        line = head.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        parts = line.split(" ")
        if len(parts) < 2:
            return self._reply(400, "Bad request")
        method, target = parts[0].upper(), parts[1]

        if method == "GET" and target.split("?")[0] in ("/ets.pac", "/proxy.pac"):
            body = mgr.pac().encode()
            client.sendall(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/x-ns-proxy-autoconfig\r\n"
                b"Cache-Control: no-store\r\n"
                + f"Content-Length: {len(body)}\r\n".encode()
                + b"Connection: close\r\n\r\n" + body)
            return

        if method != "CONNECT":
            # A listed site typed as http://: send the browser to https, which
            # is the only way through. Anything else is not ours to carry.
            split = urlsplit(target)
            if split.scheme == "http" and host_listed(split.hostname or "", mgr.domains):
                location = "https://" + target[len("http://"):]
                client.sendall(
                    f"HTTP/1.1 301 Moved Permanently\r\nLocation: {location}\r\n"
                    "Content-Length: 0\r\nConnection: close\r\n\r\n".encode())
                return
            return self._reply(403, "Only listed sites, over https.")

        host, _, port_text = target.rpartition(":")
        host = host.strip("[]")
        port = int(port_text) if port_text.isdigit() else 0
        if port != 443 or not host_listed(host, mgr.domains):
            return self._reply(403, f"{host} is not sent through the office server.")
        # SIGNED OUT, OR THE TUNNEL REFUSED: GO DIRECT, NEVER BLOCK.
        #
        # The same host serves customers too (portal.99rdp.com is the client
        # area; only /admin/* is staff-only). A browser that still holds the
        # PAC from before sign-out sends the site here, and refusing it broke
        # the whole portal — "Ye galat hai, ye URL clients v open krta hai".
        # HTTPS hides the path from a proxy, so /admin cannot be told apart
        # here; the web-protection rule does that, by IP. Direct means the
        # employee's own IP: the client area opens, /admin is refused there.
        upstream, leftover = None, b""
        token = mgr.token()
        if token:
            try:
                upstream, leftover = mgr.open_upstream(host, port, token)
            except Exception as error:
                _log(f"{host} not through the office server, going direct — {error}")
        if upstream is None:
            try:
                upstream = mgr.open_direct(host, port)
            except OSError as error:
                return self._reply(502, f"{host} could not be reached: {error}")

        client.settimeout(None)
        try:
            client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            if leftover:
                client.sendall(leftover)
            if early:
                upstream.sendall(early)
        except OSError:
            upstream.close()
            return
        mgr._track(upstream)
        back = threading.Thread(target=_pipe, args=(upstream, client), daemon=True)
        back.start()
        _pipe(client, upstream)
        back.join(timeout=5)
        mgr._untrack(upstream)
        upstream.close()

    def _reply(self, status, message):
        reason = {400: "Bad Request", 403: "Forbidden", 502: "Bad Gateway"}.get(status, "Error")
        body = message.encode()
        try:
            self.request.sendall(
                f"HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain; charset=utf-8\r\n"
                f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode() + body)
        except OSError:
            pass


class _Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = False


# ── the system's proxy setting ──────────────────────────────────────────────
class SystemProxy:
    """
    Points the system's automatic proxy configuration at our PAC, and puts
    back what was there before. Never raises: a machine where this cannot be
    set simply does not get the tunnel, and the app carries on.
    """

    def __init__(self, state_file: str = STATE_FILE):
        self.state_file = state_file

    def _load(self) -> dict:
        try:
            with open(self.state_file, encoding="utf-8") as fh:
                return json.load(fh)
        except Exception:
            return {}

    def _save(self, state: dict) -> None:
        try:
            with open(self.state_file, "w", encoding="utf-8") as fh:
                json.dump(state, fh)
        except Exception:
            pass

    def install(self, pac_url: str) -> bool:
        try:
            if sys.platform.startswith("win"):
                return self._win_install(pac_url)
            if sys.platform == "darwin":
                return self._mac_install(pac_url)
            return self._linux_install(pac_url)
        except Exception as error:
            _log(f"could not set the proxy configuration — {error}")
            return False

    def restore(self) -> None:
        try:
            if sys.platform.startswith("win"):
                self._win_restore()
            elif sys.platform == "darwin":
                self._mac_restore()
            else:
                self._linux_restore()
        except Exception as error:
            _log(f"could not restore the proxy configuration — {error}")

    # Windows: per-user, no administrator needed.
    _WIN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"

    def _win_notify(self):
        import ctypes
        wininet = ctypes.windll.wininet
        wininet.InternetSetOptionW(0, 39, 0, 0)   # SETTINGS_CHANGED
        wininet.InternetSetOptionW(0, 37, 0, 0)   # REFRESH

    def _win_install(self, pac_url):
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, self._WIN_KEY, 0,
                            winreg.KEY_READ | winreg.KEY_WRITE) as key:
            try:
                current = winreg.QueryValueEx(key, "AutoConfigURL")[0]
            except FileNotFoundError:
                current = None
            if current == pac_url:
                return True
            state = self._load()
            if not str(current or "").startswith("http://127.0.0.1:478"):
                state["win_previous"] = current
            self._save(state)
            winreg.SetValueEx(key, "AutoConfigURL", 0, winreg.REG_SZ, pac_url)
        self._win_notify()
        return True

    def _win_restore(self):
        import winreg
        state = self._load()
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, self._WIN_KEY, 0,
                            winreg.KEY_READ | winreg.KEY_WRITE) as key:
            try:
                current = winreg.QueryValueEx(key, "AutoConfigURL")[0]
            except FileNotFoundError:
                return
            if not str(current).startswith("http://127.0.0.1:478"):
                return      # somebody else's setting now; leave it alone
            previous = state.get("win_previous")
            if previous:
                winreg.SetValueEx(key, "AutoConfigURL", 0, winreg.REG_SZ, previous)
            else:
                winreg.DeleteValue(key, "AutoConfigURL")
        self._win_notify()

    # macOS: networksetup, per network service.
    @staticmethod
    def _mac_services():
        out = subprocess.run(["networksetup", "-listallnetworkservices"],
                             capture_output=True, text=True, timeout=10).stdout
        return [s for s in out.splitlines()[1:] if s and not s.startswith("*")]

    @staticmethod
    def _mac_current(service):
        out = subprocess.run(["networksetup", "-getautoproxyurl", service],
                             capture_output=True, text=True, timeout=10).stdout
        url, on = None, False
        for line in out.splitlines():
            if line.startswith("URL:"):
                url = line[4:].strip()
                url = None if url in ("", "(null)") else url
            elif line.startswith("Enabled:"):
                on = line.split(":", 1)[1].strip().lower() == "yes"
        return url, on

    def _mac_run(self, commands) -> bool:
        """Run networksetup commands; one administrator prompt if needed."""
        failed = False
        for cmd in commands:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if r.returncode != 0 or "admin" in (r.stdout + r.stderr).lower():
                failed = True
                break
        if not failed:
            return True
        script = " && ".join(" ".join(_sh_quote(c) for c in cmd) for cmd in commands)
        prompt = ("Amaze Connect needs to set the proxy configuration once, so "
                  "that your company's admin sites open through the office server.")
        r = subprocess.run(
            ["osascript", "-e",
             f'do shell script {json.dumps(script)} with prompt {json.dumps(prompt)} '
             f'with administrator privileges'],
            capture_output=True, text=True, timeout=120)
        return r.returncode == 0

    def _mac_install(self, pac_url):
        services = self._mac_services()
        state = self._load()
        previous = state.get("mac_previous", {})
        commands = []
        for svc in services:
            url, on = self._mac_current(svc)
            if url == pac_url and on:
                continue
            if svc not in previous and not str(url or "").startswith("http://127.0.0.1:478"):
                previous[svc] = {"url": url, "on": on}
            commands.append(["networksetup", "-setautoproxyurl", svc, pac_url])
            commands.append(["networksetup", "-setautoproxystate", svc, "on"])
        state["mac_previous"] = previous
        self._save(state)
        return self._mac_run(commands) if commands else True

    def _mac_restore(self):
        # Never asks for a password on the way out: if putting it back needs
        # one, the setting stays. That is harmless — with the app closed the
        # PAC address does not answer and browsers go direct.
        state = self._load()
        for svc, prev in state.get("mac_previous", {}).items():
            url, _ = self._mac_current(svc)
            if not str(url or "").startswith("http://127.0.0.1:478"):
                continue
            if prev.get("url"):
                cmds = [["networksetup", "-setautoproxyurl", svc, prev["url"]],
                        ["networksetup", "-setautoproxystate", svc,
                         "on" if prev.get("on") else "off"]]
            else:
                cmds = [["networksetup", "-setautoproxystate", svc, "off"]]
            for cmd in cmds:
                subprocess.run(cmd, capture_output=True, timeout=10)

    # Linux (GNOME and friends): gsettings, per user.
    def _linux_install(self, pac_url):
        def get(k):
            return subprocess.run(["gsettings", "get", "org.gnome.system.proxy", k],
                                  capture_output=True, text=True, timeout=10).stdout.strip()
        mode, url = get("mode"), get("autoconfig-url")
        if mode == "'auto'" and url == f"'{pac_url}'":
            return True
        state = self._load()
        if "127.0.0.1:478" not in url:
            state["linux_previous"] = {"mode": mode, "url": url}
        self._save(state)
        subprocess.run(["gsettings", "set", "org.gnome.system.proxy", "autoconfig-url", pac_url],
                       timeout=10, check=True)
        subprocess.run(["gsettings", "set", "org.gnome.system.proxy", "mode", "auto"],
                       timeout=10, check=True)
        return True

    def _linux_restore(self):
        prev = self._load().get("linux_previous")
        if not prev:
            return
        url = prev.get("url", "''").strip("'")
        mode = prev.get("mode", "'none'").strip("'")
        subprocess.run(["gsettings", "set", "org.gnome.system.proxy", "autoconfig-url", url],
                       timeout=10)
        subprocess.run(["gsettings", "set", "org.gnome.system.proxy", "mode", mode], timeout=10)


def _sh_quote(text: str) -> str:
    return "'" + str(text).replace("'", "'\\''") + "'"


# ── the manager ─────────────────────────────────────────────────────────────
class TunnelManager:
    """One per app. Started on sign-in, emptied on sign-out, removed on quit."""

    _instance = None

    def __init__(self, token_source=None, system_proxy=None, base_url=None,
                 fetch_domains=None):
        self._token_source = token_source or self._session_token
        self._system = system_proxy or SystemProxy()
        self._base_url = base_url
        self._fetch_domains = fetch_domains or self._fetch_from_server
        self.domains: list[str] = []
        self.port: int | None = None
        self._server = None
        self._signed_in = False
        self._upstreams = set()
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._refresher = None

    # entry points used by SessionManager
    @classmethod
    def instance(cls) -> "TunnelManager":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def signed_in(cls):
        if not enabled():
            return
        threading.Thread(target=cls.instance().start, daemon=True,
                         name="tunnel-start").start()

    @classmethod
    def signed_out(cls):
        if cls._instance is not None:
            cls._instance.stop_session()

    @classmethod
    def app_quitting(cls):
        if cls._instance is not None:
            cls._instance.shutdown()

    # pieces
    @staticmethod
    def _session_token():
        from client.application.managers.session_manager import SessionManager
        return SessionManager.auth_token if SessionManager.is_authenticated else None

    def token(self):
        return self._token_source() if self._signed_in else None

    def _fetch_from_server(self):
        token = self._token_source()
        if not token:
            return []
        r = _http.get(f"{(self._base_url or API_BASE_URL).rstrip('/')}/vpn/config",
                      headers={"Authorization": f"Bearer {token}"}, timeout=10)
        data = r.json()
        if not data.get("success"):
            raise ConnectionError(data.get("message") or f"status {r.status_code}")
        return [normalise(d) for d in data.get("domains") or [] if normalise(d)]

    def pac(self) -> str:
        return build_pac(self.domains if self._signed_in else [], self.port or 0)

    def pac_url(self) -> str:
        return f"http://127.0.0.1:{self.port}/ets.pac"

    def open_upstream(self, host, port, token):
        return open_upstream(host, port, token, self._base_url)

    @staticmethod
    def open_direct(host, port):
        """Straight to the site from this machine, as if there were no proxy."""
        sock = socket.create_connection((host, port), timeout=15)
        sock.settimeout(None)
        return sock

    def _track(self, s):
        with self._lock:
            self._upstreams.add(s)

    def _untrack(self, s):
        with self._lock:
            self._upstreams.discard(s)

    def _close_upstreams(self):
        with self._lock:
            open_now, self._upstreams = list(self._upstreams), set()
        for s in open_now:
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                s.close()
            except OSError:
                pass

    def _listen(self):
        if self._server is not None:
            return True
        for port in PREFERRED_PORTS:
            try:
                server = _Server(("127.0.0.1", port), _Handler)
            except OSError:
                continue
            server.manager = self
            self._server, self.port = server, port
            threading.Thread(target=server.serve_forever, daemon=True,
                             name="tunnel-proxy").start()
            return True
        _log("no local port free for the proxy; the tunnel is off on this machine")
        return False

    def refresh_domains(self):
        try:
            self.domains = self._fetch_domains()
        except Exception as error:
            # Keep what we had: a blip in the network must not drop WHMCS.
            _log(f"could not fetch the site list — {error}")

    def start(self):
        self._signed_in = True
        self._stop.clear()
        self.refresh_domains()
        if not self._listen():
            return
        if self.domains:
            if self._system.install(self.pac_url()):
                _log(f"on — {', '.join(self.domains)} through the office server")
        if self._refresher is None or not self._refresher.is_alive():
            self._refresher = threading.Thread(target=self._refresh_loop, daemon=True,
                                               name="tunnel-refresh")
            self._refresher.start()

    def _refresh_loop(self):
        while not self._stop.wait(REFRESH_SECONDS):
            if not self._signed_in:
                continue
            before = list(self.domains)
            self.refresh_domains()
            if self.domains and not before:
                self._system.install(self.pac_url())

    def stop_session(self):
        """Signed out: every site direct, and what was open is closed."""
        self._signed_in = False
        self._close_upstreams()

    def shutdown(self):
        self.stop_session()
        self._stop.set()
        if self._server is not None:
            self._system.restore()
            try:
                self._server.shutdown()
                self._server.server_close()
            except Exception:
                pass
            self._server = None
