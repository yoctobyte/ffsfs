#!/usr/bin/env python3
"""ffsportal.py — tiny fixed-port landing page that links to each realm's
FFSFS dashboard.

Each realm's peer/dashboard HTTP server binds a realm-derived port (and falls
back to the next free port if that one is busy), so the actual dashboard URL is
not obvious — especially when FFSFS runs as a systemd service. This portal
listens on ONE easy-to-remember fixed port and reads the local realm configs +
runtime portfiles to offer a clickable link to each live dashboard.

It is read-only, loopback-only, and has no FFSFS dependencies (stdlib only), so
it stays up regardless of any realm's state.

Run:
    ./ffsportal.py                # http://127.0.0.1:4085/
    ./ffsportal.py --port 50000   # override
    FFSFS_STATE_DIR=~/.ffsfs ./ffsportal.py
"""

import argparse
import html
import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# 0xFF5 = 4085. "FF5" ~ FFSFS; not in /etc/services and not a common dev port
# (8080/8000/4040/4200…); unprivileged so no root needed.
DEFAULT_PORT = 0xFF5
BIND_HOST = "127.0.0.1"          # loopback only, matching the dashboards
RUNTIME_FRESH_SECS = 120         # runtime.json older than this = treat as stale


def _state_dir() -> str:
    base = os.environ.get("FFSFS_STATE_DIR", os.path.expanduser("~/.ffsfs"))
    return os.path.join(base, ".storage")


def _load_json(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def collect_realms() -> list:
    """Scan the state dir for configured realms and their dashboard ports."""
    storage = _state_dir()
    realms = []
    try:
        entries = sorted(os.listdir(storage))
    except OSError:
        return realms
    for name in entries:
        cfg_path = os.path.join(storage, name, "realm-config.json")
        if not os.path.isfile(cfg_path):
            continue
        cfg = _load_json(cfg_path)
        state = cfg.get("setup_state") or {}
        rt = _load_json(os.path.join(storage, name, "runtime.json"))
        rt_port = rt.get("port")
        rt_age = (time.time() - rt.get("updated", 0)) if rt.get("updated") else None
        running = bool(rt_port) and rt_age is not None and rt_age <= RUNTIME_FRESH_SECS
        # Prefer the live (runtime) port; fall back to the configured one.
        port = rt_port if running else cfg.get("port")
        realms.append({
            "realm": name,
            "port": port,
            "configured_port": cfg.get("port"),
            "live": running,
            "activated": bool(state.get("activated")) if state else True,
            "mountpoint": cfg.get("mountpoint") or "",
        })
    return realms


def render_page(realms: list) -> str:
    e = html.escape
    rows = []
    for r in realms:
        name = e(r["realm"])
        mount = e(r["mountpoint"])
        port = r["port"]
        if port:
            url = f"http://127.0.0.1:{int(port)}/dashboard"
            link = f'<a href="{e(url)}">{e(url)}</a>'
        else:
            link = '<span class="muted">no port configured</span>'
        if r["live"]:
            state = '<span class="ok">● live</span>'
        elif not r["activated"]:
            state = '<span class="muted">○ inactive</span>'
        else:
            state = '<span class="warn">○ stopped</span>'
        note = ""
        if r["live"] and r["configured_port"] and port != r["configured_port"]:
            note = f' <span class="muted">(configured {e(str(r["configured_port"]))})</span>'
        rows.append(
            f"<tr><td>{name}</td><td>{state}</td>"
            f"<td>{link}{note}</td><td class='muted'>{mount}</td></tr>")
    if not rows:
        rows.append('<tr><td colspan="4" class="muted">No realms configured. '
                    'Run ./setup.sh to create one.</td></tr>')
    table = "\n".join(rows)
    return f"""<!doctype html>
<html><head><meta charset="utf-8">
<meta http-equiv="refresh" content="10">
<title>FFSFS portal</title>
<style>
  body {{ font-family: system-ui, sans-serif; margin: 2rem; color: #222; }}
  h1 {{ font-size: 1.3rem; }}
  table {{ border-collapse: collapse; margin-top: 1rem; }}
  th, td {{ text-align: left; padding: .4rem .8rem; border-bottom: 1px solid #ddd; }}
  .ok {{ color: #137333; }} .warn {{ color: #b06000; }}
  .muted {{ color: #888; }}
  footer {{ margin-top: 2rem; color: #888; font-size: .85rem; }}
</style></head><body>
<h1>FFSFS realms on this host</h1>
<table>
<tr><th>Realm</th><th>State</th><th>Dashboard</th><th>Mountpoint</th></tr>
{table}
</table>
<footer>Loopback only — open from this machine or an SSH tunnel.
Dashboards are not exposed off-host. Page refreshes every 10s.</footer>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path in ("/", "/index.html"):
            body = render_page(collect_realms()).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
        elif self.path == "/realms.json":
            body = json.dumps({"realms": collect_realms()}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
        elif self.path == "/healthz":
            body = b"ok"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
        else:
            body = b"not found"
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass  # quiet


def main():
    ap = argparse.ArgumentParser(description="FFSFS fixed-port realm portal")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT,
                    help=f"listen port (default {DEFAULT_PORT} = 0xFF5)")
    ap.add_argument("--host", default=BIND_HOST,
                    help="bind host (default 127.0.0.1, loopback only)")
    args = ap.parse_args()
    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    url = f"http://{args.host}:{args.port}/"
    print(f"[portal] FFSFS realm portal at {url}  (Ctrl-C to stop)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n[portal] stopped")


if __name__ == "__main__":
    main()
