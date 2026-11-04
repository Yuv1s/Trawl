#!/usr/bin/env python3
"""Build Trawl if it needs it, serve it on http://localhost:8000 and open a browser.

    python serve.py

It serves the same static files as the live site, with the same clean URLs, and
only this machine can reach it. Press Ctrl+C to stop.
"""

import http.server
import io
import shutil
import subprocess
import sys
import threading
import webbrowser
from pathlib import Path

HOST = "127.0.0.1"
PORT = 8000
URL = f"http://localhost:{PORT}"

ROOT = Path(__file__).resolve().parent
BUILD = ROOT / "build"
WASM = ROOT / "src" / "lib" / "wasm"
LOCKFILE = ROOT / "package-lock.json"
INSTALLED = ROOT / "node_modules" / ".package-lock.json"

# A change to any of these means the build is out of date.
SOURCES = (
    "src",
    "static",
    "trawl-core/src",
    "trawl-core/Cargo.toml",
    "trawl-core/Cargo.lock",
    "trawl-core/build.rs",
    "package.json",
    "package-lock.json",
    "svelte.config.js",
    "vite.config.ts",
)

# Windows can map these to the wrong type in its registry, and a browser refuses
# to run a module script or compile wasm that arrives as text/plain.
TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".json": "application/json",
    ".svg": "image/svg+xml",
    ".wasm": "application/wasm",
    ".woff2": "font/woff2",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".gif": "image/gif",
    ".bmp": "image/bmp",
    ".wav": "audio/wav",
    ".pdf": "application/pdf",
    ".zip": "application/zip",
    ".txt": "text/plain; charset=utf-8",
    ".md": "text/plain; charset=utf-8",
    ".ps1": "text/plain; charset=utf-8",
    ".sh": "text/plain; charset=utf-8",
}


def fail(message):
    print(f"\n{message}", file=sys.stderr)
    sys.exit(1)


def source_files():
    for name in SOURCES:
        path = ROOT / name
        if path.is_file():
            yield path
        elif path.is_dir():
            for item in path.rglob("*"):
                # The build generates the wasm package into src/ itself.
                if item.is_file() and WASM not in item.parents:
                    yield item


def build_is_current():
    index = BUILD / "index.html"
    if not index.exists():
        return False
    built = index.stat().st_mtime
    return all(item.stat().st_mtime <= built for item in source_files())


def run(*command):
    print(f"> {' '.join(command)}", flush=True)
    result = subprocess.run([shutil.which(command[0]), *command[1:]], cwd=ROOT)
    if result.returncode != 0:
        fail(f"{' '.join(command)} failed, and the output above says why.")


def build():
    if build_is_current():
        print("The build is up to date.")
        return

    missing = [tool for tool in ("npm", "cargo", "wasm-pack") if shutil.which(tool) is None]
    if missing:
        fail(
            f"Building Trawl needs {', '.join(missing)}, which this machine doesn't have. "
            'See "Running it locally" in README.md.'
        )

    print("Building Trawl. The first build compiles the Rust core and takes a few minutes.")
    if not INSTALLED.exists() or INSTALLED.stat().st_mtime < LOCKFILE.stat().st_mtime:
        run("npm", "ci")
    run("npm", "run", "build")


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(BUILD), **kwargs)

    def send_head(self):
        """Resolve clean URLs and the 404 page the way vercel.json does on the live site."""
        path = self.path.split("?", 1)[0].split("#", 1)[0]
        local = Path(self.translate_path(path))

        if local.is_file() or (local / "index.html").is_file():
            return super().send_head()

        if local.with_name(f"{local.name}.html").is_file():
            self.path = f"{path.rstrip('/')}.html"
            return super().send_head()

        return self.send_not_found()

    def send_not_found(self):
        body = (BUILD / "404.html").read_bytes()
        self.send_response(404)
        self.send_header("Content-Type", TYPES[".html"])
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        return io.BytesIO(body)

    def guess_type(self, path):
        return TYPES.get(Path(path).suffix.lower(), "application/octet-stream")

    def end_headers(self):
        # Fetch afresh every time, so a rebuild shows up on the next reload.
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        super().end_headers()

    def log_message(self, format, *args):
        pass


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    # On Windows this flag lets a second server share a busy port, which would hide
    # the conflict. Elsewhere it only allows a quick restart.
    allow_reuse_address = sys.platform != "win32"

    def handle_error(self, request, client_address):
        # A browser closing a connection early is routine.
        if not isinstance(sys.exc_info()[1], ConnectionError):
            super().handle_error(request, client_address)


def main():
    build()

    try:
        server = Server((HOST, PORT), Handler)
    except OSError as error:
        fail(
            f"Could not open port {PORT}: {error}\n"
            f"If Trawl is already running in another terminal, it is at {URL}. "
            "Otherwise stop whatever is using the port and try again."
        )

    print(f"\nTrawl is running at {URL}")
    print("Press Ctrl+C to stop.\n", flush=True)
    threading.Timer(0.2, webbrowser.open, args=(URL,)).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Stopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
