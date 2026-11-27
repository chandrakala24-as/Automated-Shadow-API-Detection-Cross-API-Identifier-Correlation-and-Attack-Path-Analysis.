"""Start ShadowAPI and, unless --no-demo is given, the vulnerable demo lab.

Both listen on 127.0.0.1 only.
"""
from __future__ import annotations

import argparse
import socket
import sys
import threading
import time
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path[:0] = [str(ROOT), str(ROOT / "backend")]

import uvicorn  # noqa: E402


def port_free(port: int) -> bool:
    with socket.socket() as sock:
        return sock.connect_ex(("127.0.0.1", port)) != 0


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--no-demo", action="store_true", help="do not start the vulnerable lab")
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()

    needed = [args.port] + ([] if args.no_demo else [8001])
    busy = [p for p in needed if not port_free(p)]
    if busy:
        sys.exit(f"Port(s) already in use: {busy}. Stop the other program and try again.")

    if not args.no_demo:
        from demo_lab.app import app as lab
        server = uvicorn.Server(uvicorn.Config(lab, host="127.0.0.1", port=8001,
                                               log_level="warning"))
        threading.Thread(target=server.run, daemon=True).start()
        print("Demo lab (deliberately vulnerable): http://127.0.0.1:8001")

    from app.main import create_app
    url = f"http://127.0.0.1:{args.port}"
    print(f"ShadowAPI: {url}   (press Ctrl+C to stop)")
    if not args.no_browser:
        threading.Thread(target=lambda: (time.sleep(1.5), webbrowser.open(url)),
                         daemon=True).start()
    uvicorn.run(create_app(), host="127.0.0.1", port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
