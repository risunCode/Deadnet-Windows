"""CLI entrypoint: python -m app."""

import argparse
import logging
import platform
import threading
import time
import webbrowser

from app import create_app


def _is_windows() -> bool:
    return platform.system().lower().startswith("win")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="DeadNet Python server")
    parser.add_argument("--browser", "-b", action="store_true", help="Run in browser mode")
    parser.add_argument("--webview", "-w", action="store_true", help="Run in webview mode")
    parser.add_argument("--host", default="0.0.0.0", help="Bind host (default: 0.0.0.0)")
    parser.add_argument("--port", "-p", type=int, default=5000, help="Port (default: 5000)")
    parser.add_argument("--no-open", action="store_true", help="Do not open browser")

    args = parser.parse_args()
    if args.browser and args.webview:
        parser.error("Cannot use both --browser and --webview")

    return args


def _url_host(bind_host: str) -> str:
    return "127.0.0.1" if bind_host in {"0.0.0.0", "::"} else bind_host


def _open_browser_later(url: str) -> None:
    threading.Thread(
        target=lambda: (time.sleep(1.0), webbrowser.open(url)),
        daemon=True,
    ).start()


def _run_browser_mode(app, host: str, port: int, no_open: bool) -> None:
    state = app.config["STATE"]
    state.runtime.set_mode("browser")
    state.runtime.set_webview_window(None)

    if not no_open:
        _open_browser_later(f"http://{_url_host(host)}:{port}")

    app.run(host=host, port=port, debug=False, threaded=True)


def _run_webview_mode(app, host: str, port: int, no_open: bool) -> None:
    state = app.config["STATE"]
    state.runtime.set_mode("webview")
    state.runtime.set_webview_window(None)

    try:
        import webview  # type: ignore
    except ImportError:
        logging.warning("pywebview is not installed, falling back to browser mode")
        _run_browser_mode(app=app, host=host, port=port, no_open=no_open)
        return

    threading.Thread(
        target=lambda: app.run(host=host, port=port, debug=False, threaded=True),
        daemon=True,
    ).start()
    time.sleep(1.2)

    window = webview.create_window(
        "DeadNet",
        f"http://{_url_host(host)}:{port}",
        width=1100,
        height=700,
        resizable=True,
        min_size=(900, 600),
    )
    state.runtime.set_webview_window(window)
    webview.start()


def main() -> None:
    args = parse_args()
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    app = create_app()

    if args.browser:
        mode = "browser"
    elif args.webview:
        mode = "webview"
    else:
        mode = "webview" if _is_windows() else "browser"

    if mode == "webview":
        _run_webview_mode(app=app, host=args.host, port=args.port, no_open=args.no_open)
    else:
        _run_browser_mode(app=app, host=args.host, port=args.port, no_open=args.no_open)


if __name__ == "__main__":
    main()
