"""DeadNet Python backend package."""

from pathlib import Path

from flask import Flask, send_from_directory

try:
    from flask_cors import CORS as _CORS
except Exception:  # pragma: no cover
    _CORS = None


def enable_cors(app: Flask) -> None:
    if _CORS is not None:
        _CORS(app)

from app.api.routes import api_bp
from app.core.state import AppState


def _static_root() -> Path:
    root = Path(__file__).resolve().parent.parent
    return root / "app" / "web"


def _validate_static_root(static_root: Path) -> None:
    index_file = static_root / "index.html"
    if index_file.exists():
        return

    raise RuntimeError(
        "Missing frontend assets at app/web/index.html. "
        "Place built frontend files in app/web before running python -m app."
    )


def create_app() -> Flask:
    static_root = _static_root()
    _validate_static_root(static_root)
    app = Flask(__name__)
    enable_cors(app)

    app.config["STATIC_ROOT"] = str(static_root)
    app.config["STATE"] = AppState()
    app.register_blueprint(api_bp)

    @app.get("/")
    def index():
        return send_from_directory(static_root, "index.html")

    @app.get("/<path:path>")
    def assets(path: str):
        if path.startswith("api/"):
            return {"error": "Not found"}, 404
        return send_from_directory(static_root, path)

    return app
