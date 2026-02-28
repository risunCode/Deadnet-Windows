from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import create_app


def main() -> None:
    app = create_app()
    print("app_ok", app.name)


if __name__ == "__main__":
    main()
