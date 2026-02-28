# Changelog

All notable changes to this project are documented in this file.

## [2.1] - 2026-02-28

Initial clean Python recode release.

### Added
- New package-first architecture under `app/` with `python -m app` entrypoint.
- App-owned static frontend folder at `app/web` populated with built assets.
- Runtime context in app state for GUI mode and webview window references.
- Browser and webview CLI modes with legacy-style flags (`--browser`, `--webview`, `--no-open`, `--host`, `--port`).
- Optional `webview` dependency extra in `pyproject.toml` for `pywebview`.

### Changed
- Static serving now uses only `app/web`; removed runtime fallback to `.old/dist`.
- `/api/minimize` now minimizes the active window in webview mode and returns compatibility messages otherwise.
- Documentation rewritten for the new Python architecture and command flow.

### Migration Notes
- Android-specific code and packaging were removed from the active codebase.
- `.old/` is retained only as historical reference during migration.
- Any workflow that previously depended on legacy runtime paths must now use `app/web` assets.
