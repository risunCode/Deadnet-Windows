#!/usr/bin/env sh

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ -z "$SCRIPT_DIR" ] || ! cd "$SCRIPT_DIR"; then
  printf '%s\n' "Error: Unable to set working directory to script location." >&2
  exit 1
fi

if [ -x ".venv/bin/python" ]; then
  PYTHON_EXE=".venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
  PYTHON_EXE="python3"
elif command -v python >/dev/null 2>&1; then
  PYTHON_EXE="python"
else
  printf '%s\n' "Error: Python not found. Install Python 3 or create .venv/bin/python." >&2
  exit 1
fi

"$PYTHON_EXE" -m app --browser "$@"
