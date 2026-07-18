"""
Zero-Dependency .env Loader
=============================
Loads key=value pairs from a .env file into os.environ.

Why this exists instead of just using python-dotenv:
─────────────────────────────────────────────────────
All entry points (web_app.py, run.py, gui_app.py) previously did:

    try:
        from dotenv import load_dotenv
        load_dotenv(...)
    except ImportError:
        pass   # ← silently does NOTHING if python-dotenv isn't installed

This is a dangerous silent failure: if a user's virtualenv was created
before python-dotenv was added to requirements.txt (or they never ran
`pip install -r requirements.txt` again after pulling an update), the
.env file is never read and any config it holds (ZAP proxy settings,
Interactsh OOB tokens, etc.) silently never reaches os.environ — with
NO error message anywhere.

This module has ZERO external dependencies — it's plain Python file
reading — so this entire class of failure is now structurally
impossible. It is used as the ONLY .env loading mechanism going
forward; python-dotenv is no longer required (though still listed in
requirements.txt for compatibility with any code that imports it
directly).
"""

import os
from pathlib import Path
from typing import Optional


def load_env_file(start_path: Optional[Path] = None, verbose: bool = False) -> dict:
    """
    Parse a .env file and load its key=value pairs into os.environ
    (without overriding any variable already set in the real environment —
    real environment variables always take priority over .env file values).

    Searches for .env starting at `start_path` (or the caller's directory)
    and walking up to 2 parent directories, so it works whether called
    from the project root or from modules/ subdirectory.

    Returns a dict of {key: "found"/"already_set"/"missing_file"} for
    diagnostic purposes.
    """
    result = {"env_file": "not found", "keys_loaded": []}

    if start_path is None:
        start_path = Path.cwd()
    elif not isinstance(start_path, Path):
        start_path = Path(start_path)

    search_dirs = [start_path, start_path.parent, start_path.parent.parent]
    env_file = None
    for d in search_dirs:
        candidate = d / ".env"
        if candidate.exists():
            env_file = candidate
            break

    if env_file is None:
        if verbose:
            print(f"[env_loader] No .env file found (searched: {[str(d) for d in search_dirs]})")
        return result

    result["env_file"] = str(env_file)

    try:
        with open(env_file, "r", encoding="utf-8") as f:
            for line_num, raw_line in enumerate(f, 1):
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    continue

                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip()

                # Strip matching quotes if present: KEY="value" or KEY='value'
                if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
                    value = value[1:-1]

                if not key:
                    continue

                # Real environment variables always win over .env file —
                # this matches standard dotenv behaviour and lets ops teams
                # override via system env without editing the file.
                if key in os.environ:
                    continue

                os.environ[key] = value
                result["keys_loaded"].append(key)

    except Exception as exc:
        if verbose:
            print(f"[env_loader] Error reading {env_file}: {exc}")

    if verbose:
        if result["keys_loaded"]:
            print(f"[env_loader] Loaded from {env_file}: {', '.join(result['keys_loaded'])}")
        else:
            print(f"[env_loader] Found {env_file} but no new keys loaded "
                  f"(either empty, malformed, or all keys already set in environment)")

    return result
