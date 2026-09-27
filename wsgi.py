"""SecureMailScope — WSGI entrypoint for production runners.

    gunicorn -w 2 -b 127.0.0.1:8000 wsgi:app

Loads persisted settings at import (WSGI-safe), runs the boot-time retention
sweep, and prints the same startup banner as `python app.py` (minus the
dev-server line). Equivalent to app.py's __main__ block, runner-agnostic.
"""
import os
import time

from app import app, apply_retention, SETTINGS, SETTINGS_PATH, HISTORY, HISTORY_PATH

removed = apply_retention().get("removed", 0)
if removed:
    print(f"Retention sweep: removed {removed} expired report artifact(s).")
print(f"SecureMailScope WSGI ready — settings: data_mode={SETTINGS['data_mode']} "
      f"retention={SETTINGS['retention']} ({SETTINGS_PATH})")
print(f"History: {len(HISTORY)} comparison slot(s) restored ({HISTORY_PATH})")
