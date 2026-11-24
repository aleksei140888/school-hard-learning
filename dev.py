"""Local run without installing Postgres: embedded database in .pgdata/.
Usage: python dev.py  ->  http://localhost:8000  (first-run code: dev)"""
import os
from pathlib import Path

import pgserver
import uvicorn

os.chdir(Path(__file__).parent)  # so it runs from any directory
pg = pgserver.get_server(Path(".pgdata").resolve())
os.environ.setdefault("DATABASE_URL", pg.get_uri())
os.environ.setdefault("SECRET_KEY", "dev-only-secret")
os.environ.setdefault("SETUP_CODE", "dev")
uvicorn.run("app.main:app", app_dir=".", port=int(os.environ.get("PORT", 8000)))
