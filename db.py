"""
This file is used for SQLite database setup for the LabPulse project.

This module opens SQLite connections, 
creates the schema, 
and resets the local development database when a clean state is needed.
"""

import os
import sqlite3
from pathlib import Path

from dotenv import load_dotenv


load_dotenv()


# Schema location and configured database path.
SCHEMA_PATH = Path(__file__).with_name("schema.sql")

DEFAULT_DATABASE_PATH = Path(
    os.getenv("DATABASE_PATH", "data/labpulse.db")
)


# Use an explicit database path or the configured default.
def resolve_database_path(database_path=None):
    if database_path is not None:
        return Path(database_path)

    return DEFAULT_DATABASE_PATH


# Open SQLite with named rows and foreign-key enforcement.
def get_connection(database_path=None):
    path = resolve_database_path(database_path)

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row

    # SQLite foreign-key checks must be enabled for each connection.
    connection.execute("PRAGMA foreign_keys = ON")

    return connection


# Create all tables and indexes from schema.sql.
def init_db(database_path=None):
    path = resolve_database_path(database_path)

    if not SCHEMA_PATH.exists():
        raise FileNotFoundError(
            f"Database schema not found: {SCHEMA_PATH}"
        )

    schema = SCHEMA_PATH.read_text(
        encoding="utf-8"
    )

    connection = get_connection(path)

    try:
        connection.executescript(schema)
        connection.commit()
    finally:
        connection.close()

    return path


# Remove local SQLite files and create a clean database.
def reset_db(database_path=None):
    path = resolve_database_path(database_path)

    # SQLite may create auxiliary write-ahead-log files.
    for candidate in (
        path,
        Path(f"{path}-wal"),
        Path(f"{path}-shm"),
    ):
        candidate.unlink(missing_ok=True)

    return init_db(path)


# Initialize the configured database when this file is run directly.
if __name__ == "__main__":
    created_path = init_db()

    print(
        "Initialized database at: "
        f"{created_path}"
    )
