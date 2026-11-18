"""Main Flask application for the anonymous messaging project.

This module creates and configures the Flask application, registers
feature routes, and implements authentication and Admin-only account
provisioning.
"""

import hashlib
import os
import re
import secrets
import sqlite3
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask, g, jsonify, request, session
from werkzeug.security import (check_password_hash, generate_password_hash)

from audit import write_audit_event
from auth import (ALLOWED_ROLES, SESSION_ACCOUNT_KEY, init_auth, login_required, require_role, unauthorized_response)
from db import get_connection, init_db
from messaging import register_messaging_routes
from moderation import register_moderation_routes
from rounds_tokens import register_round_and_token_routes


load_dotenv()


# Allowed lab positions and username format.
LAB_POSITIONS = frozenset(
    {
        "PI",
        "Professor",
        "Postdoc",
        "PhD Student",
        "Undergraduate",
    }
)

USERNAME_PATTERN = re.compile( r"^[a-z0-9][a-z0-9._-]{2,49}$" )

# Unknown usernames still perform a password-hash check so their login
# path more closely resembles the wrong-password path.
DUMMY_PASSWORD_HASH = generate_password_hash(
    "LabPulse invalid credential sentinel"
)


# Shared request and response helpers.
# Return a small JSON error response.
def json_error(message, status_code):
    response = jsonify({"error": message})
    response.status_code = status_code
    return response

# Return a JSON object body, or None for invalid input.
def json_object():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return None

    return data


def required_text(data, field_name, *, maximum_length):
    """Read a stripped, nonempty text field."""
    value = data.get(field_name)

    if not isinstance(value, str):
        return None

    value = value.strip()

    if not value or len(value) > maximum_length:
        return None

    return value

# Return a positive integer while rejecting booleans.
def positive_integer(value):
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value <= 0
    ):
        return None

    return value

# Return non-secret account information.
def public_account(account):
    return {
        "username": account["username"],
        "role": account["role"],
        "display_name": account["display_name"],
        "lab_position": account["lab_position"],
    }

# Create and configure the Flask application.
def create_app(
    *,
    database_path=None,
    audit_log_path=None,
    testing=False,
):
    app = Flask(__name__)

    if testing:
        secret_key = "labpulse-test-secret-key"
    else:
        secret_key = os.getenv("FLASK_SECRET_KEY")

    if not secret_key:
        raise RuntimeError(
            "FLASK_SECRET_KEY is missing from .env"
        )

    configured_database_path = Path(
        database_path
        if database_path is not None
        else os.getenv(
            "DATABASE_PATH",
            "data/labpulse.db",
        )
    )

    configured_audit_log_path = Path(
        audit_log_path
        if audit_log_path is not None
        else os.getenv(
            "AUDIT_LOG_PATH",
            "logs/audit_log.jsonl",
        )
    )

    app.config.update(
        SECRET_KEY=secret_key,
        TESTING=testing,
        DATABASE_PATH=configured_database_path,
        AUDIT_LOG_PATH=configured_audit_log_path,
        SESSION_COOKIE_NAME="labpulse_session",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=False,
    )

    # Initialize shared services and attach feature routes.
    init_db(configured_database_path)
    init_auth(app)
    register_round_and_token_routes(app)
    register_messaging_routes(app)
    register_moderation_routes(app)

    # Public service endpoints.
    @app.get("/")
    def home():
        """Return a basic landing response."""
        return {
            "service": "LabPulse",
            "message": "LabPulse server is running.",
            "health_check": "/health",
        }, 200

    @app.get("/health")
    def health():
        """Confirm that the server is running."""
        return {
            "status": "ok",
            "service": "LabPulse",
        }, 200

    # Authentication endpoints.
    @app.post("/auth/login")
    def login():
        """Authenticate one role-specific account."""
        data = json_object()

        if data is None:
            return json_error(
                "A JSON request body is required.",
                400,
            )

        username = required_text(
            data,
            "username",
            maximum_length=50,
        )
        password = data.get("password")

        if (
            username is None
            or not isinstance(password, str)
            or not password
            or len(password) > 256
        ):
            return json_error(
                "username and password are required.",
                400,
            )

        # A new login replaces the previously active account.
        session.clear()

        with get_connection(
            app.config["DATABASE_PATH"]
        ) as connection:
            row = connection.execute(
                """
                SELECT
                    accounts.id AS account_id,
                    accounts.username,
                    accounts.password_hash,
                    accounts.role,
                    accounts.active,
                    people.display_name,
                    people.lab_position
                FROM accounts
                JOIN people
                  ON people.id = accounts.person_id
                WHERE accounts.username = ?
                """,
                (username,),
            ).fetchone()

        stored_hash = (
            row["password_hash"]
            if row is not None
            else DUMMY_PASSWORD_HASH
        )

        password_is_valid = check_password_hash(
            stored_hash,
            password,
        )

        if (
            row is None
            or row["active"] != 1
            or not password_is_valid
        ):
            # Unknown, incorrect, and disabled accounts receive the same response.
            return unauthorized_response(
                "Invalid username or password."
            )

        account = dict(row)

        # Store only the account ID. The role is reloaded from the database for every request.
        session[SESSION_ACCOUNT_KEY] = int(
            account["account_id"]
        )

        write_audit_event(
            "LOGIN_SUCCESS",
            account["role"],
            "SUCCESS",
            log_path=app.config["AUDIT_LOG_PATH"],
        )

        return {
            "account": public_account(account)
        }, 200

    @app.post("/auth/logout")
    @login_required
    def logout():
        """End the current role-specific session."""
        role = g.account["role"]

        session.clear()

        write_audit_event(
            "LOGOUT",
            role,
            "SUCCESS",
            log_path=app.config["AUDIT_LOG_PATH"],
        )

        return {"message": "Logged out."}, 200

    @app.get("/auth/me")
    @login_required
    def current_account():
        """Return the active account's public information."""
        return {
            "account": public_account(g.account)
        }, 200

    # Admin-only person and account provisioning.
    @app.post("/admin/people")
    @require_role("Admin")
    def create_person():
        """Create one fictional lab member record."""
        data = json_object()

        if data is None:
            return json_error(
                "A JSON request body is required.",
                400,
            )

        display_name = required_text(
            data,
            "display_name",
            maximum_length=100,
        )
        lab_position = data.get("lab_position")

        if (
            display_name is None
            or not isinstance(lab_position, str)
            or lab_position not in LAB_POSITIONS
        ):
            return json_error(
                "A valid display_name and lab_position are required.",
                400,
            )

        # Store only a hash of random anonymous-handle material.
        abuse_handle_hash = hashlib.sha256(
            secrets.token_bytes(32)
        ).hexdigest()

        try:
            with get_connection(
                app.config["DATABASE_PATH"]
            ) as connection:
                cursor = connection.execute(
                    """
                    INSERT INTO people (
                        display_name,
                        lab_position,
                        abuse_handle_hash
                    )
                    VALUES (?, ?, ?)
                    """,
                    (
                        display_name,
                        lab_position,
                        abuse_handle_hash,
                    ),
                )

                person_id = int(cursor.lastrowid)
                connection.commit()

        except sqlite3.IntegrityError:
            return json_error(
                "The person record could not be created.",
                409,
            )

        write_audit_event(
            "PERSON_CREATED",
            "Admin",
            "SUCCESS",
            log_path=app.config["AUDIT_LOG_PATH"],
        )

        return {
            "person": {
                "person_id": person_id,
                "display_name": display_name,
                "lab_position": lab_position,
            }
        }, 201

    @app.post("/admin/accounts")
    @require_role("Admin")
    def create_account():
        """Create one account with one assigned role."""
        data = json_object()

        if data is None:
            return json_error(
                "A JSON request body is required.",
                400,
            )

        person_id = positive_integer(
            data.get("person_id")
        )
        username = required_text(
            data,
            "username",
            maximum_length=50,
        )
        password = data.get("password")
        role = data.get("role")

        if (
            person_id is None
            or username is None
            or USERNAME_PATTERN.fullmatch(username) is None
            or not isinstance(password, str)
            or len(password) < 8
            or len(password) > 256
            or not isinstance(role, str)
            or role not in ALLOWED_ROLES
        ):
            return json_error(
                "Valid person_id, username, password, and role "
                "are required.",
                400,
            )

        with get_connection(
            app.config["DATABASE_PATH"]
        ) as connection:
            person_exists = connection.execute(
                """
                SELECT 1
                FROM people
                WHERE id = ?
                """,
                (person_id,),
            ).fetchone()

        if person_exists is None:
            return json_error(
                "The requested person does not exist.",
                404,
            )

        inbox_tag = (
            secrets.token_urlsafe(32)
            if role == "Recipient"
            else None
        )

        password_hash = generate_password_hash(
            password
        )

        try:
            with get_connection(
                app.config["DATABASE_PATH"]
            ) as connection:
                cursor = connection.execute(
                    """
                    INSERT INTO accounts (
                        person_id,
                        username,
                        password_hash,
                        role,
                        inbox_tag
                    )
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        person_id,
                        username,
                        password_hash,
                        role,
                        inbox_tag,
                    ),
                )

                account_id = int(cursor.lastrowid)
                connection.commit()

        except sqlite3.IntegrityError:
            return json_error(
                "The account conflicts with an existing "
                "username or role assignment.",
                409,
            )

        write_audit_event(
            "ACCOUNT_CREATED",
            "Admin",
            "SUCCESS",
            log_path=app.config["AUDIT_LOG_PATH"],
        )

        return {
            "account": {
                "account_id": account_id,
                "person_id": person_id,
                "username": username,
                "role": role,
                "inbox_tag": inbox_tag,
            }
        }, 201

    # List non-secret account metadata for administration.
    @app.get("/admin/accounts")
    @require_role("Admin")
    def list_accounts():
        with get_connection(
            app.config["DATABASE_PATH"]
        ) as connection:
            rows = connection.execute(
                """
                SELECT
                    accounts.id AS account_id,
                    accounts.person_id,
                    accounts.username,
                    accounts.role,
                    accounts.active,
                    accounts.inbox_tag,
                    accounts.public_key_fingerprint,
                    people.display_name,
                    people.lab_position
                FROM accounts
                JOIN people
                  ON people.id = accounts.person_id
                ORDER BY people.display_name, accounts.role
                """
            ).fetchall()

        return {
            "accounts": [
                dict(row)
                for row in rows
            ]
        }, 200

    return app


app = create_app()


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5001,
        debug=True,
    )
