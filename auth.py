"""
This file is for authentication and role-based access control for the LabPulse.

This module loads the active account for each request and provides
reusable checks for login and exact role permissions.
"""

from functools import wraps
from flask import current_app, g, jsonify, session
from audit import write_audit_event
from db import get_connection


# Session key and allowed account roles.
SESSION_ACCOUNT_KEY = "account_id"

ALLOWED_ROLES = frozenset(
    {
        "Sender",
        "Recipient",
        "Moderator",
        "Admin",
    }
)


# Authentication and authorization response helpers.
def unauthorized_response(
    message="Authentication required.",
):
    response = jsonify({"error": message})
    response.status_code = 401
    response.headers["WWW-Authenticate"] = (
        'Session realm="LabPulse"'
    )
    return response


def forbidden_response(
    message=(
        "This account is not permitted to perform that action."
    ),
):
    response = jsonify({"error": message})
    response.status_code = 403
    return response


# Load the active account from the signed session before each request.
def load_current_account():
    account_id = session.get(SESSION_ACCOUNT_KEY)

    # Keep only one account ID in the session. 
    # Any client-supplied role or identity fields are discarded.
    unexpected_keys = set(session.keys()) - {
        SESSION_ACCOUNT_KEY
    }

    if unexpected_keys:
        session.clear()

        if (
            isinstance(account_id, int)
            and not isinstance(account_id, bool)
        ):
            session[SESSION_ACCOUNT_KEY] = account_id

    if (
        not isinstance(account_id, int)
        or isinstance(account_id, bool)
    ):
        session.clear()
        g.account = None
        return

    with get_connection(
        current_app.config["DATABASE_PATH"]
    ) as connection:
        row = connection.execute(
            """
            SELECT
                accounts.id AS account_id,
                accounts.person_id,
                accounts.username,
                accounts.role,
                accounts.active,
                people.display_name,
                people.lab_position
            FROM accounts
            JOIN people
              ON people.id = accounts.person_id
            WHERE accounts.id = ?
              AND accounts.active = 1
            """,
            (account_id,),
        ).fetchone()

    if row is None:
        session.clear()
        g.account = None
        return

    # Convert the row before its database connection closes.
    g.account = dict(row)


# Reusable decorators for authentication and exact role checks.
def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if getattr(g, "account", None) is None:
            return unauthorized_response()

        return view(*args, **kwargs)

    return wrapped_view


def require_role(required_role):
    if required_role not in ALLOWED_ROLES:
        raise ValueError(
            f"Unsupported role: {required_role}"
        )

    def decorator(view):
        @wraps(view)
        def wrapped_view(*args, **kwargs):
            account = getattr(g, "account", None)

            if account is None:
                return unauthorized_response()

            if account["role"] != required_role:
                # Record only the active role, not an account ID or username.
                write_audit_event(
                    "ACCESS_DENIED",
                    account["role"],
                    "DENIED",
                    log_path=current_app.config[
                        "AUDIT_LOG_PATH"
                    ],
                )

                return forbidden_response()

            return view(*args, **kwargs)

        return wrapped_view

    return decorator


# Register account loading for every Flask request.
def init_auth(app):
    app.before_request(load_current_account)
