"""
This file is used for weekly rounds and PulsePass issuance for the project.

This module manages the round lifecycle, 
issues one anonymous token per sender per round, 
and blocks previously frozen sources.
"""

import hashlib
import secrets
import sqlite3
from flask import (
    current_app,
    g,
    jsonify,
    request,
)

from audit import write_audit_event
from auth import login_required, require_role
from db import get_connection
from crypto_utils import encrypt_small_payload


# Allowed round transitions and their audit actions.
ROUND_TRANSITIONS = {
    "OPEN": "LOCKED",
    "LOCKED": "RELEASED",
    "RELEASED": "ARCHIVED",
}

ROUND_AUDIT_ACTIONS = {
    "LOCKED": "ROUND_LOCKED",
    "RELEASED": "ROUND_RELEASED",
    "ARCHIVED": "ROUND_ARCHIVED",
}


# Shared request, response, and audit helpers.
def json_error(
    message,
    status_code,
):
    response = jsonify({"error": message})
    response.status_code = status_code
    return response


def json_object():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return None

    return data


def round_payload(row):
    return {
        "round_id": int(row["id"]),
        "label": str(row["label"]),
        "status": str(row["status"]),
    }


def audit_token_denial(round_id):
    write_audit_event(
        "TOKEN_REQUEST_DENIED",
        "Sender",
        "DENIED",
        round_id=round_id,
        log_path=current_app.config[
            "AUDIT_LOG_PATH"
        ],
    )


# Register round lifecycle and PulsePass routes.
def register_round_and_token_routes(app):

    # Create one open weekly round.
    @app.post("/admin/rounds")
    @require_role("Admin")
    def create_round():
        data = json_object()

        if data is None:
            return json_error(
                "A JSON request body is required.",
                400,
            )

        label = data.get("label")

        if (
            not isinstance(label, str)
            or not label.strip()
            or len(label.strip()) > 80
            or "\n" in label
            or "\r" in label
        ):
            return json_error(
                "A valid round label is required.",
                400,
            )

        label = label.strip()

        connection = get_connection(
            current_app.config["DATABASE_PATH"]
        )

        try:
            # Start the write transaction before checking for another round.
            connection.execute("BEGIN IMMEDIATE")

            existing_round = connection.execute(
                """
                SELECT id
                FROM rounds
                WHERE status != 'ARCHIVED'
                LIMIT 1
                """
            ).fetchone()

            if existing_round is not None:
                connection.rollback()

                return json_error(
                    "A non-archived round already exists.",
                    409,
                )

            cursor = connection.execute(
                """
                INSERT INTO rounds (
                    label,
                    status
                )
                VALUES (?, 'OPEN')
                """,
                (label,),
            )

            round_id = int(cursor.lastrowid)

            row = connection.execute(
                """
                SELECT id, label, status
                FROM rounds
                WHERE id = ?
                """,
                (round_id,),
            ).fetchone()

            connection.commit()

        except sqlite3.IntegrityError:
            connection.rollback()

            return json_error(
                "The round could not be created.",
                409,
            )

        finally:
            connection.close()

        assert row is not None

        write_audit_event(
            "ROUND_OPENED",
            "Admin",
            "SUCCESS",
            round_id=round_id,
            log_path=current_app.config[
                "AUDIT_LOG_PATH"
            ],
        )

        return {
            "round": round_payload(row)
        }, 201

    # Return the current non-archived round.
    @app.get("/rounds/current")
    @login_required
    def get_current_round():
        connection = get_connection(
            current_app.config["DATABASE_PATH"]
        )

        try:
            row = connection.execute(
                """
                SELECT id, label, status
                FROM rounds
                WHERE status != 'ARCHIVED'
                ORDER BY id DESC
                LIMIT 1
                """
            ).fetchone()

        finally:
            connection.close()

        if row is None:
            return json_error(
                "No current round exists.",
                404,
            )

        return {
            "round": round_payload(row)
        }, 200

    # Move a round through its required lifecycle order.
    @app.patch(
        "/admin/rounds/<int:round_id>/status"
    )
    @require_role("Admin")
    def change_round_status(round_id):
        data = json_object()

        if data is None:
            return json_error(
                "A JSON request body is required.",
                400,
            )

        new_status = data.get("status")

        if new_status not in {
            "LOCKED",
            "RELEASED",
            "ARCHIVED",
        }:
            return json_error(
                "status must be LOCKED, RELEASED, or ARCHIVED.",
                400,
            )

        connection = get_connection(
            current_app.config["DATABASE_PATH"]
        )

        try:
            connection.execute("BEGIN IMMEDIATE")

            current_row = connection.execute(
                """
                SELECT id, label, status
                FROM rounds
                WHERE id = ?
                """,
                (round_id,),
            ).fetchone()

            if current_row is None:
                connection.rollback()

                return json_error(
                    "Round not found.",
                    404,
                )

            current_status = str(
                current_row["status"]
            )

            expected_status = ROUND_TRANSITIONS.get(
                current_status
            )

            if new_status != expected_status:
                connection.rollback()

                return json_error(
                    "Invalid round status transition.",
                    409,
                )

            if new_status == "LOCKED":
                # Only unused valid tokens expire.
                connection.execute(
                    """
                    UPDATE tokens
                    SET status = 'EXPIRED'
                    WHERE round_id = ?
                      AND status = 'VALID'
                    """,
                    (round_id,),
                )

            if new_status == "RELEASED":
                connection.execute(
                    """
                    UPDATE rounds
                    SET
                        status = ?,
                        released_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                    """,
                    (
                        new_status,
                        round_id,
                    ),
                )

                # Release all queued envelopes in one weekly batch.
                connection.execute(
                    """
                    UPDATE messages
                    SET
                        status = 'RELEASED',
                        released_at = CURRENT_TIMESTAMP
                    WHERE round_id = ?
                    AND status = 'QUEUED'
                    """,
                    (round_id,),
                )

            else:
                connection.execute(
                    """
                    UPDATE rounds
                    SET status = ?
                    WHERE id = ?
                    """,
                    (
                        new_status,
                        round_id,
                    ),
                )

            updated_row = connection.execute(
                """
                SELECT id, label, status
                FROM rounds
                WHERE id = ?
                """,
                (round_id,),
            ).fetchone()

            connection.commit()

        finally:
            connection.close()

        assert updated_row is not None

        write_audit_event(
            ROUND_AUDIT_ACTIONS[new_status],
            "Admin",
            "SUCCESS",
            round_id=round_id,
            log_path=current_app.config[
                "AUDIT_LOG_PATH"
            ],
        )

        if new_status == "RELEASED":
            write_audit_event(
                "MESSAGE_RELEASED",
                "Admin",
                "SUCCESS",
                round_id=round_id,
                log_path=current_app.config[
                    "AUDIT_LOG_PATH"
                ],
            )

        return {
            "round": round_payload(updated_row)
        }, 200

    # Issue one anonymous PulsePass to an eligible Sender.
    @app.post("/sender/tokens")
    @require_role("Sender")
    def request_pulsepass():
        connection = get_connection(
            current_app.config["DATABASE_PATH"]
        )

        round_id = None

        try:
            # Start the write transaction before eligibility and duplicate checks.
            connection.execute("BEGIN IMMEDIATE")

            round_row = connection.execute(
                """
                SELECT id
                FROM rounds
                WHERE status = 'OPEN'
                ORDER BY id DESC
                LIMIT 1
                """
            ).fetchone()

            if round_row is None:
                connection.rollback()
                audit_token_denial(None)

                return json_error(
                    "No round is open for token issuance.",
                    409,
                )

            round_id = int(round_row["id"])

            person_row = connection.execute(
                """
                SELECT abuse_handle_hash
                FROM people
                WHERE id = ?
                """,
                (g.account["person_id"],),
            ).fetchone()

            if person_row is None:
                connection.rollback()
                audit_token_denial(round_id)

                return json_error(
                    "The account is not eligible for a PulsePass.",
                    403,
                )

            abuse_handle_hash = str(
                person_row["abuse_handle_hash"]
            )

            frozen = connection.execute(
                """
                SELECT 1
                FROM frozen_handles
                WHERE abuse_handle_hash = ?
                """,
                (abuse_handle_hash,),
            ).fetchone()

            if frozen is not None:
                connection.rollback()
                audit_token_denial(round_id)

                return json_error(
                    "This source is not eligible for a PulsePass.",
                    403,
                )

            moderator_row = connection.execute(
                """
                SELECT public_key
                FROM accounts
                WHERE role = 'Moderator'
                AND active = 1
                AND public_key IS NOT NULL
                ORDER BY id
                LIMIT 1
                """
            ).fetchone()

            if moderator_row is None:
                connection.rollback()
                audit_token_denial(round_id)

                return json_error(
                    "Moderator key is not configured.",
                    409,
                )

            try:
                # Randomized encryption prevents direct handle comparison.
                sealed_abuse_handle = encrypt_small_payload(
                    abuse_handle_hash.encode("ascii"),
                    str(moderator_row["public_key"]),
                )
            except ValueError:
                connection.rollback()
                audit_token_denial(round_id)

                return json_error(
                    "Moderator key is invalid.",
                    409,
                )

            prior_issuance = connection.execute(
                """
                SELECT 1
                FROM token_issuance
                WHERE sender_account_id = ?
                  AND round_id = ?
                """,
                (
                    g.account["account_id"],
                    round_id,
                ),
            ).fetchone()

            if prior_issuance is not None:
                connection.rollback()
                audit_token_denial(round_id)

                return json_error(
                    "A PulsePass has already been issued "
                    "for this round.",
                    409,
                )

            # Generate a cryptographically secure bearer token.
            raw_token = secrets.token_urlsafe(32)

            # Store only a SHA-256 digest, never the raw PulsePass.
            token_hash = hashlib.sha256(
                raw_token.encode("utf-8")
            ).hexdigest()

            connection.execute(
                """
                INSERT INTO token_issuance (
                    sender_account_id,
                    round_id
                )
                VALUES (?, ?)
                """,
                (
                    g.account["account_id"],
                    round_id,
                ),
            )

            connection.execute(
                """
                INSERT INTO tokens (
                    token_hash,
                    round_id,
                    status,
                    sealed_abuse_handle
                )
                VALUES (?, ?, 'VALID', ?)
                """,
                (
                    token_hash,
                    round_id,
                    sealed_abuse_handle,
                ),
            )

            connection.commit()

        except sqlite3.IntegrityError:
            connection.rollback()
            audit_token_denial(round_id)

            return json_error(
                "A PulsePass has already been issued "
                "for this round.",
                409,
            )

        finally:
            connection.close()

        write_audit_event(
            "TOKEN_ISSUED",
            "Sender",
            "SUCCESS",
            round_id=round_id,
            log_path=current_app.config[
                "AUDIT_LOG_PATH"
            ],
        )

        return {
            "round_id": round_id,
            "pulsepass": raw_token,
            "message": (
                "This PulsePass is displayed only once."
            ),
        }, 201