"""
This is file is the moderation routes for the project.

This module accepts encrypted flags, 
restricts case review to the moderator, 
and freezes anonymous sources after confirmed violations.
"""

import json
import re
import secrets
import sqlite3
from flask import (
    current_app,
    g,
    jsonify,
    request,
)

from audit import write_audit_event
from auth import require_role
from crypto_utils import decode_bytes, encode_bytes
from db import get_connection


# Allowed categories, encrypted packet fields, and size limits.
FLAG_CATEGORIES = frozenset(
    {
        "Harassment",
        "Discrimination",
        "Identity-Revealing",
        "Spam",
        "Other",
    }
)

HANDLE_PATTERN = re.compile(
    r"^[0-9a-f]{64}$"
)

PACKET_FIELDS = frozenset(
    {
        "encrypted_aes_key",
        "ciphertext",
        "nonce",
    }
)

MAX_ENCRYPTED_KEY_BYTES = 1024
MAX_CIPHERTEXT_BYTES = 8192
AES_GCM_NONCE_SIZE = 12


# Shared request validation and response helpers.
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


def validated_packet(data):
    packet = data.get("encrypted_packet")

    if (
        not isinstance(packet, dict)
        or set(packet) != PACKET_FIELDS
    ):
        raise ValueError(
            "encrypted_packet must contain encrypted_aes_key, "
            "ciphertext, and nonce"
        )

    normalized = {}

    for field_name in PACKET_FIELDS:
        value = packet.get(field_name)

        if (
            not isinstance(value, str)
            or not value.strip()
        ):
            raise ValueError(
                "encrypted moderation fields must be "
                "nonempty text"
            )

        normalized[field_name] = value.strip()

    encrypted_aes_key = decode_bytes(
        normalized["encrypted_aes_key"]
    )
    ciphertext = decode_bytes(
        normalized["ciphertext"]
    )
    nonce = decode_bytes(
        normalized["nonce"]
    )

    if (
        not encrypted_aes_key
        or len(encrypted_aes_key)
        > MAX_ENCRYPTED_KEY_BYTES
    ):
        raise ValueError(
            "invalid encrypted AES key"
        )

    if (
        not ciphertext
        or len(ciphertext)
        > MAX_CIPHERTEXT_BYTES
    ):
        raise ValueError(
            "invalid encrypted moderation packet"
        )

    if len(nonce) != AES_GCM_NONCE_SIZE:
        raise ValueError(
            "AES-GCM nonce must be 12 bytes"
        )

    packet_bytes = json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    return normalized, packet_bytes


# Register Recipient flagging and Moderator review routes.
def register_moderation_routes(app):

    # Return the active Moderator public key to Recipients.
    @app.get("/directory/moderator-key")
    @require_role("Recipient")
    def moderator_key():
        with get_connection(
            current_app.config["DATABASE_PATH"]
        ) as connection:
            row = connection.execute(
                """
                SELECT
                    public_key,
                    public_key_fingerprint
                FROM accounts
                WHERE role = 'Moderator'
                  AND active = 1
                  AND public_key IS NOT NULL
                ORDER BY id
                LIMIT 1
                """
            ).fetchone()

        if row is None:
            return json_error(
                "Moderator key is not configured.",
                409,
            )

        return {
            "public_key": str(row["public_key"]),
            "public_key_fingerprint": str(
                row["public_key_fingerprint"]
            ),
        }, 200

    # Store one encrypted flag for a released message owned by the Recipient.
    @app.post(
        "/recipient/messages/<message_id>/flag"
    )
    @require_role("Recipient")
    def flag_message(message_id):
        data = json_object()

        if data is None:
            return json_error(
                "A JSON request body is required.",
                400,
            )

        category = data.get("category")

        if (
            not isinstance(category, str)
            or category not in FLAG_CATEGORIES
        ):
            return json_error(
                "category must be one of the approved values.",
                400,
            )

        try:
            _, packet_bytes = validated_packet(data)
        except ValueError as error:
            return json_error(
                str(error),
                400,
            )

        connection = get_connection(
            current_app.config["DATABASE_PATH"]
        )

        case_id = secrets.token_urlsafe(24)
        round_id = None
        flagged_count = 0

        try:
            # Keep case creation, message status, and flag counting atomic.
            connection.execute(
                "BEGIN IMMEDIATE"
            )

            account_row = connection.execute(
                """
                SELECT inbox_tag
                FROM accounts
                WHERE id = ?
                  AND role = 'Recipient'
                  AND active = 1
                """,
                (
                    g.account["account_id"],
                ),
            ).fetchone()

            if (
                account_row is None
                or account_row["inbox_tag"] is None
            ):
                connection.rollback()

                return json_error(
                    "Recipient inbox is unavailable.",
                    404,
                )

            message_row = connection.execute(
                """
                SELECT
                    messages.round_id,
                    messages.status,
                    tokens.sealed_abuse_handle
                FROM messages
                JOIN tokens
                  ON tokens.token_hash =
                     messages.token_hash
                WHERE messages.message_id = ?
                  AND messages.recipient_inbox_tag = ?
                """,
                (
                    message_id,
                    account_row["inbox_tag"],
                ),
            ).fetchone()

            if message_row is None:
                connection.rollback()

                return json_error(
                    "Message not found.",
                    404,
                )

            if message_row["status"] == "FLAGGED":
                connection.rollback()

                return json_error(
                    "This message has already been flagged.",
                    409,
                )

            if message_row["status"] != "RELEASED":
                connection.rollback()

                return json_error(
                    "Only released messages can be flagged.",
                    409,
                )

            sealed_handle = message_row[
                "sealed_abuse_handle"
            ]

            if sealed_handle is None:
                connection.rollback()

                return json_error(
                    "This message has no sealed source handle.",
                    409,
                )

            round_id = int(
                message_row["round_id"]
            )

            connection.execute(
                """
                INSERT INTO moderation_cases (
                    case_id,
                    message_id,
                    category,
                    encrypted_packet,
                    sealed_abuse_handle,
                    status
                )
                VALUES (?, ?, ?, ?, ?, 'OPEN')
                """,
                (
                    case_id,
                    message_id,
                    category,
                    packet_bytes,
                    bytes(sealed_handle),
                ),
            )

            connection.execute(
                """
                UPDATE messages
                SET status = 'FLAGGED'
                WHERE message_id = ?
                  AND status = 'RELEASED'
                """,
                (message_id,),
            )

            flagged_count = int(
                connection.execute(
                    """
                    SELECT COUNT(*)
                    FROM moderation_cases
                    JOIN messages
                      ON messages.message_id =
                         moderation_cases.message_id
                    WHERE messages.round_id = ?
                    """,
                    (round_id,),
                ).fetchone()[0]
            )

            connection.commit()

        except sqlite3.IntegrityError:
            connection.rollback()

            return json_error(
                "This message has already been flagged.",
                409,
            )

        finally:
            connection.close()

        assert round_id is not None

        write_audit_event(
            "MESSAGE_FLAGGED",
            "Recipient",
            "SUCCESS",
            round_id=round_id,
            case_id=case_id,
            log_path=current_app.config[
                "AUDIT_LOG_PATH"
            ],
        )

        # Trigger one alert when a round reaches three flags.
        if flagged_count == 3:
            write_audit_event(
                "ALERT_TRIGGERED",
                "Moderator",
                "SUCCESS",
                round_id=round_id,
                log_path=current_app.config[
                    "AUDIT_LOG_PATH"
                ],
            )

        return {
            "case_id": case_id,
            "round_id": round_id,
            "status": "OPEN",
        }, 201

    # Return encrypted cases and round-level alerts to the Moderator.
    @app.get("/moderator/cases")
    @require_role("Moderator")
    def moderator_cases():
        with get_connection(
            current_app.config["DATABASE_PATH"]
        ) as connection:
            rows = connection.execute(
                """
                SELECT
                    moderation_cases.case_id,
                    moderation_cases.message_id,
                    moderation_cases.category,
                    moderation_cases.encrypted_packet,
                    moderation_cases.sealed_abuse_handle,
                    moderation_cases.status,
                    moderation_cases.created_at,
                    messages.round_id
                FROM moderation_cases
                JOIN messages
                  ON messages.message_id =
                     moderation_cases.message_id
                ORDER BY
                    moderation_cases.created_at,
                    moderation_cases.case_id
                """
            ).fetchall()

            alert_rows = connection.execute(
                """
                SELECT
                    messages.round_id,
                    COUNT(*) AS flagged_count
                FROM moderation_cases
                JOIN messages
                  ON messages.message_id =
                     moderation_cases.message_id
                GROUP BY messages.round_id
                HAVING COUNT(*) >= 3
                ORDER BY messages.round_id
                """
            ).fetchall()

        cases = []

        for row in rows:
            packet = json.loads(
                bytes(
                    row["encrypted_packet"]
                ).decode("utf-8")
            )

            cases.append(
                {
                    "case_id": row["case_id"],
                    "message_id": row["message_id"],
                    "round_id": row["round_id"],
                    "category": row["category"],
                    "encrypted_packet": packet,
                    "sealed_abuse_handle": (
                        encode_bytes(
                            bytes(
                                row[
                                    "sealed_abuse_handle"
                                ]
                            )
                        )
                    ),
                    "status": row["status"],
                    "created_at": row["created_at"],
                }
            )

        write_audit_event(
            "FLAGGED_QUEUE_ACCESSED",
            "Moderator",
            "SUCCESS",
            log_path=current_app.config[
                "AUDIT_LOG_PATH"
            ],
        )

        return {
            "cases": cases,
            "alerts": [
                {
                    "round_id": int(
                        row["round_id"]
                    ),
                    "flagged_count": int(
                        row["flagged_count"]
                    ),
                }
                for row in alert_rows
            ],
        }, 200

    # Dismiss a case or freeze its anonymous source.
    @app.patch(
        "/moderator/cases/<case_id>"
    )
    @require_role("Moderator")
    def decide_case(case_id):
        data = json_object()

        if data is None:
            return json_error(
                "A JSON request body is required.",
                400,
            )

        decision = data.get("decision")

        if decision not in {
            "DISMISS",
            "CONFIRM_VIOLATION",
        }:
            return json_error(
                "decision must be DISMISS "
                "or CONFIRM_VIOLATION.",
                400,
            )

        abuse_handle_hash = None

        if decision == "CONFIRM_VIOLATION":
            candidate = data.get(
                "abuse_handle_hash"
            )

            if (
                not isinstance(candidate, str)
                or HANDLE_PATTERN.fullmatch(
                    candidate
                ) is None
            ):
                return json_error(
                    "A valid anonymous abuse handle "
                    "is required.",
                    400,
                )

            abuse_handle_hash = candidate

        connection = get_connection(
            current_app.config["DATABASE_PATH"]
        )

        round_id = None
        new_status = "DISMISSED"

        try:
            # Keep case resolution and source freezing atomic.
            connection.execute(
                "BEGIN IMMEDIATE"
            )

            row = connection.execute(
                """
                SELECT
                    moderation_cases.status,
                    messages.round_id
                FROM moderation_cases
                JOIN messages
                  ON messages.message_id =
                     moderation_cases.message_id
                WHERE moderation_cases.case_id = ?
                """,
                (case_id,),
            ).fetchone()

            if row is None:
                connection.rollback()

                return json_error(
                    "Case not found.",
                    404,
                )

            if row["status"] != "OPEN":
                connection.rollback()

                return json_error(
                    "This case has already been resolved.",
                    409,
                )

            round_id = int(row["round_id"])

            if decision == "CONFIRM_VIOLATION":
                assert abuse_handle_hash is not None

                known_handle = connection.execute(
                    """
                    SELECT 1
                    FROM people
                    WHERE abuse_handle_hash = ?
                    """,
                    (abuse_handle_hash,),
                ).fetchone()

                if known_handle is None:
                    connection.rollback()

                    return json_error(
                        "The anonymous abuse handle "
                        "is invalid.",
                        400,
                    )

                connection.execute(
                    """
                    INSERT OR IGNORE INTO frozen_handles (
                        abuse_handle_hash,
                        reason
                    )
                    VALUES (
                        ?,
                        'Confirmed policy violation'
                    )
                    """,
                    (abuse_handle_hash,),
                )

                new_status = (
                    "VIOLATION_CONFIRMED"
                )

            connection.execute(
                """
                UPDATE moderation_cases
                SET
                    status = ?,
                    resolved_at = CURRENT_TIMESTAMP
                WHERE case_id = ?
                """,
                (
                    new_status,
                    case_id,
                ),
            )

            connection.commit()

        finally:
            connection.close()

        assert round_id is not None

        if decision == "DISMISS":
            write_audit_event(
                "CASE_DISMISSED",
                "Moderator",
                "SUCCESS",
                round_id=round_id,
                case_id=case_id,
                log_path=current_app.config[
                    "AUDIT_LOG_PATH"
                ],
            )

        else:
            write_audit_event(
                "VIOLATION_CONFIRMED",
                "Moderator",
                "SUCCESS",
                round_id=round_id,
                case_id=case_id,
                log_path=current_app.config[
                    "AUDIT_LOG_PATH"
                ],
            )

            write_audit_event(
                "HANDLE_FROZEN",
                "Moderator",
                "SUCCESS",
                round_id=round_id,
                case_id=case_id,
                log_path=current_app.config[
                    "AUDIT_LOG_PATH"
                ],
            )

        return {
            "case_id": case_id,
            "status": new_status,
        }, 200