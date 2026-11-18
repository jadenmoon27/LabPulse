"""
This file is used for secure-message routes for project

This module registers public keys, 
stores encrypted message envelopes,
and returns released envelopes to the intended Recipient.
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
from crypto_utils import (
    AES_GCM_NONCE_SIZE,
    decode_bytes,
    encode_bytes,
    load_rsa_public_key,
    public_key_fingerprint,
    serialize_public_key,
)
from db import get_connection


# Request-size limits for public keys, tokens, and encrypted fields.
MAX_PUBLIC_KEY_TEXT = 10000
MAX_PULSEPASS_TEXT = 512
MAX_INBOX_TAG_TEXT = 256
MAX_ENCRYPTED_KEY_BYTES = 1024
MAX_CIPHERTEXT_BYTES = 4096


# Shared request validation and response helpers.
def json_error(message, status_code):
    response = jsonify({"error": message})
    response.status_code = status_code
    return response


def json_object():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return None

    return data


def required_text(
    data,
    field_name,
    maximum_length,
):
    value = data.get(field_name)

    if not isinstance(value, str):
        return None

    value = value.strip()

    if not value or len(value) > maximum_length:
        return None

    return value


# Register public-key and encrypted-message routes.
def register_messaging_routes(app):

    # Register one initial public key for the active account.
    @app.put("/keys/me")
    @login_required
    def register_public_key():
        data = json_object()

        if data is None:
            return json_error(
                "A JSON request body is required.",
                400,
            )

        public_key_text = required_text(
            data,
            "public_key",
            MAX_PUBLIC_KEY_TEXT,
        )

        if public_key_text is None:
            return json_error(
                "A public_key value is required.",
                400,
            )

        try:
            public_key = load_rsa_public_key(
                public_key_text
            )
        except ValueError as error:
            return json_error(
                str(error),
                400,
            )

        canonical_public_key = serialize_public_key(
            public_key
        )
        fingerprint = public_key_fingerprint(
            public_key
        )

        with get_connection(
            current_app.config["DATABASE_PATH"]
        ) as connection:
            cursor = connection.execute(
                """
                UPDATE accounts
                SET
                    public_key = ?,
                    public_key_fingerprint = ?
                WHERE id = ?
                  AND public_key IS NULL
                """,
                (
                    canonical_public_key,
                    fingerprint,
                    g.account["account_id"],
                ),
            )

            if cursor.rowcount != 1:
                connection.rollback()

                return json_error(
                    "A public key is already registered "
                    "for this account.",
                    409,
                )

            connection.commit()

        write_audit_event(
            "PUBLIC_KEY_REGISTERED",
            g.account["role"],
            "SUCCESS",
            log_path=current_app.config[
                "AUDIT_LOG_PATH"
            ],
        )

        return {
            "public_key_fingerprint": fingerprint
        }, 200

    # Return only the public Recipient data needed for encryption.
    @app.get("/directory/recipients")
    @require_role("Sender")
    def recipient_directory():
        with get_connection(
            current_app.config["DATABASE_PATH"]
        ) as connection:
            rows = connection.execute(
                """
                SELECT
                    people.display_name,
                    accounts.inbox_tag,
                    accounts.public_key,
                    accounts.public_key_fingerprint
                FROM accounts
                JOIN people
                  ON people.id = accounts.person_id
                WHERE accounts.role = 'Recipient'
                  AND accounts.active = 1
                  AND accounts.public_key IS NOT NULL
                  AND accounts.inbox_tag IS NOT NULL
                ORDER BY people.display_name
                """
            ).fetchall()

        return {
            "recipients": [
                {
                    "display_name": row[
                        "display_name"
                    ],
                    "inbox_tag": row[
                        "inbox_tag"
                    ],
                    "public_key": row[
                        "public_key"
                    ],
                    "public_key_fingerprint": row[
                        "public_key_fingerprint"
                    ],
                }
                for row in rows
            ]
        }, 200

    # Consume one valid PulsePass and store one encrypted envelope.
    @app.post("/sender/messages")
    @require_role("Sender")
    def submit_message():
        data = json_object()

        if data is None:
            return json_error(
                "A JSON request body is required.",
                400,
            )

        pulsepass = required_text(
            data,
            "pulsepass",
            MAX_PULSEPASS_TEXT,
        )
        recipient_inbox_tag = required_text(
            data,
            "recipient_inbox_tag",
            MAX_INBOX_TAG_TEXT,
        )
        encrypted_aes_key_text = required_text(
            data,
            "encrypted_aes_key",
            4096,
        )
        ciphertext_text = required_text(
            data,
            "ciphertext",
            10000,
        )
        nonce_text = required_text(
            data,
            "nonce",
            256,
        )

        if None in {
            pulsepass,
            recipient_inbox_tag,
            encrypted_aes_key_text,
            ciphertext_text,
            nonce_text,
        }:
            return json_error(
                "A complete encrypted message envelope "
                "is required.",
                400,
            )

        try:
            encrypted_aes_key = decode_bytes(
                encrypted_aes_key_text
            )
            ciphertext = decode_bytes(
                ciphertext_text
            )
            nonce = decode_bytes(nonce_text)
        except ValueError:
            return json_error(
                "Encrypted fields must contain valid Base64.",
                400,
            )

        if (
            not encrypted_aes_key
            or len(encrypted_aes_key)
            > MAX_ENCRYPTED_KEY_BYTES
        ):
            return json_error(
                "Invalid encrypted AES key.",
                400,
            )

        if (
            not ciphertext
            or len(ciphertext)
            > MAX_CIPHERTEXT_BYTES
        ):
            return json_error(
                "Invalid encrypted message.",
                400,
            )

        if len(nonce) != AES_GCM_NONCE_SIZE:
            return json_error(
                "AES-GCM nonce must be 12 bytes.",
                400,
            )

        token_hash = hashlib.sha256(
            pulsepass.encode("utf-8")
        ).hexdigest()

        message_id = secrets.token_urlsafe(24)

        connection = get_connection(
            current_app.config["DATABASE_PATH"]
        )

        round_id = None

        try:
            # Keep token consumption and message insertion atomic.
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

                return json_error(
                    "No round is open for message submission.",
                    409,
                )

            round_id = int(round_row["id"])

            token_row = connection.execute(
                """
                SELECT token_hash
                FROM tokens
                WHERE token_hash = ?
                  AND round_id = ?
                  AND status = 'VALID'
                """,
                (
                    token_hash,
                    round_id,
                ),
            ).fetchone()

            if token_row is None:
                connection.rollback()

                return json_error(
                    "PulsePass is invalid, expired, or already used.",
                    409,
                )

            recipient_row = connection.execute(
                """
                SELECT 1
                FROM accounts
                WHERE inbox_tag = ?
                  AND role = 'Recipient'
                  AND active = 1
                  AND public_key IS NOT NULL
                """,
                (recipient_inbox_tag,),
            ).fetchone()

            if recipient_row is None:
                connection.rollback()

                return json_error(
                    "Recipient is unavailable.",
                    404,
                )

            token_update = connection.execute(
                """
                UPDATE tokens
                SET
                    status = 'USED',
                    used_at = CURRENT_TIMESTAMP
                WHERE token_hash = ?
                  AND round_id = ?
                  AND status = 'VALID'
                """,
                (
                    token_hash,
                    round_id,
                ),
            )

            if token_update.rowcount != 1:
                connection.rollback()

                return json_error(
                    "PulsePass is invalid, expired, or already used.",
                    409,
                )

            connection.execute(
                """
                INSERT INTO messages (
                    message_id,
                    recipient_inbox_tag,
                    round_id,
                    encrypted_aes_key,
                    ciphertext,
                    nonce,
                    token_hash,
                    status
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, 'QUEUED')
                """,
                (
                    message_id,
                    recipient_inbox_tag,
                    round_id,
                    encrypted_aes_key,
                    ciphertext,
                    nonce,
                    token_hash,
                ),
            )

            connection.commit()

        except sqlite3.IntegrityError:
            connection.rollback()

            return json_error(
                "The encrypted message could not be stored.",
                409,
            )

        finally:
            connection.close()

        write_audit_event(
            "MESSAGE_SENT",
            "Sender",
            "SUCCESS",
            round_id=round_id,
            log_path=current_app.config[
                "AUDIT_LOG_PATH"
            ],
        )

        return {
            "message_id": message_id,
            "round_id": round_id,
            "status": "QUEUED",
        }, 201

    # Return only released envelopes owned by the active Recipient.
    @app.get("/recipient/messages")
    @require_role("Recipient")
    def recipient_messages():
        with get_connection(
            current_app.config["DATABASE_PATH"]
        ) as connection:
            account_row = connection.execute(
                """
                SELECT inbox_tag
                FROM accounts
                WHERE id = ?
                  AND role = 'Recipient'
                  AND active = 1
                """,
                (g.account["account_id"],),
            ).fetchone()

            if (
                account_row is None
                or account_row["inbox_tag"] is None
            ):
                return json_error(
                    "Recipient inbox is unavailable.",
                    404,
                )

            rows = connection.execute(
                """
                SELECT
                    message_id,
                    round_id,
                    encrypted_aes_key,
                    ciphertext,
                    nonce
                FROM messages
                WHERE recipient_inbox_tag = ?
                  AND status = 'RELEASED'
                ORDER BY created_at, message_id
                """,
                (account_row["inbox_tag"],),
            ).fetchall()

        return {
            "messages": [
                {
                    "message_id": row["message_id"],
                    "round_id": row["round_id"],
                    "encrypted_aes_key": encode_bytes(
                        bytes(row["encrypted_aes_key"])
                    ),
                    "ciphertext": encode_bytes(
                        bytes(row["ciphertext"])
                    ),
                    "nonce": encode_bytes(
                        bytes(row["nonce"])
                    ),
                }
                for row in rows
            ]
        }, 200
