"""
This file is used for message flagging and moderation.

This module encrypts flagged content for the Moderator and lets the
moderator review cases and submit decisions using local private keys.
"""

import argparse
import getpass
import hashlib
import json
import sys
from pathlib import Path

import requests

from crypto_utils import (
    decode_bytes,
    decrypt_message,
    decrypt_small_payload,
    encrypt_message,
    load_private_key,
)


# Default server address and available flag categories.
DEFAULT_SERVER = "http://127.0.0.1:5001"

FLAG_CATEGORIES = (
    "Harassment",
    "Discrimination",
    "Identity-Revealing",
    "Spam",
    "Other",
)


# Shared API, login, key-path, and selection helpers.
def response_json(response):
    try:
        data = response.json()
    except ValueError as error:
        raise RuntimeError(
            "Server returned non-JSON data: "
            f"{response.status_code}"
        ) from error

    if not response.ok:
        message = (
            data.get("error", str(data))
            if isinstance(data, dict)
            else str(data)
        )

        raise RuntimeError(
            f"HTTP {response.status_code}: {message}"
        )

    if not isinstance(data, dict):
        raise RuntimeError(
            "Server returned an unexpected response."
        )

    return data


def login(
    session,
    server,
    username,
    password,
):
    response = session.post(
        f"{server}/auth/login",
        json={
            "username": username,
            "password": password,
        },
        timeout=10,
    )

    response_json(response)


def default_key_path(username):
    return (
        Path("keys")
        / f"{username}_private.pem"
    )


def choose_item(
    items,
    label,
):
    raw_choice = input(
        f"{label} number: "
    ).strip()

    try:
        index = int(raw_choice) - 1

        if (
            index < 0
            or index >= len(items)
        ):
            raise IndexError

        return items[index]

    except (
        ValueError,
        IndexError,
    ) as error:
        raise ValueError(
            f"Invalid {label.lower()} selection."
        ) from error


# Decrypt one released message and submit an encrypted flag packet.
def flag_message(
    server,
    username,
    key_path,
):
    account_password = getpass.getpass(
        "Account password: "
    )
    key_password = getpass.getpass(
        "Local private-key password: "
    )

    session = requests.Session()

    login(
        session,
        server,
        username,
        account_password,
    )

    inbox = response_json(
        session.get(
            f"{server}/recipient/messages",
            timeout=10,
        )
    )

    messages = inbox.get(
        "messages",
        [],
    )

    if not messages:
        raise RuntimeError(
            "No released messages are available to flag."
        )

    print()
    print("Released messages:")

    for index, message in enumerate(
        messages,
        start=1,
    ):
        print(
            f"{index}. "
            f"{message['message_id']} "
            f"(round {message['round_id']})"
        )

    selected = choose_item(
        messages,
        "Message",
    )

    private_key = load_private_key(
        key_path,
        key_password,
    )

    plaintext = decrypt_message(
        selected,
        private_key,
    )

    moderator_key = response_json(
        session.get(
            f"{server}/directory/moderator-key",
            timeout=10,
        )
    )

    print()
    print("Flag categories:")

    for index, category in enumerate(
        FLAG_CATEGORIES,
        start=1,
    ):
        print(f"{index}. {category}")

    raw_category = input(
        "Category number: "
    ).strip()

    try:
        category_index = int(raw_category) - 1

        if (
            category_index < 0
            or category_index >= len(
                FLAG_CATEGORIES
            )
        ):
            raise IndexError

        category = FLAG_CATEGORIES[
            category_index
        ]

    except (
        ValueError,
        IndexError,
    ) as error:
        raise ValueError(
            "Invalid category selection."
        ) from error

    explanation = input(
        "Optional explanation "
        "(max 300 characters): "
    ).strip()

    if len(explanation) > 300:
        raise ValueError(
            "Explanation must be "
            "300 characters or fewer."
        )

    packet = {
        "message_id": selected["message_id"],
        "plaintext": plaintext,
        "message_hash": hashlib.sha256(
            plaintext.encode("utf-8")
        ).hexdigest(),
        "category": category,
        "explanation": explanation,
    }

    packet_text = json.dumps(
        packet,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )

    encrypted_packet = encrypt_message(
        packet_text,
        moderator_key["public_key"],
    )

    result = response_json(
        session.post(
            f"{server}/recipient/messages/"
            f"{selected['message_id']}/flag",
            json={
                "category": category,
                "encrypted_packet": (
                    encrypted_packet
                ),
            },
            timeout=10,
        )
    )

    print(
        "Flag submitted as case: "
        f"{result['case_id']}"
    )


# Decrypt one open case and submit a Moderator decision.
def moderate_cases(
    server,
    username,
    key_path,
):
    account_password = getpass.getpass(
        "Account password: "
    )
    key_password = getpass.getpass(
        "Local private-key password: "
    )

    session = requests.Session()

    login(
        session,
        server,
        username,
        account_password,
    )

    queue = response_json(
        session.get(
            f"{server}/moderator/cases",
            timeout=10,
        )
    )

    open_cases = [
        case
        for case in queue.get(
            "cases",
            [],
        )
        if case["status"] == "OPEN"
    ]

    if not open_cases:
        print(
            "No open moderation cases."
        )
        return

    print()
    print("Open cases:")

    for index, case in enumerate(
        open_cases,
        start=1,
    ):
        print(
            f"{index}. "
            f"{case['case_id']} "
            f"(round {case['round_id']}, "
            f"{case['category']})"
        )

    selected = choose_item(
        open_cases,
        "Case",
    )

    private_key = load_private_key(
        key_path,
        key_password,
    )

    packet_text = decrypt_message(
        selected["encrypted_packet"],
        private_key,
    )

    packet = json.loads(
        packet_text
    )

    handle_bytes = decrypt_small_payload(
        decode_bytes(
            selected[
                "sealed_abuse_handle"
            ]
        ),
        private_key,
    )

    abuse_handle_hash = (
        handle_bytes.decode("ascii")
    )

    print()
    print("Flagged content:")
    print(packet["plaintext"])
    print(
        f"Category: {packet['category']}"
    )
    print(
        "Explanation: "
        f"{packet['explanation'] or '(none)'}"
    )

    print()
    print("1. Dismiss")
    print(
        "2. Confirm violation and freeze source"
    )

    choice = input(
        "Decision number: "
    ).strip()

    if choice == "1":
        request_body = {
            "decision": "DISMISS"
        }

    elif choice == "2":
        request_body = {
            "decision": (
                "CONFIRM_VIOLATION"
            ),
            "abuse_handle_hash": (
                abuse_handle_hash
            ),
        }

    else:
        raise ValueError(
            "Invalid decision selection."
        )

    result = response_json(
        session.patch(
            f"{server}/moderator/cases/"
            f"{selected['case_id']}",
            json=request_body,
            timeout=10,
        )
    )

    print(
        f"Case {result['case_id']} "
        f"is now {result['status']}."
    )


# Define the flag and moderate command-line actions.
def build_parser():
    parser = argparse.ArgumentParser(
        description=(
            "Local moderation client"
        )
    )

    parser.add_argument(
        "--server",
        default=DEFAULT_SERVER,
        help=(
            "Server URL "
            f"(default: {DEFAULT_SERVER})"
        ),
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    flag_parser = subparsers.add_parser(
        "flag",
        help="Flag one released message",
    )
    flag_parser.add_argument(
        "username"
    )
    flag_parser.add_argument(
        "--key-path",
        type=Path,
    )

    moderate_parser = subparsers.add_parser(
        "moderate",
        help="Review one flagged case",
    )
    moderate_parser.add_argument(
        "username"
    )
    moderate_parser.add_argument(
        "--key-path",
        type=Path,
    )

    return parser


# Run the selected moderation command and report readable errors.
def main():
    parser = build_parser()
    args = parser.parse_args()

    key_path = (
        args.key_path
        or default_key_path(
            args.username
        )
    )

    try:
        if args.command == "flag":
            flag_message(
                args.server,
                args.username,
                key_path,
            )

        elif args.command == "moderate":
            moderate_cases(
                args.server,
                args.username,
                key_path,
            )

        else:
            parser.error(
                "Unknown command"
            )

    except (
        FileNotFoundError,
        RuntimeError,
        ValueError,
        requests.RequestException,
    ) as error:
        print(
            f"Error: {error}",
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
