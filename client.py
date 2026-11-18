"""
This file is used by client for secure messaging.

This module creates local key pairs, 
encrypts messages before upload,
and decrypts released messages with local private keys.
"""

import argparse
import getpass
import sys
from pathlib import Path

import requests

from crypto_utils import (
    decrypt_message,
    encrypt_message,
    generate_key_pair,
    load_private_key,
    public_key_fingerprint,
    save_private_key,
    serialize_public_key,
)


# Default local server address.
DEFAULT_SERVER = "http://127.0.0.1:5001"


# Shared API and login helpers.
def response_json(response):
    try:
        data = response.json()
    except ValueError as error:
        raise RuntimeError(
            "Server returned non-JSON data: "
            f"{response.status_code}"
        ) from error

    if not response.ok:
        if isinstance(data, dict):
            message = data.get(
                "error",
                str(data),
            )
        else:
            message = str(data)

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

    return response_json(response)


def default_key_path(username):
    return Path("keys") / f"{username}_private.pem"


# Generate a local key pair and register only the public key.
def setup_key(
    server,
    username,
    key_path,
):
    account_password = getpass.getpass(
        "Account password: "
    )
    key_password = getpass.getpass(
        "New local private-key password: "
    )
    confirmation = getpass.getpass(
        "Confirm local private-key password: "
    )

    if not key_password:
        raise ValueError(
            "The private-key password must not be empty."
        )

    if key_password != confirmation:
        raise ValueError(
            "The private-key passwords do not match."
        )

    session = requests.Session()

    login(
        session,
        server,
        username,
        account_password,
    )

    private_key, public_key = generate_key_pair()

    save_private_key(
        private_key,
        key_path,
        key_password,
    )

    public_key_pem = serialize_public_key(
        public_key
    )

    response = session.put(
        f"{server}/keys/me",
        json={
            "public_key": public_key_pem,
        },
        timeout=10,
    )

    data = response_json(response)

    local_fingerprint = public_key_fingerprint(
        public_key
    )

    if (
        data["public_key_fingerprint"]
        != local_fingerprint
    ):
        raise RuntimeError(
            "Server fingerprint does not match local key."
        )

    print(f"Private key saved to: {key_path}")
    print(
        "Public-key fingerprint: "
        f"{local_fingerprint}"
    )


# Encrypt one message locally and submit the sealed envelope.
def send_message(
    server,
    username,
):
    account_password = getpass.getpass(
        "Account password: "
    )
    pulsepass = getpass.getpass(
        "PulsePass: "
    )

    session = requests.Session()

    login(
        session,
        server,
        username,
        account_password,
    )

    directory_response = session.get(
        f"{server}/directory/recipients",
        timeout=10,
    )

    directory = response_json(
        directory_response
    )

    recipients = directory.get(
        "recipients",
        [],
    )

    if not recipients:
        raise RuntimeError(
            "No Recipients have registered public keys."
        )

    print()
    print("Available Recipients:")

    for index, recipient in enumerate(
        recipients,
        start=1,
    ):
        print(
            f"{index}. "
            f"{recipient['display_name']} "
            f"[{recipient['public_key_fingerprint'][:12]}...]"
        )

    raw_choice = input(
        "Recipient number: "
    ).strip()

    try:
        selected_index = int(raw_choice) - 1

        if (
            selected_index < 0
            or selected_index >= len(recipients)
        ):
            raise IndexError

        recipient = recipients[selected_index]

    except (
        ValueError,
        IndexError,
    ) as error:
        raise ValueError(
            "Invalid Recipient selection."
        ) from error

    compliment = input(
        "Compliment: "
    )

    envelope = encrypt_message(
        compliment,
        recipient["public_key"],
    )

    response = session.post(
        f"{server}/sender/messages",
        json={
            "pulsepass": pulsepass,
            "recipient_inbox_tag": recipient[
                "inbox_tag"
            ],
            **envelope,
        },
        timeout=10,
    )

    data = response_json(response)

    print(
        "Encrypted message queued with ID: "
        f"{data['message_id']}"
    )


# Retrieve released envelopes and decrypt them locally.
def view_inbox(
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

    response = session.get(
        f"{server}/recipient/messages",
        timeout=10,
    )

    data = response_json(response)

    messages = data.get(
        "messages",
        [],
    )

    if not messages:
        print("No released messages.")
        return

    private_key = load_private_key(
        key_path,
        key_password,
    )

    for message in messages:
        plaintext = decrypt_message(
            message,
            private_key,
        )

        print()
        print(
            f"Message {message['message_id']} "
            f"(round {message['round_id']}):"
        )
        print(plaintext)


# Define the setup-key, send, and inbox command-line actions.
def build_parser():
    parser = argparse.ArgumentParser(
        description=(
            "Local secure-messaging client"
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

    setup_parser = subparsers.add_parser(
        "setup-key",
        help=(
            "Generate a local key pair and upload "
            "the public key"
        ),
    )
    setup_parser.add_argument("username")
    setup_parser.add_argument(
        "--key-path",
        type=Path,
    )

    send_parser = subparsers.add_parser(
        "send",
        help="Encrypt and send one compliment",
    )
    send_parser.add_argument("username")

    inbox_parser = subparsers.add_parser(
        "inbox",
        help=(
            "Retrieve and decrypt released messages"
        ),
    )
    inbox_parser.add_argument("username")
    inbox_parser.add_argument(
        "--key-path",
        type=Path,
    )

    return parser


# Run the selected client command and report readable errors.
def main():
    parser = build_parser()
    args = parser.parse_args()

    try:
        if args.command == "setup-key":
            setup_key(
                args.server,
                args.username,
                (
                    args.key_path
                    or default_key_path(
                        args.username
                    )
                ),
            )

        elif args.command == "send":
            send_message(
                args.server,
                args.username,
            )

        elif args.command == "inbox":
            view_inbox(
                args.server,
                args.username,
                (
                    args.key_path
                    or default_key_path(
                        args.username
                    )
                ),
            )

        else:
            parser.error(
                "Unknown command"
            )

    except (
        FileExistsError,
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
