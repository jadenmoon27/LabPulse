"""
This file is used for creating fictional demonstration accounts for local testing.

This script resets the local database, 
creates role-isolated accounts,
and uses random inbox tags and anonymous source handles.
"""

import hashlib
import secrets

from werkzeug.security import generate_password_hash

from audit import reset_audit_log
from db import get_connection, init_db, reset_db


# Shared local demo password and fictional account assignments.
DEMO_PASSWORD = "Password123!"

DEMO_PEOPLE = (
    {
        "display_name": "Dr. Andrew Campbell",
        "lab_position": "PI",
        "accounts": (
            ("pi.admin", "Admin"),
            ("pi.sender", "Sender"),
            ("pi.recipient", "Recipient"),
        ),
    },
    {
        "display_name": "Dr. Yvonne Wu",
        "lab_position": "Postdoc",
        "accounts": (
            ("postdoc.moderator", "Moderator"),
            ("postdoc.sender", "Sender"),
            ("postdoc.recipient", "Recipient"),
        ),
    },
    {
        "display_name": "Leo Chen",
        "lab_position": "PhD Student",
        "accounts": (
            ("phd.sender", "Sender"),
            ("phd.recipient", "Recipient"),
        ),
    },
    {
        "display_name": "Jaden Moon",
        "lab_position": "Undergraduate",
        "accounts": (
            ("undergrad.sender", "Sender"),
            ("undergrad.recipient", "Recipient"),
        ),
    },
)


# Create a clean fictional roster with one role per account.
def seed_demo_data(
    database_path=None,
    *,
    reset_database=True,
):
    if reset_database:
        path = reset_db(database_path)
    else:
        path = init_db(database_path)

    account_ids = {}

    with get_connection(path) as connection:
        for person in DEMO_PEOPLE:
            # Generate one stable anonymous handle for this database.
            abuse_handle_hash = hashlib.sha256(
                secrets.token_bytes(32)
            ).hexdigest()

            person_cursor = connection.execute(
                """
                INSERT INTO people (
                    display_name,
                    lab_position,
                    abuse_handle_hash
                )
                VALUES (?, ?, ?)
                """,
                (
                    person["display_name"],
                    person["lab_position"],
                    abuse_handle_hash,
                ),
            )

            person_id = int(
                person_cursor.lastrowid
            )

            for username, role in person["accounts"]:
                # Recipient accounts use random pseudonymous inbox tags.
                inbox_tag = (
                    secrets.token_urlsafe(32)
                    if role == "Recipient"
                    else None
                )

                account_cursor = connection.execute(
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
                        generate_password_hash(
                            DEMO_PASSWORD
                        ),
                        role,
                        inbox_tag,
                    ),
                )

                account_ids[username] = int(
                    account_cursor.lastrowid
                )

        connection.commit()

    return account_ids


# Reset local audit state and print the created demo accounts.
if __name__ == "__main__":
    reset_audit_log()
    created_accounts = seed_demo_data()

    print("Created local demo accounts:")

    for username in created_accounts:
        print(f"  {username}")

    print()
    print(f"Shared demo password: {DEMO_PASSWORD}")
    print(
        "Do not use these fictional credentials "
        "outside the local demonstration."
    )
