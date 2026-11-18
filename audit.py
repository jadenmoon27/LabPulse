"""
This file is to use for audit logging for the LabPulse project.

This module stores one JSON event per line, 
links entries with SHA-256 hashes, 
validates the log before appending, 
and excludes identity data.
"""



import hashlib
import json
import os
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Lock

from dotenv import load_dotenv


load_dotenv()


# Audit configuration and allowed event values.
DEFAULT_AUDIT_LOG_PATH = Path(
    os.getenv("AUDIT_LOG_PATH", "logs/audit_log.jsonl")
)

GENESIS_HASH = "0" * 64

ALLOWED_ROLES = frozenset(
    {
        "Sender",
        "Recipient",
        "Moderator",
        "Admin",
    }
)

ALLOWED_RESULTS = frozenset(
    {
        "SUCCESS",
        "DENIED",
        "FAILURE",
    }
)

# A fixed schema prevents identity, token, plaintext, and key fields from being added to audit events.
REQUIRED_FIELDS = frozenset(
    {
        "timestamp",
        "action",
        "role",
        "result",
        "round_id",
        "case_id",
        "previous_hash",
        "entry_hash",
    }
)

ACTION_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]*$")
WRITE_LOCK = Lock()


# Shared path, serialization, hashing, and validation helpers.
def resolve_log_path(log_path):
    if log_path is not None:
        return Path(log_path)

    return DEFAULT_AUDIT_LOG_PATH


def stable_json(data):
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def sha256_text(text):
    return hashlib.sha256(
        text.encode("utf-8")
    ).hexdigest()


def validate_event(
    action,
    role,
    result,
    round_id,
    case_id,
):
    if (
        not isinstance(action, str)
        or not ACTION_PATTERN.fullmatch(action)
    ):
        raise ValueError(
            "action must use uppercase letters, digits, "
            "and underscores"
        )

    if (
        not isinstance(role, str)
        or role not in ALLOWED_ROLES
    ):
        raise ValueError(
            f"role must be one of: {sorted(ALLOWED_ROLES)}"
        )

    if (
        not isinstance(result, str)
        or result not in ALLOWED_RESULTS
    ):
        raise ValueError(
            f"result must be one of: {sorted(ALLOWED_RESULTS)}"
        )

    if round_id is not None and (
        isinstance(round_id, bool)
        or not isinstance(round_id, int)
        or round_id <= 0
    ):
        raise ValueError(
            "round_id must be a positive integer or None"
        )

    if case_id is not None:
        if (
            not isinstance(case_id, str)
            or not case_id.strip()
        ):
            raise ValueError(
                "case_id must be a nonempty string or None"
            )

        # Reject line breaks so one field cannot inject extra log lines.
        if "\r" in case_id or "\n" in case_id:
            raise ValueError(
                "case_id must not contain line breaks"
            )


def is_sha256_hex(value):
    if (
        not isinstance(value, str)
        or len(value) != 64
    ):
        return False

    try:
        int(value, 16)
    except ValueError:
        return False

    return True


def last_entry_hash(path):
    if not path.exists():
        return GENESIS_HASH

    last_hash = GENESIS_HASH

    with path.open(
        "r",
        encoding="utf-8",
    ) as log_file:
        for raw_line in log_file:
            if raw_line.strip():
                event = json.loads(raw_line)
                last_hash = str(
                    event["entry_hash"]
                )

    return last_hash


# Append one validated event to the tamper-evident hash chain.
def write_audit_event(
    action,
    role,
    result,
    *,
    round_id=None,
    case_id=None,
    log_path=None,
):
    validate_event(
        action,
        role,
        result,
        round_id,
        case_id,
    )

    path = resolve_log_path(log_path)

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    # The lock prevents same-process threads from using the same previous hash for competing entries.
    with WRITE_LOCK:
        valid, message = verify_audit_log(path)

        if not valid:
            raise RuntimeError(
                "Refusing to append to an invalid audit log: "
                f"{message}"
            )

        payload = {
            "timestamp": datetime.now(UTC).isoformat(
                timespec="seconds"
            ),
            "action": action,
            "role": role,
            "result": result,
            "round_id": round_id,
            "case_id": case_id,
            "previous_hash": last_entry_hash(path),
        }

        event = {
            **payload,
            "entry_hash": sha256_text(
                stable_json(payload)
            ),
        }

        # Append one complete JSON object per line, then flush it.
        with path.open(
            "a",
            encoding="utf-8",
            newline="\n",
        ) as log_file:
            log_file.write(
                stable_json(event) + "\n"
            )
            log_file.flush()
            os.fsync(log_file.fileno())

    return event


# Verify event structure, timestamps, hash links, and entry hashes.
def verify_audit_log(log_path=None):
    path = resolve_log_path(log_path)

    if not path.exists():
        return (
            True,
            "Audit log is valid and contains 0 entries.",
        )

    previous_hash = GENESIS_HASH
    count = 0

    try:
        with path.open(
            "r",
            encoding="utf-8",
        ) as log_file:
            for line_number, raw_line in enumerate(
                log_file,
                start=1,
            ):
                if not raw_line.strip():
                    return (
                        False,
                        f"Blank line at line {line_number}.",
                    )

                try:
                    event = json.loads(raw_line)
                except json.JSONDecodeError as error:
                    return (
                        False,
                        "Invalid JSON at line "
                        f"{line_number}: {error.msg}.",
                    )

                if (
                    not isinstance(event, dict)
                    or set(event) != REQUIRED_FIELDS
                ):
                    return (
                        False,
                        "Invalid fields at line "
                        f"{line_number}.",
                    )

                try:
                    validate_event(
                        event["action"],
                        event["role"],
                        event["result"],
                        event["round_id"],
                        event["case_id"],
                    )
                except ValueError as error:
                    return (
                        False,
                        "Invalid event data at line "
                        f"{line_number}: {error}.",
                    )

                try:
                    timestamp = datetime.fromisoformat(
                        str(event["timestamp"])
                    )
                except ValueError:
                    return (
                        False,
                        "Invalid timestamp at line "
                        f"{line_number}.",
                    )

                if (
                    timestamp.tzinfo is None
                    or timestamp.utcoffset()
                    != timedelta(0)
                ):
                    return (
                        False,
                        "Timestamp is not UTC-aware at line "
                        f"{line_number}.",
                    )

                if (
                    not is_sha256_hex(
                        event["previous_hash"]
                    )
                    or not is_sha256_hex(
                        event["entry_hash"]
                    )
                ):
                    return (
                        False,
                        "Invalid hash format at line "
                        f"{line_number}.",
                    )

                if (
                    event["previous_hash"]
                    != previous_hash
                ):
                    return (
                        False,
                        "Hash-chain link mismatch at line "
                        f"{line_number}.",
                    )

                payload = {
                    key: value
                    for key, value in event.items()
                    if key != "entry_hash"
                }

                expected_hash = sha256_text(
                    stable_json(payload)
                )

                if (
                    event["entry_hash"]
                    != expected_hash
                ):
                    return (
                        False,
                        "Hash mismatch at line "
                        f"{line_number}.",
                    )

                previous_hash = str(
                    event["entry_hash"]
                )
                count += 1

    except OSError as error:
        return (
            False,
            f"Could not read audit log: {error}.",
        )

    return (
        True,
        f"Audit log is valid and contains {count} entries.",
    )


# Remove a local test or development audit log.
def reset_audit_log(log_path=None):
    path = resolve_log_path(log_path)

    with WRITE_LOCK:
        path.unlink(missing_ok=True)


# Verify the configured audit log when this file is run directly.
if __name__ == "__main__":
    is_valid, verification_message = (
        verify_audit_log()
    )

    print(verification_message)

    raise SystemExit(
        0 if is_valid else 1
    )
