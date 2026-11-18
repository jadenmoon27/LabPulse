-- Database schema for the anonymous messaging project.
-- This schema separates role accounts, anonymous token validation,
-- encrypted messages, moderation cases, and frozen source handles.

PRAGMA foreign_keys = ON;


-- People and their stable anonymous moderation handles.
CREATE TABLE IF NOT EXISTS people (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    display_name TEXT NOT NULL,

    lab_position TEXT NOT NULL CHECK (
        lab_position IN (
            'PI',
            'Professor',
            'Postdoc',
            'PhD Student',
            'Undergraduate'
        )
    ),

    abuse_handle_hash TEXT NOT NULL UNIQUE,

    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);


-- Role-specific login accounts.
CREATE TABLE IF NOT EXISTS accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    person_id INTEGER NOT NULL,

    username TEXT NOT NULL UNIQUE,

    password_hash TEXT NOT NULL,

    role TEXT NOT NULL CHECK (
        role IN (
            'Sender',
            'Recipient',
            'Moderator',
            'Admin'
        )
    ),

    public_key TEXT,
    public_key_fingerprint TEXT,

    inbox_tag TEXT UNIQUE,

    active INTEGER NOT NULL DEFAULT 1 CHECK (
        active IN (0, 1)
    ),

    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

    -- Only Recipient accounts receive inbox tags.
    CHECK (
        (role = 'Recipient' AND inbox_tag IS NOT NULL)
        OR
        (role != 'Recipient' AND inbox_tag IS NULL)
    ),

    FOREIGN KEY (person_id)
        REFERENCES people(id)
        ON DELETE CASCADE
);


-- Limit each person to one Sender, one Recipient, and one control role.
CREATE UNIQUE INDEX IF NOT EXISTS one_sender_per_person
ON accounts(person_id)
WHERE role = 'Sender';

CREATE UNIQUE INDEX IF NOT EXISTS one_recipient_per_person
ON accounts(person_id)
WHERE role = 'Recipient';

CREATE UNIQUE INDEX IF NOT EXISTS one_control_role_per_person
ON accounts(person_id)
WHERE role IN ('Admin', 'Moderator');

-- The encryption workflow uses one active Moderator public key.
CREATE UNIQUE INDEX IF NOT EXISTS one_active_moderator
ON accounts(role)
WHERE role = 'Moderator'
  AND active = 1;


-- Weekly message-collection rounds.
CREATE TABLE IF NOT EXISTS rounds (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    label TEXT NOT NULL UNIQUE,

    status TEXT NOT NULL DEFAULT 'OPEN' CHECK (
        status IN (
            'OPEN',
            'LOCKED',
            'RELEASED',
            'ARCHIVED'
        )
    ),

    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    released_at TEXT
);


-- Identity-linked ledger enforcing one issuance per Sender and round.
CREATE TABLE IF NOT EXISTS token_issuance (
    sender_account_id INTEGER NOT NULL,
    round_id INTEGER NOT NULL,
    issued_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (
        sender_account_id,
        round_id
    ),

    FOREIGN KEY (sender_account_id)
        REFERENCES accounts(id)
        ON DELETE CASCADE,

    FOREIGN KEY (round_id)
        REFERENCES rounds(id)
        ON DELETE CASCADE
);


-- Anonymous PulsePass validation records with no Sender identifier.
CREATE TABLE IF NOT EXISTS tokens (
    token_hash TEXT PRIMARY KEY,

    round_id INTEGER NOT NULL,

    status TEXT NOT NULL DEFAULT 'VALID' CHECK (
        status IN (
            'VALID',
            'USED',
            'EXPIRED',
            'FROZEN'
        )
    ),

    -- Moderator-encrypted anonymous source handle.
    sealed_abuse_handle BLOB,

    used_at TEXT,

    FOREIGN KEY (round_id)
        REFERENCES rounds(id)
        ON DELETE CASCADE
);


-- Encrypted message envelopes with no Sender identifier.
CREATE TABLE IF NOT EXISTS messages (
    message_id TEXT PRIMARY KEY,

    recipient_inbox_tag TEXT NOT NULL,

    round_id INTEGER NOT NULL,

    encrypted_aes_key BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    nonce BLOB NOT NULL,

    -- One anonymous token can authorize at most one message.
    token_hash TEXT NOT NULL UNIQUE,

    status TEXT NOT NULL DEFAULT 'QUEUED' CHECK (
        status IN (
            'QUEUED',
            'RELEASED',
            'FLAGGED'
        )
    ),

    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    released_at TEXT,

    FOREIGN KEY (recipient_inbox_tag)
        REFERENCES accounts(inbox_tag)
        ON UPDATE CASCADE
        ON DELETE RESTRICT,

    FOREIGN KEY (round_id)
        REFERENCES rounds(id)
        ON DELETE CASCADE,

    FOREIGN KEY (token_hash)
        REFERENCES tokens(token_hash)
        ON DELETE RESTRICT
);


-- One encrypted moderation case may be created for each message.
CREATE TABLE IF NOT EXISTS moderation_cases (
    case_id TEXT PRIMARY KEY,

    message_id TEXT NOT NULL UNIQUE,

    category TEXT NOT NULL CHECK (
        category IN (
            'Harassment',
            'Discrimination',
            'Identity-Revealing',
            'Spam',
            'Other'
        )
    ),

    encrypted_packet BLOB NOT NULL,

    sealed_abuse_handle BLOB NOT NULL,

    status TEXT NOT NULL DEFAULT 'OPEN' CHECK (
        status IN (
            'OPEN',
            'DISMISSED',
            'VIOLATION_CONFIRMED',
            'CLOSED'
        )
    ),

    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    resolved_at TEXT,

    FOREIGN KEY (message_id)
        REFERENCES messages(message_id)
        ON DELETE CASCADE
);


-- Anonymous source handles blocked from future token issuance.
CREATE TABLE IF NOT EXISTS frozen_handles (
    abuse_handle_hash TEXT PRIMARY KEY,

    reason TEXT NOT NULL DEFAULT 'Confirmed policy violation',

    frozen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);


-- Indexes for recurring token, inbox, and moderation lookups.
CREATE INDEX IF NOT EXISTS tokens_round_status_idx
ON tokens(round_id, status);

CREATE INDEX IF NOT EXISTS messages_inbox_status_idx
ON messages(recipient_inbox_tag, status);

CREATE INDEX IF NOT EXISTS moderation_cases_status_idx
ON moderation_cases(status);
