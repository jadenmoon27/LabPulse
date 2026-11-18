# LabPulse

LabPulse is a local implementation of the WhisperChain+ assignment. It supports anonymous encrypted messages, role-based access control, moderation, and audit logging.

## Main features

- Sender, Recipient, Moderator, and Admin roles
- One PulsePass per Sender per round
- Encrypted messages stored on the server
- Local message decryption by the Recipient
- Recipient flagging and Moderator review
- Anonymous source freezing after confirmed abuse
- Audit logging without Sender identity

## Files

```text
app.py                  Main Flask application
auth.py                 Login and role checks
audit.py                Audit-log writing and verification
db.py                   Database setup
schema.sql              SQLite schema
rounds_tokens.py        Rounds and PulsePass issuance
crypto_utils.py         Encryption and key functions
messaging.py            Message routes
moderation.py           Flagging and moderation routes
client.py               Key setup, sending, and inbox commands
moderation_client.py    Flagging and Moderator commands
seed_demo.py            Demo accounts
```

## Setup

Create and activate the virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install the packages:

```bash
python -m pip install -r requirements.txt
```

Create the environment file:

```bash
cp .env.example .env
```

Use this format in .env:

```text
FLASK_SECRET_KEY=replace-with-a-random-secret
DATABASE_PATH=data/labpulse.db
AUDIT_LOG_PATH=logs/audit_log.jsonl
```

Generate a Flask secret with:

```bash
python -c 'import secrets; print(secrets.token_hex(32))'
```

Paste the result into FLASK_SECRET_KEY.

## Reset the demo

Delete old private-key files:

```bash
find keys -maxdepth 1 -type f -name '*.pem' -delete
```

Create a fresh database and demo accounts:

```bash
python seed_demo.py
```

All demo accounts use this account password:

```text
Password123!
```

Main accounts:

| Username | Role |
|---|---|
| pi.admin | Admin |
| undergrad.sender | Sender |
| phd.recipient | Recipient |
| postdoc.moderator | Moderator |

The account password logs in to the server. The private-key password is chosen during key setup and protects a local PEM file.

## Start the server

In Terminal 1:

```bash
source .venv/bin/activate
python app.py
```

The server runs at:

```text
http://127.0.0.1:5001
```

In Terminal 2:

```bash
source .venv/bin/activate
SERVER="http://127.0.0.1:5001"
```

Check the server:

```bash
curl -sS "$SERVER/health" | python -m json.tool
```

## Demo

### 1. Register the Moderator key

```bash
python client.py setup-key postdoc.moderator
```

Use Password123! as the account password. Choose a local private-key password.

### 2. Register the Recipient key

```bash
python client.py setup-key phd.recipient
```

Use Password123! as the account password. Choose a local private-key password.

### 3. Log in as Admin

```bash
curl -sS   -c /tmp/labpulse-admin.txt   -H "Content-Type: application/json"   -d '{
    "username": "pi.admin",
    "password": "Password123!"
  }'   "$SERVER/auth/login"   | python -m json.tool
```

### 4. Open Week 1

```bash
curl -sS   -b /tmp/labpulse-admin.txt   -H "Content-Type: application/json"   -d '{"label": "Week 1"}'   "$SERVER/admin/rounds"   | python -m json.tool
```

After a fresh reset, the round ID is 1.

### 5. Log in as Sender

```bash
curl -sS   -c /tmp/labpulse-sender.txt   -H "Content-Type: application/json"   -d '{
    "username": "undergrad.sender",
    "password": "Password123!"
  }'   "$SERVER/auth/login"   | python -m json.tool
```

### 6. Request a PulsePass

```bash
curl -sS   -b /tmp/labpulse-sender.txt   -X POST   "$SERVER/sender/tokens"   | python -m json.tool
```

Copy the pulsepass value.

### 7. Send a message

```bash
python client.py send undergrad.sender
```

Enter the account password, PulsePass, Recipient number, and message.

### 8. Lock and release the round

```bash
curl -sS   -b /tmp/labpulse-admin.txt   -X PATCH   -H "Content-Type: application/json"   -d '{"status": "LOCKED"}'   "$SERVER/admin/rounds/1/status"   | python -m json.tool
```

```bash
curl -sS   -b /tmp/labpulse-admin.txt   -X PATCH   -H "Content-Type: application/json"   -d '{"status": "RELEASED"}'   "$SERVER/admin/rounds/1/status"   | python -m json.tool
```

### 9. Read the message

```bash
python client.py inbox phd.recipient
```

Enter the account password and the Recipient private-key password.

### 10. Flag the message

```bash
python moderation_client.py flag phd.recipient
```

Select the message and category.

### 11. Review the case

```bash
python moderation_client.py moderate postdoc.moderator
```

Select the case and decision.

## Audit log

Verify the live audit log:

```bash
python audit.py
```

The live log is stored at:

```text
logs/audit_log.jsonl
```

The submitted sample is stored at:

```text
samples/audit_log_sample.jsonl
```

The audit log does not store the Sender username, plaintext message, raw PulsePass, password, or private key.

## Sources I used for coding
Flask documentation — routes, requests, sessions, decorators, and testing
https://flask.palletsprojects.com/

Werkzeug security helpers — password hashing and password verification
https://werkzeug.palletsprojects.com/en/stable/utils/#module-werkzeug.security

Python documentation — sqlite3, secrets, hashlib, json, and pathlib
https://docs.python.org/3/

SQLite documentation — tables, constraints, foreign keys, indexes, and transactions
https://www.sqlite.org/docs.html

Python cryptography documentation — RSA, RSA-OAEP, key serialization, and AES-GCM
https://cryptography.io/en/stable/

pytest documentation — fixtures, temporary files, assertions, and exception testing
https://docs.pytest.org/