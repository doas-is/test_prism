# SecureBank API

A lightweight banking REST API built with Flask and SQLite.
Handles user accounts, transactions, and reporting.

## Setup

```bash
pip install -r requirements.txt
python run.py
```

## Endpoints

- `POST /auth/login` — Authenticate user
- `GET  /users/search` — Search users
- `GET  /reports/download` — Download account report
- `POST /admin/ping` — Ping remote host
- `POST /transactions/transfer` — Transfer funds
