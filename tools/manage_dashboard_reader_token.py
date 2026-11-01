#!/usr/bin/env python3
"""Provision and manage opaque dashboard-reader credentials.

Run this with the database owner/setup identity, not the dashboard runtime
identity.  Plaintext tokens are printed exactly once by create/rotate.
"""

import argparse
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import dashboard_connector as connector
import db


def _connection(args):
    cfg = db.load_config(args.db_config, sqlite_fallback=args.db,
                         credentials_path=args.db_credentials)
    if args.initialize:
        db.initialize(cfg)
    return db.connect(cfg)


def main():
    parser = argparse.ArgumentParser(description="Manage mini-SIEM dashboard reader tokens")
    parser.add_argument("--db", default="siem.db", help="SQLite fallback path")
    parser.add_argument("--db-config", default=None)
    parser.add_argument("--db-credentials", default=None,
                        help="owner/setup PostgreSQL credential overlay")
    parser.add_argument("--initialize", action="store_true",
                        help="owner-only: initialize/upgrade connector tables first")
    sub = parser.add_subparsers(dest="command", required=True)

    create = sub.add_parser("create")
    create.add_argument("--principal", required=True)
    create.add_argument("--tenant", required=True)
    create.add_argument("--days", type=int, default=90)
    create.add_argument("--scope", action="append", dest="scopes")

    rotate = sub.add_parser("rotate")
    rotate.add_argument("token_id")
    rotate.add_argument("--days", type=int, default=90)
    rotate.add_argument("--overlap-hours", type=int, default=24)

    revoke = sub.add_parser("revoke")
    revoke.add_argument("token_id")
    sub.add_parser("list")

    args = parser.parse_args()
    conn = _connection(args)
    try:
        if args.command == "create":
            plain, token_id = connector.create_reader_token(
                conn, args.principal, args.tenant, args.scopes, args.days)
            print(json.dumps({"token_id": token_id, "token": plain,
                              "warning": "Store this token now; it cannot be recovered."}, indent=2))
        elif args.command == "rotate":
            plain, token_id = connector.rotate_reader_token(
                conn, args.token_id, args.days, args.overlap_hours)
            print(json.dumps({"token_id": token_id, "token": plain,
                              "warning": "Store this token now; it cannot be recovered."}, indent=2))
        elif args.command == "revoke":
            connector.revoke_reader_token(conn, args.token_id)
            print(json.dumps({"revoked": args.token_id}))
        else:
            rows = conn.execute(
                """SELECT id,principal_id,tenant_id,source_instance_id,token_prefix,
                          scopes_json,created_at,expires_at,revoked_at,rotation_group,last_used_at
                   FROM dashboard_reader_tokens ORDER BY created_at""").fetchall()
            print(json.dumps([dict(row) for row in rows], indent=2))
    finally:
        conn.close()


if __name__ == "__main__":
    main()
