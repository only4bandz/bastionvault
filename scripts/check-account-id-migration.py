#!/usr/bin/env python3
"""Read-only v4/v5 preflight for lowercase account-id migration."""

from __future__ import annotations

import json
import sqlite3
import sys
import tempfile
from pathlib import Path


def inspect(database: Path) -> dict[str, int]:
    database = database.resolve(strict=True)
    connection = sqlite3.connect(f"{database.as_uri()}?mode=ro", uri=True)
    try:
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        if version not in (4, 5):
            raise ValueError(f"unsupported schema version {version}; expected 4 or 5")
        account_collisions = connection.execute(
            """
            SELECT COUNT(*) FROM (
              SELECT lower(email) AS canonical
                FROM accounts
               GROUP BY canonical
              HAVING COUNT(*)>1
            )
            """
        ).fetchone()[0]
        challenge_collisions = connection.execute(
            """
            SELECT COUNT(*) FROM (
              SELECT lower(c.email) AS canonical
                FROM registration_challenges c
               WHERE NOT EXISTS(
                 SELECT 1 FROM accounts a WHERE lower(a.email)=lower(c.email)
               )
               GROUP BY canonical
              HAVING COUNT(*)>1
            )
            """
        ).fetchone()[0]
        noncanonical_accounts = connection.execute(
            "SELECT COUNT(*) FROM accounts WHERE email<>lower(email)"
        ).fetchone()[0]
        noncanonical_challenges = connection.execute(
            """
            SELECT COUNT(*) FROM registration_challenges c
             WHERE c.email<>lower(c.email)
               AND NOT EXISTS(
                 SELECT 1 FROM accounts a WHERE lower(a.email)=lower(c.email)
               )
            """
        ).fetchone()[0]
        return {
            "schema_version": version,
            "account_case_collisions": account_collisions,
            "challenge_case_collisions": challenge_collisions,
            "noncanonical_accounts": noncanonical_accounts,
            "noncanonical_challenges": noncanonical_challenges,
        }
    finally:
        connection.close()


def self_test() -> None:
    with tempfile.TemporaryDirectory(prefix="bastion-account-id-preflight-") as directory:
        database = Path(directory) / "bastion.db"
        connection = sqlite3.connect(database)
        connection.executescript(
            """
            PRAGMA user_version=4;
            CREATE TABLE accounts(email TEXT PRIMARY KEY);
            CREATE TABLE registration_challenges(email TEXT PRIMARY KEY);
            INSERT INTO accounts VALUES('Alice@Example.COM');
            INSERT INTO registration_challenges VALUES('Proof@Example.COM');
            """
        )
        connection.commit()
        connection.close()

        result = inspect(database)
        assert result["account_case_collisions"] == 0
        assert result["challenge_case_collisions"] == 0
        assert result["noncanonical_accounts"] == 1
        assert result["noncanonical_challenges"] == 1

        connection = sqlite3.connect(database)
        connection.execute("INSERT INTO accounts VALUES('alice@example.com')")
        connection.execute(
            "INSERT INTO registration_challenges VALUES('proof@example.com')"
        )
        connection.commit()
        connection.close()
        result = inspect(database)
        assert result["account_case_collisions"] == 1
        assert result["challenge_case_collisions"] == 1
    print("Account-id migration preflight self-test passed.")


def main() -> int:
    if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
        self_test()
        return 0
    if len(sys.argv) != 2:
        print(f"usage: {Path(sys.argv[0]).name} <database>", file=sys.stderr)
        return 2
    try:
        result = inspect(Path(sys.argv[1]))
    except (OSError, sqlite3.Error, ValueError) as error:
        print(f"account-id migration preflight failed: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    if result["account_case_collisions"] or result["challenge_case_collisions"]:
        print(
            "account-id migration is blocked by case-fold collisions; "
            "no records were modified",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
