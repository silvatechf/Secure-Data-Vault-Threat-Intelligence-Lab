"""
app/insecure/sql_injection_demo.py
=====================================

EX-07, vulnerable half. See app/vault/secure_queries.py for the fixed
version of the exact same function -- read them side by side.

*** THIS CODE IS INTENTIONALLY BROKEN. NEVER DEPLOY THIS. ***
It exists for one reason: you cannot fully understand why parameterized
queries matter until you've seen the raw string concatenation that makes
SQL injection possible, and proven to yourself that it works. See
docs/week-01-02-foundation.md for a guided walkthrough with a real attack
string, and tests/test_sql_injection.py for a test that proves this
function is exploitable (and that the fixed version in app/vault/ is not).
"""

import sqlite3


def find_user_by_username_VULNERABLE(db_path: str, username: str) -> list[tuple]:
    """
    Looks up a user by username using raw f-string interpolation.

    THE BUG: `username` is inserted directly into the SQL string. The
    database can't tell the difference between "data" and "code" here --
    anything the caller passes becomes part of the query itself.

    THE ATTACK: pass this as `username`:
        ' OR '1'='1

    The query becomes:
        SELECT * FROM users WHERE username = '' OR '1'='1'

    `'1'='1'` is always true, so the WHERE clause matches EVERY row in the
    table, regardless of what username was actually being searched for.
    A real attacker could go further and use a UNION SELECT to pull data
    out of a completely different table, or a stacked query to modify
    data -- this demo keeps it to the classic auth-bypass example because
    it's the clearest illustration of the core problem: user input
    became part of the query's logic, not just its data.
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # vvv THE VULNERABILITY IS THIS ONE LINE vvv
    query = f"SELECT id, username, email FROM users WHERE username = '{username}'"
    # ^^^ never build SQL by inserting a variable into the string ^^^

    cursor.execute(query)
    results = cursor.fetchall()
    conn.close()
    return results
