"""
app/vault/secure_queries.py
==============================

EX-07, secure half. Same function, same purpose, as
app/insecure/sql_injection_demo.py -- compare them directly.
"""

import sqlite3


def find_user_by_username(db_path: str, username: str) -> list[tuple]:
    """
    Looks up a user by username using a parameterized query.

    THE FIX: the `?` placeholder tells the SQLite driver "this is DATA,
    not part of the query structure." The driver sends the query
    structure and the data to the database SEPARATELY -- the database
    compiles the query first, then substitutes the value in, so there is
    no way for `username` to change what the query DOES, no matter what
    string is passed in.

    Try the exact same attack string used against the vulnerable version:
        ' OR '1'='1
    Here, the database looks for a user whose username is LITERALLY the
    11-character string `' OR '1'='1` -- which doesn't exist, so this
    returns zero rows instead of every row in the table. The attack
    string is treated as inert data, not executable logic.

    This is the ONLY reliable defense against SQL injection. Escaping
    quotes yourself, blocklisting keywords like "OR" or "UNION", or
    "sanitizing" input are all incomplete -- attackers have repeatedly
    found bypasses for every hand-rolled escaping scheme. Parameterized
    queries close the vulnerability at the protocol level, not by trying
    to filter malicious-looking strings.
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # vvv THE FIX IS THIS ONE LINE vvv
    query = "SELECT id, username, email FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    # ^^^ the value is passed separately, never inserted into the string ^^^

    results = cursor.fetchall()
    conn.close()
    return results
