"""
app/database.py
=================

Sets up the SQLAlchemy engine, session, and declarative base that every
model in this project inherits from.

WHY SQLITE FOR A "PRODUCTION-GRADE" PROJECT?
-----------------------------------------------
SQLite is a deliberate choice for a portfolio project, not a limitation:
it needs zero setup (no separate database server to install or configure),
which means anyone cloning this repo can run it in under a minute. The
*security patterns* here (parameterized queries, encryption at rest,
connection handling) are the same whether the engine underneath is SQLite,
PostgreSQL, or MySQL — SQLAlchemy's ORM abstracts that away. Swapping to
PostgreSQL later is a one-line change to DATABASE_URL, not a rewrite.
"""

import os
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

# The database file lives at the project root by default, but this can be
# overridden via the DATABASE_URL environment variable (e.g. to point at
# Postgres in a real deployment, or an in-memory DB for tests).
DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "vault.db"
DATABASE_URL = os.environ.get("DATABASE_URL", f"sqlite:///{DEFAULT_DB_PATH}")

# check_same_thread=False is required for SQLite specifically, because
# FastAPI can handle a single request across multiple threads. This has no
# equivalent (or need) on PostgreSQL/MySQL.
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    """Every ORM model (see app/models.py) inherits from this."""

    pass


def get_db():
    """
    FastAPI dependency that yields a database session and guarantees it's
    closed afterward, even if the request raises an exception. This
    pattern (yield, then cleanup in a finally block) is the standard way
    to manage any resource with a lifecycle in FastAPI -- not just
    databases.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
